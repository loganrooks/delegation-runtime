"""Versioned policy validation, private-binding detachment, and identities.

Standard library only. See ``docs/proposals/2026-07-20-composable-claude-
capability-and-scope-policy.md`` section 18 for the normative schema this
module implements.
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping


class PolicyValidationError(ValueError):
    """The requested policy cannot be normalized without guessing."""


@dataclass(frozen=True)
class PrivateBinding:
    binding_id: str
    kind: str
    resolved_path: Path
    lineage_identity: str | None


@dataclass(frozen=True)
class CompiledPolicy:
    document: dict[str, object]
    semantic_sha256: str
    authority_sha256: str
    authority_grants: frozenset[str]
    authority_denies: frozenset[str]
    private_bindings: tuple[PrivateBinding, ...]
    unresolved_dimensions: tuple[str, ...]
    cache_inputs_complete: bool


TOP_LEVEL = {
    "schema_version", "profile", "model_inputs", "context", "runtime",
    "filesystem", "tools", "mcp", "commands", "network", "git",
    "host_effects", "installation", "descendants", "output", "sandbox",
    "resources", "lifecycle", "notices", "confirmation",
}
NOTICE_MODES = {"always", "once", "never"}
CONFIRMATION_MODES = {"ask", "never"}
MCP_MODES = {"deny", "readonly", "selected", "unrestricted", "unavailable"}
COMMAND_MODES = {"deny", "selected", "unrestricted", "unavailable"}
HOST_EFFECT_MODES = {"deny", "selected", "unrestricted", "unavailable"}
HOST_EFFECT_OPERATIONS = {
    "process-signal", "process-debug", "unix-socket", "service-control",
    "device-control", "application-automation",
}
NETWORK_MODES = {"deny", "allowlist", "unrestricted"}
SANDBOX_MODES = {"off", "preferred", "required"}
SANDBOX_UNAVAILABLE = {"fail", "warn-and-run", "run"}
LIMIT_MODES = {"unavailable", "bounded", "unbounded"}
ASSURANCE = {"os-enforced", "claude-enforced", "manager-controlled", "detected", "unknown"}
SUPPORTED_SCHEMA_VERSIONS = frozenset({1})

_FILESYSTEM_OPERATIONS = {"read", "write"}
_ALLOW_EFFECTS = {"allow", "hard-deny"}
_TARGET_ID_RE = __import__("re").compile(r"^[A-Za-z][A-Za-z0-9_-]*$")

_COMMAND_TEMPLATE_FIELDS = {
    "id", "revision", "argv", "cwd_scope", "environment", "stdin",
    "write_scopes", "wall_time_seconds", "shared_log_bytes", "per_file_bytes",
    "network", "sandbox", "evidence_id",
}
_COMMAND_SANDBOX_MODES = {"required", "preferred", "outside"}
_STDIN_MODES = {"closed", "inherit"}
_ROOT_KINDS = {"project", "scratch", "output", "state", "external", "owned"}
_ACTIVATION_MODES = {"available", "unavailable", "unknown"}
_CAPABILITY_MODES = {"deny", "allow", "unavailable"}
_OUTPUT_MODES = {"manager", "worker", "unavailable"}
_LIFECYCLE_RESUME_MODES = {"allow", "deny", "unavailable"}
_LIFECYCLE_RECOVERY_MODES = {"foreground", "background", "unavailable"}


def _default_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "profile": {"id": "custom", "preset_revision": None, "legacy_contract_version": None},
        "model_inputs": {"model": None, "effort": None, "system_input_hashes": []},
        "context": {"objective_hash": None, "workspace_identity": None, "source_identity_hashes": []},
        "runtime": {"provider": "claude-code", "version": None, "activation": "unavailable"},
        "filesystem": {"defaults": {"read": "deny", "write": "deny"}, "roots": {}, "rules": []},
        "tools": {"builtins": [], "deny": []},
        "mcp": {"mode": "deny", "servers": [], "selected_tools": []},
        "commands": {"mode": "deny", "templates": []},
        "network": {"subprocess": "deny", "mcp_open_world": "deny", "allowed_destinations": []},
        "host_effects": {"mode": "deny", "grants": []},
        "git": {"mutation": "deny"},
        "installation": {"mode": "deny"},
        "descendants": {"mode": "deny"},
        "output": {"mode": "manager", "roots": []},
        "sandbox": {"mode": "off", "unavailable": "fail", "unsandboxed_commands": []},
        "resources": {
            "wall_time_seconds": {"mode": "unavailable", "value": None},
            "process_count": {"mode": "unavailable", "value": None},
            "memory_bytes": {"mode": "unavailable", "value": None},
            "log_bytes": {"mode": "unavailable", "value": None},
            "generated_state_bytes": {"mode": "unavailable", "value": None},
            "generated_state_admission_bytes": {"mode": "unavailable", "value": None},
        },
        "lifecycle": {"resume": "allow", "recovery": "foreground"},
        "notices": {
            "profile_transition": "always",
            "cache_impact": "always",
            "authority_change": "always",
            "context_change": "always",
            "runtime_change": "always",
            "sandbox_change": "always",
        },
        "confirmation": {
            "profile_transition": "never",
            "authority_expansion": "ask",
            "unsandboxed_command": "ask",
        },
    }


def _require_keys(section_name: str, raw: Mapping[str, object], allowed: set[str]) -> None:
    if not isinstance(raw, Mapping):
        raise PolicyValidationError(f"{section_name} must be an object")
    unknown = set(raw) - allowed
    if unknown:
        raise PolicyValidationError(f"{section_name} has unknown field(s): {sorted(unknown)}")


def _merge_section(default: dict, raw: Mapping[str, object] | None, section_name: str) -> dict:
    if raw is None:
        return copy.deepcopy(default)
    _require_keys(section_name, raw, set(default))
    merged = copy.deepcopy(default)
    merged.update(copy.deepcopy(dict(raw)))
    return merged


def _validate_limit(name: str, value: object) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {"mode", "value"}:
        raise PolicyValidationError(f"resources.{name} must be {{mode, value}}")
    mode = value["mode"]
    amount = value["value"]
    if not isinstance(mode, str) or mode not in LIMIT_MODES:
        raise PolicyValidationError(f"resources.{name} has unknown mode: {mode!r}")
    if mode == "bounded":
        if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
            raise PolicyValidationError(f"resources.{name} bounded requires a positive integer")
    else:
        if amount is not None:
            raise PolicyValidationError(f"resources.{name} {mode} requires a null value")
    return {"mode": mode, "value": amount}


def _validate_notices(raw: dict) -> dict:
    for key, value in raw.items():
        if not isinstance(value, str) or value not in NOTICE_MODES:
            raise PolicyValidationError(f"notices.{key} has invalid mode: {value!r}")
    return raw


def _validate_confirmation(raw: dict) -> dict:
    for key, value in raw.items():
        if not isinstance(value, str) or value not in CONFIRMATION_MODES:
            raise PolicyValidationError(f"confirmation.{key} has invalid mode: {value!r}")
    return raw


def _require_string(value: object, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise PolicyValidationError(f"{name} must be a {'non-empty ' if not allow_empty else ''}string")
    return value


def _string_set(value: object, name: str, *, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list):
        raise PolicyValidationError(f"{name} must be a list of strings")
    result: set[str] = set()
    for item in value:
        result.add(_require_string(item, name))
    if not allow_empty and not result:
        raise PolicyValidationError(f"{name} must not be empty")
    return sorted(result)


def _string_mapping(value: object, name: str) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise PolicyValidationError(f"{name} must be an object mapping strings to strings")
    result: dict[str, str] = {}
    for key, item in value.items():
        key_text = _require_string(key, f"{name} key")
        result[key_text] = _require_string(item, f"{name}.{key_text}", allow_empty=True)
    return {key: result[key] for key in sorted(result)}


def _validate_profile(raw: dict) -> dict[str, object]:
    _require_string(raw["id"], "profile.id")
    for field in ("preset_revision", "legacy_contract_version"):
        value = raw[field]
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            raise PolicyValidationError(f"profile.{field} must be a non-negative integer or null")
    return raw


def _validate_model_inputs(raw: dict) -> dict[str, object]:
    for field in ("model", "effort"):
        value = raw[field]
        if value is not None:
            _require_string(value, f"model_inputs.{field}")
    raw["system_input_hashes"] = _string_set(raw["system_input_hashes"], "model_inputs.system_input_hashes")
    return raw


def _validate_context(raw: dict) -> dict[str, object]:
    for field in ("objective_hash", "workspace_identity"):
        value = raw[field]
        if value is not None:
            _require_string(value, f"context.{field}")
    raw["source_identity_hashes"] = _string_set(raw["source_identity_hashes"], "context.source_identity_hashes")
    return raw


def _validate_runtime(raw: dict) -> dict[str, object]:
    _require_string(raw["provider"], "runtime.provider")
    if raw["version"] is not None:
        _require_string(raw["version"], "runtime.version")
    if not isinstance(raw["activation"], str) or raw["activation"] not in _ACTIVATION_MODES:
        raise PolicyValidationError(f"runtime.activation has invalid mode: {raw['activation']!r}")
    return raw


def _validate_tools(raw: dict) -> dict[str, object]:
    raw["builtins"] = _string_set(raw["builtins"], "tools.builtins")
    raw["deny"] = _string_set(raw["deny"], "tools.deny")
    return raw


def _validate_network(raw: dict) -> dict[str, object]:
    for field in ("subprocess", "mcp_open_world"):
        if not isinstance(raw[field], str) or raw[field] not in NETWORK_MODES:
            raise PolicyValidationError(f"network.{field} has invalid mode: {raw[field]!r}")
    raw["allowed_destinations"] = _string_set(raw["allowed_destinations"], "network.allowed_destinations")
    return raw


def _validate_mcp(raw: dict) -> dict[str, object]:
    if not isinstance(raw["mode"], str) or raw["mode"] not in MCP_MODES:
        raise PolicyValidationError(f"mcp.mode invalid: {raw['mode']!r}")
    raw["servers"] = _string_set(raw["servers"], "mcp.servers")
    raw["selected_tools"] = _string_set(raw["selected_tools"], "mcp.selected_tools")
    return raw


def _validate_capability_section(raw: dict, section: str) -> dict[str, object]:
    if not isinstance(raw["mode"], str) or raw["mode"] not in _CAPABILITY_MODES:
        raise PolicyValidationError(f"{section}.mode has invalid mode: {raw['mode']!r}")
    return raw


def _validate_command_template(raw: object, declared_scopes: set[str]) -> dict:
    if not isinstance(raw, Mapping):
        raise PolicyValidationError("command template must be an object")
    unknown = set(raw) - _COMMAND_TEMPLATE_FIELDS
    if unknown:
        raise PolicyValidationError(f"command template has unknown field(s): {sorted(unknown)}")
    missing = _COMMAND_TEMPLATE_FIELDS - set(raw)
    if missing:
        raise PolicyValidationError(f"command template missing field(s): {sorted(missing)}")
    template = copy.deepcopy(dict(raw))
    _require_string(template["id"], "command template id")
    if (
        not isinstance(template["revision"], int)
        or isinstance(template["revision"], bool)
        or template["revision"] <= 0
    ):
        raise PolicyValidationError("command template revision must be a positive integer")
    if not isinstance(template["argv"], list) or not template["argv"] or any(
        not isinstance(arg, str) or not arg for arg in template["argv"]
    ):
        raise PolicyValidationError("command template argv must be a non-empty list of non-empty strings")
    if not isinstance(template["cwd_scope"], str) or template["cwd_scope"] not in declared_scopes:
        raise PolicyValidationError(
            f"command template cwd_scope must reference a declared root: {template['cwd_scope']!r}"
        )
    env = template["environment"]
    if not isinstance(env, Mapping) or set(env) != {"fixed", "pass"}:
        raise PolicyValidationError("command template environment must be {fixed, pass}")
    env_fixed = _string_mapping(env["fixed"], "command template environment.fixed")
    env_pass = _string_set(env["pass"], "command template environment.pass")
    template["environment"] = {"fixed": env_fixed, "pass": env_pass}
    if not isinstance(template["stdin"], str) or template["stdin"] not in _STDIN_MODES:
        raise PolicyValidationError(f"command template stdin invalid: {template['stdin']!r}")
    template["write_scopes"] = _string_set(template["write_scopes"], "command template write_scopes")
    for scope in template["write_scopes"]:
        if scope not in declared_scopes:
            raise PolicyValidationError(
                f"command template write_scopes must reference declared roots: {scope!r}"
            )
    for field in ("wall_time_seconds", "shared_log_bytes", "per_file_bytes"):
        value = template[field]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise PolicyValidationError(f"command template {field} must be a positive integer")
    network = template["network"]
    if not isinstance(network, Mapping) or set(network) != {"mode", "destinations"}:
        raise PolicyValidationError("command template network must be {mode, destinations}")
    if not isinstance(network["mode"], str) or network["mode"] not in NETWORK_MODES:
        raise PolicyValidationError(f"command template network mode invalid: {network['mode']!r}")
    destinations = _string_set(network["destinations"], "command template network.destinations")
    network = {"mode": network["mode"], "destinations": destinations}
    if network["mode"] == "allowlist" and not destinations:
        network = {"mode": "deny", "destinations": []}
        template["network"] = network
    else:
        template["network"] = network
    if not isinstance(template["sandbox"], str) or template["sandbox"] not in _COMMAND_SANDBOX_MODES:
        raise PolicyValidationError(f"command template sandbox invalid: {template['sandbox']!r}")
    _require_string(template["evidence_id"], "command template evidence_id")
    return template


def _authority_template_hash(template: Mapping[str, object]) -> str:
    projection = {key: value for key, value in template.items() if key != "evidence_id"}
    return _sha256_json(projection)


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def normalize_policy(raw: Mapping[str, object]) -> CompiledPolicy:
    if not isinstance(raw, Mapping):
        raise PolicyValidationError("policy must be an object")
    unknown = set(raw) - TOP_LEVEL
    if unknown:
        raise PolicyValidationError(f"unknown top-level field(s): {sorted(unknown)}")
    for field, value in raw.items():
        if field != "schema_version" and value is None:
            raise PolicyValidationError(f"{field} must be an object, not null")

    schema_version = raw.get("schema_version", 1)
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise PolicyValidationError(f"unsupported schema_version: {schema_version!r}")

    default = _default_document()
    document: dict[str, object] = {"schema_version": schema_version}

    for section in (
        "profile", "model_inputs", "context", "runtime", "tools", "network",
        "git", "installation", "descendants", "lifecycle",
    ):
        document[section] = _merge_section(default[section], raw.get(section), section)

    _validate_profile(document["profile"])
    _validate_model_inputs(document["model_inputs"])
    _validate_context(document["context"])
    _validate_runtime(document["runtime"])
    _validate_tools(document["tools"])

    document["notices"] = _validate_notices(
        _merge_section(default["notices"], raw.get("notices"), "notices")
    )
    document["confirmation"] = _validate_confirmation(
        _merge_section(default["confirmation"], raw.get("confirmation"), "confirmation")
    )

    _validate_network(document["network"])
    if document["network"]["subprocess"] == "allowlist" and not document["network"]["allowed_destinations"]:
        document["network"]["subprocess"] = "deny"
    if document["network"]["mcp_open_world"] == "allowlist" and not document["network"]["allowed_destinations"]:
        document["network"]["mcp_open_world"] = "deny"

    private_bindings: list[PrivateBinding] = []
    deny_binding_paths: dict[str, Path] = {}
    unresolved: list[str] = []
    if "runtime" in raw and document["runtime"]["activation"] == "unavailable":
        unresolved.append("runtime.activation")

    # --- filesystem: roots and private bindings ---
    fs_raw = raw.get("filesystem", {})
    _require_keys("filesystem", fs_raw, {"defaults", "roots", "rules"})
    if "defaults" in fs_raw and fs_raw["defaults"] is None:
        raise PolicyValidationError("filesystem.defaults must be an object")
    defaults = _merge_section(default["filesystem"]["defaults"], fs_raw.get("defaults"), "filesystem.defaults")
    for op, value in defaults.items():
        if not isinstance(value, str) or value not in ("allow", "deny"):
            raise PolicyValidationError(f"filesystem.defaults.{op} must be allow or deny")

    declared_roots: dict[str, str] = {}
    root_bindings: dict[str, str] = {}
    roots_raw = fs_raw.get("roots", {})
    if not isinstance(roots_raw, Mapping):
        raise PolicyValidationError("filesystem.roots must be an object")
    for root_id, root_raw in roots_raw.items():
        _require_string(root_id, "filesystem root id")
        if not isinstance(root_raw, Mapping) or set(root_raw) != {"kind", "binding"}:
            raise PolicyValidationError(f"filesystem.roots.{root_id} must be {{kind, binding}}")
        kind = root_raw["kind"]
        binding = root_raw["binding"]
        if not isinstance(kind, str) or kind not in _ROOT_KINDS:
            raise PolicyValidationError(f"filesystem.roots.{root_id} has invalid kind: {kind!r}")
        if binding not in (None, "unbound") and (
            not isinstance(binding, (str, Path)) or not str(binding)
        ):
            raise PolicyValidationError(f"filesystem.roots.{root_id}.binding must be a path string or unbound")
        declared_roots[root_id] = kind
        if binding in (None, "unbound"):
            root_bindings[root_id] = "unbound"
        else:
            private_bindings.append(
                PrivateBinding(
                    binding_id=root_id, kind="root",
                    resolved_path=Path(binding), lineage_identity=None,
                )
            )
            root_bindings[root_id] = "bound"

    rules_raw = fs_raw.get("rules", [])
    if not isinstance(rules_raw, list):
        raise PolicyValidationError("filesystem.rules must be a list")
    canonical_rules: list[dict[str, object]] = []
    fs_grants: set[str] = set()
    fs_denies: set[str] = set()
    for rule in rules_raw:
        if not isinstance(rule, Mapping):
            raise PolicyValidationError("filesystem rule must be an object")
        if set(rule) - {"operations", "scope", "path", "effect", "rule_id"}:
            raise PolicyValidationError(f"filesystem rule has unknown field(s): {sorted(set(rule) - {'operations', 'scope', 'path', 'effect', 'rule_id'})}")
        operations = tuple(_string_set(rule.get("operations"), "filesystem rule operations", allow_empty=False))
        if not set(operations).issubset(_FILESYSTEM_OPERATIONS):
            raise PolicyValidationError(f"filesystem rule has invalid operations: {operations!r}")
        effect = rule.get("effect")
        if effect not in _ALLOW_EFFECTS:
            raise PolicyValidationError(f"filesystem rule has invalid effect: {effect!r}")
        has_scope = "scope" in rule
        has_path = "path" in rule
        if has_scope and has_path:
            raise PolicyValidationError("filesystem rule cannot use both scope and path")
        if effect == "allow":
            if not has_scope:
                raise PolicyValidationError("allow rule must use a declared scope, not a raw path")
            scope = _require_string(rule["scope"], "filesystem rule scope")
            if scope not in declared_roots:
                raise PolicyValidationError(f"allow rule references undeclared scope: {scope!r}")
            for op in operations:
                fs_grants.add(f"filesystem.{op}:{scope}")
            canonical_rules.append({"operations": list(operations), "scope": scope, "effect": effect})
        else:  # hard-deny
            if has_scope:
                scope = _require_string(rule["scope"], "filesystem rule scope")
                if scope not in declared_roots:
                    raise PolicyValidationError(f"deny rule references undeclared scope: {scope!r}")
                for op in operations:
                    fs_denies.add(f"filesystem.{op}.deny:{scope}")
                canonical_rules.append({"operations": list(operations), "scope": scope, "effect": effect})
            else:
                if not has_path:
                    raise PolicyValidationError("deny rule must use scope or path")
                rule_id = rule.get("rule_id")
                if not isinstance(rule_id, str) or not rule_id:
                    raise PolicyValidationError("raw-path deny requires a stable rule_id")
                path = rule.get("path")
                if not isinstance(path, (str, Path)) or not str(path):
                    raise PolicyValidationError("raw-path deny requires a non-empty path string")
                resolved_path = Path(path)
                previous_path = deny_binding_paths.get(rule_id)
                if previous_path is not None and previous_path != resolved_path:
                    raise PolicyValidationError(
                        f"raw-path deny rule_id is bound to conflicting paths: {rule_id!r}"
                    )
                if previous_path is None:
                    deny_binding_paths[rule_id] = resolved_path
                    private_bindings.append(
                        PrivateBinding(
                            binding_id=rule_id, kind="deny-rule",
                            resolved_path=resolved_path, lineage_identity=None,
                        )
                    )
                for op in operations:
                    fs_denies.add(f"filesystem.{op}.deny:{rule_id}")
                canonical_rules.append(
                    {"operations": list(operations), "rule_id": rule_id, "path": "private-selector", "effect": effect}
                )

    canonical_rules = sorted(
        {
            json.dumps(rule, sort_keys=True, separators=(",", ":")): rule
            for rule in canonical_rules
        }.values(),
        key=lambda rule: json.dumps(rule, sort_keys=True, separators=(",", ":")),
    )
    document["filesystem"] = {
        "defaults": defaults,
        "roots": {rid: {"kind": kind, "binding": root_bindings[rid]} for rid, kind in sorted(declared_roots.items())},
        "rules": canonical_rules,
    }

    # A non-deny operation default is an authority atom in its own right. The
    # implicit deny defaults intentionally remain absent from deny atoms so an
    # empty policy retains an empty authority set while deny->allow transitions
    # are still directional.
    for operation, value in defaults.items():
        if value == "allow":
            fs_grants.add(f"filesystem.default.{operation}:allow")

    # --- tools ---
    grants: set[str] = set(fs_grants)
    denies: set[str] = set(fs_denies)
    for name in document["tools"]["builtins"]:
        grants.add(f"tools.builtin:{name}")
    for name in document["tools"]["deny"]:
        denies.add(f"tools.deny:{name}")

    # --- mcp ---
    mcp_raw = _merge_section(default["mcp"], raw.get("mcp"), "mcp")
    _validate_mcp(mcp_raw)
    if mcp_raw["mode"] == "selected":
        if not mcp_raw["selected_tools"]:
            raise PolicyValidationError("mcp.mode selected requires selected_tools")
        if not mcp_raw["servers"]:
            raise PolicyValidationError("mcp.mode selected requires at least one declared server")
        for tool in mcp_raw["selected_tools"]:
            if not any(tool.startswith(f"mcp__{server}__") for server in mcp_raw["servers"]):
                raise PolicyValidationError(f"mcp selected tool does not match a declared server: {tool!r}")
        for tool in mcp_raw["selected_tools"]:
            grants.add(f"mcp.tool:{tool}")
    elif mcp_raw["mode"] == "readonly":
        grants.add("mcp.mode:readonly")
        unresolved.append("mcp.registry")
    elif mcp_raw["mode"] == "unavailable":
        unresolved.append("mcp.activation")
    elif mcp_raw["mode"] == "unrestricted":
        grants.add("mcp.mode:unrestricted")
    document["mcp"] = mcp_raw

    # --- commands ---
    commands_raw = _merge_section(default["commands"], raw.get("commands"), "commands")
    if not isinstance(commands_raw["mode"], str) or commands_raw["mode"] not in COMMAND_MODES:
        raise PolicyValidationError(f"commands.mode invalid: {commands_raw['mode']!r}")
    declared_scopes = set(declared_roots)
    templates = []
    seen_ids: dict[str, str] = {}
    template_hashes: dict[str, str] = {}
    if not isinstance(commands_raw.get("templates"), list):
        raise PolicyValidationError("commands.templates must be a list")
    for template_raw in commands_raw.get("templates"):
        template = _validate_command_template(template_raw, declared_scopes)
        template_hash = _authority_template_hash(template)
        template_id = template["id"]
        if template_id in seen_ids and seen_ids[template_id] != template_hash:
            raise PolicyValidationError(f"duplicate command template id with different authority: {template_id!r}")
        seen_ids[template_id] = template_hash
        template_hashes[template_id] = template_hash
        templates.append(template)
    if commands_raw["mode"] == "selected" and not templates:
        raise PolicyValidationError("commands.mode selected requires at least one template")
    templates.sort(key=lambda t: (t["id"], _authority_template_hash(t), t["evidence_id"]))
    # Duplicate templates with identical authority are a set-like duplicate;
    # conflicting definitions under one ID were rejected above.
    deduped_templates: list[dict[str, object]] = []
    seen_template_keys: set[tuple[str, str]] = set()
    for template in templates:
        key = (template["id"], _authority_template_hash(template))
        if key not in seen_template_keys:
            deduped_templates.append(template)
            seen_template_keys.add(key)
    templates = deduped_templates
    commands_raw["templates"] = templates
    if commands_raw["mode"] == "selected":
        for template in templates:
            grants.add(f"command:{template['id']}@{template_hashes[template['id']]}")
    elif commands_raw["mode"] == "unrestricted":
        grants.add("commands.mode:unrestricted")
    elif commands_raw["mode"] == "unavailable":
        unresolved.append("commands.activation")
    document["commands"] = commands_raw

    if document["network"]["subprocess"] == "unrestricted":
        grants.add("network.subprocess:unrestricted")
    elif document["network"]["subprocess"] == "allowlist":
        for dest in document["network"]["allowed_destinations"]:
            grants.add(f"network.subprocess.destination:{dest}")
    if document["network"]["mcp_open_world"] == "unrestricted":
        grants.add("network.mcp_open_world:unrestricted")
    elif document["network"]["mcp_open_world"] == "allowlist":
        for dest in document["network"]["allowed_destinations"]:
            grants.add(f"network.mcp_open_world.destination:{dest}")

    # --- host effects ---
    host_raw = _merge_section(default["host_effects"], raw.get("host_effects"), "host_effects")
    if not isinstance(host_raw["mode"], str) or host_raw["mode"] not in HOST_EFFECT_MODES:
        raise PolicyValidationError(f"host_effects.mode invalid: {host_raw['mode']!r}")
    if not isinstance(host_raw["grants"], list):
        raise PolicyValidationError("host_effects.grants must be a list")
    normalized_host_grants: dict[tuple[str, str], dict[str, str]] = {}
    for grant in host_raw["grants"]:
        if not isinstance(grant, Mapping) or set(grant) != {"operation", "target_id"}:
            raise PolicyValidationError("host effect grant must be {operation, target_id}")
        operation = grant["operation"]
        target_id = grant["target_id"]
        if not isinstance(operation, str) or operation not in HOST_EFFECT_OPERATIONS:
            raise PolicyValidationError(f"host effect grant has unknown operation: {operation!r}")
        if not isinstance(target_id, str) or not _TARGET_ID_RE.match(target_id):
            raise PolicyValidationError(f"host effect grant has unstable target_id: {target_id!r}")
        normalized_host_grants[(operation, target_id)] = {"operation": operation, "target_id": target_id}
    host_raw["grants"] = list(normalized_host_grants.values())
    if host_raw["mode"] == "selected":
        if not host_raw["grants"]:
            raise PolicyValidationError("host_effects.mode selected requires at least one grant")
        for grant in host_raw["grants"]:
            grants.add(f"host_effect:{grant['operation']}:{grant['target_id']}")
    elif host_raw["mode"] == "unrestricted":
        grants.add("host_effects.mode:unrestricted")
    elif host_raw["mode"] == "unavailable":
        unresolved.append("host_effects.activation")
    host_raw["grants"] = sorted(
        host_raw["grants"], key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":"))
    )
    document["host_effects"] = host_raw

    git_mutation = document["git"]["mutation"]
    if not isinstance(git_mutation, str) or git_mutation not in _CAPABILITY_MODES:
        raise PolicyValidationError(f"git.mutation has invalid mode: {git_mutation!r}")
    if git_mutation == "unavailable":
        unresolved.append("git.activation")
    elif git_mutation != "deny":
        grants.add("git.mutation:allow")
    installation_mode = document["installation"]["mode"]
    if not isinstance(installation_mode, str) or installation_mode not in _CAPABILITY_MODES:
        raise PolicyValidationError(f"installation.mode has invalid mode: {installation_mode!r}")
    if installation_mode == "unavailable":
        unresolved.append("installation.activation")
    elif installation_mode != "deny":
        grants.add("installation:allow")
    descendants_mode = document["descendants"]["mode"]
    if not isinstance(descendants_mode, str) or descendants_mode not in _CAPABILITY_MODES:
        raise PolicyValidationError(f"descendants.mode has invalid mode: {descendants_mode!r}")
    if descendants_mode == "unavailable":
        unresolved.append("descendants.activation")
    elif descendants_mode != "deny":
        grants.add("descendants:allow")

    # --- output ---
    output_raw = _merge_section(default["output"], raw.get("output"), "output")
    if not isinstance(output_raw["mode"], str) or output_raw["mode"] not in _OUTPUT_MODES:
        raise PolicyValidationError(f"output.mode invalid: {output_raw['mode']!r}")
    output_raw["roots"] = _string_set(output_raw["roots"], "output.roots")
    for root_id in output_raw["roots"]:
        if root_id not in declared_roots:
            raise PolicyValidationError(f"output.roots references undeclared root: {root_id!r}")
    if output_raw["mode"] == "worker":
        grants.add("output.mode:worker")
        for root_id in output_raw["roots"]:
            grants.add(f"output.root:{root_id}")
    elif output_raw["mode"] == "unavailable":
        unresolved.append("output.activation")
    document["output"] = output_raw

    # --- sandbox ---
    sandbox_raw = _merge_section(default["sandbox"], raw.get("sandbox"), "sandbox")
    if not isinstance(sandbox_raw["mode"], str) or sandbox_raw["mode"] not in SANDBOX_MODES:
        raise PolicyValidationError(f"sandbox.mode invalid: {sandbox_raw['mode']!r}")
    if not isinstance(sandbox_raw["unavailable"], str) or sandbox_raw["unavailable"] not in SANDBOX_UNAVAILABLE:
        raise PolicyValidationError(f"sandbox.unavailable invalid: {sandbox_raw['unavailable']!r}")
    sandbox_raw["unsandboxed_commands"] = _string_set(
        sandbox_raw["unsandboxed_commands"], "sandbox.unsandboxed_commands"
    )
    for command_id in sandbox_raw["unsandboxed_commands"]:
        matching = next((t for t in templates if t["id"] == command_id), None)
        if matching is None or matching["sandbox"] != "outside":
            raise PolicyValidationError(
                f"unsandboxed command id does not name an 'outside' template: {command_id!r}"
            )
    document["sandbox"] = sandbox_raw

    lifecycle = document["lifecycle"]
    if not isinstance(lifecycle["resume"], str) or lifecycle["resume"] not in _LIFECYCLE_RESUME_MODES:
        raise PolicyValidationError(f"lifecycle.resume has invalid mode: {lifecycle['resume']!r}")
    if not isinstance(lifecycle["recovery"], str) or lifecycle["recovery"] not in _LIFECYCLE_RECOVERY_MODES:
        raise PolicyValidationError(f"lifecycle.recovery has invalid mode: {lifecycle['recovery']!r}")

    # --- resources ---
    resources_out = {}
    resources_in = raw.get("resources", {})
    if not isinstance(resources_in, Mapping):
        raise PolicyValidationError("resources must be an object")
    _require_keys("resources", resources_in, set(default["resources"]))
    for name, default_value in default["resources"].items():
        value = resources_in.get(name, default_value)
        resources_out[name] = _validate_limit(name, value)
    document["resources"] = resources_out

    model_inputs = document["model_inputs"]
    runtime = document["runtime"]
    cache_inputs_complete = bool(
        model_inputs.get("model")
        and model_inputs.get("effort")
        and model_inputs.get("system_input_hashes")
        and runtime.get("version")
    )

    private_bindings.sort(key=lambda b: (b.kind, b.binding_id))

    authority_commands = {
        "mode": document["commands"]["mode"],
        # The command document retains evidence_id for semantic/provenance
        # identity, while authority identity is content-addressed over the
        # complete executable definition with that provenance field removed.
        "templates": [
            {"id": template["id"], "authority_sha256": _authority_template_hash(template)}
            for template in document["commands"]["templates"]
        ],
    }
    authority_projection = {
        "schema_version": document["schema_version"],
        "filesystem": document["filesystem"],
        "tools": document["tools"],
        "mcp": document["mcp"],
        "commands": authority_commands,
        "network": document["network"],
        "host_effects": document["host_effects"],
        "git": document["git"],
        "installation": document["installation"],
        "descendants": document["descendants"],
        "output": document["output"],
        "sandbox": document["sandbox"],
        "resources": document["resources"],
    }
    authority_sha256 = _sha256_json(authority_projection)
    semantic_sha256 = _sha256_json(document)

    return CompiledPolicy(
        document=document,
        semantic_sha256=semantic_sha256,
        authority_sha256=authority_sha256,
        authority_grants=frozenset(grants),
        authority_denies=frozenset(denies),
        private_bindings=tuple(private_bindings),
        unresolved_dimensions=tuple(sorted(set(unresolved))),
        cache_inputs_complete=cache_inputs_complete,
    )


def canonical_document(policy: CompiledPolicy) -> dict[str, object]:
    return copy.deepcopy(policy.document)
