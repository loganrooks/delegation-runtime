"""Pure, versioned Claude execution-profile resolution.

No filesystem, subprocess, environment, or network access belongs here.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re


PROFILE_VERSION = 3

# First-release read-only MCP registry. These identifiers were selected from the
# codebase-memory server's observed non-mutating query surface; unknown identifiers
# fail closed until they receive an explicit capability audit and contract update.
PINNED_READONLY_MCP_TOOLS: tuple[str, ...] = (
    "mcp__codebase-memory-mcp__detect_changes",
    "mcp__codebase-memory-mcp__get_architecture",
    "mcp__codebase-memory-mcp__get_code_snippet",
    "mcp__codebase-memory-mcp__get_graph_schema",
    "mcp__codebase-memory-mcp__index_status",
    "mcp__codebase-memory-mcp__list_projects",
    "mcp__codebase-memory-mcp__query_graph",
    "mcp__codebase-memory-mcp__search_code",
    "mcp__codebase-memory-mcp__search_graph",
    "mcp__codebase-memory-mcp__trace_path",
)

# Descendant spawning is denied under the current identifier and the older one,
# because an unrecognised-but-live alias would silently reopen the boundary.
_GLOBAL_DENIED_TOOLS = (
    "WebFetch",
    "WebSearch",
    "Agent",
    "Task",
    "mcp__codebase-memory-mcp__delete_project",
    "mcp__codebase-memory-mcp__index_repository",
    "mcp__codebase-memory-mcp__ingest_traces",
    "mcp__codebase-memory-mcp__manage_adr",
)

_FORBIDDEN_COMMAND_CHARS = set(";&|<>`$*?[]\n\x00")

_PERMISSION_RULE = re.compile(r"^(?P<base>[A-Za-z][A-Za-z0-9_-]*)\((?P<specifier>.*)\)$", re.DOTALL)

MATCH = "match"
NARROWER = "narrower"
BROADER = "broader"
UNKNOWN = "unknown"


class ProfileError(ValueError):
    """Raised for any invalid or conflicting profile resolution request."""


@dataclass(frozen=True)
class _ProfileDefinition:
    permission_mode: str
    tools: tuple[str, ...]
    extra_denied_tools: tuple[str, ...]
    requires_command: bool
    allows_command: bool
    requires_native_sandbox: bool = False
    uses_scratch_cwd: bool = False
    requires_artifact_output: bool = False
    requires_owned_paths: bool = False
    requires_auto_mode: bool = False


_PROFILE_DEFINITIONS: dict[str, _ProfileDefinition] = {
    "strict-readonly": _ProfileDefinition(
        permission_mode="dontAsk",
        tools=("Read", "Grep", "Glob", "Skill"),
        extra_denied_tools=("Bash", "Write", "Edit", "NotebookEdit"),
        requires_command=False,
        allows_command=False,
    ),
    "verified-review": _ProfileDefinition(
        permission_mode="dontAsk",
        tools=("Read", "Grep", "Glob", "Skill", "Bash"),
        extra_denied_tools=("Write", "Edit", "NotebookEdit"),
        requires_command=True,
        allows_command=True,
        requires_native_sandbox=True,
        uses_scratch_cwd=True,
    ),
    "artifact-review": _ProfileDefinition(
        permission_mode="dontAsk",
        tools=("Read", "Grep", "Glob", "Skill", "Bash"),
        extra_denied_tools=("Write", "Edit", "NotebookEdit"),
        requires_command=True,
        allows_command=True,
        requires_native_sandbox=True,
        uses_scratch_cwd=True,
        requires_artifact_output=True,
    ),
    "implementation": _ProfileDefinition(
        permission_mode="acceptEdits",
        tools=("Read", "Grep", "Glob", "Skill", "Bash", "Write", "Edit"),
        extra_denied_tools=(),
        requires_command=False,
        allows_command=False,
        requires_native_sandbox=True,
        requires_owned_paths=True,
    ),
    "implementation-auto": _ProfileDefinition(
        permission_mode="auto",
        tools=("Read", "Grep", "Glob", "Skill", "Bash", "Write", "Edit"),
        extra_denied_tools=(),
        requires_command=False,
        allows_command=False,
        requires_native_sandbox=True,
        requires_owned_paths=True,
        requires_auto_mode=True,
    ),
}

_ALIASES: dict[str, str] = {
    "readonly-review": "strict-readonly",
}

PROFILE_IDS: tuple[str, ...] = tuple(_PROFILE_DEFINITIONS) + tuple(_ALIASES)


@dataclass(frozen=True)
class ResolvedProfile:
    profile_id: str
    profile_requested: str
    version: int
    permission_mode: str
    tools: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    denied_tools: tuple[str, ...]
    allowed_commands: tuple[str, ...]
    warning: str | None
    manifest_sha256: str
    expected_tools: tuple[str, ...]
    exposed_but_denied: tuple[str, ...]
    requires_native_sandbox: bool
    uses_scratch_cwd: bool
    requires_artifact_output: bool
    requires_owned_paths: bool
    requires_auto_mode: bool


def expected_startup_tools(
    tools: tuple[str, ...], allowed_tools: tuple[str, ...]
) -> tuple[str, ...]:
    """Normalize the startup surface a compliant runtime may expose as *allowed*.

    Three kinds of entry are folded into one comparable identifier set:
    requested built-ins, explicitly allowed exact identifiers (notably MCP tools),
    and permission-rule specifiers such as ``Bash(pytest -q)`` — which normalize to
    their base tool only when that base tool was itself requested.
    """
    expected: set[str] = set(tools)
    for entry in allowed_tools:
        rule = _PERMISSION_RULE.match(entry)
        if rule:
            base = rule.group("base")
            if base in expected:
                expected.add(base)
            continue
        expected.add(entry)
    return tuple(sorted(expected))


def classify_manifest(
    expected_tools: tuple[str, ...],
    exposed_but_denied: tuple[str, ...],
    observed_tools: tuple[str, ...] | None,
) -> tuple[str, tuple[str, ...]]:
    """Compare an observed startup manifest against the expected allowed surface.

    ``observed_tools is None`` means the startup event was absent or omitted its tool
    list; that is ``unknown``, never an empty or narrower manifest. A tool that is
    exposed but explicitly denied is recorded without counting as allowed surface.
    """
    if observed_tools is None:
        return UNKNOWN, ()
    expected = set(expected_tools)
    denied = set(exposed_but_denied)
    observed = set(observed_tools)
    unexpected = tuple(sorted(observed - expected - denied))
    if unexpected:
        return BROADER, unexpected
    if observed & expected == expected:
        return MATCH, ()
    return NARROWER, ()


def canonical_profile_id(profile_id: str) -> str:
    if profile_id in _PROFILE_DEFINITIONS:
        return profile_id
    if profile_id in _ALIASES:
        return _ALIASES[profile_id]
    raise ProfileError(f"unknown profile id: {profile_id!r}")


def _dedupe_preserve_first(values: tuple[str, ...]) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return tuple(ordered)


def _validate_command(value: str) -> str:
    if not value or not value.strip():
        raise ProfileError("--allowed-command values must not be empty")
    if any(char in _FORBIDDEN_COMMAND_CHARS for char in value):
        raise ProfileError(
            f"--allowed-command rejected: shell composition or wildcards are not permitted: {value!r}"
        )
    return value


def _manifest_hash(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def resolve_profile(
    profile_id: str,
    permission_mode: str | None,
    tools: tuple[str, ...] = (),
    allowed_tools: tuple[str, ...] = (),
    disallowed_tools: tuple[str, ...] = (),
    allowed_commands: tuple[str, ...] = (),
) -> ResolvedProfile:
    canonical_id = canonical_profile_id(profile_id)
    definition = _PROFILE_DEFINITIONS[canonical_id]
    warning = None
    if profile_id != canonical_id:
        warning = (
            f"'{profile_id}' is a deprecated alias for '{canonical_id}'; "
            "use the canonical profile id."
        )

    if permission_mode is not None and permission_mode != definition.permission_mode:
        raise ProfileError(
            f"profile {canonical_id} pins permission mode to "
            f"{definition.permission_mode!r}; got {permission_mode!r}"
        )
    resolved_permission_mode = definition.permission_mode

    resolved_tools = definition.tools
    if tools:
        tool_set = set(tools)
        if not tool_set.issubset(set(definition.tools)):
            raise ProfileError(
                f"profile {canonical_id} does not permit tool broadening: "
                f"{sorted(tool_set - set(definition.tools))}"
            )
        resolved_tools = tuple(t for t in definition.tools if t in tool_set)

    denied_tools = _dedupe_preserve_first(
        _GLOBAL_DENIED_TOOLS + definition.extra_denied_tools + tuple(disallowed_tools)
    )

    denied_set = set(denied_tools)
    for tool in allowed_tools:
        if tool in denied_set:
            raise ProfileError(
                f"profile {canonical_id} cannot allow denied tool: {tool!r}"
            )
        if tool.startswith("mcp__") and tool not in PINNED_READONLY_MCP_TOOLS:
            raise ProfileError(
                f"profile {canonical_id} admits only pinned read-only MCP tools; "
                f"got {tool!r}"
            )

    # Claude's init event reports every tool exposed by a connected MCP server,
    # not only the identifiers permission-allowed for this invocation. Make the
    # remainder explicit denies so startup exposure and callable authority stay
    # distinct and auditable under dontAsk.
    denied_tools = _dedupe_preserve_first(
        denied_tools
        + tuple(
            tool
            for tool in PINNED_READONLY_MCP_TOOLS
            if tool not in set(allowed_tools)
        )
    )

    if allowed_commands and not definition.allows_command:
        raise ProfileError(
            f"profile {canonical_id} has no Bash tool; --allowed-command is not permitted"
        )
    if definition.requires_command and not allowed_commands:
        raise ProfileError(
            f"profile {canonical_id} requires at least one --allowed-command value"
        )

    validated_commands = tuple(_validate_command(value) for value in allowed_commands)
    command_rules = tuple(f"Bash({value})" for value in validated_commands)

    resolved_allowed_tools = _dedupe_preserve_first(tuple(allowed_tools) + command_rules)

    expected_tools = expected_startup_tools(resolved_tools, resolved_allowed_tools)

    manifest_payload = {
        "profile_id": canonical_id,
        "version": PROFILE_VERSION,
        "permission_mode": resolved_permission_mode,
        "tools": list(resolved_tools),
        "allowed_tools": list(resolved_allowed_tools),
        "denied_tools": list(denied_tools),
        "allowed_commands": list(validated_commands),
        "expected_tools": list(expected_tools),
    }

    return ResolvedProfile(
        profile_id=canonical_id,
        profile_requested=profile_id,
        version=PROFILE_VERSION,
        permission_mode=resolved_permission_mode,
        tools=resolved_tools,
        allowed_tools=resolved_allowed_tools,
        denied_tools=denied_tools,
        allowed_commands=validated_commands,
        warning=warning,
        manifest_sha256=_manifest_hash(manifest_payload),
        expected_tools=expected_tools,
        exposed_but_denied=denied_tools,
        requires_native_sandbox=definition.requires_native_sandbox,
        uses_scratch_cwd=definition.uses_scratch_cwd,
        requires_artifact_output=definition.requires_artifact_output,
        requires_owned_paths=definition.requires_owned_paths,
        requires_auto_mode=definition.requires_auto_mode,
    )
