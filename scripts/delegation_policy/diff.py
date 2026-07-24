"""Directional transition, cache, notice, and confirmation analysis."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .schema import CompiledPolicy, _authority_template_hash

_SANDBOX_ORDER = {"required": 0, "preferred": 1, "off": 2}
_FALLBACK_ORDER = {"fail": 0, "warn-and-run": 1, "run": 2}

_NOTICE_CATEGORIES = (
    "profile_transition", "cache_impact", "authority_change",
    "context_change", "runtime_change", "sandbox_change",
)


@dataclass(frozen=True)
class TransitionReport:
    kind: str
    known_kind: str
    broader_authority: tuple[str, ...]
    narrower_authority: tuple[str, ...]
    changed_fields: tuple[str, ...]
    unresolved_dimensions: tuple[str, ...]
    transition_sha256: str
    cache_impact: str
    notice_events: tuple[dict[str, object], ...]
    confirmation_events: tuple[dict[str, object], ...]


def _classify_known(broader: set[str], narrower: set[str]) -> str:
    if not broader and not narrower:
        return "exact"
    if broader and not narrower:
        return "broader"
    if narrower and not broader:
        return "narrower"
    return "mixed"


def _sandbox_diff(before: CompiledPolicy, after: CompiledPolicy, changed_fields: list[str],
                   broader: set[str], narrower: set[str]) -> None:
    b_sandbox = before.document["sandbox"]
    a_sandbox = after.document["sandbox"]
    if b_sandbox["mode"] != a_sandbox["mode"]:
        changed_fields.append("sandbox.mode")
        target = broader if _SANDBOX_ORDER[a_sandbox["mode"]] > _SANDBOX_ORDER[b_sandbox["mode"]] else narrower
        target.add(f"sandbox.mode:{b_sandbox['mode']}->{a_sandbox['mode']}")
    if b_sandbox["unavailable"] != a_sandbox["unavailable"]:
        changed_fields.append("sandbox.unavailable")
        target = (
            broader if _FALLBACK_ORDER[a_sandbox["unavailable"]] > _FALLBACK_ORDER[b_sandbox["unavailable"]]
            else narrower
        )
        target.add(f"sandbox.unavailable:{b_sandbox['unavailable']}->{a_sandbox['unavailable']}")
    if set(b_sandbox["unsandboxed_commands"]) != set(a_sandbox["unsandboxed_commands"]):
        changed_fields.append("sandbox.unsandboxed_commands")
        added = set(a_sandbox["unsandboxed_commands"]) - set(b_sandbox["unsandboxed_commands"])
        removed = set(b_sandbox["unsandboxed_commands"]) - set(a_sandbox["unsandboxed_commands"])
        for command_id in added:
            broader.add(f"sandbox.unsandboxed:{command_id}")
        for command_id in removed:
            narrower.add(f"sandbox.unsandboxed:{command_id}")


def _resources_diff(before: CompiledPolicy, after: CompiledPolicy, changed_fields: list[str],
                     broader: set[str], narrower: set[str], unresolved: set[str]) -> None:
    for name, b_limit in before.document["resources"].items():
        a_limit = after.document["resources"][name]
        if b_limit == a_limit:
            continue
        changed_fields.append(f"resources.{name}")
        if b_limit["mode"] == "unavailable" or a_limit["mode"] == "unavailable":
            unresolved.add(f"resources.{name}")
            continue
        if a_limit["mode"] == "unbounded" and b_limit["mode"] != "unbounded":
            broader.add(f"resources.{name}:unbounded")
        elif b_limit["mode"] == "unbounded" and a_limit["mode"] != "unbounded":
            narrower.add(f"resources.{name}:bounded")
        elif a_limit["mode"] == "bounded" and b_limit["mode"] == "bounded":
            if a_limit["value"] > b_limit["value"]:
                broader.add(f"resources.{name}:{b_limit['value']}->{a_limit['value']}")
            elif a_limit["value"] < b_limit["value"]:
                narrower.add(f"resources.{name}:{b_limit['value']}->{a_limit['value']}")


_ACTIVATABLE_ORDER = {"deny": 0, "selected": 1, "allowlist": 1, "unrestricted": 2}


def _mode_ordered_diff(
    before: CompiledPolicy, after: CompiledPolicy,
    *, section: str, mode_field: str, prefixes: tuple[str, ...],
    dimension_name: str,
    broader: set[str], narrower: set[str], unresolved: set[str],
    changed_fields: list[str],
) -> None:
    """Deny < selected < unrestricted ladders for commands/network/host effects.

    A mode-level jump (e.g. selected -> unrestricted) is classified by ladder
    order rather than by the incidental content atoms that disappear or
    appear alongside it, so allowlist-to-unrestricted reads as broader, not
    mixed.
    """
    b_mode = before.document[section][mode_field]
    a_mode = after.document[section][mode_field]
    if b_mode == a_mode:
        return
    changed_fields.append(f"{section}.{mode_field}")
    for prefix in prefixes:
        broader.difference_update({a for a in list(broader) if a.startswith(prefix)})
        narrower.difference_update({n for n in list(narrower) if n.startswith(prefix)})
    if b_mode == "unavailable" or a_mode == "unavailable":
        unresolved.add(dimension_name)
        return
    if b_mode not in _ACTIVATABLE_ORDER or a_mode not in _ACTIVATABLE_ORDER:
        unresolved.add(dimension_name)
        return
    target = broader if _ACTIVATABLE_ORDER[a_mode] > _ACTIVATABLE_ORDER[b_mode] else narrower
    target.add(f"{dimension_name}:{b_mode}->{a_mode}")


def _rebinding_diff(before: CompiledPolicy, after: CompiledPolicy, unresolved: set[str]) -> bool:
    before_bindings = {(b.kind, b.binding_id): b for b in before.private_bindings}
    after_bindings = {(b.kind, b.binding_id): b for b in after.private_bindings}
    rebound = set(before_bindings) != set(after_bindings)
    for key in set(before_bindings) & set(after_bindings):
        before_binding = before_bindings[key]
        after_binding = after_bindings[key]
        if (
            before_binding.resolved_path != after_binding.resolved_path
            or before_binding.lineage_identity != after_binding.lineage_identity
        ):
            rebound = True
            if key[0] == "deny-rule":
                unresolved.add(f"binding.{key[1]}")
    return rebound


def _cache_relevant_projection(policy: CompiledPolicy) -> dict[str, object]:
    document = policy.document
    return {
        "model": document["model_inputs"]["model"],
        "effort": document["model_inputs"]["effort"],
        "system_input_hashes": sorted(document["model_inputs"]["system_input_hashes"]),
        "tools": {
            "builtins": sorted(document["tools"]["builtins"]),
            "deny": sorted(document["tools"]["deny"]),
        },
        "command_templates": sorted([
            {
                "id": t["id"],
                "authority_sha256": _authority_template_hash(t),
            }
            for t in document["commands"]["templates"]
        ], key=lambda item: (item["id"], item["authority_sha256"])),
        "mcp": {
            "mode": document["mcp"]["mode"],
            "servers": sorted(document["mcp"]["servers"]),
            "selected_tools": sorted(document["mcp"]["selected_tools"]),
        },
        "provider": document["runtime"]["provider"],
        "runtime_version": document["runtime"]["version"],
    }


def _cache_impact(before: CompiledPolicy, after: CompiledPolicy) -> str:
    if not (before.cache_inputs_complete and after.cache_inputs_complete):
        return "unknown"
    if _cache_relevant_projection(before) == _cache_relevant_projection(after):
        return "unchanged"
    return "likely-invalidated"


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def compare_policies(before: CompiledPolicy, after: CompiledPolicy) -> TransitionReport:
    broader: set[str] = set(after.authority_grants - before.authority_grants)
    narrower: set[str] = set(before.authority_grants - after.authority_grants)
    broader.update(before.authority_denies - after.authority_denies)
    narrower.update(after.authority_denies - before.authority_denies)

    changed_fields: list[str] = []
    diff_unresolved: set[str] = set()

    _sandbox_diff(before, after, changed_fields, broader, narrower)
    _resources_diff(before, after, changed_fields, broader, narrower, diff_unresolved)
    _mode_ordered_diff(
        before, after, section="commands", mode_field="mode",
        prefixes=("command:", "commands.mode:"), dimension_name="commands.mode",
        broader=broader, narrower=narrower, unresolved=diff_unresolved, changed_fields=changed_fields,
    )
    _mode_ordered_diff(
        before, after, section="network", mode_field="subprocess",
        prefixes=("network.subprocess",), dimension_name="network.subprocess",
        broader=broader, narrower=narrower, unresolved=diff_unresolved, changed_fields=changed_fields,
    )
    _mode_ordered_diff(
        before, after, section="network", mode_field="mcp_open_world",
        prefixes=("network.mcp_open_world",), dimension_name="network.mcp_open_world",
        broader=broader, narrower=narrower, unresolved=diff_unresolved, changed_fields=changed_fields,
    )
    _mode_ordered_diff(
        before, after, section="host_effects", mode_field="mode",
        prefixes=("host_effect:", "host_effects.mode:"), dimension_name="host_effects.mode",
        broader=broader, narrower=narrower, unresolved=diff_unresolved, changed_fields=changed_fields,
    )
    rebound = _rebinding_diff(before, after, diff_unresolved)

    known_kind = _classify_known(broader, narrower)
    authority_hash_changed = before.authority_sha256 != after.authority_sha256
    root_authority_changed = (
        before.document["filesystem"]["roots"]
        != after.document["filesystem"]["roots"]
    )
    if root_authority_changed:
        changed_fields.append("filesystem.roots")
        diff_unresolved.add("filesystem.roots")
    if known_kind == "exact" and authority_hash_changed:
        diff_unresolved.add("authority.projection")

    # Either side can carry an unavailable activation/runtime dimension. A
    # resume must retain both markers because resolving only one side does not
    # establish the relation for the transition as a whole.
    unresolved_dimensions = (
        set(before.unresolved_dimensions)
        | set(after.unresolved_dimensions)
        | diff_unresolved
    )
    # Root kind and binding-status changes are authority-bearing but do not
    # have a supported directional order. Preserve that distinction as unknown
    # rather than manufacturing a broader/narrower relation from set atoms.
    kind = (
        "unknown"
        if unresolved_dimensions
        or root_authority_changed
        or (known_kind == "exact" and authority_hash_changed)
        else known_kind
    )

    cache_impact = _cache_impact(before, after)

    # An unresolved authority dimension is itself an authority transition
    # fact. This remains true when the set-based relation is otherwise exact;
    # the final kind is what drives the current operator presentation.
    authority_unresolved = any(
        dimension != "runtime.activation"
        for dimension in unresolved_dimensions
    )
    authority_triggered = known_kind != "exact" or authority_hash_changed or authority_unresolved
    profile_triggered = before.document["profile"] != after.document["profile"]
    context_triggered = (
        before.document["context"] != after.document["context"]
        or root_authority_changed
        or rebound
    )
    runtime_triggered = before.document["runtime"] != after.document["runtime"]
    sandbox_triggered = before.document["sandbox"] != after.document["sandbox"]
    cache_triggered = cache_impact == "likely-invalidated"

    triggered_by_category = {
        "profile_transition": profile_triggered,
        "cache_impact": cache_triggered,
        "authority_change": authority_triggered,
        "context_change": context_triggered,
        "runtime_change": runtime_triggered,
        "sandbox_change": sandbox_triggered,
    }

    after_notices = after.document["notices"]
    before_notices = before.document["notices"]
    after_confirmation = after.document["confirmation"]
    unsandboxed_added = (
        set(after.document["sandbox"]["unsandboxed_commands"])
        - set(before.document["sandbox"]["unsandboxed_commands"])
    )

    notice_events: list[dict[str, object]] = []
    confirmation_events: list[dict[str, object]] = []

    for category in _NOTICE_CATEGORIES:
        triggered = triggered_by_category[category]
        mode = after_notices[category]
        display = bool(triggered and mode in ("always", "once"))
        requires_confirmation = False
        if category == "profile_transition" and triggered:
            requires_confirmation = after_confirmation["profile_transition"] == "ask"
        elif category == "authority_change" and triggered and kind in ("broader", "mixed", "unknown"):
            requires_confirmation = after_confirmation["authority_expansion"] == "ask"
        elif category == "sandbox_change" and triggered and unsandboxed_added:
            requires_confirmation = after_confirmation["unsandboxed_command"] == "ask"
        summary = (
            f"known {known_kind}; {len(broader)} added; {len(narrower)} removed; "
            f"{len(unresolved_dimensions)} unresolved dimension(s)"
            if category == "authority_change"
            else f"{category} {'changed' if triggered else 'unchanged'}"
        )
        notice_events.append({
            "category": category,
            "mode": mode,
            "triggered": triggered,
            "display": display,
            "requires_confirmation": requires_confirmation,
            "summary": summary,
        })
        if requires_confirmation:
            confirmation_category = (
                "unsandboxed_command"
                if category == "sandbox_change" and unsandboxed_added
                else category
            )
            confirmation_events.append({
                "category": confirmation_category,
                "mode": after_confirmation.get(
                    "unsandboxed_command"
                    if confirmation_category == "unsandboxed_command"
                    else "profile_transition"
                    if category == "profile_transition"
                    else "authority_expansion"
                ),
                "summary": summary,
            })

    presentation_changed = (
        before_notices != after_notices
        or before.document["confirmation"] != after_confirmation
    )
    if presentation_changed:
        changed_fields.append("presentation")
        notice_events.append({
            "category": "presentation_change",
            "mode": "n/a",
            "display": False,
            "requires_confirmation": False,
            "notices_changed": before_notices != after_notices,
            "confirmation_changed": before.document["confirmation"] != after_confirmation,
            "summary": "notice/confirmation settings changed on this transition",
        })

    transition_payload = {
        "before_semantic_sha256": before.semantic_sha256,
        "after_semantic_sha256": after.semantic_sha256,
        "before_authority_sha256": before.authority_sha256,
        "after_authority_sha256": after.authority_sha256,
        "known_kind": known_kind,
        "broader": sorted(broader),
        "narrower": sorted(narrower),
        "unresolved_dimensions": sorted(unresolved_dimensions),
        "triggered": triggered_by_category,
        "presentation": {
            "notices_changed": before_notices != after_notices,
            "confirmation_changed": before.document["confirmation"] != after_confirmation,
            "notice_modes": after_notices,
            "confirmation_modes": after_confirmation,
        },
    }
    transition_sha256 = _sha256_json(transition_payload)

    return TransitionReport(
        kind=kind,
        known_kind=known_kind,
        broader_authority=tuple(sorted(broader)),
        narrower_authority=tuple(sorted(narrower)),
        changed_fields=tuple(changed_fields),
        unresolved_dimensions=tuple(sorted(unresolved_dimensions)),
        transition_sha256=transition_sha256,
        cache_impact=cache_impact,
        notice_events=tuple(notice_events),
        confirmation_events=tuple(confirmation_events),
    )
