"""Sanitized, allowlisted explanation rendering.

Never imports provider preset modules; assurance labels are supplied
explicitly by the caller.
"""

from __future__ import annotations

from typing import Mapping

from .diff import TransitionReport
from .schema import ASSURANCE, CompiledPolicy, PolicyValidationError


def _roots(policy: CompiledPolicy, operation: str) -> list[dict[str, object]]:
    scopes = set()
    for rule in policy.document["filesystem"]["rules"]:
        if rule["effect"] == "allow" and operation in rule["operations"] and "scope" in rule:
            scopes.add(rule["scope"])
    roots = policy.document["filesystem"]["roots"]
    return [
        {"id": root_id, "binding": roots[root_id]["binding"]}
        for root_id in sorted(scopes)
    ]


def _transition_view(transition: TransitionReport | None) -> dict[str, object] | None:
    if transition is None:
        return None
    return {
        "kind": transition.kind,
        "known_kind": transition.known_kind,
        "broader_authority": list(transition.broader_authority),
        "narrower_authority": list(transition.narrower_authority),
        "unresolved_dimensions": list(transition.unresolved_dimensions),
        "changed_fields": list(transition.changed_fields),
        "cache_impact": transition.cache_impact,
        "transition_sha256": transition.transition_sha256,
        "notice_events": [dict(event) for event in transition.notice_events],
        "confirmation_events": [dict(event) for event in transition.confirmation_events],
    }


def build_explanation(
    policy: CompiledPolicy,
    transition: TransitionReport | None = None,
    *,
    assurance: Mapping[str, str] | None = None,
) -> dict[str, object]:
    document = policy.document
    if assurance is not None:
        if not isinstance(assurance, Mapping):
            raise PolicyValidationError("assurance must be an object mapping labels to grades")
        for label, grade in assurance.items():
            if not isinstance(label, str) or not label:
                raise PolicyValidationError("assurance labels must be non-empty strings")
            if not isinstance(grade, str) or grade not in ASSURANCE:
                raise PolicyValidationError(f"assurance.{label} has invalid grade: {grade!r}")
    return {
        "stage": "compiled",
        "schema_version": document["schema_version"],
        "profile": {
            "id": document["profile"]["id"],
            "preset_revision": document["profile"]["preset_revision"],
            "legacy_contract_version": document["profile"]["legacy_contract_version"],
        },
        "semantic_sha256": policy.semantic_sha256,
        "authority_sha256": policy.authority_sha256,
        "activation": document["runtime"]["activation"],
        "roots": {
            "read": _roots(policy, "read"),
            "write": _roots(policy, "write"),
        },
        "capabilities": {
            "commands": document["commands"]["mode"],
            "mcp": document["mcp"]["mode"],
            "host_effects": document["host_effects"]["mode"],
        },
        "resources": {
            name: dict(value) for name, value in document["resources"].items()
        },
        "assurance": dict(assurance) if assurance else {},
        "sandbox": {
            "mode": document["sandbox"]["mode"],
            "unavailable": document["sandbox"]["unavailable"],
            "unsandboxed_commands": list(document["sandbox"]["unsandboxed_commands"]),
        },
        "presentation": {
            "notices": dict(document["notices"]),
            "confirmation": dict(document["confirmation"]),
        },
        "transition": _transition_view(transition),
        "unresolved": list(policy.unresolved_dimensions),
    }


_FIELD_ORDER = (
    "stage", "schema_version", "profile", "semantic_sha256", "authority_sha256",
    "activation", "roots", "capabilities", "resources", "assurance", "sandbox", "presentation",
    "transition", "unresolved",
)


def render_text(explanation: Mapping[str, object]) -> str:
    lines: list[str] = []
    for field in _FIELD_ORDER:
        if field not in explanation:
            continue
        value = explanation[field]
        if field == "assurance":
            if not value:
                lines.append("assurance: unknown (none supplied)")
            else:
                for label, grade in sorted(value.items()):
                    lines.append(f"assurance.{label}: {grade}")
            continue
        lines.append(f"{field}: {value}")
    return "\n".join(lines)
