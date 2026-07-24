"""Claude-specific, non-activating C0 policy presets.

Imports the shared provider-neutral normalizer; keeps preset assurance labels
and any Claude-specific evidence local to this adapter.
"""

from __future__ import annotations

import copy
from typing import Mapping

from delegation_policy import CompiledPolicy, PolicyValidationError, normalize_policy

PRESET_REVISION = 1
LEGACY_CONTRACT_VERSION = 3

PRESET_IDS: tuple[str, ...] = (
    "strict-readonly", "verified-review", "artifact-review",
    "implementation", "implementation-auto", "readonly-review",
)
ALIASES: dict[str, str] = {"readonly-review": "strict-readonly"}

PRESET_ASSURANCE: Mapping[str, Mapping[str, str]] = {
    "strict-readonly": {
        "built-in-read": "claude-enforced",
        "built-in-write": "claude-enforced",
        "bash-filesystem": "unknown",
        "artifact-materialization": "manager-controlled",
    },
    "verified-review": {
        "built-in-read": "claude-enforced",
        "built-in-write": "claude-enforced",
        "bash-filesystem": "unknown",
        "artifact-materialization": "manager-controlled",
    },
    "artifact-review": {
        "built-in-read": "claude-enforced",
        "built-in-write": "claude-enforced",
        "bash-filesystem": "unknown",
        "artifact-materialization": "manager-controlled",
    },
    "implementation": {
        "built-in-read": "claude-enforced",
        "built-in-write": "detected",
        "bash-filesystem": "unknown",
        "artifact-materialization": "manager-controlled",
    },
    "implementation-auto": {
        "built-in-read": "claude-enforced",
        "built-in-write": "detected",
        "bash-filesystem": "unknown",
        "artifact-materialization": "manager-controlled",
    },
}

_GENERATED_STATE_BYTES = 240 * 1024 * 1024
_GENERATED_STATE_ADMISSION_BYTES = 192 * 1024 * 1024

_COMMON_ROOTS = {
    "project": {"kind": "project", "binding": "unbound"},
    "scratch": {"kind": "scratch", "binding": "unbound"},
}

_RESOURCE_DEFAULTS = {
    "generated_state_bytes": {"mode": "bounded", "value": _GENERATED_STATE_BYTES},
    "generated_state_admission_bytes": {"mode": "bounded", "value": _GENERATED_STATE_ADMISSION_BYTES},
}


def _base_read_only_rules() -> list[dict[str, object]]:
    return [{"operations": ["read"], "scope": "project", "effect": "allow"}]


def _profile(preset_id: str) -> dict[str, object]:
    return {
        "id": preset_id,
        "preset_revision": PRESET_REVISION,
        "legacy_contract_version": LEGACY_CONTRACT_VERSION,
    }


def _raw_document(
    preset_id: str,
    *,
    roots: dict[str, dict[str, object]],
    rules: list[dict[str, object]],
    sandbox_mode: str,
) -> dict[str, object]:
    return {
        "profile": _profile(preset_id),
        "runtime": {"provider": "claude-code", "version": None, "activation": "unavailable"},
        "filesystem": {"roots": roots, "rules": rules},
        "mcp": {"mode": "unavailable", "servers": [], "selected_tools": []},
        "commands": {"mode": "unavailable", "templates": []},
        "host_effects": {"mode": "deny", "grants": []},
        "sandbox": {"mode": sandbox_mode, "unavailable": "fail", "unsandboxed_commands": []},
        "resources": copy.deepcopy(_RESOURCE_DEFAULTS),
    }


_PRESET_BUILDERS: dict[str, "callable[[], dict[str, object]]"] = {
    "strict-readonly": lambda: _raw_document(
        "strict-readonly",
        roots={"project": _COMMON_ROOTS["project"]},
        rules=_base_read_only_rules(),
        sandbox_mode="off",
    ),
    "verified-review": lambda: _raw_document(
        "verified-review",
        roots=copy.deepcopy(_COMMON_ROOTS),
        rules=_base_read_only_rules() + [
            {"operations": ["write"], "scope": "scratch", "effect": "allow"},
        ],
        sandbox_mode="required",
    ),
    "artifact-review": lambda: _raw_document(
        "artifact-review",
        roots=copy.deepcopy(_COMMON_ROOTS),
        rules=_base_read_only_rules() + [
            {"operations": ["write"], "scope": "scratch", "effect": "allow"},
        ],
        sandbox_mode="required",
    ),
    "implementation": lambda: _raw_document(
        "implementation",
        roots={**copy.deepcopy(_COMMON_ROOTS), "owned": {"kind": "owned", "binding": "unbound"}},
        rules=_base_read_only_rules() + [
            {"operations": ["write"], "scope": "owned", "effect": "allow"},
            {"operations": ["write"], "scope": "scratch", "effect": "allow"},
        ],
        sandbox_mode="required",
    ),
    "implementation-auto": lambda: _raw_document(
        "implementation-auto",
        roots={**copy.deepcopy(_COMMON_ROOTS), "owned": {"kind": "owned", "binding": "unbound"}},
        rules=_base_read_only_rules() + [
            {"operations": ["write"], "scope": "owned", "effect": "allow"},
            {"operations": ["write"], "scope": "scratch", "effect": "allow"},
        ],
        sandbox_mode="required",
    ),
}

PRESET_DOCUMENTS: dict[str, dict[str, object]] = {
    preset_id: builder() for preset_id, builder in _PRESET_BUILDERS.items()
}


def canonical_preset_id(profile_id: str) -> tuple[str, str | None]:
    if profile_id in ALIASES:
        return ALIASES[profile_id], f"{profile_id} is deprecated; use {ALIASES[profile_id]}"
    if profile_id not in PRESET_DOCUMENTS:
        raise PolicyValidationError(f"unknown profile preset: {profile_id}")
    return profile_id, None


def preset_policy(profile_id: str) -> CompiledPolicy:
    canonical_id, _ = canonical_preset_id(profile_id)
    raw = copy.deepcopy(PRESET_DOCUMENTS[canonical_id])
    return normalize_policy(raw)
