"""Provider-neutral policy contract primitives.

Standard-library only. This package must never import any Claude adapter
module (``delegate_to_claude`` or its submodules); Claude-specific presets and
assurance evidence stay in ``delegate-to-claude``.
"""

from __future__ import annotations

from .schema import (
    CompiledPolicy,
    PolicyValidationError,
    PrivateBinding,
    canonical_document,
    normalize_policy,
)

__all__ = [
    "CompiledPolicy",
    "PolicyValidationError",
    "PrivateBinding",
    "canonical_document",
    "normalize_policy",
]
