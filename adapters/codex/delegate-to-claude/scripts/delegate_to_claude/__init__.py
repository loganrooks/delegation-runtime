"""Codex-managed Claude adapter package.

Import discovery for a directly executed, uninstalled candidate: locate the
repo-local shared policy package so that importing any module in this package
resolves `delegation_policy` without requiring the caller to assemble
PYTHONPATH. `claude_delegate.py` performs the same bootstrap for the directly
executed CLI entrypoint; this covers library and test imports, which do not go
through that entrypoint. Not a general plugin search, install, or activation
path.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SHARED_SCRIPTS_DIR = str(Path(__file__).resolve().parents[3] / "scripts")
if _SHARED_SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SHARED_SCRIPTS_DIR)
