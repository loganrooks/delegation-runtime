"""Scratch-root lifecycle and aggregate generated-state accounting.

Accounting is *sampled*, not quota-backed: a per-file resource limit and a bounded
in-process watchdog make accidental overshoot unlikely, but neither establishes an
adversarial byte ceiling. Nothing here deletes a user file as budget recovery.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import threading
from typing import Callable, Iterable
from dataclasses import dataclass


MIB = 1024 * 1024
CEILING_BYTES = 240 * MIB
STOP_BYTES = 192 * MIB
_STOP_RATIO = 0.8

OWNERSHIP_MARKER = ".delegate-to-claude-scratch.json"
SCRATCH_MARKER_VERSION = 1
MAX_WORKER_FILE_BYTES = 32 * MIB


class BudgetError(ValueError):
    """Raised for any refused path or exceeded generated-state budget."""


def validate_limit_bytes(limit_bytes: int) -> int:
    if limit_bytes <= 0:
        raise BudgetError("state limit must be positive")
    if limit_bytes > CEILING_BYTES:
        raise BudgetError(
            f"configured state limit exceeds the 240 MiB ceiling: {limit_bytes} bytes"
        )
    return limit_bytes


def stop_threshold_bytes(limit_bytes: int) -> int:
    """Execution stops below the admission ceiling, never at it."""
    return min(int(limit_bytes * _STOP_RATIO), STOP_BYTES)


def dedupe_roots(paths: Iterable[Path]) -> tuple[Path, ...]:
    """Drop any root contained by another so overlapping roots are counted once."""
    resolved: list[Path] = []
    for path in paths:
        candidate = Path(path).resolve()
        if candidate not in resolved:
            resolved.append(candidate)
    kept: list[Path] = []
    for candidate in resolved:
        if any(
            other != candidate and other in candidate.parents for other in resolved
        ):
            continue
        kept.append(candidate)
    return tuple(kept)


def _directory_size(path: Path, *, exclude_roots: Iterable[Path] = ()) -> int:
    total = 0
    if not path.exists():
        return 0
    if path.is_file() and not path.is_symlink():
        return path.stat().st_size
    excluded = {Path(item).resolve() for item in exclude_roots}
    for current, directories, files in os.walk(path):
        current_path = Path(current).resolve()
        directories[:] = [
            name for name in directories if (current_path / name).resolve() not in excluded
        ]
        if current_path in excluded:
            directories[:] = []
            continue
        for name in files:
            entry = current_path / name
            try:
                if entry.is_file() and not entry.is_symlink():
                    total += entry.stat().st_size
            except OSError:
                continue
    return total


def aggregate_size(paths: Iterable[Path]) -> int:
    return sum(_directory_size(root) for root in dedupe_roots(paths))


def preflight(paths: Iterable[Path], *, limit_bytes: int, headroom_bytes: int) -> int:
    """Account for managed state plus every declared scratch root before launching."""
    total = aggregate_size(paths)
    if total + max(0, headroom_bytes) >= limit_bytes:
        raise BudgetError(
            f"accounted generated state plus reserved log headroom "
            f"({total} + {headroom_bytes} bytes) reaches the configured limit of "
            f"{limit_bytes} bytes"
        )
    return total


@dataclass(frozen=True)
class ExecutionWatchScope:
    fixed_bytes: int
    dynamic_roots: tuple[Path, ...]
    dynamic_threshold_bytes: int


def execution_watch_scope(
    *,
    state_root: Path,
    run_dir: Path,
    scratch_root: Path | None,
    stop_bytes: int,
) -> ExecutionWatchScope:
    """Separate fixed history from roots that may grow during this attempt."""
    dynamic_roots = dedupe_roots(
        [Path(run_dir)] + ([Path(scratch_root)] if scratch_root is not None else [])
    )
    state = Path(state_root).resolve()
    excluded_from_state = tuple(
        root for root in dynamic_roots if root == state or state in root.parents
    )
    fixed_bytes = _directory_size(state, exclude_roots=excluded_from_state)
    threshold = stop_bytes - fixed_bytes
    if threshold <= 0:
        raise BudgetError(
            f"historical generated state ({fixed_bytes} bytes) already reaches the "
            f"execution stop threshold of {stop_bytes} bytes"
        )
    return ExecutionWatchScope(
        fixed_bytes=fixed_bytes,
        dynamic_roots=dynamic_roots,
        dynamic_threshold_bytes=threshold,
    )


def conservative_file_limit(*, remaining_bytes: int) -> int:
    """Return a per-file accident guard no larger than current aggregate headroom."""
    return max(1, min(MAX_WORKER_FILE_BYTES, int(remaining_bytes)))


class SharedLogBudget:
    """One byte budget shared by stdout and stderr, not two independent maxima."""

    def __init__(self, limit_bytes: int):
        self._limit = max(0, int(limit_bytes))
        self._used = 0
        self._truncated = False
        self._lock = threading.Lock()

    def take(self, requested: int) -> int:
        with self._lock:
            allowed = max(0, min(requested, self._limit - self._used))
            self._used += allowed
            if allowed < requested:
                self._truncated = True
            return allowed

    @property
    def used(self) -> int:
        return self._used

    @property
    def truncated(self) -> bool:
        return self._truncated


def reject_symlinked_path(path: Path) -> None:
    """Refuse a symlinked leaf or any caller-redirectable symlinked ancestor.

    The walk stops at the first administratively-owned ancestor: components above it
    are not redirectable by the caller, and on macOS they include benign platform
    links such as ``/var -> /private/var``.
    """
    current = path
    while True:
        if current.is_symlink():
            raise BudgetError(f"refusing a scratch root through a symlink: {current}")
        parent = current.parent
        if parent == current or not os.access(parent, os.W_OK):
            return
        current = parent


def _marker_path(directory: Path) -> Path:
    return directory / OWNERSHIP_MARKER


def resolve_scratch_dir(
    requested: Path | None, *, run_dir: Path
) -> tuple[Path, str]:
    """Validate or create the one worker-writable scratch root.

    Returns the canonical root and its provenance (``default`` or ``argument``).
    An existing directory must be empty or carry this manager's ownership marker;
    an unowned, non-empty directory is refused rather than adopted or cleared.
    """
    provenance = "argument" if requested is not None else "default"
    target = Path(requested).expanduser() if requested is not None else run_dir / "scratch"

    reject_symlinked_path(target)
    if target.exists() and not target.is_dir():
        raise BudgetError(f"scratch root is not a directory: {target}")
    if not target.exists():
        if not target.parent.is_dir():
            raise BudgetError(f"scratch parent directory does not exist: {target.parent}")
        target.mkdir(mode=0o700)
        os.chmod(target, 0o700)
    reject_symlinked_path(target)
    resolved = target.resolve()

    current_uid = os.getuid() if hasattr(os, "getuid") else None
    target_stat = resolved.stat()
    if current_uid is not None and target_stat.st_uid != current_uid:
        raise BudgetError(
            f"scratch root is not owned by the current user: {resolved}"
        )
    mode = stat.S_IMODE(target_stat.st_mode)
    if (mode & 0o077) or (mode & 0o700) != 0o700:
        raise BudgetError(
            f"scratch root permissions must be private (0700): {resolved} has {mode:04o}"
        )

    marker = _marker_path(resolved)
    entries = [entry for entry in resolved.iterdir() if entry.name != OWNERSHIP_MARKER]
    if entries and not marker.is_file():
        raise BudgetError(
            f"refusing an unowned scratch root that is not empty: {resolved}"
        )
    expected_marker = {
        "schema_version": SCRATCH_MARKER_VERSION,
        "owner": "delegate-to-claude",
        "provenance": provenance,
        "run_id": run_dir.resolve().name,
        "root": str(resolved),
        "uid": current_uid,
    }
    if marker.exists() and not marker.is_file():
        raise BudgetError(f"scratch ownership marker is not a file: {marker}")
    if marker.is_file():
        try:
            observed_marker = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BudgetError(f"invalid scratch ownership marker: {marker}") from exc
        if observed_marker != expected_marker:
            raise BudgetError(
                f"scratch ownership marker does not authorize this run: {marker}"
            )
    else:
        marker.write_text(json.dumps(expected_marker, sort_keys=True), encoding="utf-8")
        os.chmod(marker, 0o600)
    return resolved, provenance


class ScratchWatchdog:
    """Bounded in-process sampler — not a service, daemon, or persistent monitor."""

    def __init__(
        self,
        roots: Iterable[Path],
        *,
        threshold_bytes: int,
        on_exceed: Callable[[int], None],
        interval: float = 0.25,
    ):
        self._roots = dedupe_roots(roots)
        self._threshold = threshold_bytes
        self._on_exceed = on_exceed
        self._interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.exceeded = False

    def sample(self) -> int:
        return sum(_directory_size(root) for root in self._roots)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            total = self.sample()
            if total >= self._threshold:
                self.exceeded = True
                self._on_exceed(total)
                return

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
