"""Owned-path reconciliation for profiled implementation runs.

Detection, never rollback: this module reads Git-visible state and classifies it. It
never stages, restores, deletes, checks out, or overwrites anything, so an undeclared
change fails the attempt while remaining intact for root disposition.

The algorithm is correct for a worktree that was already dirty at launch — a
pre-existing modification is only exonerated when its content fingerprint is
unchanged, so a worker edit on top of a user edit is still detected.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
from typing import Iterable, Sequence


REPOSITORY_FINGERPRINT_VERSION = 1
MAX_IGNORED_PATHS = 50_000


class ReconcileError(ValueError):
    """Raised for a non-Git project root or an unusable ownership declaration."""


def require_git_repo(project_root: Path) -> Path:
    root = Path(project_root).expanduser().resolve()
    if not root.is_dir():
        raise ReconcileError(f"project root is not a directory: {root}")
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise ReconcileError(f"git is unavailable for reconciliation: {exc}") from exc
    if result.returncode != 0:
        raise ReconcileError(
            f"profiled implementation requires a git project root: {root}"
        )
    toplevel = Path(result.stdout.strip()).resolve()
    if toplevel != root:
        raise ReconcileError(
            f"project root is not the git toplevel ({toplevel}): {root}"
        )
    return root


def git_control_paths(project_root: Path) -> tuple[Path, ...]:
    """Return the visible .git entry plus resolved worktree/common control roots."""
    root = require_git_repo(project_root)
    paths = [root / ".git"]
    for flag in ("--absolute-git-dir", "--git-common-dir"):
        raw = _git_output(root, "rev-parse", flag).decode("utf-8", errors="replace").strip()
        path = Path(raw)
        if not path.is_absolute():
            path = root / path
        paths.append(path.resolve())
    unique: list[Path] = []
    for path in paths:
        candidate = path.resolve() if path.exists() else path.absolute()
        if candidate not in unique:
            unique.append(candidate)
    return tuple(unique)


def validate_owned_path(project_root: Path, raw: str) -> str:
    """Normalize one ``--owned-path`` to a project-relative POSIX path.

    Both the declaration and its real location must stay inside the project, so a
    symlink cannot be used to claim ownership of something outside the boundary.
    """
    root = Path(project_root).expanduser().resolve()
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    # Canonicalize the ancestors but not the leaf: platform links such as
    # /var -> /private/var must not read as an escape, while a symlinked leaf
    # still fails the realpath check below.
    lexical = Path(os.path.realpath(candidate.parent)) / candidate.name
    real = Path(os.path.realpath(candidate))
    for path in (lexical, real):
        if path != root and root not in path.parents:
            raise ReconcileError(f"owned path resolves outside the project root: {raw}")
    relative = lexical.relative_to(root)
    if str(relative) in ("", "."):
        raise ReconcileError("owned path must name a file or directory, not the root")
    return relative.as_posix()


def _fingerprint_file(path: Path) -> str | None:
    try:
        if path.is_symlink():
            return "symlink:" + os.readlink(path)
        if not path.exists():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return "unreadable"


def _is_within(relpath: str, prefixes: Iterable[str]) -> bool:
    for prefix in prefixes:
        if relpath == prefix or relpath.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def worktree_fingerprint(
    project_root: Path, *, exclude_relpaths: Sequence[str] = ()
) -> dict[str, dict]:
    """Fingerprint every Git-visible change, with content hashes for dirty paths.

    ``--no-renames`` is deliberate: a rename becomes an explicit delete plus add, so
    ownership is decided per concrete path instead of per heuristic similarity score.
    Git never reports its own internals here, and declared scratch roots are excluded.
    """
    root = Path(project_root).expanduser().resolve()
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--no-renames",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise ReconcileError(f"git status failed in {root}: {result.stderr.strip()}")

    fingerprint: dict[str, dict] = {}
    for entry in result.stdout.split("\0"):
        if len(entry) < 4:
            continue
        status = entry[:2]
        relpath = entry[3:]
        if relpath.startswith(".git/") or _is_within(relpath, exclude_relpaths):
            continue
        fingerprint[relpath] = {
            "status": status,
            "sha256": _fingerprint_file(root / relpath),
        }
    return fingerprint


def _git_output(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise ReconcileError(f"git {' '.join(args)} failed in {root}: {stderr}")
    return result.stdout


def _head_oid(root: Path) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return result.stdout.strip()
    # An unborn repository has no HEAD object but is still a valid Git repository.
    if result.returncode == 128:
        return None
    raise ReconcileError(f"git rev-parse failed in {root}: {result.stderr.strip()}")


def _index_sha256(root: Path) -> str:
    return hashlib.sha256(_git_output(root, "ls-files", "--stage", "-z")).hexdigest()


def _git_control_tree(root: Path, relative: str) -> dict[str, str | None]:
    target_raw = _git_output(root, "rev-parse", "--git-path", relative)
    target = Path(target_raw.decode("utf-8", errors="replace").strip())
    if not target.is_absolute():
        target = root / target
    target = target.resolve()
    if target.is_file() or target.is_symlink():
        return {relative: _fingerprint_file(target)}
    if not target.is_dir():
        return {}
    return {
        f"{relative}/{path.relative_to(target).as_posix()}": _fingerprint_file(path)
        for path in sorted(target.rglob("*"))
        if path.is_file() or path.is_symlink()
    }


def ignored_fingerprint(
    project_root: Path, *, exclude_relpaths: Sequence[str] = ()
) -> dict[str, str | None]:
    """Hash every ignored non-scratch file without retaining its contents.

    Ignored trees are where package installation and build side effects commonly hide
    from ``git status``. The path-count bound fails closed before the private baseline
    itself can become an unbounded generated-state artifact; file hashing is streaming.
    """
    root = Path(project_root).expanduser().resolve()
    raw = _git_output(
        root, "ls-files", "--others", "--ignored", "--exclude-standard", "-z"
    )
    paths = [
        item.decode("utf-8", errors="surrogateescape")
        for item in raw.split(b"\0")
        if item
    ]
    if len(paths) > MAX_IGNORED_PATHS:
        raise ReconcileError(
            f"ignored-file snapshot exceeds the {MAX_IGNORED_PATHS}-path safety bound"
        )
    fingerprint = {
        relpath: _fingerprint_file(root / relpath)
        for relpath in sorted(paths)
        if not _is_within(relpath, exclude_relpaths)
    }
    ignored_status = _git_output(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--ignored=matching",
        "--untracked-files=all",
        "--no-renames",
    )
    for raw_entry in ignored_status.split(b"\0"):
        if not raw_entry.startswith(b"!! "):
            continue
        relpath = raw_entry[3:].decode("utf-8", errors="surrogateescape")
        if not relpath.endswith("/") or _is_within(relpath.rstrip("/"), exclude_relpaths):
            continue
        fingerprint.setdefault(relpath, "directory")
    return fingerprint


def repository_fingerprint(
    project_root: Path, *, exclude_relpaths: Sequence[str] = ()
) -> dict:
    """Capture Git control state plus visible and ignored worktree state."""
    root = require_git_repo(project_root)
    return {
        "version": REPOSITORY_FINGERPRINT_VERSION,
        "head": _head_oid(root),
        "index_sha256": _index_sha256(root),
        "refs_sha256": hashlib.sha256(
            _git_output(root, "for-each-ref", "--format=%(refname)%00%(objectname)")
        ).hexdigest(),
        "config_sha256": hashlib.sha256(
            _git_output(root, "config", "--local", "--null", "--list")
        ).hexdigest(),
        "hooks": _git_control_tree(root, "hooks"),
        "info": _git_control_tree(root, "info"),
        "worktree": worktree_fingerprint(root, exclude_relpaths=exclude_relpaths),
        "ignored": ignored_fingerprint(root, exclude_relpaths=exclude_relpaths),
    }


def reconcile(
    baseline: dict[str, dict],
    final: dict[str, dict],
    *,
    owned_paths: Sequence[str],
    scratch_relpaths: Sequence[str] = (),
) -> dict:
    """Classify final Git-visible state as owned, pre-existing, scratch, or undeclared."""
    owned: list[str] = []
    pre_existing: list[str] = []
    scratch: list[str] = []
    undeclared: list[str] = []

    for relpath in sorted(set(baseline) | set(final)):
        if _is_within(relpath, scratch_relpaths):
            if relpath in final:
                scratch.append(relpath)
            continue
        before = baseline.get(relpath)
        after = final.get(relpath)
        if before is not None and before == after:
            pre_existing.append(relpath)
            continue
        if _is_within(relpath, owned_paths):
            owned.append(relpath)
        else:
            undeclared.append(relpath)

    return {
        "owned": owned,
        "pre_existing_unchanged": pre_existing,
        "scratch": scratch,
        "undeclared": undeclared,
        "reconciled": not undeclared,
    }


def reconcile_repository(
    baseline: dict,
    final: dict,
    *,
    owned_paths: Sequence[str],
    scratch_relpaths: Sequence[str] = (),
) -> dict:
    """Reconcile product paths while refusing Git-control and ignored side effects."""
    if baseline.get("version") != REPOSITORY_FINGERPRINT_VERSION:
        raise ReconcileError("unsupported baseline repository fingerprint version")
    if final.get("version") != REPOSITORY_FINGERPRINT_VERSION:
        raise ReconcileError("unsupported final repository fingerprint version")

    report = reconcile(
        baseline.get("worktree", {}),
        final.get("worktree", {}),
        owned_paths=owned_paths,
        scratch_relpaths=scratch_relpaths,
    )
    control_changes: list[str] = []
    if baseline.get("head") != final.get("head"):
        control_changes.append("git:HEAD")
    if baseline.get("index_sha256") != final.get("index_sha256"):
        control_changes.append("git:index")
    if baseline.get("refs_sha256") != final.get("refs_sha256"):
        control_changes.append("git:refs")
    if baseline.get("config_sha256") != final.get("config_sha256"):
        control_changes.append("git:config")
    if baseline.get("hooks") != final.get("hooks"):
        control_changes.append("git:hooks")
    if baseline.get("info") != final.get("info"):
        control_changes.append("git:info")

    before_ignored = baseline.get("ignored", {})
    after_ignored = final.get("ignored", {})
    raw_ignored_changes = sorted(
        path
        for path in set(before_ignored) | set(after_ignored)
        if before_ignored.get(path) != after_ignored.get(path)
        and not _is_within(path, scratch_relpaths)
    )
    ignored_changes = [
        path
        for path in raw_ignored_changes
        if not (
            path.endswith("/")
            and any(
                other != path and other.startswith(path)
                for other in raw_ignored_changes
            )
        )
    ]
    report["control_changes"] = control_changes
    report["ignored_changes"] = ignored_changes
    report["reconciled"] = bool(
        report["reconciled"] and not control_changes and not ignored_changes
    )
    return report
