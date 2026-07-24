#!/usr/bin/env python3
"""Run resumable Claude CLI workers with bounded, structured local evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
import uuid

from delegate_to_claude.profiles import (
    BROADER,
    PROFILE_IDS,
    PROFILE_VERSION,
    UNKNOWN,
    ProfileError,
    classify_manifest,
    expected_startup_tools,
    resolve_profile,
)
# Import discovery for a directly executed, uninstalled candidate: locate the
# repo-local shared policy package without requiring PYTHONPATH. Not a general
# plugin search, install, or activation path.
_SHARED_SCRIPTS_DIR = str(Path(__file__).resolve().parents[2] / "scripts")
if _SHARED_SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SHARED_SCRIPTS_DIR)

from delegation_policy import PolicyValidationError, normalize_policy  # noqa: E402
from delegation_policy.diff import compare_policies  # noqa: E402
from delegation_policy.explain import build_explanation, render_text  # noqa: E402
from delegate_to_claude.policy_presets import (  # noqa: E402
    PRESET_ASSURANCE,
    PRESET_IDS,
    canonical_preset_id,
    preset_policy,
)
from delegate_to_claude.reconcile import (  # noqa: E402
    ReconcileError,
    git_control_paths,
    reconcile_repository,
    repository_fingerprint,
    require_git_repo,
    validate_owned_path,
)
from delegate_to_claude.runtime_policy import (  # noqa: E402
    PolicyError,
    build_runtime_policy,
    missing_capabilities,
    policy_mode_for_profile,
)
from delegate_to_claude.state_budget import (  # noqa: E402
    MIB,
    BudgetError,
    ScratchWatchdog,
    SharedLogBudget,
    aggregate_size,
    conservative_file_limit,
    execution_watch_scope,
    preflight,
    reject_symlinked_path,
    resolve_scratch_dir,
    stop_threshold_bytes,
    validate_limit_bytes,
)

try:  # pragma: no cover - platform dependent
    import resource
except ImportError:  # pragma: no cover - platform dependent
    resource = None


SCHEMA_VERSION = 2
DEFAULT_STATE_ROOT = Path("~/.codex/state/delegate-to-claude").expanduser()
PERMISSION_MODES = ("acceptEdits", "auto", "dontAsk", "manual", "plan")
EFFORTS = ("low", "medium", "high", "xhigh", "max")
PROFILES = PROFILE_IDS
STRICT_MANIFEST_PROFILES = ("strict-readonly", "verified-review", "artifact-review")
MANIFEST_VIOLATION_EXIT_CODE = 3
BUDGET_VIOLATION_EXIT_CODE = 4
RECONCILE_VIOLATION_EXIT_CODE = 5
COMMAND_POLICY_VERSION = 1
TERMINATE_GRACE_SECONDS = 2.0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            if value and not value.endswith("\n"):
                handle.write("\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def read_json(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected object in {path}")
    return value


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_result(event: dict) -> dict:
    usage = event.get("usage") if isinstance(event.get("usage"), dict) else {}
    model_usage = event.get("modelUsage") if isinstance(event.get("modelUsage"), dict) else {}
    observed_models = sorted(str(key) for key in model_usage)
    if len(observed_models) == 1:
        observed = {"status": "observed", "value": observed_models[0]}
    elif observed_models:
        observed = {"status": "conflicted", "value": observed_models}
    else:
        observed = {"status": "unobserved", "value": None}
    return {
        "subtype": event.get("subtype"),
        "is_error": event.get("is_error"),
        "session_id": event.get("session_id"),
        "stop_reason": event.get("stop_reason"),
        "num_turns": event.get("num_turns"),
        "total_cost_usd": event.get("total_cost_usd"),
        "usage": {
            key: usage.get(key)
            for key in (
                "input_tokens",
                "output_tokens",
                "cache_creation_input_tokens",
                "cache_read_input_tokens",
            )
            if key in usage
        },
        "observed_model": observed,
        "model_usage": {
            model: {
                key: details.get(key)
                for key in (
                    "inputTokens",
                    "outputTokens",
                    "cacheReadInputTokens",
                    "cacheCreationInputTokens",
                    "costUSD",
                )
                if key in details
            }
            for model, details in model_usage.items()
            if isinstance(details, dict)
        },
    }


def observed_manifest(init_event: dict | None) -> tuple[tuple[str, ...] | None, list[str]]:
    """Observed startup surface. ``None`` tools means absent or omitted, not empty."""
    if not isinstance(init_event, dict):
        return None, []
    raw_tools = init_event.get("tools")
    tools = (
        tuple(sorted({str(t) for t in raw_tools}))
        if isinstance(raw_tools, list)
        else None
    )
    raw_servers = init_event.get("mcp_servers")
    servers: list[str] = []
    if isinstance(raw_servers, list):
        names = set()
        for entry in raw_servers:
            if isinstance(entry, dict) and "name" in entry:
                names.add(str(entry["name"]))
            elif isinstance(entry, str):
                names.add(entry)
        servers = sorted(names)
    return tools, servers


def is_materializable(attempt: dict) -> bool:
    """Eligibility for materialization, with legacy metadata still readable.

    An explicit value is authoritative in both directions — a recorded ``false`` is
    never reinterpreted. Only when the field is absent (a contract-version-1 record)
    is eligibility derived from the terminal evidence that predates the field.
    """
    if "materializable" in attempt:
        return bool(attempt["materializable"])
    result = attempt.get("result")
    return (
        attempt.get("status") == "terminal"
        and attempt.get("exit_code") == 0
        and not attempt.get("stream_truncated")
        and isinstance(result, dict)
        and result.get("is_error") is not True
    )


def materialize_attempt_result(attempt: dict, output: Path, *, overwrite: bool) -> dict:
    """The single materialization primitive: every writer path goes through here."""
    event, result_text = last_result(Path(attempt["stream_path"]))
    if not event or event.get("is_error") is True or result_text is None:
        raise ValueError("selected attempt has no successful final result text")
    raw_output = Path(output).expanduser()
    reject_symlinked_path(raw_output)
    resolved = Path(os.path.realpath(raw_output.parent)) / raw_output.name
    if resolved.exists() and not overwrite:
        raise FileExistsError(f"output already exists: {resolved}")
    atomic_text(resolved, result_text)
    return {
        "attempt": attempt.get("number"),
        "output": str(resolved),
        "bytes": resolved.stat().st_size,
        "sha256": file_sha256(resolved),
    }


def terminate_child(process: subprocess.Popen) -> None:
    """Graceful stop, then a bounded kill — used for manifest and budget violations."""
    try:
        process.terminate()
        process.wait(timeout=TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=TERMINATE_GRACE_SECONDS)
        except (OSError, subprocess.TimeoutExpired):
            pass
    except OSError:
        pass


def select_attempt(attempts: list[dict], number: int | None = None) -> dict:
    if number is not None:
        for attempt in attempts:
            if attempt.get("number") == number:
                if not is_materializable(attempt):
                    raise ValueError(f"attempt {number} is not a successful terminal run")
                return attempt
        raise ValueError(f"attempt not found: {number}")
    for attempt in reversed(attempts):
        if is_materializable(attempt):
            return attempt
    raise ValueError("run has no successful terminal attempt")


def last_result(stream_path: Path) -> tuple[dict | None, str | None]:
    event_found = None
    result_text = None
    if not stream_path.exists():
        return None, None
    with stream_path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("type") == "result":
                event_found = event
                if isinstance(event.get("result"), str):
                    result_text = event["result"]
    return event_found, result_text


def state_paths(state_root: Path, run_id: str) -> tuple[Path, Path]:
    run_dir = state_root / "runs" / run_id
    return run_dir, run_dir / "metadata.json"


def load_run(state_root: Path, run_id: str) -> tuple[Path, Path, dict]:
    run_dir, metadata_path = state_paths(state_root, run_id)
    if not metadata_path.exists():
        raise FileNotFoundError(f"run not found: {run_id}")
    return run_dir, metadata_path, read_json(metadata_path)


def add_common_run_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--prompt-file", required=True, type=Path)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    parser.add_argument("--claude-bin", default="claude")
    parser.add_argument("--max-log-mib", type=float, default=32.0)


def base_command(metadata: dict, claude_bin: str, *, resume: bool) -> list[str]:
    requested = metadata["requested"]
    command = [claude_bin, "-p"]
    if resume:
        command += ["--resume", metadata["session_id"]]
    else:
        command += ["--session-id", metadata["session_id"]]
    command += [
        "--model",
        requested["model"],
        "--effort",
        requested["effort"],
        "--permission-mode",
        requested["permission_mode"],
        "--name",
        metadata["name"],
        "--output-format",
        "stream-json",
        "--verbose",
        "--include-hook-events",
    ]
    if requested.get("max_turns") is not None:
        command += ["--max-turns", str(requested["max_turns"])]
    if requested.get("max_budget_usd") is not None:
        command += ["--max-budget-usd", str(requested["max_budget_usd"])]
    command += list(metadata.get("runtime", {}).get("cli_args", []))
    for directory in metadata.get("add_dirs", []):
        command += ["--add-dir", directory]
    denied = metadata.get("disallowed_tools", [])
    if denied:
        command += ["--disallowedTools", ",".join(denied)]
    tools = metadata.get("tools", [])
    if tools:
        command += ["--tools", ",".join(tools)]
    allowed = metadata.get("allowed_tools", [])
    if allowed:
        command += ["--allowedTools", ",".join(allowed)]
    return command


def bounded_copy(source, destination, budget: SharedLogBudget) -> None:
    """Drain a child stream into a log under the run's single shared byte budget."""
    while True:
        chunk = source.read(8192)
        if not chunk:
            return
        allowed = budget.take(len(chunk))
        if allowed:
            destination.write(chunk[:allowed])
            destination.flush()


def _scratch_relpaths(metadata: dict) -> tuple[str, ...]:
    """Scratch roots expressed relative to the project, when they live inside it."""
    project = Path(metadata["cwd"]).resolve()
    root = metadata.get("scratch", {}).get("root")
    if not root:
        return ()
    scratch = Path(root).resolve()
    if scratch == project or project not in scratch.parents:
        return ()
    return (scratch.relative_to(project).as_posix(),)


def _capture_baseline(metadata: dict, attempt_dir: Path) -> dict:
    baseline = repository_fingerprint(
        Path(metadata["cwd"]), exclude_relpaths=_scratch_relpaths(metadata)
    )
    atomic_json(attempt_dir / "worktree-baseline.json", baseline)
    return baseline


def _resource_limiter(limit_bytes: int):
    """Per-file ceiling for the worker and its subprocesses, where supported.

    This is a coarse accident guard, not a quota: it bounds any single file, not the
    aggregate a determined subprocess could spread across many files.
    """
    if resource is None:
        return None

    def apply() -> None:  # pragma: no cover - runs in the forked child
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
            ceiling = limit_bytes if hard == resource.RLIM_INFINITY else min(limit_bytes, hard)
            resource.setrlimit(resource.RLIMIT_FSIZE, (ceiling, hard))
        except (ValueError, OSError):
            pass

    return apply


def execute_attempt(
    run_dir: Path,
    metadata_path: Path,
    metadata: dict,
    prompt_file: Path,
    claude_bin: str,
    max_log_bytes: int,
    *,
    resume: bool,
) -> int:
    if not prompt_file.is_file():
        raise FileNotFoundError(f"prompt file not found: {prompt_file}")
    number = len(metadata["attempts"]) + 1
    attempt_dir = run_dir / f"attempt-{number:03d}"
    attempt_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(attempt_dir, 0o700)
    stream_path = attempt_dir / "stream.jsonl"
    stderr_path = attempt_dir / "stderr.log"
    attempt = {
        "number": number,
        "started_at": utc_now(),
        "status": "starting",
        "prompt": {"path": str(prompt_file.resolve()), "sha256": file_sha256(prompt_file)},
        "stream_path": str(stream_path),
        "stderr_path": str(stderr_path),
        "resume": resume,
    }
    metadata["attempts"].append(attempt)
    atomic_json(metadata_path, metadata)

    runtime = metadata.get("runtime", {})
    process_cwd = runtime.get("cwd", metadata["cwd"])
    child_env = os.environ.copy()
    child_env.update(runtime.get("env", {}))
    for name in ("XDG_CACHE_HOME", "PYTHONPYCACHEPREFIX"):
        value = runtime.get("env", {}).get(name)
        if value:
            Path(value).mkdir(parents=True, exist_ok=True)

    owned_paths = tuple(metadata.get("owned_paths", []))
    scratch_relpaths = _scratch_relpaths(metadata)
    baseline = _capture_baseline(metadata, attempt_dir) if owned_paths else None

    expected_tools = tuple(metadata.get("expected_tools", []))
    exposed_but_denied = tuple(metadata.get("exposed_but_denied", []))
    manifest_enforced = metadata.get("profile") in STRICT_MANIFEST_PROFILES

    state_limit_bytes = metadata.get("state_limit_bytes", 0)
    stop_bytes = metadata.get("stop_threshold_bytes") or stop_threshold_bytes(
        state_limit_bytes or MIB
    )
    scratch_root = (
        Path(metadata["scratch"]["root"])
        if metadata.get("scratch", {}).get("root")
        else None
    )
    watch_scope = None
    if state_limit_bytes:
        watch_scope = execution_watch_scope(
            state_root=Path(metadata["state_root"]),
            run_dir=run_dir,
            scratch_root=scratch_root,
            stop_bytes=stop_bytes,
        )
        current_dynamic_bytes = aggregate_size(watch_scope.dynamic_roots)
        attempt["state_watch"] = {
            "fixed_bytes": watch_scope.fixed_bytes,
            "dynamic_roots": [str(path) for path in watch_scope.dynamic_roots],
            "dynamic_threshold_bytes": watch_scope.dynamic_threshold_bytes,
        }
        per_file_limit = conservative_file_limit(
            remaining_bytes=watch_scope.dynamic_threshold_bytes - current_dynamic_bytes
        )
    else:
        per_file_limit = 0

    command = base_command(metadata, claude_bin, resume=resume)
    result_event = None
    log_budget = SharedLogBudget(max_log_bytes)
    stream_truncated = False
    interrupted = False
    manifest_failure = None
    manifest_status = UNKNOWN
    unexpected_tools: tuple[str, ...] = ()
    budget_exceeded_at = None
    watchdog = None

    with (
        prompt_file.open("rb") as prompt,
        stream_path.open("wb") as stream,
        stderr_path.open("wb") as stderr_log,
    ):
        os.chmod(stream_path, 0o600)
        os.chmod(stderr_path, 0o600)
        try:
            process = subprocess.Popen(
                command,
                cwd=process_cwd,
                env=child_env,
                stdin=prompt,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=_resource_limiter(per_file_limit) if per_file_limit else None,
            )
        except OSError as exc:
            attempt.update({
                "status": "launch-failed",
                "ended_at": utc_now(),
                "launch_error": type(exc).__name__,
            })
            metadata["updated_at"] = utc_now()
            atomic_json(metadata_path, metadata)
            raise
        attempt.update({"status": "running", "pid": process.pid})
        atomic_json(metadata_path, metadata)
        stderr_thread = threading.Thread(
            target=bounded_copy,
            args=(process.stderr, stderr_log, log_budget),
            daemon=True,
        )
        stderr_thread.start()

        def on_over_budget(total: int) -> None:
            nonlocal budget_exceeded_at
            budget_exceeded_at = (
                (watch_scope.fixed_bytes if watch_scope is not None else 0) + total
            )
            terminate_child(process)

        if watch_scope is not None:
            watchdog = ScratchWatchdog(
                watch_scope.dynamic_roots,
                threshold_bytes=watch_scope.dynamic_threshold_bytes,
                on_exceed=on_over_budget,
            )
            watchdog.start()

        init_event = None
        try:
            assert process.stdout is not None
            for raw in iter(process.stdout.readline, b""):
                allowed = log_budget.take(len(raw))
                if allowed:
                    stream.write(raw[:allowed])
                    stream.flush()
                if allowed < len(raw):
                    stream_truncated = True
                try:
                    event = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if (
                    manifest_enforced
                    and init_event is None
                    and not (
                        event.get("type") == "system"
                        and event.get("subtype") == "init"
                    )
                ):
                    manifest_failure = (
                        f"meaningful {event.get('type', 'unknown')} event arrived before init "
                        f"for profile {metadata['profile']}"
                    )
                    manifest_status = UNKNOWN
                    terminate_child(process)
                    break
                if event.get("type") == "system" and event.get("subtype") == "init":
                    init_event = event
                    print(json.dumps({
                        "event": "init",
                        "session_id": event.get("session_id"),
                        "model": event.get("model"),
                        "permission_mode": event.get("permissionMode"),
                    }), flush=True)
                    if manifest_enforced:
                        observed_tools, _ = observed_manifest(event)
                        manifest_status, unexpected_tools = classify_manifest(
                            expected_tools, exposed_but_denied, observed_tools
                        )
                        if manifest_status in (BROADER, UNKNOWN):
                            # Compare and stop before any assistant or tool event is
                            # accepted: an unexpected surface is a permission failure
                            # even if the model never calls the extra tool.
                            manifest_failure = (
                                f"startup manifest is {manifest_status} for profile "
                                f"{metadata['profile']}"
                            )
                            terminate_child(process)
                            break
                elif event.get("type") == "result":
                    result_event = event
                    print(json.dumps({"event": "result", **safe_result(event)}), flush=True)
        except KeyboardInterrupt:
            interrupted = True
            process.send_signal(signal.SIGINT)
        return_code = process.wait()
        if watchdog is not None:
            watchdog.stop()
        stderr_thread.join(timeout=TERMINATE_GRACE_SECONDS)
        if watch_scope is not None and budget_exceeded_at is None:
            final_dynamic_bytes = aggregate_size(watch_scope.dynamic_roots)
            if final_dynamic_bytes >= watch_scope.dynamic_threshold_bytes:
                budget_exceeded_at = watch_scope.fixed_bytes + final_dynamic_bytes

    observed_tools, observed_mcp_servers = observed_manifest(init_event)
    if not manifest_failure:
        manifest_status, unexpected_tools = classify_manifest(
            expected_tools, exposed_but_denied, observed_tools
        )
        if manifest_enforced and manifest_status in (BROADER, UNKNOWN):
            manifest_failure = (
                f"startup manifest is {manifest_status} for profile {metadata['profile']}"
            )

    has_successful_result = (
        isinstance(result_event, dict) and result_event.get("is_error") is not True
    )
    materializable = (
        not interrupted
        and return_code == 0
        and not stream_truncated
        and not log_budget.truncated
        and has_successful_result
        and manifest_failure is None
        and budget_exceeded_at is None
    )

    attempt.update({
        "status": "interrupted" if interrupted else "terminal",
        "ended_at": utc_now(),
        "exit_code": return_code,
        "stream_truncated": stream_truncated,
        "stderr_truncated": log_budget.truncated,
        "log_bytes": log_budget.used,
        "result": safe_result(result_event) if isinstance(result_event, dict) else None,
        "observed_tools": list(observed_tools) if observed_tools is not None else None,
        "observed_mcp_servers": observed_mcp_servers,
        "manifest_status": manifest_status,
        "manifest_failure_reason": manifest_failure,
        "unexpected_tools": list(unexpected_tools),
        "budget_exceeded_bytes": budget_exceeded_at,
    })

    if metadata.get("scratch", {}).get("root"):
        metadata["scratch"]["final_bytes"] = aggregate_size([metadata["scratch"]["root"]])
        metadata["scratch"]["disposition"] = (
            "over-budget" if budget_exceeded_at is not None else "within-budget"
        )

    reconciliation_failed = False
    if owned_paths:
        final = repository_fingerprint(
            Path(metadata["cwd"]), exclude_relpaths=scratch_relpaths
        )
        report = reconcile_repository(
            baseline or {},
            final,
            owned_paths=owned_paths,
            scratch_relpaths=scratch_relpaths,
        )
        attempt["reconciliation"] = report
        if not report["reconciled"]:
            # Detection, not rollback: the worktree is left exactly as found.
            reconciliation_failed = True
            materializable = False
    attempt["materializable"] = materializable

    artifact_error = None
    artifact = metadata.get("artifact")
    if artifact and artifact.get("output") and materializable:
        try:
            record = materialize_attempt_result(
                attempt, Path(artifact["output"]), overwrite=bool(artifact.get("overwrite"))
            )
            artifact.update({
                "attempt": record["attempt"],
                "sha256": record["sha256"],
                "bytes": record["bytes"],
                "materialized_at": utc_now(),
            })
        except (OSError, ValueError) as exc:
            artifact_error = f"{type(exc).__name__}: {exc}"
            artifact["error"] = artifact_error
            attempt["materializable"] = False

    metadata["updated_at"] = utc_now()
    atomic_json(metadata_path, metadata)

    if interrupted:
        return 130
    if manifest_failure:
        print(f"manifest violation: {manifest_failure}", file=sys.stderr)
        return MANIFEST_VIOLATION_EXIT_CODE
    if budget_exceeded_at is not None:
        print(
            "generated-state budget exceeded: execution stopped at "
            f"{budget_exceeded_at} bytes",
            file=sys.stderr,
        )
        return BUDGET_VIOLATION_EXIT_CODE
    if return_code:
        return return_code
    if log_budget.truncated:
        print("shared stdout/stderr log budget was truncated", file=sys.stderr)
        return 2
    if not has_successful_result:
        return 1
    if reconciliation_failed:
        print(
            "reconciliation failed: " + json.dumps(attempt["reconciliation"], sort_keys=True),
            file=sys.stderr,
        )
        return RECONCILE_VIOLATION_EXIT_CODE
    if artifact and artifact.get("output") and artifact.get("attempt") is None:
        # An artifact contract that produced no artifact is a failed attempt, even
        # when the child exited cleanly — a truncated stream is the common cause.
        print(
            "artifact was not materialized: "
            + (artifact_error or "attempt is not materializable"),
            file=sys.stderr,
        )
        return 2
    return 0


def _parse_named_root(value: str, *, reserved: set[str]) -> tuple[str, str]:
    name, sep, path = value.partition("=")
    if not sep or not name or not path:
        raise ValueError(f"expected NAME=PATH: {value!r}")
    if name in reserved:
        raise ValueError(f"root name is reserved: {name!r}")
    return name, path


def _parse_override(value: str) -> tuple[str, str]:
    key, sep, mode = value.partition("=")
    if not sep or not key or not mode:
        raise ValueError(f"expected CATEGORY=MODE: {value!r}")
    return key, mode


_EXPLAIN_NOTICE_KEYS = {
    "profile_transition", "cache_impact", "authority_change",
    "context_change", "runtime_change", "sandbox_change",
}
_EXPLAIN_CONFIRMATION_KEYS = {
    "profile_transition", "authority_expansion", "unsandboxed_command",
}
_EXPLAIN_OUTPUT_MODES = {"manager", "worker", "unavailable"}


def _validate_explain_override_sections(document: dict) -> None:
    output = document.get("output", {})
    if not isinstance(output, dict):
        raise PolicyValidationError("output must be an object")
    unknown_output = set(output) - {"mode", "roots"}
    if unknown_output:
        raise PolicyValidationError(f"output has unknown field(s): {sorted(unknown_output)}")
    output_mode = output.get("mode", "manager")
    if not isinstance(output_mode, str) or output_mode not in _EXPLAIN_OUTPUT_MODES:
        raise PolicyValidationError(f"output.mode invalid: {output_mode!r}")
    output_roots = output.get("roots", [])
    if not isinstance(output_roots, list) or any(
        not isinstance(root_id, str) or not root_id for root_id in output_roots
    ):
        raise PolicyValidationError("output.roots must be a list of non-empty strings")

    for section, allowed_keys, allowed_modes in (
        ("notices", _EXPLAIN_NOTICE_KEYS, {"always", "once", "never"}),
        ("confirmation", _EXPLAIN_CONFIRMATION_KEYS, {"ask", "never"}),
    ):
        values = document.get(section, {})
        if not isinstance(values, dict):
            raise PolicyValidationError(f"{section} must be an object")
        unknown = set(values) - allowed_keys
        if unknown:
            raise PolicyValidationError(f"{section} has unknown field(s): {sorted(unknown)}")
        for key, mode in values.items():
            if not isinstance(mode, str) or mode not in allowed_modes:
                raise PolicyValidationError(f"{section}.{key} has invalid mode: {mode!r}")


def _validate_explain_override_values(
    overrides: list[tuple[str, str]], *, section: str,
    allowed_keys: set[str], allowed_modes: set[str],
) -> None:
    for key, mode in overrides:
        if key not in allowed_keys:
            raise PolicyValidationError(f"{section} has unknown field(s): {[key]!r}")
        if mode not in allowed_modes:
            raise PolicyValidationError(f"{section}.{key} has invalid mode: {mode!r}")


def _build_explain_document(args: argparse.Namespace) -> dict:
    if args.profile:
        canonical_id, _ = canonical_preset_id(args.profile)
        from delegate_to_claude.policy_presets import PRESET_DOCUMENTS
        document = copy.deepcopy(PRESET_DOCUMENTS[canonical_id])
    else:
        document = json.loads(args.policy_file.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise PolicyValidationError("policy file must contain a JSON object")
    _validate_explain_override_sections(document)
    notice_overrides = [_parse_override(value) for value in args.notice]
    confirmation_overrides = [_parse_override(value) for value in args.confirmation]
    _validate_explain_override_values(
        notice_overrides,
        section="notices", allowed_keys=_EXPLAIN_NOTICE_KEYS,
        allowed_modes={"always", "once", "never"},
    )
    _validate_explain_override_values(
        confirmation_overrides,
        section="confirmation", allowed_keys=_EXPLAIN_CONFIRMATION_KEYS,
        allowed_modes={"ask", "never"},
    )

    filesystem = document.setdefault("filesystem", {})
    if not isinstance(filesystem, dict):
        raise PolicyValidationError("filesystem must be an object")
    roots = filesystem.setdefault("roots", {})
    if not isinstance(roots, dict):
        raise PolicyValidationError("filesystem.roots must be an object")
    rules = filesystem.setdefault("rules", [])
    if not isinstance(rules, list):
        raise PolicyValidationError("filesystem.rules must be a list")
    reserved = {"project", "scratch", "state", "output"}
    declared_named_roots: set[str] = set(roots)

    if args.profile and "project" in roots:
        roots["project"]["binding"] = str(args.workspace)
    if args.profile and args.scratch_dir and "scratch" in roots:
        roots["scratch"]["binding"] = str(args.scratch_dir)
    if args.output_dir:
        roots["output"] = {"kind": "output", "binding": str(args.output_dir)}
        output_section = document.setdefault("output", {"mode": "manager", "roots": []})
        if "output" not in output_section.get("roots", []):
            output_section["roots"] = list(output_section.get("roots", [])) + ["output"]

    for value in args.read_root:
        name, path = _parse_named_root(value, reserved=reserved)
        if name in declared_named_roots:
            raise ValueError(f"duplicate root name: {name!r}")
        roots[name] = {"kind": "external", "binding": path}
        rules.append({"operations": ["read"], "scope": name, "effect": "allow"})
        declared_named_roots.add(name)
    for value in args.write_root:
        name, path = _parse_named_root(value, reserved=reserved)
        if name in declared_named_roots:
            raise ValueError(f"duplicate root name: {name!r}")
        roots[name] = {"kind": "external", "binding": path}
        rules.append({"operations": ["write"], "scope": name, "effect": "allow"})
        declared_named_roots.add(name)

    notices = document.setdefault("notices", {})
    for key, mode in notice_overrides:
        notices[key] = mode
    confirmation = document.setdefault("confirmation", {})
    for key, mode in confirmation_overrides:
        confirmation[key] = mode

    return document


def command_explain(args: argparse.Namespace) -> int:
    try:
        document = _build_explain_document(args)
        policy = normalize_policy(document)
    except (PolicyValidationError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"explain refused: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    transition = None
    if args.compare_profile:
        try:
            compare_from = preset_policy(args.compare_profile)
            transition = compare_policies(compare_from, policy)
        except PolicyValidationError as exc:
            print(f"explain refused: {exc}", file=sys.stderr)
            return 2

    assurance = None
    if args.profile:
        canonical_id, _ = canonical_preset_id(args.profile)
        assurance = PRESET_ASSURANCE.get(canonical_id)

    explanation = build_explanation(policy, transition, assurance=assurance)
    if args.format == "json":
        print(json.dumps(explanation, indent=2, sort_keys=True))
    else:
        print(render_text(explanation))
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    report = {
        "claude_bin": args.claude_bin,
        "version": None,
        "auth": {"logged_in": False, "auth_method": None, "provider": None, "subscription": None},
        "auto_mode": {"advertised": False, "eligibility": "unchecked-until-real-run"},
    }
    try:
        version = subprocess.run(
            [args.claude_bin, "--version"], capture_output=True, text=True, check=True
        )
        report["version"] = version.stdout.strip()
        help_result = subprocess.run(
            [args.claude_bin, "--help"], capture_output=True, text=True, check=False
        )
        permission_choices = re.search(
            r"--permission-mode[\s\S]{0,500}?\(choices:\s*([^)]+)\)",
            help_result.stdout,
        )
        report["auto_mode"]["advertised"] = bool(
            permission_choices and re.search(r'["\']auto["\']', permission_choices.group(1))
        )
        auth_result = subprocess.run(
            [args.claude_bin, "auth", "status", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        if auth_result.returncode == 0:
            auth = json.loads(auth_result.stdout)
            report["auth"] = {
                "logged_in": bool(auth.get("loggedIn")),
                "auth_method": auth.get("authMethod"),
                "provider": auth.get("apiProvider"),
                "subscription": auth.get("subscriptionType"),
            }
        config_result = subprocess.run(
            [args.claude_bin, "auto-mode", "config"],
            capture_output=True,
            text=True,
            check=False,
        )
        report["auto_mode"]["config_readable"] = config_result.returncode == 0
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        report["error"] = type(exc).__name__
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["auth"]["logged_in"] else 1


def _probe_help(claude_bin: str) -> str:
    result = subprocess.run(
        [claude_bin, "--help"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise OSError(f"{claude_bin} --help exited {result.returncode}")
    return result.stdout


def _probe_auto_mode(claude_bin: str) -> None:
    result = subprocess.run(
        [claude_bin, "auto-mode", "config"], capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise OSError(
            f"auto-mode configuration check exited {result.returncode}"
        )


def command_run(args: argparse.Namespace) -> int:
    state_root = args.state_root.expanduser().resolve()
    max_log_bytes = int(args.max_log_mib * MIB)
    try:
        limit_bytes = validate_limit_bytes(int(args.state_limit_mib * MIB))
    except BudgetError as exc:
        print(f"state preflight refused: {exc}", file=sys.stderr)
        return 2
    cwd = args.cwd.expanduser().resolve()
    if not cwd.is_dir():
        print(f"working directory not found: {cwd}", file=sys.stderr)
        return 2

    resolved = None
    allowed_tools = list(args.allowed_tool)
    if args.profile:
        try:
            resolved = resolve_profile(
                args.profile,
                args.permission_mode,
                tuple(args.tool),
                tuple(args.allowed_tool),
                tuple(args.disallowed_tool),
                tuple(args.allowed_command),
            )
        except ProfileError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        if resolved.warning:
            print(resolved.warning, file=sys.stderr)
        permission_mode = resolved.permission_mode
        tools = list(resolved.tools)
        allowed_tools = list(resolved.allowed_tools)
        args.disallowed_tool = list(resolved.denied_tools)
    else:
        permission_mode = args.permission_mode
        tools = list(args.tool)
        if permission_mode is None:
            print("--permission-mode is required unless --profile supplies it", file=sys.stderr)
            return 2
        if args.allowed_command:
            print("--allowed-command requires --profile", file=sys.stderr)
            return 2

    # Authority-bearing arguments must agree with the resolved contract; there is no
    # last-flag-wins behaviour, and every conflict is refused before a paid launch.
    for flag, value in (
        ("--owned-path", args.owned_path),
        ("--artifact-output", args.artifact_output),
        ("--scratch-dir", args.scratch_dir),
    ):
        if value and resolved is None:
            print(f"{flag} requires --profile", file=sys.stderr)
            return 2
    if resolved is not None:
        if resolved.requires_artifact_output and not args.artifact_output:
            print(
                f"profile {resolved.profile_id} requires --artifact-output",
                file=sys.stderr,
            )
            return 2
        if args.artifact_output and not resolved.requires_artifact_output:
            print(
                f"profile {resolved.profile_id} has no output artifact contract; "
                "--artifact-output is not permitted",
                file=sys.stderr,
            )
            return 2
        if resolved.requires_owned_paths and not args.owned_path:
            print(
                f"profile {resolved.profile_id} requires at least one --owned-path",
                file=sys.stderr,
            )
            return 2
        if args.owned_path and not resolved.requires_owned_paths:
            print(
                f"profile {resolved.profile_id} has no ownership manifest; "
                "--owned-path is not permitted",
                file=sys.stderr,
            )
            return 2

    # Non-generative capability preflight: fail before a paid launch, never after.
    help_text = ""
    if resolved is not None and resolved.requires_native_sandbox:
        try:
            help_text = _probe_help(args.claude_bin)
        except OSError as exc:
            print(f"capability preflight failed: {exc}", file=sys.stderr)
            return 2
        missing = missing_capabilities(help_text, requires_native_sandbox=True)
        if missing:
            print(
                f"profile {resolved.profile_id} requires native sandboxing, but the "
                f"installed CLI does not advertise: {', '.join(missing)}",
                file=sys.stderr,
            )
            return 2
    if resolved is not None and resolved.requires_auto_mode:
        try:
            _probe_auto_mode(args.claude_bin)
        except OSError as exc:
            print(f"auto-mode capability preflight failed: {exc}", file=sys.stderr)
            return 2

    owned_relpaths: tuple[str, ...] = ()
    if resolved is not None and resolved.requires_owned_paths:
        try:
            project = require_git_repo(cwd)
            owned_relpaths = tuple(
                validate_owned_path(project, value) for value in args.owned_path
            )
        except ReconcileError as exc:
            print(f"ownership preflight failed: {exc}", file=sys.stderr)
            return 2

    declared_mcp = [Path(value).expanduser() for value in args.mcp_config]
    for path in declared_mcp:
        if not path.is_file():
            print(f"--mcp-config path is not a file: {path}", file=sys.stderr)
            return 2
    if not declared_mcp:
        for entry in allowed_tools:
            if entry.startswith("mcp__"):
                print(
                    "allowed mcp tool has no declared server configuration: "
                    f"{entry!r}; pass --mcp-config",
                    file=sys.stderr,
                )
                return 2

    artifact_output = None
    if args.artifact_output:
        artifact_output = Path(args.artifact_output).expanduser()
        try:
            reject_symlinked_path(artifact_output)
        except BudgetError as exc:
            print(f"artifact output refused: {exc}", file=sys.stderr)
            return 2
        artifact_output = (
            Path(os.path.realpath(artifact_output.parent)) / artifact_output.name
        )
        if not artifact_output.parent.is_dir():
            print(
                f"artifact output directory does not exist: {artifact_output.parent}",
                file=sys.stderr,
            )
            return 2
        if artifact_output.exists() and not args.overwrite_artifact:
            print(f"artifact output already exists: {artifact_output}", file=sys.stderr)
            return 2

    session_id = args.session_id or str(uuid.uuid4())
    try:
        uuid.UUID(session_id)
    except ValueError:
        print("session ID must be a UUID", file=sys.stderr)
        return 2
    run_id = session_id
    run_dir, metadata_path = state_paths(state_root, run_id)
    if run_dir.exists():
        print(f"run already exists: {run_id}", file=sys.stderr)
        return 2
    run_dir.mkdir(parents=True, mode=0o700)
    os.chmod(run_dir, 0o700)

    scratch_root = None
    scratch_provenance = None
    if resolved is not None and (resolved.uses_scratch_cwd or args.scratch_dir):
        try:
            scratch_root, scratch_provenance = resolve_scratch_dir(
                args.scratch_dir, run_dir=run_dir
            )
        except BudgetError as exc:
            print(f"scratch preflight refused: {exc}", file=sys.stderr)
            return 2

    if not declared_mcp:
        # With nothing declared, materialize an empty run-local configuration so
        # --strict-mcp-config has an explicit, hashable source to pin.
        empty_mcp = run_dir / "mcp.json"
        atomic_json(empty_mcp, {"mcpServers": {}})
        declared_mcp = [empty_mcp]

    settings_path = run_dir / "settings.json"
    try:
        policy = build_runtime_policy(
            mode=policy_mode_for_profile(resolved.profile_id if resolved else None),
            permission_mode=permission_mode,
            tools=tuple(tools),
            allowed_tools=tuple(allowed_tools),
            denied_tools=tuple(args.disallowed_tool),
            settings_path=settings_path,
            mcp_config_paths=tuple(declared_mcp),
            scratch_dir=scratch_root,
            project_root=cwd if resolved is not None else None,
            git_control_paths=(
                git_control_paths(cwd)
                if resolved is not None and resolved.requires_owned_paths
                else ()
            ),
            help_text=help_text,
        )
    except PolicyError as exc:
        print(f"runtime policy refused: {exc}", file=sys.stderr)
        return 2
    atomic_json(settings_path, policy.settings)

    add_dirs = [str(path.expanduser().resolve()) for path in args.add_dir]
    process_cwd = cwd
    if scratch_root is not None and resolved is not None and resolved.uses_scratch_cwd:
        # Claude runs from scratch with the project attached read-only, so the
        # writable boundary is scratch while the project stays readable.
        process_cwd = scratch_root
        if str(cwd) not in add_dirs:
            add_dirs.insert(0, str(cwd))

    budget_roots = [state_root] + ([scratch_root] if scratch_root else [])
    try:
        initial_bytes = preflight(
            budget_roots,
            limit_bytes=stop_threshold_bytes(limit_bytes),
            headroom_bytes=max_log_bytes,
        )
    except BudgetError as exc:
        print(f"state preflight refused: {exc}", file=sys.stderr)
        return 2

    expected_tools = expected_startup_tools(tuple(tools), tuple(allowed_tools))
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "session_id": session_id,
        "name": args.name or f"codex-{args.model}-{session_id[:8]}",
        "cwd": str(cwd),
        "state_root": str(state_root),
        "requested": {
            "model": args.model,
            "effort": args.effort,
            "permission_mode": permission_mode,
            "max_turns": args.max_turns,
            "max_budget_usd": args.max_budget_usd,
        },
        "profile": resolved.profile_id if resolved else None,
        "profile_requested": resolved.profile_requested if resolved else None,
        "profile_version": resolved.version if resolved else None,
        "profile_manifest_sha256": resolved.manifest_sha256 if resolved else None,
        "add_dirs": add_dirs,
        "disallowed_tools": args.disallowed_tool,
        "tools": tools,
        "allowed_tools": allowed_tools,
        "expected_tools": list(expected_tools),
        "exposed_but_denied": list(args.disallowed_tool),
        "command_policy": {
            "version": COMMAND_POLICY_VERSION,
            "commands": list(resolved.allowed_commands) if resolved else [],
            "enforcement": "permission-rule-only",
            "note": (
                "exact command permission rules bound which commands may be requested; "
                "the filesystem and network boundary is the runtime's native sandbox"
            ),
        },
        "sandbox_policy": {
            "required": policy.requires_native_sandbox,
            "status": policy.sandbox_status,
            "policy_sha256": policy.policy_sha256,
            "settings_sources_suppressed": policy.settings_sources_suppressed,
            "note": (
                "requested configuration recorded from the adapter side; managed "
                "settings layers outside adapter control remain unverified until an "
                "actual-runtime probe measures effective behaviour"
            ),
        },
        "mcp": {
            "strict": True,
            "declared": [str(path) for path in declared_mcp],
            "config_hashes": [
                {"path": path, "sha256": digest}
                for path, digest in policy.mcp_config_hashes
            ],
            "executable_hashes": [
                {"server": server, "sha256": digest}
                for server, digest in policy.mcp_executable_hashes
            ],
            "trust": "local-executable-pinned-semantics-unproven",
        },
        "scratch": (
            {
                "root": str(scratch_root),
                "provenance": scratch_provenance,
                "initial_bytes": aggregate_size([scratch_root]),
                "final_bytes": None,
                "disposition": None,
            }
            if scratch_root is not None
            else {}
        ),
        "owned_paths": list(owned_relpaths),
        "artifact": (
            {
                "output": str(artifact_output),
                "overwrite": bool(args.overwrite_artifact),
                "attempt": None,
                "sha256": None,
            }
            if artifact_output is not None
            else {}
        ),
        "runtime": {
            "cwd": str(process_cwd),
            "cli_args": list(policy.cli_args),
            "env": dict(policy.env),
            "settings_path": str(settings_path),
        },
        "state_limit_bytes": limit_bytes,
        "stop_threshold_bytes": stop_threshold_bytes(limit_bytes),
        "max_log_bytes": max_log_bytes,
        "accounted_bytes_at_admission": initial_bytes,
        "created_at": utc_now(),
        "updated_at": utc_now(),
        "attempts": [],
    }
    atomic_json(metadata_path, metadata)
    try:
        return execute_attempt(
            run_dir,
            metadata_path,
            metadata,
            args.prompt_file.expanduser().resolve(),
            args.claude_bin,
            max_log_bytes,
            resume=False,
        )
    except (OSError, ValueError) as exc:
        print(f"launch failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


def command_resume(args: argparse.Namespace) -> int:
    state_root = args.state_root.expanduser().resolve()
    try:
        run_dir, metadata_path, metadata = load_run(state_root, args.run_id)
        for key in ("session_id", "cwd", "requested", "attempts", "name"):
            if key not in metadata:
                raise ValueError(f"missing resume provenance: {key}")
        stored_version = metadata.get("profile_version")
        if metadata.get("profile") and stored_version != PROFILE_VERSION:
            # A profiled session records the boundary it was launched under. Resuming
            # it beneath a different contract would silently re-scope that boundary,
            # so the run stays inspectable and materializable but is not continued.
            print(
                f"refusing to resume: stored profile version {stored_version} does not "
                f"match the current profile version {PROFILE_VERSION}; start a fresh "
                "session with new lineage",
                file=sys.stderr,
            )
            return 2
        max_log_bytes = metadata.get("max_log_bytes") or int(args.max_log_mib * MIB)
        limit_bytes = metadata.get("state_limit_bytes")
        if limit_bytes:
            roots = [Path(metadata.get("state_root", state_root))]
            if metadata.get("scratch", {}).get("root"):
                roots.append(Path(metadata["scratch"]["root"]))
            preflight(
                roots,
                limit_bytes=stop_threshold_bytes(limit_bytes),
                headroom_bytes=max_log_bytes,
            )
        return execute_attempt(
            run_dir,
            metadata_path,
            metadata,
            args.prompt_file.expanduser().resolve(),
            args.claude_bin,
            max_log_bytes,
            resume=True,
        )
    except BudgetError as exc:
        print(f"state preflight refused: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"resume failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


def sanitized_status(metadata: dict) -> dict:
    attempts = []
    for attempt in metadata.get("attempts", []):
        item = {
            key: attempt.get(key)
            for key in (
                "number",
                "status",
                "pid",
                "started_at",
                "ended_at",
                "exit_code",
                "resume",
                "stream_path",
                "stderr_path",
                "stream_truncated",
                "stderr_truncated",
                "log_bytes",
                "result",
                "observed_tools",
                "observed_mcp_servers",
                "manifest_status",
                "manifest_failure_reason",
                "unexpected_tools",
                "materializable",
                "budget_exceeded_bytes",
                "reconciliation",
            )
            if key in attempt
        }
        if item.get("status") == "running" and isinstance(item.get("pid"), int):
            try:
                os.kill(item["pid"], 0)
                item["process_state"] = "running"
            except OSError:
                item["process_state"] = "unknown-or-terminal"
        attempts.append(item)
    return {
        "run_id": metadata.get("run_id"),
        "session_id": metadata.get("session_id"),
        "name": metadata.get("name"),
        "cwd": metadata.get("cwd"),
        "requested": metadata.get("requested"),
        "profile": metadata.get("profile"),
        "profile_requested": metadata.get("profile_requested"),
        "profile_version": metadata.get("profile_version"),
        "profile_manifest_sha256": metadata.get("profile_manifest_sha256"),
        "add_dirs": metadata.get("add_dirs", []),
        "disallowed_tools": metadata.get("disallowed_tools", []),
        "tools": metadata.get("tools", []),
        "allowed_tools": metadata.get("allowed_tools", []),
        "expected_tools": metadata.get("expected_tools", []),
        "exposed_but_denied": metadata.get("exposed_but_denied", []),
        "command_policy": metadata.get("command_policy", {}),
        "sandbox_policy": metadata.get("sandbox_policy", {}),
        "mcp": metadata.get("mcp", {}),
        "scratch": metadata.get("scratch", {}),
        "owned_paths": metadata.get("owned_paths", []),
        "artifact": metadata.get("artifact", {}),
        "attempts": attempts,
    }


def command_status(args: argparse.Namespace) -> int:
    try:
        _, _, metadata = load_run(args.state_root.expanduser().resolve(), args.run_id)
    except (OSError, ValueError) as exc:
        print(f"status failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(sanitized_status(metadata), indent=2, sort_keys=True))
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    try:
        _, _, metadata = load_run(args.state_root.expanduser().resolve(), args.run_id)
        report = sanitized_status(metadata)
        if args.include_result and metadata.get("attempts"):
            stream_path = Path(metadata["attempts"][-1]["stream_path"])
            _, result_text = last_result(stream_path)
            report["final_result"] = result_text
    except (OSError, ValueError, KeyError) as exc:
        print(f"inspect failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def command_materialize(args: argparse.Namespace) -> int:
    try:
        _, _, metadata = load_run(args.state_root.expanduser().resolve(), args.run_id)
        attempts = metadata.get("attempts", [])
        if not attempts:
            raise ValueError("run has no attempts")
        attempt = select_attempt(attempts, args.attempt)
        report = {
            "run_id": metadata.get("run_id"),
            **materialize_attempt_result(
                attempt, args.output, overwrite=args.overwrite
            ),
        }
    except (OSError, ValueError, KeyError) as exc:
        print(f"materialize failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="run non-generative CLI/auth checks")
    doctor.add_argument("--claude-bin", default="claude")
    doctor.set_defaults(func=command_doctor)

    explain = sub.add_parser("explain", help="compile and explain policy without a model call")
    source = explain.add_mutually_exclusive_group(required=True)
    source.add_argument("--profile", choices=PRESET_IDS)
    source.add_argument("--policy-file", type=Path)
    explain.add_argument("--compare-profile", choices=PRESET_IDS)
    explain.add_argument("--workspace", type=Path, default=Path.cwd())
    explain.add_argument("--scratch-dir", type=Path)
    explain.add_argument("--output-dir", type=Path)
    explain.add_argument("--read-root", action="append", default=[])
    explain.add_argument("--write-root", action="append", default=[])
    explain.add_argument("--notice", action="append", default=[])
    explain.add_argument("--confirmation", action="append", default=[])
    explain.add_argument("--format", choices=("text", "json"), default="text")
    explain.set_defaults(func=command_explain)

    run = sub.add_parser("run", help="run a new foreground Claude worker")
    run.add_argument("--cwd", required=True, type=Path)
    run.add_argument("--model", required=True)
    run.add_argument("--effort", required=True, choices=EFFORTS)
    run.add_argument("--permission-mode", choices=PERMISSION_MODES)
    run.add_argument("--profile", choices=PROFILES)
    run.add_argument("--name")
    run.add_argument("--session-id")
    run.add_argument("--max-turns", type=int)
    run.add_argument("--max-budget-usd", type=float)
    run.add_argument("--add-dir", action="append", type=Path, default=[])
    run.add_argument("--disallowed-tool", action="append", default=[])
    run.add_argument("--tool", action="append", default=[])
    run.add_argument("--allowed-tool", action="append", default=[])
    run.add_argument("--allowed-command", action="append", default=[])
    run.add_argument("--mcp-config", action="append", default=[])
    run.add_argument("--scratch-dir", type=Path, default=None)
    run.add_argument("--owned-path", action="append", default=[])
    run.add_argument("--artifact-output", type=Path, default=None)
    run.add_argument("--overwrite-artifact", action="store_true")
    run.add_argument("--state-limit-mib", type=float, default=240.0)
    add_common_run_args(run)
    run.set_defaults(func=command_run)

    resume = sub.add_parser("resume", help="resume the same semantic task")
    resume.add_argument("run_id")
    add_common_run_args(resume)
    resume.set_defaults(func=command_resume)

    for name, help_text, func in (
        ("status", "show sanitized run status", command_status),
        ("inspect", "inspect sanitized result metadata", command_inspect),
        ("materialize", "write a successful final result to one explicit path", command_materialize),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("run_id")
        command.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
        if name == "inspect":
            command.add_argument("--include-result", action="store_true")
        if name == "materialize":
            command.add_argument("--output", required=True, type=Path)
            command.add_argument("--overwrite", action="store_true")
            command.add_argument("--attempt", type=positive_int, default=None)
        command.set_defaults(func=func)
    return parser


def main(argv: list[str] | None = None) -> int:
    old_umask = os.umask(0o077)
    try:
        args = build_parser().parse_args(argv)
        return int(args.func(args))
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
