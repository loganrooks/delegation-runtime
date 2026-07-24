#!/usr/bin/env python3
"""Thin, local-only adapter for delegating a task to the installed ``agy`` CLI."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time
import uuid


CONFIG_ERROR = 2
MODEL_ERROR = 3
STATE_BUDGET_ERROR = 4
PROVIDER_ERROR = 6
PROMPT_LIMIT_BYTES = 64 * 1024
STOP_BYTES = 192 * 1024 * 1024
MAX_STATE_BYTES = 240 * 1024 * 1024
DEFAULT_TIMEOUT_SECONDS = 900


class DelegateError(Exception):
    """A safe, user-facing adapter error with a stable exit status."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


def build_run_argv(
    agy_bin: str, profile: str, model: str, log_file: Path, prompt: str
) -> list[str]:
    """Build the only provider invocation this adapter permits."""
    argv = [agy_bin, "--model", model]
    if profile == "review":
        argv.extend(["--mode", "plan", "--sandbox"])
    elif profile == "implementation-auto":
        argv.extend(
            ["--mode", "accept-edits", "--sandbox", "--dangerously-skip-permissions"]
        )
    else:  # argparse validates profiles; keep this helper safe to call directly.
        raise DelegateError(CONFIG_ERROR, "unsupported profile")
    return [*argv, "--log-file", str(log_file), "-p", prompt]


def state_tree_size(root: Path) -> int:
    """Return apparent bytes without following directory symlinks."""
    total = 0
    try:
        for directory, _, files in os.walk(root, followlinks=False):
            for name in files:
                try:
                    total += (Path(directory) / name).lstat().st_size
                except FileNotFoundError:
                    continue
    except FileNotFoundError:
        return 0
    return total


def private_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def private_log(path: Path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, "wb", buffering=0)


def validate_workspace(value: str) -> Path:
    path = Path(value).expanduser()
    try:
        canonical = path.resolve(strict=True)
    except OSError as exc:
        raise DelegateError(CONFIG_ERROR, "workspace must be an existing directory") from exc
    if not canonical.is_dir():
        raise DelegateError(CONFIG_ERROR, "workspace must be an existing directory")
    return canonical


def read_prompt(value: str) -> str:
    path = Path(value).expanduser()
    if path.is_symlink() or not path.is_file():
        raise DelegateError(CONFIG_ERROR, "prompt file must be a regular non-symlink file")
    try:
        metadata = path.stat()
        if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise DelegateError(CONFIG_ERROR, "prompt file must be private and owned by this user")
        with path.open("rb") as handle:
            payload = handle.read(PROMPT_LIMIT_BYTES + 1)
    except OSError as exc:
        raise DelegateError(CONFIG_ERROR, "prompt file could not be read") from exc
    if len(payload) > PROMPT_LIMIT_BYTES:
        raise DelegateError(CONFIG_ERROR, "prompt file exceeds 64 KiB")
    try:
        prompt = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DelegateError(CONFIG_ERROR, "prompt file must be UTF-8 text") from exc
    if "\x00" in prompt:
        raise DelegateError(CONFIG_ERROR, "prompt file must not contain NUL")
    return prompt


def validate_model(model: str) -> str:
    if not model or not model.strip():
        raise DelegateError(CONFIG_ERROR, "model must be nonempty")
    try:
        length = len(model.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise DelegateError(CONFIG_ERROR, "model must be UTF-8") from exc
    if length > 256:
        raise DelegateError(CONFIG_ERROR, "model exceeds 256 bytes")
    if "\x00" in model:
        raise DelegateError(CONFIG_ERROR, "model must not contain NUL")
    return model


def provider_models(agy_bin: str) -> str:
    try:
        completed = subprocess.run(
            [agy_bin, "models"],
            shell=False,
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise DelegateError(MODEL_ERROR, "could not execute agy models") from exc
    if completed.returncode != 0:
        raise DelegateError(MODEL_ERROR, "agy models failed")
    return completed.stdout.decode("utf-8", errors="replace")


def ensure_listed_model(agy_bin: str, model: str) -> None:
    listing = provider_models(agy_bin)
    if model not in {line for line in listing.splitlines() if line.strip()}:
        raise DelegateError(MODEL_ERROR, "requested model is not listed by agy")


def emit_status(profile: str, model: str, exit_value: int | str, run_dir: Path) -> None:
    # Deliberately omit prompt and provider output from this status surface.
    status = {"profile": profile, "model": model, "exit": exit_value, "run_dir": str(run_dir)}
    print(json.dumps(status, separators=(",", ":"), ensure_ascii=False), file=sys.stderr)


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.terminate()


def run_provider(
    argv: list[str], workspace: Path, state_root: Path, stdout_log: Path, stderr_log: Path, timeout: int
) -> tuple[int | str, bool]:
    """Capture a provider run while enforcing its timeout and state budget."""
    reason: int | str | None = None
    with private_log(stdout_log) as stdout_handle, private_log(stderr_log) as stderr_handle:
        try:
            process = subprocess.Popen(
                argv,
                shell=False,
                cwd=workspace,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as exc:
            raise DelegateError(PROVIDER_ERROR, "could not execute agy") from exc

        selector = selectors.DefaultSelector()
        assert process.stdout is not None and process.stderr is not None
        selector.register(process.stdout, selectors.EVENT_READ, stdout_handle)
        selector.register(process.stderr, selectors.EVENT_READ, stderr_handle)
        deadline = time.monotonic() + timeout
        terminated_at: float | None = None
        while selector.get_map() or process.poll() is None:
            if reason is None and state_tree_size(state_root) >= STOP_BYTES:
                reason = "state_budget"
                terminate(process)
                terminated_at = time.monotonic()
            elif reason is None and time.monotonic() >= deadline:
                reason = "timeout"
                terminate(process)
                terminated_at = time.monotonic()
            elif (
                reason is not None
                and process.poll() is None
                and terminated_at is not None
                and time.monotonic() - terminated_at >= 2
            ):
                process.kill()

            for key, _ in selector.select(0.1):
                data = os.read(key.fileobj.fileno(), 64 * 1024)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if reason is None and state_tree_size(state_root) + len(data) >= STOP_BYTES:
                    reason = "state_budget"
                    terminate(process)
                    terminated_at = time.monotonic()
                    continue
                if reason is None:
                    key.data.write(data)

        return (reason if reason is not None else process.returncode), reason is not None


def command_models(args: argparse.Namespace) -> int:
    listing = provider_models(args.agy_bin)
    sys.stdout.write(listing)
    return 0


def command_run(args: argparse.Namespace) -> int:
    if not 1 <= args.timeout <= 3600:
        raise DelegateError(CONFIG_ERROR, "timeout must be from 1 to 3600 seconds")
    model = validate_model(args.model)
    workspace = validate_workspace(args.workspace)
    prompt = read_prompt(args.prompt_file)
    ensure_listed_model(args.agy_bin, model)

    state_root = private_directory(Path(args.state_root).expanduser())
    if state_tree_size(state_root) >= STOP_BYTES or state_tree_size(state_root) >= MAX_STATE_BYTES:
        raise DelegateError(STATE_BUDGET_ERROR, "state budget admission refused")
    run_dir = private_directory(state_root / str(uuid.uuid4()))
    provider_log = run_dir / "provider.log"
    with private_log(provider_log):
        pass
    stdout_log = run_dir / "stdout.log"
    stderr_log = run_dir / "stderr.log"
    argv = build_run_argv(args.agy_bin, args.profile, model, provider_log, prompt)
    exit_value, stopped = run_provider(
        argv, workspace, state_root, stdout_log, stderr_log, args.timeout
    )
    try:
        sys.stdout.write(stdout_log.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        pass
    emit_status(args.profile, model, exit_value, run_dir)
    return 0 if not stopped and exit_value == 0 else PROVIDER_ERROR


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    models = commands.add_parser("models")
    models.add_argument("--agy-bin", default="agy")
    models.set_defaults(handler=command_models)
    run = commands.add_parser("run")
    run.add_argument("--profile", required=True, choices=("review", "implementation-auto"))
    run.add_argument("--model", required=True)
    run.add_argument("--workspace", required=True)
    run.add_argument("--prompt-file", required=True)
    run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    run.add_argument("--state-root", default=str(Path.home() / ".codex/state/delegate-to-antigravity"))
    run.add_argument("--agy-bin", default="agy")
    run.set_defaults(handler=command_run)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.handler(args)
    except DelegateError as exc:
        print(str(exc), file=sys.stderr)
        return exc.code


if __name__ == "__main__":
    raise SystemExit(main())
