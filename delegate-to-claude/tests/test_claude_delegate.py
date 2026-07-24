from __future__ import annotations

import json
import importlib.util
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid
import warnings


ADAPTER_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ADAPTER_ROOT / "scripts" / "claude_delegate.py"


FAKE_CLAUDE = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys, time
args = sys.argv[1:]
ALL_FLAGS = ["--settings", "--setting-sources", "--mcp-config", "--strict-mcp-config", "--add-dir"]
missing = set(filter(None, os.environ.get("FAKE_MISSING_FLAGS", "").split(",")))
if args == ["--version"]:
    print("9.9.9 (Claude Code fake)")
    raise SystemExit(0)
if args == ["--help"]:
    advertised = " ".join(flag for flag in ALL_FLAGS if flag not in missing)
    print("--permission-mode <mode> (choices: 'default', 'acceptEdits', 'plan', 'auto', 'dontAsk') --session-id --resume --output-format " + advertised)
    raise SystemExit(0)
if args == ["auth", "status", "--json"]:
    print(json.dumps({"loggedIn": True, "authMethod": "test", "apiProvider": "fake", "subscriptionType": "max", "email": "secret@example.test", "orgId": "secret-org", "orgName": "Secret Org"}))
    raise SystemExit(0)
if args == ["auto-mode", "config"]:
    if os.environ.get("FAKE_AUTO_MODE_CONFIG") == "unreadable":
        print("auto mode configuration unavailable", file=sys.stderr)
        raise SystemExit(4)
    print("{}")
    raise SystemExit(0)
prompt = sys.stdin.read()
log = os.environ.get("FAKE_ARGS_LOG")
if log:
    with open(log, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(args) + "\n")
cwd_log = os.environ.get("FAKE_CWD_LOG")
if cwd_log:
    with open(cwd_log, "a", encoding="utf-8") as handle:
        handle.write(os.getcwd() + "\n")
model = args[args.index("--model") + 1]
permission = args[args.index("--permission-mode") + 1]
session = args[args.index("--resume") + 1] if "--resume" in args else args[args.index("--session-id") + 1]
declared_tools = args[args.index("--tools") + 1].split(",") if "--tools" in args else []
init_event = {"type": "system", "subtype": "init", "session_id": session, "model": "observed-init-model", "permissionMode": permission}
fake_tools = os.environ.get("FAKE_INIT_TOOLS")
if fake_tools is not None:
    init_event["tools"] = fake_tools.split(",") if fake_tools else []
elif os.environ.get("FAKE_INIT_TOOLS_ABSENT") != "1":
    init_event["tools"] = declared_tools
fake_mcp = os.environ.get("FAKE_INIT_MCP_SERVERS")
if fake_mcp is not None:
    init_event["mcp_servers"] = [{"name": n} for n in fake_mcp.split(",")] if fake_mcp else []
if os.environ.get("FAKE_EVENT_BEFORE_INIT") == "1":
    print(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "pre-init"}]}}), flush=True)
print(json.dumps(init_event), flush=True)
pause = float(os.environ.get("FAKE_PAUSE_AFTER_INIT", "0") or 0)
if pause:
    deadline = time.time() + pause
    while time.time() < deadline:
        time.sleep(0.05)
fill = int(os.environ.get("FAKE_SCRATCH_FILL_BYTES", "0") or 0)
if fill:
    with open(os.path.join(os.getcwd(), "fill.bin"), "wb") as handle:
        handle.write(b"x" * fill)
        handle.flush()
    time.sleep(float(os.environ.get("FAKE_FILL_LINGER", "5")))
for path in filter(None, os.environ.get("FAKE_WRITE_FILES", "").split(",")):
    target, _, payload = path.partition("=")
    pathlib.Path(target).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(target).write_text(payload or "worker wrote this\n", encoding="utf-8")
for path in filter(None, os.environ.get("FAKE_DELETE_FILES", "").split(",")):
    pathlib.Path(path).unlink(missing_ok=True)
git_commit_path = os.environ.get("FAKE_GIT_COMMIT_PATH")
if git_commit_path:
    subprocess.run(["git", "add", git_commit_path], check=True)
    subprocess.run(
        ["git", "-c", "user.email=fake@example.invalid", "-c", "user.name=Fake", "commit", "-qm", "fake worker commit"],
        check=True,
    )
if os.environ.get("FAKE_PARTIAL") == "1":
    print(json.dumps({"type": "assistant", "message": {"content": [{"type": "text", "text": "partial"}]}}), flush=True)
    print("partial stderr", file=sys.stderr, flush=True)
    raise SystemExit(int(os.environ.get("FAKE_EXIT", "7")))
usage = {"input_tokens": 3, "output_tokens": 5, "cache_creation_input_tokens": 7, "cache_read_input_tokens": 11}
if os.environ.get("FAKE_CACHE") == "cold":
    usage["cache_creation_input_tokens"] = 0
    usage["cache_read_input_tokens"] = 0
elif os.environ.get("FAKE_CACHE") == "absent":
    usage.pop("cache_creation_input_tokens")
    usage.pop("cache_read_input_tokens")
mode = os.environ.get("FAKE_MODEL_USAGE", "one")
if mode == "none":
    model_usage = {}
elif mode == "conflict":
    model_usage = {"model-a": {"inputTokens": 1}, "model-b": {"inputTokens": 2}}
else:
    model_usage = {"claude-observed-model": {"inputTokens": 3, "outputTokens": 5, "cacheReadInputTokens": usage.get("cache_read_input_tokens"), "cacheCreationInputTokens": usage.get("cache_creation_input_tokens"), "costUSD": 0.25}}
is_error = os.environ.get("FAKE_IS_ERROR") == "1"
result_text = os.environ.get("FAKE_RESULT_TEXT", "FINAL SECRET RESULT")
print(json.dumps({"type": "result", "subtype": "error_during_execution" if is_error else "success", "is_error": is_error, "session_id": session, "stop_reason": "refusal" if is_error else "end_turn", "num_turns": 2, "total_cost_usd": 0.25, "usage": usage, "modelUsage": model_usage, "result": result_text}), flush=True)
print("fake stderr", file=sys.stderr, flush=True)
stderr_fill = int(os.environ.get("FAKE_STDERR_BYTES", "0") or 0)
if stderr_fill:
    print("x" * stderr_fill, file=sys.stderr, flush=True)
'''


class AdapterHarness:
    """Shared fixture: fake Claude CLI, a Git project root, prompt, and managed state."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        # Resolved: the manager canonicalizes every path it records, and on macOS the
        # temp root arrives as /var -> /private/var.
        self.root = Path(self.temp.name).resolve()
        self.fake = self.root / "claude"
        self.fake.write_text(FAKE_CLAUDE, encoding="utf-8")
        self.fake.chmod(0o755)
        self.cwd = self.root / "project"
        self.cwd.mkdir()
        subprocess.run(
            ["git", "init", "-q", str(self.cwd)],
            check=True,
            capture_output=True,
        )
        self.prompt = self.root / "prompt.md"
        self.prompt.write_text("PROMPT SECRET BODY", encoding="utf-8")
        self.state = self.root / "state"
        self.args_log = self.root / "args.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def invoke(self, *args: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
        merged = os.environ.copy()
        merged["FAKE_ARGS_LOG"] = str(self.args_log)
        if env:
            merged.update(env)
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            env=merged,
        )

    def run_worker(self, permission: str = "acceptEdits") -> subprocess.CompletedProcess[str]:
        return self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "requested-model",
            "--effort", "high",
            "--permission-mode", permission,
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            "--max-turns", "5",
        )

    def metadata(self) -> tuple[Path, dict]:
        metadata_path = next((self.state / "runs").glob("*/metadata.json"))
        return metadata_path, json.loads(metadata_path.read_text(encoding="utf-8"))

    def write_metadata(self, metadata_path: Path, metadata: dict) -> None:
        metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8")

    def mcp_config(self, name: str = "mcp.json") -> Path:
        server = self.root / "codebase-memory-mcp"
        server.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        server.chmod(0o755)
        path = self.root / name
        path.write_text(
            json.dumps({"mcpServers": {"codebase-memory-mcp": {"command": str(server)}}}),
            encoding="utf-8",
        )
        return path

    def profile_args(self, profile: str) -> list[str]:
        """Arguments a profile now requires beyond the bare --profile flag."""
        if profile in ("verified-review", "artifact-review"):
            extra = ["--allowed-command", "python3 -m unittest discover"]
            if profile == "artifact-review":
                extra += ["--artifact-output", str(self.root / f"artifact-{uuid.uuid4().hex}.md")]
            return extra
        if profile in ("implementation", "implementation-auto"):
            extra = ["--owned-path", "src"]
            if profile == "implementation-auto":
                extra += ["--permission-mode", "auto"]
            return extra
        return []

    def run_profile(self, profile: str, *extra: str, env: dict | None = None):
        return self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", profile,
            *self.profile_args(profile),
            *extra,
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env=env,
        )


class DelegateToClaudeTests(AdapterHarness, unittest.TestCase):
    def test_doctor_redacts_identity(self):
        result = self.invoke("doctor", "--claude-bin", str(self.fake))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("secret@example", result.stdout)
        self.assertNotIn("secret-org", result.stdout)
        report = json.loads(result.stdout)
        self.assertTrue(report["auth"]["logged_in"])
        self.assertTrue(report["auto_mode"]["advertised"])
        self.assertEqual(report["auto_mode"]["eligibility"], "unchecked-until-real-run")

    def test_readonly_review_profile_pins_mode_and_tools(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--profile", "readonly-review",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("deprecated", result.stderr)
        _, metadata = self.metadata()
        self.assertEqual(metadata["profile"], "strict-readonly")
        self.assertEqual(metadata["profile_requested"], "readonly-review")
        self.assertEqual(metadata["requested"]["permission_mode"], "dontAsk")
        self.assertEqual(metadata["tools"], ["Read", "Grep", "Glob", "Skill"])
        args = json.loads(self.args_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(args[args.index("--permission-mode") + 1], "dontAsk")
        self.assertEqual(args[args.index("--tools") + 1], "Read,Grep,Glob,Skill")

    def test_readonly_review_rejects_broader_permission_mode(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--profile", "readonly-review",
            "--permission-mode", "auto",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("pins permission mode", result.stderr)
        self.assertFalse(list((self.state / "runs").glob("*")) if (self.state / "runs").exists() else [])

    def test_every_canonical_profile_resolves_exact_manifest(self):
        expected = {
            "strict-readonly": ("dontAsk", "Read,Grep,Glob,Skill"),
            "implementation": ("acceptEdits", "Read,Grep,Glob,Skill,Bash,Write,Edit"),
            "implementation-auto": ("auto", "Read,Grep,Glob,Skill,Bash,Write,Edit"),
        }
        for profile, (permission, tools) in expected.items():
            with self.subTest(profile=profile):
                self.state = self.root / f"state-{profile}"
                result = self.invoke(
                    "run",
                    "--cwd", str(self.cwd),
                    "--prompt-file", str(self.prompt),
                    "--model", "opus",
                    "--effort", "xhigh",
                    "--profile", profile,
                    *self.profile_args(profile),
                    "--state-root", str(self.state),
                    "--claude-bin", str(self.fake),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                _, metadata = self.metadata()
                self.assertEqual(metadata["profile"], profile)
                self.assertEqual(metadata["profile_requested"], profile)
                self.assertEqual(metadata["requested"]["permission_mode"], permission)
                self.assertEqual(metadata["tools"], tools.split(","))
                self.assertIn("profile_version", metadata)
                self.assertIn("profile_manifest_sha256", metadata)

        for profile in ("verified-review", "artifact-review"):
            with self.subTest(profile=profile):
                self.state = self.root / f"state-{profile}"
                result = self.invoke(
                    "run",
                    "--cwd", str(self.cwd),
                    "--prompt-file", str(self.prompt),
                    "--model", "opus",
                    "--effort", "xhigh",
                    "--profile", profile,
                    *self.profile_args(profile),
                    "--state-root", str(self.state),
                    "--claude-bin", str(self.fake),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                _, metadata = self.metadata()
                self.assertEqual(metadata["tools"], ["Read", "Grep", "Glob", "Skill", "Bash"])
                self.assertIn(
                    "Bash(python3 -m unittest discover)", metadata["allowed_tools"]
                )

    def test_implementation_auto_conflicting_permission_creates_no_run(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--profile", "implementation-auto",
            "--permission-mode", "acceptEdits",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.state / "runs").exists())
        self.assertEqual(self.args_log.read_text(encoding="utf-8") if self.args_log.exists() else "", "")

    def test_verified_review_without_allowed_command_fails_before_launch(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--profile", "verified-review",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("allowed-command", result.stderr)
        self.assertFalse((self.state / "runs").exists())

    def test_accepted_commands_appear_as_exact_bash_rules_under_allowed_tools(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--profile", "verified-review",
            "--allowed-command", "python3 -m unittest discover",
            "--allowed-command", "pytest -q",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertEqual(
            metadata["allowed_tools"],
            ["Bash(python3 -m unittest discover)", "Bash(pytest -q)"],
        )
        args = json.loads(self.args_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(
            args[args.index("--allowedTools") + 1],
            "Bash(python3 -m unittest discover),Bash(pytest -q)",
        )

    def test_mutating_mcp_and_write_tools_are_denied(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--profile", "strict-readonly",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertIn("Write", metadata["disallowed_tools"])
        self.assertIn("Bash", metadata["disallowed_tools"])
        self.assertIn(
            "mcp__codebase-memory-mcp__delete_project", metadata["disallowed_tools"]
        )
        args = json.loads(self.args_log.read_text(encoding="utf-8").splitlines()[-1])
        disallowed_arg = args[args.index("--disallowedTools") + 1]
        self.assertIn("mcp__codebase-memory-mcp__delete_project", disallowed_arg)
        self.assertIn("Write", disallowed_arg)

    def test_custom_mode_still_requires_explicit_permission_mode(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--permission-mode is required", result.stderr)

    def test_custom_mode_preserves_direct_tool_flags_and_null_profile_fields(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--permission-mode", "acceptEdits",
            "--tool", "Read",
            "--tool", "Write",
            "--disallowed-tool", "CustomDeny",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertIsNone(metadata["profile"])
        self.assertIsNone(metadata["profile_requested"])
        self.assertIsNone(metadata["profile_version"])
        self.assertIsNone(metadata["profile_manifest_sha256"])
        self.assertEqual(metadata["tools"], ["Read", "Write"])
        self.assertEqual(metadata["disallowed_tools"], ["CustomDeny"])

    def test_metadata_carries_profile_fields_without_prompt_or_raw_command(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--profile", "verified-review",
            "--allowed-command", "python3 -m unittest discover",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        serialized = json.dumps(metadata)
        for key in (
            "profile_requested",
            "profile",
            "profile_version",
            "profile_manifest_sha256",
            "tools",
            "allowed_tools",
            "disallowed_tools",
        ):
            self.assertIn(key, metadata)
        self.assertNotIn("PROMPT SECRET BODY", serialized)
        self.assertNotIn('"command"', serialized)
        self.assertNotIn("allowed_commands", metadata)

    def test_run_preserves_controls_without_prompt_or_command_in_metadata(self):
        result = self.run_worker()
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        serialized = json.dumps(metadata)
        self.assertNotIn("PROMPT SECRET BODY", serialized)
        self.assertNotIn('"command"', serialized)
        self.assertEqual(metadata["requested"]["model"], "requested-model")
        observed = metadata["attempts"][0]["result"]["observed_model"]
        self.assertEqual(observed, {"status": "observed", "value": "claude-observed-model"})
        args = json.loads(self.args_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(args[args.index("--max-turns") + 1], "5")

    def test_result_integrity_distinguishes_unobserved_conflicted_cold_and_unknown(self):
        scripts_dir = str(SCRIPT.parent)
        sys.path.insert(0, scripts_dir)
        try:
            spec = importlib.util.spec_from_file_location("claude_delegate", SCRIPT)
            module = importlib.util.module_from_spec(spec)
            assert spec.loader is not None
            spec.loader.exec_module(module)
        finally:
            sys.path.remove(scripts_dir)
        unobserved = module.safe_result({"modelUsage": {}, "usage": {}})
        conflicted = module.safe_result({"modelUsage": {"a": {}, "b": {}}, "usage": {}})
        cold = module.safe_result({
            "modelUsage": {},
            "usage": {"cache_read_input_tokens": 0, "cache_creation_input_tokens": 0},
        })
        unknown = module.safe_result({"modelUsage": {}, "usage": {}})
        self.assertEqual(unobserved["observed_model"]["status"], "unobserved")
        self.assertEqual(conflicted["observed_model"]["status"], "conflicted")
        self.assertEqual(cold["usage"]["cache_read_input_tokens"], 0)
        self.assertNotIn("cache_read_input_tokens", unknown["usage"])

    def test_error_result_returns_nonzero_and_preserves_structured_error(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "xhigh",
            "--permission-mode", "auto",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env={"FAKE_IS_ERROR": "1"},
        )
        self.assertEqual(result.returncode, 1)
        _, metadata = self.metadata()
        self.assertTrue(metadata["attempts"][0]["result"]["is_error"])

    def test_launch_failure_is_terminally_recorded(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "sonnet",
            "--effort", "high",
            "--permission-mode", "acceptEdits",
            "--state-root", str(self.state),
            "--claude-bin", str(self.root / "missing-claude"),
        )
        self.assertEqual(result.returncode, 2)
        _, metadata = self.metadata()
        self.assertEqual(metadata["attempts"][0]["status"], "launch-failed")

    def test_direct_write_permission_modes_pass_through_unchanged(self):
        for permission in ("acceptEdits", "auto"):
            with self.subTest(permission=permission):
                self.state = self.root / f"state-{permission}"
                result = self.run_worker(permission)
                self.assertEqual(result.returncode, 0, result.stderr)
                _, metadata = self.metadata()
                self.assertEqual(metadata["requested"]["permission_mode"], permission)
                args = json.loads(self.args_log.read_text(encoding="utf-8").splitlines()[-1])
                self.assertEqual(args[args.index("--permission-mode") + 1], permission)

    def test_resume_reuses_session_and_controls_without_overwriting(self):
        first = self.run_worker("auto")
        self.assertEqual(first.returncode, 0, first.stderr)
        _, before = self.metadata()
        run_id = before["run_id"]
        second_prompt = self.root / "resume.md"
        second_prompt.write_text("NEW SECRET BODY", encoding="utf-8")
        resumed = self.invoke(
            "resume", run_id,
            "--prompt-file", str(second_prompt),
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(resumed.returncode, 0, resumed.stderr)
        _, after = self.metadata()
        self.assertEqual(len(after["attempts"]), 2)
        self.assertNotEqual(after["attempts"][0]["stream_path"], after["attempts"][1]["stream_path"])
        resume_args = json.loads(self.args_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(resume_args[resume_args.index("--resume") + 1], before["session_id"])
        self.assertEqual(resume_args[resume_args.index("--permission-mode") + 1], "auto")

    def test_partial_nonzero_run_retains_logs(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "sonnet",
            "--effort", "high",
            "--permission-mode", "acceptEdits",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env={"FAKE_PARTIAL": "1", "FAKE_EXIT": "7"},
        )
        self.assertEqual(result.returncode, 7)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertTrue(Path(attempt["stream_path"]).exists())
        self.assertIn("partial stderr", Path(attempt["stderr_path"]).read_text(encoding="utf-8"))

    def test_state_preflight_refuses_at_threshold(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "sonnet",
            "--effort", "high",
            "--permission-mode", "acceptEdits",
            "--state-root", str(self.state),
            "--state-limit-mib", "0",
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("state preflight refused", result.stderr)

    def test_inspect_hides_result_text_by_default(self):
        result = self.run_worker()
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        hidden = self.invoke("inspect", metadata["run_id"], "--state-root", str(self.state))
        shown = self.invoke(
            "inspect", metadata["run_id"], "--state-root", str(self.state), "--include-result"
        )
        self.assertNotIn("FINAL SECRET RESULT", hidden.stdout)
        self.assertIn("FINAL SECRET RESULT", shown.stdout)

    def test_materialize_writes_only_explicit_result_path_and_refuses_overwrite(self):
        result = self.run_worker()
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        output = self.root / "review.md"
        first = self.invoke(
            "materialize", metadata["run_id"],
            "--state-root", str(self.state),
            "--output", str(output),
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "FINAL SECRET RESULT\n")
        second = self.invoke(
            "materialize", metadata["run_id"],
            "--state-root", str(self.state),
            "--output", str(output),
        )
        self.assertEqual(second.returncode, 2)
        self.assertIn("already exists", second.stderr)

    def test_observed_tool_and_mcp_server_names_are_recorded(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", "strict-readonly",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env={
                "FAKE_INIT_TOOLS": "Read,Grep,Glob,Skill",
                "FAKE_INIT_MCP_SERVERS": "codebase-memory-mcp",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertEqual(sorted(attempt["observed_tools"]), ["Glob", "Grep", "Read", "Skill"])
        self.assertEqual(attempt["observed_mcp_servers"], ["codebase-memory-mcp"])
        self.assertEqual(attempt["unexpected_tools"], [])

    def test_denied_exposed_tool_does_not_count_as_unexpected(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", "strict-readonly",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env={"FAKE_INIT_TOOLS": "Read,Grep,Glob,Skill,Bash"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertEqual(metadata["attempts"][0]["unexpected_tools"], [])

    def test_unexpected_exposed_tool_fails_strict_run(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", "strict-readonly",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env={"FAKE_INIT_TOOLS": "Read,Grep,Glob,Skill,SurpriseTool"},
        )
        self.assertEqual(result.returncode, 3)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertEqual(attempt["unexpected_tools"], ["SurpriseTool"])
        self.assertEqual(attempt["manifest_status"], "broader")
        # The attempt is stopped at init, so no result is ever accepted.
        self.assertIsNone(attempt["result"])
        self.assertFalse(attempt["materializable"])

    def test_unexpected_tool_not_enforced_outside_strict_profiles(self):
        for extra_args, env in (
            (
                ["--profile", "implementation", "--owned-path", "src"],
                {"FAKE_INIT_TOOLS": "Read,Grep,Glob,Skill,Bash,Write,Edit,SurpriseTool"},
            ),
            (
                [
                    "--permission-mode", "acceptEdits",
                    "--tool", "Read", "--tool", "Grep", "--tool", "Glob", "--tool", "Skill",
                ],
                {"FAKE_INIT_TOOLS": "Read,Grep,Glob,Skill,SurpriseTool"},
            ),
        ):
            with self.subTest(extra_args=extra_args):
                self.state = self.root / f"state-{extra_args[-1]}"
                result = self.invoke(
                    "run",
                    "--cwd", str(self.cwd),
                    "--prompt-file", str(self.prompt),
                    "--model", "opus",
                    "--effort", "high",
                    *extra_args,
                    "--state-root", str(self.state),
                    "--claude-bin", str(self.fake),
                    env=env,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                _, metadata = self.metadata()
                self.assertEqual(metadata["attempts"][0]["unexpected_tools"], ["SurpriseTool"])

    def test_resume_reuses_profile_manifest_exactly(self):
        first = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", "verified-review",
            "--allowed-command", "python3 -m unittest discover",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        _, before = self.metadata()
        run_id = before["run_id"]
        second_prompt = self.root / "resume-profile.md"
        second_prompt.write_text("RESUME BODY", encoding="utf-8")
        second = self.invoke(
            "resume", run_id,
            "--prompt-file", str(second_prompt),
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        _, after = self.metadata()
        self.assertEqual(after["profile"], before["profile"])
        self.assertEqual(after["profile_version"], before["profile_version"])
        self.assertEqual(after["profile_manifest_sha256"], before["profile_manifest_sha256"])
        self.assertEqual(after["tools"], before["tools"])
        self.assertEqual(after["allowed_tools"], before["allowed_tools"])
        self.assertEqual(after["disallowed_tools"], before["disallowed_tools"])

    def test_resume_rejects_override_flags(self):
        first = self.run_worker()
        self.assertEqual(first.returncode, 0, first.stderr)
        _, before = self.metadata()
        run_id = before["run_id"]
        resumed = self.invoke(
            "resume", run_id,
            "--prompt-file", str(self.prompt),
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            "--profile", "implementation",
        )
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("unrecognized arguments", resumed.stderr)

    def test_materialize_attempt_flag_selects_specific_attempt(self):
        first = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--permission-mode", "acceptEdits",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env={"FAKE_RESULT_TEXT": "ATTEMPT ONE RESULT"},
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        _, before = self.metadata()
        run_id = before["run_id"]
        second_prompt = self.root / "resume-attempt.md"
        second_prompt.write_text("SECOND", encoding="utf-8")
        second = self.invoke(
            "resume", run_id,
            "--prompt-file", str(second_prompt),
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env={"FAKE_RESULT_TEXT": "ATTEMPT TWO RESULT"},
        )
        self.assertEqual(second.returncode, 0, second.stderr)
        output1 = self.root / "attempt1.md"
        result1 = self.invoke(
            "materialize", run_id,
            "--state-root", str(self.state),
            "--output", str(output1),
            "--attempt", "1",
        )
        self.assertEqual(result1.returncode, 0, result1.stderr)
        self.assertEqual(output1.read_text(encoding="utf-8"), "ATTEMPT ONE RESULT\n")
        output_default = self.root / "attempt-default.md"
        result_default = self.invoke(
            "materialize", run_id,
            "--state-root", str(self.state),
            "--output", str(output_default),
        )
        self.assertEqual(result_default.returncode, 0, result_default.stderr)
        self.assertEqual(output_default.read_text(encoding="utf-8"), "ATTEMPT TWO RESULT\n")

    def test_default_materialization_skips_failed_latest_attempt(self):
        first = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--permission-mode", "acceptEdits",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env={"FAKE_RESULT_TEXT": "GOOD ATTEMPT RESULT"},
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        _, before = self.metadata()
        run_id = before["run_id"]
        second_prompt = self.root / "resume-fail.md"
        second_prompt.write_text("SECOND", encoding="utf-8")
        failing = self.invoke(
            "resume", run_id,
            "--prompt-file", str(second_prompt),
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env={"FAKE_IS_ERROR": "1"},
        )
        self.assertEqual(failing.returncode, 1)
        output = self.root / "picked.md"
        result = self.invoke(
            "materialize", run_id,
            "--state-root", str(self.state),
            "--output", str(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "GOOD ATTEMPT RESULT\n")
        self.assertEqual(json.loads(result.stdout)["attempt"], 1)

    def test_materialize_refuses_truncated_attempt(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--permission-mode", "acceptEdits",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            "--max-log-mib", "0.0001",
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        _, metadata = self.metadata()
        self.assertTrue(metadata["attempts"][0]["stream_truncated"])
        output = self.root / "trunc.md"
        materialize = self.invoke(
            "materialize", metadata["run_id"],
            "--state-root", str(self.state),
            "--output", str(output),
        )
        self.assertEqual(materialize.returncode, 2)
        self.assertFalse(output.exists())

    def test_materialize_refuses_symlink_output(self):
        result = self.run_worker()
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        real_target = self.root / "real-target.md"
        real_target.write_text("existing", encoding="utf-8")
        link = self.root / "link.md"
        link.symlink_to(real_target)
        materialize = self.invoke(
            "materialize", metadata["run_id"],
            "--state-root", str(self.state),
            "--output", str(link),
        )
        self.assertEqual(materialize.returncode, 2)
        self.assertIn("symlink", materialize.stderr)
        self.assertEqual(real_target.read_text(encoding="utf-8"), "existing")


class RootReviewCounterexampleTests(AdapterHarness, unittest.TestCase):
    """Cases the first candidate got wrong; each must fail before the corrective change."""

    def test_explicitly_allowed_readonly_mcp_tool_is_expected_not_unexpected(self):
        config = self.mcp_config()
        result = self.run_profile(
            "strict-readonly",
            "--allowed-tool", "mcp__codebase-memory-mcp__search_graph",
            "--mcp-config", str(config),
            env={
                "FAKE_INIT_TOOLS": "Read,Grep,Glob,Skill,mcp__codebase-memory-mcp__search_graph",
                "FAKE_INIT_MCP_SERVERS": "codebase-memory-mcp",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertEqual(attempt["unexpected_tools"], [])
        self.assertEqual(attempt["manifest_status"], "match")
        self.assertIn(
            "mcp__codebase-memory-mcp__search_graph", metadata["expected_tools"]
        )

    def test_init_event_without_tools_list_is_unknown_and_fails_strict(self):
        result = self.run_profile(
            "strict-readonly", env={"FAKE_INIT_TOOLS_ABSENT": "1"}
        )
        self.assertEqual(result.returncode, 3)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertEqual(attempt["manifest_status"], "unknown")
        self.assertFalse(attempt["materializable"])

    def test_known_empty_tool_list_is_distinct_from_an_omitted_list(self):
        result = self.run_profile("strict-readonly", env={"FAKE_INIT_TOOLS": ""})
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertEqual(metadata["attempts"][0]["manifest_status"], "narrower")

    def test_broader_manifest_terminates_the_child_before_a_result_arrives(self):
        result = self.run_profile(
            "strict-readonly",
            env={
                "FAKE_INIT_TOOLS": "Read,Grep,Glob,Skill,SurpriseTool",
                "FAKE_PAUSE_AFTER_INIT": "20",
            },
        )
        self.assertEqual(result.returncode, 3)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertEqual(attempt["manifest_status"], "broader")
        self.assertEqual(attempt["unexpected_tools"], ["SurpriseTool"])
        self.assertIsNone(attempt["result"])
        self.assertFalse(attempt["materializable"])
        self.assertIn("manifest", attempt["manifest_failure_reason"])
        stream = Path(attempt["stream_path"]).read_text(encoding="utf-8")
        self.assertNotIn('"type": "result"', stream)
        self.assertNotIn('"type":"result"', stream)

    def test_meaningful_event_before_init_fails_closed(self):
        result = self.run_profile(
            "strict-readonly", env={"FAKE_EVENT_BEFORE_INIT": "1"}
        )
        self.assertEqual(result.returncode, 3)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertEqual(attempt["manifest_status"], "unknown")
        self.assertIn("before init", attempt["manifest_failure_reason"])
        self.assertFalse(attempt["materializable"])

    def test_real_mcp_init_exposure_shape_respects_explicit_query_denies(self):
        config = self.mcp_config()
        pinned = (
            "mcp__codebase-memory-mcp__detect_changes,"
            "mcp__codebase-memory-mcp__get_architecture,"
            "mcp__codebase-memory-mcp__get_code_snippet,"
            "mcp__codebase-memory-mcp__get_graph_schema,"
            "mcp__codebase-memory-mcp__index_status,"
            "mcp__codebase-memory-mcp__list_projects,"
            "mcp__codebase-memory-mcp__query_graph,"
            "mcp__codebase-memory-mcp__search_code,"
            "mcp__codebase-memory-mcp__search_graph,"
            "mcp__codebase-memory-mcp__trace_path"
        )
        result = self.run_profile(
            "strict-readonly",
            "--allowed-tool", "mcp__codebase-memory-mcp__list_projects",
            "--mcp-config", str(config),
            env={"FAKE_INIT_TOOLS": f"Read,Grep,Glob,Skill,{pinned}"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertEqual(attempt["manifest_status"], "match")
        self.assertEqual(attempt["unexpected_tools"], [])

    def test_legacy_successful_attempt_without_materializable_is_still_selectable(self):
        run = self.run_worker()
        self.assertEqual(run.returncode, 0, run.stderr)
        metadata_path, metadata = self.metadata()
        metadata["attempts"][0].pop("materializable")
        self.write_metadata(metadata_path, metadata)
        output = self.root / "legacy.md"
        result = self.invoke(
            "materialize", metadata["run_id"],
            "--state-root", str(self.state),
            "--output", str(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "FINAL SECRET RESULT\n")

    def test_explicit_false_materializable_is_never_reinterpreted(self):
        run = self.run_worker()
        self.assertEqual(run.returncode, 0, run.stderr)
        metadata_path, metadata = self.metadata()
        metadata["attempts"][0]["materializable"] = False
        self.write_metadata(metadata_path, metadata)
        result = self.invoke(
            "materialize", metadata["run_id"],
            "--state-root", str(self.state),
            "--output", str(self.root / "never.md"),
        )
        self.assertEqual(result.returncode, 2)

    def test_status_and_inspect_expose_the_full_profile_and_manifest_evidence(self):
        config = self.mcp_config()
        result = self.run_profile(
            "verified-review",
            "--allowed-tool", "mcp__codebase-memory-mcp__search_graph",
            "--mcp-config", str(config),
            env={"FAKE_INIT_MCP_SERVERS": "codebase-memory-mcp"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        status = self.invoke("status", metadata["run_id"], "--state-root", str(self.state))
        self.assertEqual(status.returncode, 0, status.stderr)
        report = json.loads(status.stdout)
        for key in (
            "profile",
            "profile_requested",
            "profile_version",
            "profile_manifest_sha256",
            "expected_tools",
            "allowed_tools",
            "exposed_but_denied",
            "sandbox_policy",
            "scratch",
        ):
            self.assertIn(key, report, key)
        self.assertEqual(report["profile_version"], 3)
        attempt = report["attempts"][0]
        for key in (
            "observed_tools",
            "observed_mcp_servers",
            "manifest_status",
            "unexpected_tools",
            "materializable",
        ):
            self.assertIn(key, attempt, key)
        self.assertEqual(attempt["observed_mcp_servers"], ["codebase-memory-mcp"])
        inspect = self.invoke("inspect", metadata["run_id"], "--state-root", str(self.state))
        self.assertEqual(inspect.returncode, 0, inspect.stderr)
        self.assertIn("manifest_status", json.loads(inspect.stdout)["attempts"][0])
        self.assertNotIn("FINAL SECRET RESULT", inspect.stdout)

    def test_accepted_command_string_is_not_recorded_as_filesystem_enforcement(self):
        result = self.run_profile("verified-review")
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertEqual(metadata["command_policy"]["enforcement"], "permission-rule-only")
        self.assertEqual(metadata["sandbox_policy"]["status"], "requested-unproven")
        self.assertTrue(metadata["sandbox_policy"]["required"])
        # Accepting a command must never promote the requested policy to an
        # observed one; only an actual-runtime probe can do that.
        self.assertNotIn(
            metadata["sandbox_policy"]["status"], ("effective", "proven", "verified")
        )

    def test_version_two_run_cannot_resume_under_version_three_but_stays_materializable(self):
        run = self.run_worker()
        self.assertEqual(run.returncode, 0, run.stderr)
        metadata_path, metadata = self.metadata()
        metadata["profile"] = "strict-readonly"
        metadata["profile_version"] = 2
        self.write_metadata(metadata_path, metadata)
        resumed = self.invoke(
            "resume", metadata["run_id"],
            "--prompt-file", str(self.prompt),
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("profile version", resumed.stderr)
        output = self.root / "legacy-version.md"
        materialized = self.invoke(
            "materialize", metadata["run_id"],
            "--state-root", str(self.state),
            "--output", str(output),
        )
        self.assertEqual(materialized.returncode, 0, materialized.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "FINAL SECRET RESULT\n")


class CapabilityPreflightIntegrationTests(AdapterHarness, unittest.TestCase):
    """Fail-closed before a paid launch, never after one."""

    def assert_never_launched(self):
        self.assertEqual(
            self.args_log.read_text(encoding="utf-8") if self.args_log.exists() else "", ""
        )

    def test_absent_sandbox_flag_fails_a_sandbox_requiring_profile_before_launch(self):
        for flag in ("--settings", "--mcp-config", "--strict-mcp-config"):
            with self.subTest(flag=flag):
                self.state = self.root / f"state-{flag.strip('-')}"
                self.args_log = self.root / f"args-{flag.strip('-')}.jsonl"
                result = self.run_profile(
                    "verified-review", env={"FAKE_MISSING_FLAGS": flag}
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(flag, result.stderr)
                self.assert_never_launched()

    def test_help_probe_error_fails_before_launch(self):
        broken = self.root / "broken-claude"
        broken.write_text("#!/bin/sh\nexit 9\n", encoding="utf-8")
        broken.chmod(0o755)
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", "verified-review",
            *self.profile_args("verified-review"),
            "--state-root", str(self.state),
            "--claude-bin", str(broken),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("capability preflight failed", result.stderr)

    def test_unreadable_auto_mode_configuration_fails_before_launch(self):
        result = self.run_profile(
            "implementation-auto", env={"FAKE_AUTO_MODE_CONFIG": "unreadable"}
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("auto-mode capability preflight failed", result.stderr)
        self.assert_never_launched()

    def test_strict_profile_needs_no_sandbox_flags(self):
        result = self.run_profile(
            "strict-readonly",
            env={"FAKE_MISSING_FLAGS": "--settings,--mcp-config,--strict-mcp-config"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertFalse(metadata["sandbox_policy"]["required"])


class GeneratedSettingsIntegrationTests(AdapterHarness, unittest.TestCase):
    def test_invocation_local_settings_are_materialized_and_passed_through(self):
        result = self.run_profile("verified-review")
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        settings_path = Path(metadata["runtime"]["settings_path"])
        self.assertTrue(settings_path.is_file())
        self.assertEqual(settings_path.stat().st_mode & 0o777, 0o600)
        settings = json.loads(settings_path.read_text(encoding="utf-8"))
        self.assertTrue(settings["sandbox"]["enabled"])
        self.assertTrue(settings["sandbox"]["failIfUnavailable"])
        self.assertFalse(settings["sandbox"]["allowUnsandboxedCommands"])
        self.assertFalse(settings["sandbox"]["autoAllowBashIfSandboxed"])
        self.assertEqual(settings["sandbox"]["excludedCommands"], [])
        self.assertEqual(settings["sandbox"]["network"]["deniedDomains"], ["*"])
        for tool in ("Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch", "Agent", "Task"):
            self.assertIn(tool, settings["permissions"]["deny"])
        args = json.loads(self.args_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(args[args.index("--settings") + 1], str(settings_path))
        self.assertIn("--strict-mcp-config", args)
        self.assertIn("--mcp-config", args)

    def test_undeclared_mcp_configuration_defaults_to_an_empty_run_local_source(self):
        result = self.run_profile("verified-review")
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        declared = metadata["mcp"]["declared"]
        self.assertEqual(len(declared), 1)
        self.assertEqual(
            json.loads(Path(declared[0]).read_text(encoding="utf-8")), {"mcpServers": {}}
        )
        self.assertEqual(len(metadata["mcp"]["config_hashes"][0]["sha256"]), 64)

    def test_allowed_mcp_tool_without_a_declared_server_fails_before_launch(self):
        result = self.run_profile(
            "strict-readonly",
            "--allowed-tool", "mcp__codebase-memory-mcp__search_graph",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("no declared server configuration", result.stderr)
        self.assertEqual(
            self.args_log.read_text(encoding="utf-8") if self.args_log.exists() else "", ""
        )

    def test_implementation_settings_keep_project_writes_while_closing_the_network(self):
        result = self.run_profile("implementation")
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        settings = json.loads(
            Path(metadata["runtime"]["settings_path"]).read_text(encoding="utf-8")
        )
        self.assertEqual(settings["sandbox"]["network"]["deniedDomains"], ["*"])
        self.assertFalse(settings["sandbox"]["allowUnsandboxedCommands"])
        self.assertNotIn("Write", settings["permissions"]["deny"])
        self.assertNotIn("Edit", settings["permissions"]["deny"])


class ScratchAndBudgetIntegrationTests(AdapterHarness, unittest.TestCase):
    def child_cwd(self) -> str:
        return self.cwd_log.read_text(encoding="utf-8").splitlines()[-1]

    def setUp(self):
        super().setUp()
        self.cwd_log = self.root / "cwd.log"

    def run_scratch(self, *extra: str, env: dict | None = None):
        merged = {"FAKE_CWD_LOG": str(self.cwd_log)}
        merged.update(env or {})
        return self.run_profile("verified-review", *extra, env=merged)

    def test_default_scratch_is_run_local_and_is_the_process_working_directory(self):
        result = self.run_scratch()
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        scratch = Path(metadata["scratch"]["root"])
        self.assertEqual(metadata["scratch"]["provenance"], "default")
        self.assertEqual(scratch.parent.name, metadata["run_id"])
        self.assertEqual(self.child_cwd(), str(scratch))
        self.assertEqual(metadata["runtime"]["cwd"], str(scratch))
        self.assertIn(str(self.cwd), metadata["add_dirs"])

    def test_explicit_external_scratch_directory_is_used(self):
        external = self.root / "external-scratch"
        external.mkdir()
        external.chmod(0o700)
        result = self.run_scratch("--scratch-dir", str(external))
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertEqual(metadata["scratch"]["provenance"], "argument")
        self.assertEqual(Path(metadata["scratch"]["root"]), external.resolve())
        self.assertEqual(self.child_cwd(), str(external.resolve()))

    def test_explicit_workspace_local_scratch_directory_is_used(self):
        workspace = self.cwd / "review-scratch"
        workspace.mkdir()
        workspace.chmod(0o700)
        result = self.run_scratch("--scratch-dir", str(workspace))
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertEqual(Path(metadata["scratch"]["root"]), workspace.resolve())

    def test_scratch_environment_redirects_temporary_directories(self):
        result = self.run_scratch()
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        scratch = metadata["scratch"]["root"]
        for name in ("TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME"):
            self.assertTrue(metadata["runtime"]["env"][name].startswith(scratch), name)

    def test_nonempty_unowned_scratch_is_refused_before_launch(self):
        external = self.root / "occupied"
        external.mkdir()
        external.chmod(0o700)
        (external / "user-file.txt").write_text("keep me", encoding="utf-8")
        result = self.run_scratch("--scratch-dir", str(external))
        self.assertEqual(result.returncode, 2)
        self.assertIn("scratch preflight refused", result.stderr)
        self.assertEqual(
            (external / "user-file.txt").read_text(encoding="utf-8"), "keep me"
        )
        self.assertFalse(self.args_log.exists())

    def test_symlinked_scratch_is_refused_before_launch(self):
        target = self.root / "target"
        target.mkdir()
        link = self.root / "link-scratch"
        link.symlink_to(target)
        result = self.run_scratch("--scratch-dir", str(link))
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)

    def test_configured_limit_above_the_ceiling_is_refused(self):
        result = self.run_profile("strict-readonly", "--state-limit-mib", "241")
        self.assertEqual(result.returncode, 2)
        self.assertIn("240", result.stderr)
        self.assertFalse(self.args_log.exists())

    def test_external_scratch_bytes_are_included_in_admission_accounting(self):
        external = self.root / "external-scratch"
        external.mkdir()
        external.chmod(0o700)
        run_id = str(uuid.uuid4())
        (external / ".delegate-to-claude-scratch.json").write_text(
            json.dumps({
                "schema_version": 1,
                "owner": "delegate-to-claude",
                "provenance": "argument",
                "run_id": run_id,
                "root": str(external.resolve()),
                "uid": os.getuid() if hasattr(os, "getuid") else None,
            }),
            encoding="utf-8",
        )
        (external / "prior.bin").write_bytes(b"x" * 1_100_000)
        result = self.run_scratch(
            "--scratch-dir", str(external),
            "--session-id", run_id,
            "--state-limit-mib", "1",
            "--max-log-mib", "0.01",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("state preflight refused", result.stderr)

    def test_scratch_growth_terminates_the_child_and_records_the_overrun(self):
        result = self.run_scratch(
            "--state-limit-mib", "0.05",
            "--max-log-mib", "0.002",
            env={"FAKE_SCRATCH_FILL_BYTES": "45000", "FAKE_FILL_LINGER": "10"},
        )
        self.assertEqual(result.returncode, 4)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertIsNotNone(attempt["budget_exceeded_bytes"])
        self.assertFalse(attempt["materializable"])
        self.assertEqual(metadata["scratch"]["disposition"], "over-budget")
        # Never a recovery delete: the oversized payload is left in place.
        self.assertTrue((Path(metadata["scratch"]["root"]) / "fill.bin").exists())

    def test_resume_preflight_refuses_when_accounted_state_is_over_budget(self):
        first = self.run_profile(
            "strict-readonly", "--state-limit-mib", "1", "--max-log-mib", "0.01"
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        _, metadata = self.metadata()
        (self.state / "ballast.bin").write_bytes(b"x" * 1_100_000)
        resumed = self.invoke(
            "resume", metadata["run_id"],
            "--prompt-file", str(self.prompt),
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(resumed.returncode, 2)
        self.assertIn("state preflight refused", resumed.stderr)

    def test_stdout_and_stderr_share_one_log_budget(self):
        limit = int(0.002 * 1024 * 1024)
        result = self.run_profile("strict-readonly", "--max-log-mib", "0.002")
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        stream_bytes = Path(attempt["stream_path"]).stat().st_size
        stderr_bytes = Path(attempt["stderr_path"]).stat().st_size
        self.assertLessEqual(stream_bytes + stderr_bytes, limit)
        self.assertLessEqual(attempt["log_bytes"], limit)

    def test_stderr_truncation_makes_the_attempt_non_materializable(self):
        result = self.run_profile(
            "strict-readonly",
            "--max-log-mib", "0.001",
            env={"FAKE_STDERR_BYTES": "10000"},
        )
        self.assertNotEqual(result.returncode, 0)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertTrue(attempt["stderr_truncated"])
        self.assertFalse(attempt["materializable"])


class ImplementationReconciliationIntegrationTests(AdapterHarness, unittest.TestCase):
    def setUp(self):
        super().setUp()
        (self.cwd / "src").mkdir()
        (self.cwd / "src" / "existing.py").write_text("original\n", encoding="utf-8")
        (self.cwd / "README.md").write_text("readme\n", encoding="utf-8")
        for args in (
            ("add", "-A"),
            ("-c", "user.email=t@example.invalid", "-c", "user.name=T", "commit", "-qm", "base"),
        ):
            subprocess.run(
                ["git", "-C", str(self.cwd), *args], check=True, capture_output=True
            )

    def test_a_clean_owned_edit_reconciles_and_succeeds(self):
        result = self.run_profile(
            "implementation",
            env={"FAKE_WRITE_FILES": f"{self.cwd}/src/existing.py=worker edit\n"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        report = metadata["attempts"][0]["reconciliation"]
        self.assertEqual(report["owned"], ["src/existing.py"])
        self.assertTrue(report["reconciled"])
        self.assertTrue(metadata["attempts"][0]["materializable"])

    def test_an_undeclared_change_fails_the_attempt_without_reverting_it(self):
        result = self.run_profile(
            "implementation",
            env={"FAKE_WRITE_FILES": f"{self.cwd}/README.md=worker touched this\n"},
        )
        self.assertEqual(result.returncode, 5)
        _, metadata = self.metadata()
        attempt = metadata["attempts"][0]
        self.assertEqual(attempt["reconciliation"]["undeclared"], ["README.md"])
        self.assertFalse(attempt["materializable"])
        # Preserved for root disposition: detection, never rollback.
        self.assertEqual(
            (self.cwd / "README.md").read_text(encoding="utf-8"), "worker touched this\n"
        )

    def test_an_undeclared_delete_fails_the_attempt(self):
        result = self.run_profile(
            "implementation",
            env={"FAKE_DELETE_FILES": f"{self.cwd}/README.md"},
        )
        self.assertEqual(result.returncode, 5)
        _, metadata = self.metadata()
        self.assertEqual(
            metadata["attempts"][0]["reconciliation"]["undeclared"], ["README.md"]
        )

    def test_committing_an_owned_edit_is_a_git_control_violation(self):
        result = self.run_profile(
            "implementation",
            env={
                "FAKE_WRITE_FILES": f"{self.cwd}/src/existing.py=committed edit\n",
                "FAKE_GIT_COMMIT_PATH": "src/existing.py",
            },
        )
        self.assertEqual(result.returncode, 5)
        _, metadata = self.metadata()
        report = metadata["attempts"][0]["reconciliation"]
        self.assertIn("git:HEAD", report["control_changes"])
        self.assertIn("git:index", report["control_changes"])
        self.assertFalse(report["reconciled"])

    def test_ignored_installation_side_effect_is_rejected(self):
        (self.cwd / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.cwd), "add", ".gitignore"], check=True)
        subprocess.run(
            [
                "git", "-C", str(self.cwd),
                "-c", "user.email=t@example.invalid",
                "-c", "user.name=T",
                "commit", "-qm", "ignore dependencies",
            ],
            check=True,
        )
        target = self.cwd / "node_modules" / "pkg" / "index.js"
        result = self.run_profile(
            "implementation",
            env={"FAKE_WRITE_FILES": f"{target}=installed\n"},
        )
        self.assertEqual(result.returncode, 5)
        _, metadata = self.metadata()
        report = metadata["attempts"][0]["reconciliation"]
        self.assertEqual(report["ignored_changes"], ["node_modules/pkg/index.js"])
        self.assertFalse(report["reconciled"])

    def test_a_pre_existing_dirty_file_is_not_attributed_to_the_worker(self):
        (self.cwd / "README.md").write_text("user edit before launch\n", encoding="utf-8")
        result = self.run_profile(
            "implementation",
            env={"FAKE_WRITE_FILES": f"{self.cwd}/src/existing.py=worker edit\n"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        report = metadata["attempts"][0]["reconciliation"]
        self.assertEqual(report["pre_existing_unchanged"], ["README.md"])
        self.assertEqual(report["undeclared"], [])
        self.assertEqual(
            (self.cwd / "README.md").read_text(encoding="utf-8"),
            "user edit before launch\n",
        )

    def test_implementation_runs_from_the_project_not_from_scratch(self):
        cwd_log = self.root / "cwd.log"
        result = self.run_profile(
            "implementation", env={"FAKE_CWD_LOG": str(cwd_log)}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            cwd_log.read_text(encoding="utf-8").strip(), str(self.cwd)
        )

    def test_declared_scratch_changes_are_not_product_edits(self):
        scratch = self.cwd / "impl-scratch"
        scratch.mkdir()
        scratch.chmod(0o700)
        result = self.run_profile(
            "implementation",
            "--scratch-dir", str(scratch),
            env={"FAKE_WRITE_FILES": f"{scratch}/tmp.txt=scratch only\n"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        _, metadata = self.metadata()
        self.assertEqual(metadata["attempts"][0]["reconciliation"]["undeclared"], [])
        runtime = metadata["runtime"]
        self.assertEqual(runtime["env"]["TMPDIR"], str(scratch.resolve()))
        settings = json.loads(Path(runtime["settings_path"]).read_text(encoding="utf-8"))
        self.assertIn(
            str(scratch.resolve()),
            settings["sandbox"]["filesystem"]["allowWrite"],
        )
        self.assertIn(
            str((self.cwd / ".git").resolve()),
            settings["sandbox"]["filesystem"]["denyWrite"],
        )

    def test_a_non_git_project_root_fails_implementation_preflight(self):
        plain = self.root / "plain-project"
        plain.mkdir()
        result = self.invoke(
            "run",
            "--cwd", str(plain),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", "implementation",
            "--owned-path", "src",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("ownership preflight failed", result.stderr)
        self.assertFalse(self.args_log.exists())

    def test_an_owned_path_outside_the_project_is_refused(self):
        result = self.run_profile("implementation", "--owned-path", str(self.root))
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside", result.stderr)

    def test_a_symlinked_owned_path_cannot_escape_the_project(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.cwd / "escape").symlink_to(outside)
        result = self.run_profile("implementation", "--owned-path", "escape")
        self.assertEqual(result.returncode, 2)
        self.assertIn("outside", result.stderr)

    def test_owned_paths_are_rejected_for_a_review_profile(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", "verified-review",
            "--allowed-command", "pytest -q",
            "--owned-path", "src",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("--owned-path is not permitted", result.stderr)


class ArtifactReviewIntegrationTests(AdapterHarness, unittest.TestCase):
    def run_artifact(self, output: Path, *extra: str, env: dict | None = None):
        return self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", "artifact-review",
            "--allowed-command", "python3 -m unittest discover",
            "--artifact-output", str(output),
            *extra,
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
            env=env,
        )

    def test_artifact_output_is_required(self):
        result = self.invoke(
            "run",
            "--cwd", str(self.cwd),
            "--prompt-file", str(self.prompt),
            "--model", "opus",
            "--effort", "high",
            "--profile", "artifact-review",
            "--allowed-command", "python3 -m unittest discover",
            "--state-root", str(self.state),
            "--claude-bin", str(self.fake),
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requires --artifact-output", result.stderr)
        self.assertFalse(self.args_log.exists())

    def test_successful_result_is_materialized_with_attempt_and_hash_recorded(self):
        output = self.root / "review.md"
        result = self.run_artifact(output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "FINAL SECRET RESULT\n")
        _, metadata = self.metadata()
        self.assertEqual(metadata["artifact"]["attempt"], 1)
        self.assertEqual(len(metadata["artifact"]["sha256"]), 64)

    def test_the_worker_receives_no_file_write_tool(self):
        output = self.root / "review.md"
        self.assertEqual(self.run_artifact(output).returncode, 0)
        _, metadata = self.metadata()
        self.assertEqual(metadata["tools"], ["Read", "Grep", "Glob", "Skill", "Bash"])
        for tool in ("Write", "Edit", "NotebookEdit"):
            self.assertIn(tool, metadata["disallowed_tools"])
        args = json.loads(self.args_log.read_text(encoding="utf-8").splitlines()[-1])
        self.assertNotIn("Write", args[args.index("--tools") + 1].split(","))

    def test_an_existing_output_is_refused_before_launch(self):
        output = self.root / "review.md"
        output.write_text("prior review\n", encoding="utf-8")
        result = self.run_artifact(output)
        self.assertEqual(result.returncode, 2)
        self.assertIn("already exists", result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "prior review\n")
        self.assertFalse(self.args_log.exists())

    def test_explicit_overwrite_is_honoured(self):
        output = self.root / "review.md"
        output.write_text("prior review\n", encoding="utf-8")
        result = self.run_artifact(output, "--overwrite-artifact")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), "FINAL SECRET RESULT\n")

    def test_a_symlinked_output_is_refused_before_launch(self):
        target = self.root / "real-target.md"
        target.write_text("existing", encoding="utf-8")
        link = self.root / "link.md"
        link.symlink_to(target)
        result = self.run_artifact(link)
        self.assertEqual(result.returncode, 2)
        self.assertIn("symlink", result.stderr)
        self.assertEqual(target.read_text(encoding="utf-8"), "existing")

    def test_a_failed_result_materializes_nothing(self):
        output = self.root / "review.md"
        result = self.run_artifact(output, env={"FAKE_IS_ERROR": "1"})
        self.assertEqual(result.returncode, 1)
        self.assertFalse(output.exists())
        _, metadata = self.metadata()
        self.assertIsNone(metadata["artifact"]["attempt"])

    def test_a_truncated_result_materializes_nothing(self):
        output = self.root / "review.md"
        result = self.run_artifact(output, "--max-log-mib", "0.0002")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())


class ExplainCommandTests(AdapterHarness, unittest.TestCase):
    """Non-generative preflight: no model call, no fake-Claude launch, no state."""

    def test_preset_explanation_as_json(self):
        result = self.invoke("explain", "--profile", "verified-review", "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        explanation = json.loads(result.stdout)
        self.assertEqual(explanation["stage"], "compiled")
        self.assertEqual(explanation["profile"]["id"], "verified-review")
        self.assertFalse(self.args_log.exists())
        self.assertFalse(self.state.exists())

    def test_preset_explanation_as_text(self):
        result = self.invoke("explain", "--profile", "strict-readonly", "--format", "text")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stage: compiled", result.stdout)
        self.assertFalse(self.args_log.exists())

    def test_custom_json_policy_file(self):
        policy_file = self.root / "policy.json"
        policy_file.write_text(json.dumps({
            "filesystem": {
                "roots": {"project": {"kind": "project", "binding": "unbound"}},
                "rules": [{"operations": ["read"], "scope": "project", "effect": "allow"}],
            }
        }), encoding="utf-8")
        result = self.invoke("explain", "--policy-file", str(policy_file), "--format", "json")
        self.assertEqual(result.returncode, 0, result.stderr)
        explanation = json.loads(result.stdout)
        self.assertEqual(explanation["roots"]["read"], [{"id": "project", "binding": "unbound"}])

    def test_compare_profile_includes_transition(self):
        result = self.invoke(
            "explain", "--profile", "verified-review",
            "--compare-profile", "strict-readonly",
            "--notice", "cache_impact=never",
            "--confirmation", "authority_expansion=never",
            "--format", "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        explanation = json.loads(result.stdout)
        self.assertIsNotNone(explanation["transition"])
        self.assertFalse(self.args_log.exists())
        self.assertFalse(self.state.exists())

    def test_named_read_write_bindings_are_path_independent_in_hash(self):
        first_root = self.root / "workspace-one"
        first_root.mkdir()
        second_root = self.root / "workspace-two"
        second_root.mkdir()
        first = self.invoke(
            "explain", "--profile", "strict-readonly",
            "--workspace", str(first_root),
            "--read-root", f"shared_docs={first_root / 'docs'}",
            "--format", "json",
        )
        second = self.invoke(
            "explain", "--profile", "strict-readonly",
            "--workspace", str(second_root),
            "--read-root", f"shared_docs={second_root / 'docs'}",
            "--format", "json",
        )
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        first_explanation = json.loads(first.stdout)
        second_explanation = json.loads(second.stdout)
        self.assertEqual(
            first_explanation["semantic_sha256"], second_explanation["semantic_sha256"]
        )
        self.assertEqual(
            first_explanation["authority_sha256"], second_explanation["authority_sha256"]
        )
        self.assertIn(
            {"id": "shared_docs", "binding": "bound"}, first_explanation["roots"]["read"]
        )

    def test_notice_and_confirmation_overrides_are_accepted(self):
        result = self.invoke(
            "explain", "--profile", "strict-readonly",
            "--notice", "profile_transition=never",
            "--notice", "cache_impact=once",
            "--confirmation", "unsandboxed_command=never",
            "--format", "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_duplicate_named_roots_are_rejected(self):
        result = self.invoke(
            "explain", "--profile", "strict-readonly",
            "--read-root", f"shared_docs={self.root / 'one'}",
            "--write-root", f"shared_docs={self.root / 'two'}",
            "--format", "json",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate root name", result.stderr)

    def test_state_is_reserved_for_named_roots(self):
        result = self.invoke(
            "explain", "--profile", "strict-readonly",
            "--read-root", f"state={self.root / 'state'}",
            "--format", "json",
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("root name is reserved", result.stderr)

    def test_structurally_invalid_policy_files_exit_two_without_traceback(self):
        for index, payload in enumerate(([], {"filesystem": None})):
            with self.subTest(index=index):
                policy_file = self.root / f"invalid-policy-{index}.json"
                policy_file.write_text(json.dumps(payload), encoding="utf-8")
                result = self.invoke(
                    "explain", "--policy-file", str(policy_file), "--format", "json",
                )
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)

    def test_invalid_config_exits_two(self):
        result = self.invoke(
            "explain", "--profile", "strict-readonly",
            "--notice", "profile_transition=sometimes",
            "--format", "json",
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.args_log.exists())

    def test_malformed_custom_override_sections_exit_two_without_traceback(self):
        cases = (
            ({"output": []}, ("--output-dir", str(self.root / "out"))),
            ({"notices": []}, ("--notice", "profile_transition=never")),
            ({"confirmation": []}, ("--confirmation", "authority_expansion=never")),
        )
        for index, (payload, override) in enumerate(cases):
            with self.subTest(index=index):
                policy_file = self.root / f"invalid-override-{index}.json"
                policy_file.write_text(json.dumps(payload), encoding="utf-8")
                result = self.invoke(
                    "explain", "--policy-file", str(policy_file), *override, "--format", "json",
                )
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("Traceback", result.stderr)

    def test_explain_never_invokes_claude_or_creates_state(self):
        result = self.invoke(
            "explain", "--profile", "implementation-auto",
            "--output-dir", str(self.root / "out"),
            "--scratch-dir", str(self.root / "scratch"),
            "--format", "json",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.args_log.exists())
        self.assertFalse(self.state.exists())
        self.assertFalse((self.root / "out").exists())
        self.assertFalse((self.root / "scratch").exists())

    def test_existing_run_resume_tests_remain_green(self):
        # Sentinel: run/resume behavior is exercised exhaustively elsewhere in
        # this module; explain must not have altered it.
        result = self.run_worker()
        self.assertEqual(result.returncode, 0, result.stderr)


def _load_claude_delegate_module():
    scripts_dir = str(SCRIPT.parent)
    sys.path.insert(0, scripts_dir)
    try:
        spec = importlib.util.spec_from_file_location("claude_delegate_boundary", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(scripts_dir)


class InProcessRuntimeBoundaryTests(AdapterHarness, unittest.TestCase):
    """Top-level import of C0 modules is allowed; runtime invocation is not."""

    def test_explain_never_calls_subprocess_popen_or_execute_attempt(self):
        import unittest.mock as mock

        module = _load_claude_delegate_module()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with (
                mock.patch.object(module.subprocess, "Popen") as popen,
                mock.patch.object(module, "execute_attempt") as execute,
            ):
                exit_code = module.main(["explain", "--profile", "strict-readonly", "--format", "json"])
        self.assertEqual(exit_code, 0)
        popen.assert_not_called()
        execute.assert_not_called()

    def test_run_and_resume_never_call_c0_entry_points(self):
        import unittest.mock as mock

        module = _load_claude_delegate_module()
        with warnings.catch_warnings(), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            warnings.simplefilter("ignore", ResourceWarning)
            with (
                mock.patch.object(module, "normalize_policy") as normalize,
                mock.patch.object(module, "compare_policies") as compare,
                mock.patch.object(module, "build_explanation") as build,
            ):
                exit_code = module.main([
                    "run",
                    "--cwd", str(self.cwd),
                    "--prompt-file", str(self.prompt),
                    "--model", "opus",
                    "--effort", "high",
                    "--permission-mode", "acceptEdits",
                    "--state-root", str(self.state),
                    "--claude-bin", str(self.fake),
                ])
        self.assertEqual(exit_code, 0)
        normalize.assert_not_called()
        compare.assert_not_called()
        build.assert_not_called()
        run_id = next((self.state / "runs").iterdir()).name
        with warnings.catch_warnings(), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            warnings.simplefilter("ignore", ResourceWarning)
            with (
                mock.patch.object(module, "normalize_policy") as normalize,
                mock.patch.object(module, "compare_policies") as compare,
                mock.patch.object(module, "build_explanation") as build,
            ):
                resume_code = module.main([
                    "resume", run_id,
                    "--prompt-file", str(self.prompt),
                    "--state-root", str(self.state),
                    "--claude-bin", str(self.fake),
                ])
        self.assertEqual(resume_code, 0)
        normalize.assert_not_called()
        compare.assert_not_called()
        build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
