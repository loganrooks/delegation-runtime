"""Focused black-box tests for the local agy delegation adapter."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[4]
ENTRYPOINT = ROOT / "adapters/codex/delegate-to-antigravity/scripts/agy_delegate.py"


FAKE_AGY = """\
#!{python}
import json
import os
from pathlib import Path
import sys
import time

if len(sys.argv) > 1 and sys.argv[1] == "models":
    sys.stdout.write(os.environ.get("FAKE_MODELS", "known\\n"))
    raise SystemExit(int(os.environ.get("FAKE_MODELS_EXIT", "0")))

record = os.environ.get("FAKE_RECORD")
if record:
    Path(record).write_text(json.dumps(sys.argv[1:]), encoding="utf-8")
time.sleep(float(os.environ.get("FAKE_SLEEP", "0")))
sys.stdout.write(os.environ.get("FAKE_STDOUT", "provider-result\\n"))
sys.stderr.write(os.environ.get("FAKE_STDERR", ""))
raise SystemExit(int(os.environ.get("FAKE_EXIT", "0")))
"""


class AgyDelegateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()
        self.prompt = self.base / "prompt.txt"
        self.prompt.write_text("TOP SECRET prompt $(touch never-run)\n", encoding="utf-8")
        self.prompt.chmod(0o600)
        self.state = self.base / "state"
        self.agy = self.base / "fake-agy"
        self.agy.write_text(
            textwrap.dedent(FAKE_AGY).format(python=sys.executable), encoding="utf-8"
        )
        self.agy.chmod(0o755)
        self.env = os.environ.copy()
        self.env["FAKE_MODELS"] = "known\nimplementation\n"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def invoke(self, *args: str, timeout: float = 5) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(ENTRYPOINT), *args],
            cwd=self.workspace,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )

    def run_args(self, profile: str, model: str = "known", **extra: str) -> list[str]:
        args = [
            "run",
            "--profile",
            profile,
            "--model",
            model,
            "--workspace",
            str(self.workspace),
            "--prompt-file",
            str(self.prompt),
            "--state-root",
            str(self.state),
            "--agy-bin",
            str(self.agy),
        ]
        for name, value in extra.items():
            args.extend([f"--{name.replace('_', '-')}", value])
        return args

    def test_models_relays_provider_listing(self) -> None:
        result = self.invoke("models", "--agy-bin", str(self.agy))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "known\nimplementation\n")

    def test_run_requires_an_exact_listed_model(self) -> None:
        result = self.invoke(*self.run_args("review", model="known "))
        self.assertEqual(result.returncode, 3)
        self.assertIn("model", result.stderr.lower())

    def test_run_requires_a_private_current_user_prompt_file(self) -> None:
        self.prompt.chmod(0o644)
        rejected = self.invoke(*self.run_args("review"))
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("prompt", rejected.stderr.lower())
        self.prompt.chmod(0o600)
        accepted = self.invoke(*self.run_args("review"))
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

    def test_review_uses_static_sandboxed_plan_argv(self) -> None:
        record = self.base / "review-argv.json"
        self.env["FAKE_RECORD"] = str(record)
        result = self.invoke(*self.run_args("review"))
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = json.loads(record.read_text(encoding="utf-8"))
        self.assertIn("--mode", argv)
        self.assertEqual(argv[argv.index("--mode") + 1], "plan")
        self.assertIn("--sandbox", argv)
        self.assertNotIn("--dangerously-skip-permissions", argv)
        self.assertIn("--log-file", argv)

    def test_implementation_auto_uses_approved_edit_argv(self) -> None:
        record = self.base / "implementation-argv.json"
        self.env["FAKE_RECORD"] = str(record)
        result = self.invoke(*self.run_args("implementation-auto", model="implementation"))
        self.assertEqual(result.returncode, 0, result.stderr)
        argv = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(argv[argv.index("--mode") + 1], "accept-edits")
        self.assertIn("--sandbox", argv)
        self.assertIn("--dangerously-skip-permissions", argv)

    def test_model_metacharacters_are_not_executed_by_a_shell(self) -> None:
        model = "safe;touch injected"
        self.env["FAKE_MODELS"] = model + "\n"
        record = self.base / "argv.json"
        self.env["FAKE_RECORD"] = str(record)
        result = self.invoke(*self.run_args("review", model=model))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.workspace / "injected").exists())
        self.assertIn(model, json.loads(record.read_text(encoding="utf-8")))

    def test_wrapper_does_not_put_prompt_in_status_or_captured_logs(self) -> None:
        result = self.invoke(*self.run_args("review"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "provider-result\n")
        self.assertNotIn("TOP SECRET", result.stderr)
        status = json.loads(result.stderr.strip().splitlines()[-1])
        self.assertEqual(status["profile"], "review")
        self.assertEqual(status["model"], "known")
        run_dir = Path(status["run_dir"])
        self.assertNotIn("TOP SECRET", (run_dir / "stdout.log").read_text(encoding="utf-8"))
        self.assertNotIn("TOP SECRET", (run_dir / "stderr.log").read_text(encoding="utf-8"))

    def test_nonzero_provider_exit_is_reported_as_provider_failure(self) -> None:
        self.env["FAKE_EXIT"] = "17"
        result = self.invoke(*self.run_args("review"))
        self.assertEqual(result.returncode, 6)
        self.assertIn('"exit":17', result.stderr)

    def test_timeout_terminates_provider(self) -> None:
        self.env["FAKE_SLEEP"] = "2"
        result = self.invoke(*self.run_args("review", timeout="1"), timeout=5)
        self.assertEqual(result.returncode, 6)
        self.assertIn('"exit":"timeout"', result.stderr)

    def test_state_budget_refuses_admission_at_192_mib(self) -> None:
        self.state.mkdir()
        with (self.state / "near-budget.bin").open("wb") as handle:
            handle.truncate(192 * 1024 * 1024)
        result = self.invoke(*self.run_args("review"))
        self.assertEqual(result.returncode, 4)
        self.assertIn("budget", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
