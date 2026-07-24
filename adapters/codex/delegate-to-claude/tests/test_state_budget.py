from __future__ import annotations

import os
import json
from pathlib import Path
import tempfile
import time
import unittest

from delegate_to_claude.state_budget import (
    CEILING_BYTES,
    MIB,
    STOP_BYTES,
    BudgetError,
    ScratchWatchdog,
    SharedLogBudget,
    aggregate_size,
    dedupe_roots,
    execution_watch_scope,
    preflight,
    resolve_scratch_dir,
    stop_threshold_bytes,
    validate_limit_bytes,
)


class BudgetConstantTests(unittest.TestCase):
    def test_ceiling_and_stop_thresholds_match_the_locked_contract(self):
        self.assertEqual(CEILING_BYTES, 240 * MIB)
        self.assertEqual(STOP_BYTES, 192 * MIB)
        self.assertLess(STOP_BYTES, 250 * MIB)

    def test_configured_limit_above_the_ceiling_is_refused(self):
        self.assertEqual(validate_limit_bytes(CEILING_BYTES), CEILING_BYTES)
        with self.assertRaisesRegex(BudgetError, "240"):
            validate_limit_bytes(CEILING_BYTES + 1)

    def test_stop_threshold_stays_below_the_configured_limit(self):
        self.assertEqual(stop_threshold_bytes(CEILING_BYTES), STOP_BYTES)
        self.assertLess(stop_threshold_bytes(10 * MIB), 10 * MIB)


class RootAccountingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def fill(self, path: Path, size: int) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"x" * size)
        return path

    def test_overlapping_roots_are_counted_once(self):
        state = self.root / "state"
        nested = state / "runs" / "scratch"
        self.fill(nested / "a.bin", 4096)
        self.assertEqual(dedupe_roots([state, nested]), (state.resolve(),))
        self.assertEqual(aggregate_size([state, nested]), 4096)

    def test_external_scratch_bytes_are_included(self):
        state = self.root / "state"
        external = self.root / "external-scratch"
        self.fill(state / "a.bin", 1000)
        self.fill(external / "b.bin", 2000)
        self.assertEqual(aggregate_size([state, external]), 3000)

    def test_new_run_preflight_refuses_at_the_aggregate_threshold(self):
        state = self.root / "state"
        external = self.root / "external"
        self.fill(state / "a.bin", 5000)
        self.fill(external / "b.bin", 5000)
        preflight([state], limit_bytes=100_000, headroom_bytes=1000)
        with self.assertRaises(BudgetError):
            preflight([state, external], limit_bytes=10_000, headroom_bytes=1000)

    def test_preflight_reserves_bounded_log_headroom(self):
        state = self.root / "state"
        self.fill(state / "a.bin", 9000)
        with self.assertRaises(BudgetError):
            preflight([state], limit_bytes=10_000, headroom_bytes=2000)

    def test_execution_watch_scope_excludes_historical_state_from_repeated_scans(self):
        state = self.root / "state"
        run = state / "runs" / "current"
        scratch = run / "scratch"
        self.fill(state / "runs" / "old" / "history.bin", 4000)
        self.fill(run / "metadata.json", 1000)
        self.fill(scratch / "current.bin", 500)
        scope = execution_watch_scope(
            state_root=state,
            run_dir=run,
            scratch_root=scratch,
            stop_bytes=10_000,
        )
        self.assertEqual(scope.fixed_bytes, 4000)
        self.assertEqual(scope.dynamic_roots, (run.resolve(),))
        self.assertEqual(scope.dynamic_threshold_bytes, 6000)


class SharedLogBudgetTests(unittest.TestCase):
    def test_stdout_and_stderr_share_one_budget_rather_than_two_maxima(self):
        budget = SharedLogBudget(100)
        self.assertEqual(budget.take(60), 60)
        self.assertEqual(budget.take(60), 40)
        self.assertTrue(budget.truncated)
        self.assertEqual(budget.used, 100)

    def test_untruncated_budget_reports_cleanly(self):
        budget = SharedLogBudget(100)
        self.assertEqual(budget.take(50), 50)
        self.assertFalse(budget.truncated)

    def test_zero_remaining_budget_records_truncation(self):
        budget = SharedLogBudget(0)
        self.assertEqual(budget.take(10), 0)
        self.assertTrue(budget.truncated)


class ScratchResolutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_default_scratch_is_run_local(self):
        scratch, provenance = resolve_scratch_dir(None, run_dir=self.run_dir)
        self.assertEqual(scratch, (self.run_dir / "scratch").resolve())
        self.assertEqual(provenance, "default")
        self.assertTrue(scratch.is_dir())
        self.assertEqual(scratch.stat().st_mode & 0o777, 0o700)

    def test_explicit_external_scratch_directory_is_accepted(self):
        external = self.root / "external"
        external.mkdir()
        external.chmod(0o700)
        scratch, provenance = resolve_scratch_dir(external, run_dir=self.run_dir)
        self.assertEqual(scratch, external.resolve())
        self.assertEqual(provenance, "argument")

    def test_explicit_workspace_local_scratch_directory_is_accepted(self):
        workspace = self.root / "workspace" / "review-scratch"
        workspace.parent.mkdir()
        workspace.mkdir()
        workspace.chmod(0o700)
        scratch, provenance = resolve_scratch_dir(workspace, run_dir=self.run_dir)
        self.assertEqual(scratch, workspace.resolve())
        self.assertEqual(provenance, "argument")

    def test_nonexistent_leaf_is_created_beneath_an_existing_parent(self):
        leaf = self.root / "existing" / "leaf"
        leaf.parent.mkdir()
        scratch, _ = resolve_scratch_dir(leaf, run_dir=self.run_dir)
        self.assertTrue(scratch.is_dir())
        self.assertEqual(scratch.stat().st_mode & 0o777, 0o700)

    def test_missing_parent_is_refused(self):
        with self.assertRaises(BudgetError):
            resolve_scratch_dir(self.root / "no" / "such" / "leaf", run_dir=self.run_dir)

    def test_symlink_leaf_is_refused(self):
        target = self.root / "target"
        target.mkdir()
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaisesRegex(BudgetError, "symlink"):
            resolve_scratch_dir(link, run_dir=self.run_dir)

    def test_symlink_ancestor_is_refused(self):
        target = self.root / "target"
        target.mkdir()
        (target / "inner").mkdir()
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaisesRegex(BudgetError, "symlink"):
            resolve_scratch_dir(link / "inner", run_dir=self.run_dir)

    def test_nonempty_unowned_scratch_is_refused(self):
        external = self.root / "external"
        external.mkdir()
        external.chmod(0o700)
        (external / "someone-elses-file").write_text("keep me", encoding="utf-8")
        with self.assertRaisesRegex(BudgetError, "not empty"):
            resolve_scratch_dir(external, run_dir=self.run_dir)
        self.assertEqual(
            (external / "someone-elses-file").read_text(encoding="utf-8"), "keep me"
        )

    def test_nonempty_scratch_with_a_matching_ownership_marker_is_reused(self):
        external = self.root / "external"
        external.mkdir()
        external.chmod(0o700)
        first, _ = resolve_scratch_dir(external, run_dir=self.run_dir)
        (first / "leftover.txt").write_text("prior run", encoding="utf-8")
        again, provenance = resolve_scratch_dir(external, run_dir=self.run_dir)
        self.assertEqual(again, first)
        self.assertEqual(provenance, "argument")

    def test_world_writable_existing_scratch_is_refused(self):
        external = self.root / "world-writable"
        external.mkdir()
        external.chmod(0o777)
        with self.assertRaisesRegex(BudgetError, "permissions"):
            resolve_scratch_dir(external, run_dir=self.run_dir)

    def test_arbitrary_marker_contents_do_not_authorize_reuse(self):
        external = self.root / "forged"
        external.mkdir(mode=0o700)
        (external / ".delegate-to-claude-scratch.json").write_text(
            "not-json", encoding="utf-8"
        )
        (external / "payload").write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(BudgetError, "marker"):
            resolve_scratch_dir(external, run_dir=self.run_dir)

    def test_marker_is_bound_to_run_root_and_current_user(self):
        external = self.root / "bound"
        external.mkdir(mode=0o700)
        scratch, _ = resolve_scratch_dir(external, run_dir=self.run_dir)
        marker = json.loads(
            (scratch / ".delegate-to-claude-scratch.json").read_text(encoding="utf-8")
        )
        self.assertEqual(marker["run_id"], self.run_dir.name)
        self.assertEqual(marker["root"], str(scratch))
        if hasattr(os, "getuid"):
            self.assertEqual(marker["uid"], os.getuid())

    def test_a_file_where_a_directory_is_expected_is_refused(self):
        target = self.root / "not-a-dir"
        target.write_text("x", encoding="utf-8")
        with self.assertRaises(BudgetError):
            resolve_scratch_dir(target, run_dir=self.run_dir)


class ScratchWatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def test_watchdog_fires_once_when_sampled_size_crosses_the_threshold(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        fired: list[int] = []
        watchdog = ScratchWatchdog(
            [scratch], threshold_bytes=4096, on_exceed=fired.append, interval=0.02
        )
        watchdog.start()
        try:
            (scratch / "big.bin").write_bytes(b"x" * 8192)
            deadline = time.time() + 5
            while not fired and time.time() < deadline:
                time.sleep(0.02)
        finally:
            watchdog.stop()
        self.assertEqual(len(fired), 1)
        self.assertGreaterEqual(fired[0], 8192)
        self.assertTrue(watchdog.exceeded)

    def test_watchdog_stays_quiet_below_the_threshold_and_deletes_nothing(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        keep = scratch / "small.bin"
        keep.write_bytes(b"x" * 16)
        fired: list[int] = []
        watchdog = ScratchWatchdog(
            [scratch], threshold_bytes=1_000_000, on_exceed=fired.append, interval=0.02
        )
        watchdog.start()
        time.sleep(0.1)
        watchdog.stop()
        self.assertEqual(fired, [])
        self.assertFalse(watchdog.exceeded)
        self.assertTrue(keep.exists())

    def test_watchdog_counts_overlapping_roots_once(self):
        state = self.root / "state"
        nested = state / "scratch"
        nested.mkdir(parents=True)
        (nested / "a.bin").write_bytes(b"x" * 3000)
        samples: list[int] = []
        watchdog = ScratchWatchdog(
            [state, nested], threshold_bytes=1_000_000, on_exceed=samples.append, interval=0.02
        )
        self.assertEqual(watchdog.sample(), 3000)


if __name__ == "__main__":
    unittest.main()
