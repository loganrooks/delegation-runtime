from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from delegate_to_claude.reconcile import (
    ReconcileError,
    reconcile,
    reconcile_repository,
    repository_fingerprint,
    require_git_repo,
    validate_owned_path,
    worktree_fingerprint,
)


class GitFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Adapter Test")
        (self.project / "src").mkdir()
        self.write("src/owned.py", "owned original\n")
        self.write("src/sibling.py", "sibling original\n")
        self.write("README.md", "readme original\n")
        self.git("add", "-A")
        self.git("commit", "-qm", "baseline")

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.project), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout

    def write(self, relpath: str, content: str) -> Path:
        path = self.project / relpath
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def classify(self, owned=("src/owned.py",), scratch=(), baseline=None):
        final = worktree_fingerprint(self.project)
        return reconcile(
            baseline if baseline is not None else self.baseline,
            final,
            owned_paths=owned,
            scratch_relpaths=scratch,
        )


class GitPreflightTests(GitFixture):
    def test_git_project_root_is_accepted(self):
        self.assertEqual(require_git_repo(self.project), self.project.resolve())

    def test_non_git_project_root_fails_preflight(self):
        plain = self.root / "plain"
        plain.mkdir()
        with self.assertRaisesRegex(ReconcileError, "git"):
            require_git_repo(plain)

    def test_owned_paths_are_normalized_relative_to_the_project(self):
        self.assertEqual(validate_owned_path(self.project, "src/owned.py"), "src/owned.py")
        self.assertEqual(validate_owned_path(self.project, "./src"), "src")
        self.assertEqual(
            validate_owned_path(self.project, str(self.project / "src" / "owned.py")),
            "src/owned.py",
        )

    def test_owned_path_outside_the_project_is_refused(self):
        with self.assertRaisesRegex(ReconcileError, "outside"):
            validate_owned_path(self.project, "../elsewhere")
        with self.assertRaisesRegex(ReconcileError, "outside"):
            validate_owned_path(self.project, str(self.root / "elsewhere"))

    def test_symlinked_owned_path_cannot_escape_the_project_root(self):
        outside = self.root / "outside"
        outside.mkdir()
        (self.project / "escape").symlink_to(outside)
        with self.assertRaisesRegex(ReconcileError, "outside"):
            validate_owned_path(self.project, "escape")


class CleanWorktreeReconciliationTests(GitFixture):
    def setUp(self):
        super().setUp()
        self.baseline = worktree_fingerprint(self.project)

    def test_a_clean_baseline_has_no_git_visible_changes(self):
        self.assertEqual(self.baseline, {})

    def test_a_clean_owned_file_edit_succeeds(self):
        self.write("src/owned.py", "owned edited\n")
        report = self.classify()
        self.assertEqual(report["owned"], ["src/owned.py"])
        self.assertEqual(report["undeclared"], [])
        self.assertTrue(report["reconciled"])

    def test_directory_ownership_covers_files_beneath_it(self):
        self.write("src/owned.py", "edited\n")
        self.write("src/sibling.py", "edited too\n")
        report = self.classify(owned=("src",))
        self.assertEqual(report["owned"], ["src/owned.py", "src/sibling.py"])
        self.assertEqual(report["undeclared"], [])

    def test_exact_file_ownership_does_not_cover_a_sibling(self):
        self.write("src/sibling.py", "edited\n")
        report = self.classify(owned=("src/owned.py",))
        self.assertEqual(report["undeclared"], ["src/sibling.py"])
        self.assertFalse(report["reconciled"])

    def test_an_unowned_tracked_edit_fails(self):
        self.write("README.md", "readme edited\n")
        self.assertEqual(self.classify()["undeclared"], ["README.md"])

    def test_an_unowned_delete_fails(self):
        (self.project / "README.md").unlink()
        self.assertEqual(self.classify()["undeclared"], ["README.md"])

    def test_an_unowned_rename_fails_at_both_ends(self):
        self.git("mv", "README.md", "RENAMED.md")
        self.assertEqual(
            self.classify()["undeclared"], ["README.md", "RENAMED.md"]
        )

    def test_an_unowned_untracked_file_fails(self):
        self.write("stray.txt", "stray\n")
        self.assertEqual(self.classify()["undeclared"], ["stray.txt"])

    def test_declared_scratch_changes_do_not_count_as_product_edits(self):
        self.write("review-scratch/notes.txt", "scratch notes\n")
        report = self.classify(scratch=("review-scratch",))
        self.assertEqual(report["scratch"], ["review-scratch/notes.txt"])
        self.assertEqual(report["undeclared"], [])
        self.assertTrue(report["reconciled"])

    def test_reconciliation_reads_git_state_without_mutating_it(self):
        self.write("README.md", "readme edited\n")
        before = self.git("status", "--porcelain")
        self.classify()
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.assertEqual(
            (self.project / "README.md").read_text(encoding="utf-8"), "readme edited\n"
        )


class DirtyWorktreeReconciliationTests(GitFixture):
    def test_pre_existing_dirty_files_are_not_attributed_to_the_worker(self):
        self.write("README.md", "user edit before launch\n")
        self.write("user-untracked.txt", "user scratch\n")
        baseline = worktree_fingerprint(self.project)
        self.write("src/owned.py", "worker edit\n")
        report = self.classify(baseline=baseline)
        self.assertEqual(report["owned"], ["src/owned.py"])
        self.assertEqual(report["undeclared"], [])
        self.assertEqual(
            report["pre_existing_unchanged"], ["README.md", "user-untracked.txt"]
        )
        self.assertTrue(report["reconciled"])

    def test_a_worker_change_to_an_already_dirty_unowned_file_is_detected(self):
        self.write("README.md", "user edit before launch\n")
        baseline = worktree_fingerprint(self.project)
        self.write("README.md", "worker overwrote the user edit\n")
        report = self.classify(baseline=baseline)
        self.assertEqual(report["undeclared"], ["README.md"])
        self.assertFalse(report["reconciled"])

    def test_a_worker_reverting_a_pre_existing_dirty_file_is_detected(self):
        self.write("README.md", "user edit before launch\n")
        baseline = worktree_fingerprint(self.project)
        self.write("README.md", "readme original\n")
        report = self.classify(baseline=baseline)
        self.assertEqual(report["undeclared"], ["README.md"])

    def test_staged_user_changes_are_preserved_and_not_attributed(self):
        self.write("README.md", "staged user change\n")
        self.git("add", "README.md")
        baseline = worktree_fingerprint(self.project)
        self.assertIn("README.md", baseline)
        self.write("src/owned.py", "worker edit\n")
        report = self.classify(baseline=baseline)
        self.assertEqual(report["pre_existing_unchanged"], ["README.md"])
        self.assertEqual(report["undeclared"], [])
        self.assertIn("M", self.git("status", "--porcelain", "README.md"))
        self.assertEqual(
            (self.project / "README.md").read_text(encoding="utf-8"),
            "staged user change\n",
        )

    def test_a_worker_editing_an_already_dirty_owned_file_stays_owned(self):
        self.write("src/owned.py", "user edit before launch\n")
        baseline = worktree_fingerprint(self.project)
        self.write("src/owned.py", "worker edit\n")
        report = self.classify(baseline=baseline)
        self.assertEqual(report["owned"], ["src/owned.py"])
        self.assertTrue(report["reconciled"])

    def test_baseline_records_content_hashes_for_already_dirty_paths(self):
        self.write("README.md", "user edit before launch\n")
        baseline = worktree_fingerprint(self.project)
        self.assertEqual(len(baseline["README.md"]["sha256"]), 64)

    def test_baseline_excludes_declared_scratch_payloads(self):
        self.write("review-scratch/big.txt", "scratch payload\n")
        baseline = worktree_fingerprint(
            self.project, exclude_relpaths=("review-scratch",)
        )
        self.assertNotIn("review-scratch/big.txt", baseline)

    def test_baseline_never_fingerprints_git_internals(self):
        self.write("src/owned.py", "edited\n")
        baseline = worktree_fingerprint(self.project)
        self.assertFalse([path for path in baseline if path.startswith(".git/")])

    def test_large_dirty_file_is_hashed_not_reduced_to_its_size(self):
        path = self.write("large.bin", "a" * (9 * 1024 * 1024))
        baseline = worktree_fingerprint(self.project)
        path.write_text("b" * (9 * 1024 * 1024), encoding="utf-8")
        final = worktree_fingerprint(self.project)
        self.assertEqual(len(baseline["large.bin"]["sha256"]), 64)
        self.assertNotEqual(
            baseline["large.bin"]["sha256"], final["large.bin"]["sha256"]
        )


class RepositoryControlReconciliationTests(GitFixture):
    def setUp(self):
        super().setUp()
        self.baseline = repository_fingerprint(self.project)

    def classify(self):
        return reconcile_repository(
            self.baseline,
            repository_fingerprint(self.project),
            owned_paths=("src/owned.py",),
        )

    def test_edit_and_commit_cannot_hide_an_owned_file_change(self):
        self.write("src/owned.py", "committed by worker\n")
        self.git("add", "src/owned.py")
        self.git("commit", "-qm", "worker commit")
        report = self.classify()
        self.assertFalse(report["reconciled"])
        self.assertIn("git:HEAD", report["control_changes"])
        self.assertIn("git:index", report["control_changes"])

    def test_index_mutation_is_a_control_state_violation(self):
        self.write("src/owned.py", "staged by worker\n")
        self.git("add", "src/owned.py")
        report = self.classify()
        self.assertFalse(report["reconciled"])
        self.assertIn("git:index", report["control_changes"])

    def test_repository_config_mutation_is_a_control_state_violation(self):
        self.git("config", "worker.changed", "true")
        report = self.classify()
        self.assertFalse(report["reconciled"])
        self.assertIn("git:config", report["control_changes"])

    def test_hook_installation_is_a_control_state_violation(self):
        hook = self.project / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        report = self.classify()
        self.assertFalse(report["reconciled"])
        self.assertIn("git:hooks", report["control_changes"])

    def test_new_ignored_installation_side_effect_is_rejected(self):
        self.write(".gitignore", "node_modules/\n")
        self.git("add", ".gitignore")
        self.git("commit", "-qm", "ignore dependencies")
        self.baseline = repository_fingerprint(self.project)
        self.write("node_modules/pkg/index.js", "installed\n")
        report = self.classify()
        self.assertFalse(report["reconciled"])
        self.assertEqual(report["ignored_changes"], ["node_modules/pkg/index.js"])

    def test_new_empty_ignored_directory_is_rejected(self):
        self.write(".gitignore", "build/\n")
        self.git("add", ".gitignore")
        self.git("commit", "-qm", "ignore build")
        self.baseline = repository_fingerprint(self.project)
        (self.project / "build").mkdir()
        report = self.classify()
        self.assertFalse(report["reconciled"])
        self.assertEqual(report["ignored_changes"], ["build/"])

    def test_preexisting_ignored_file_mutation_is_rejected(self):
        self.write(".gitignore", "build/\n")
        self.git("add", ".gitignore")
        self.git("commit", "-qm", "ignore build")
        self.write("build/cache.bin", "before\n")
        self.baseline = repository_fingerprint(self.project)
        self.write("build/cache.bin", "after\n")
        report = self.classify()
        self.assertFalse(report["reconciled"])
        self.assertEqual(report["ignored_changes"], ["build/cache.bin"])


if __name__ == "__main__":
    unittest.main()
