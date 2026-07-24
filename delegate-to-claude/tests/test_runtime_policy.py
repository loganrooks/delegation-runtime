from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from delegate_to_claude.runtime_policy import (
    REQUIRED_SANDBOX_FLAGS,
    SANDBOX_REQUEST,
    PolicyError,
    build_runtime_policy,
    missing_capabilities,
    policy_mode_for_profile,
)


class SandboxRequestShapeTests(unittest.TestCase):
    def test_requested_sandbox_block_matches_the_locked_contract(self):
        self.assertEqual(
            SANDBOX_REQUEST,
            {
                "enabled": True,
                "failIfUnavailable": True,
                "autoAllowBashIfSandboxed": False,
                "allowUnsandboxedCommands": False,
                "excludedCommands": [],
                "network": {"allowedDomains": [], "deniedDomains": ["*"]},
            },
        )

    def test_profile_to_policy_mode_mapping(self):
        self.assertEqual(policy_mode_for_profile("strict-readonly"), "strict")
        self.assertEqual(policy_mode_for_profile("verified-review"), "verified")
        self.assertEqual(policy_mode_for_profile("artifact-review"), "artifact")
        self.assertEqual(policy_mode_for_profile("implementation"), "implementation")
        self.assertEqual(policy_mode_for_profile("implementation-auto"), "implementation")
        self.assertEqual(policy_mode_for_profile(None), "custom")


class RuntimePolicyBuilderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.settings = self.root / "settings.json"
        self.mcp = self.root / "mcp.json"
        self.mcp.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")

    def tearDown(self):
        self.temp.cleanup()

    def build(self, mode: str, **kwargs):
        defaults = dict(
            mode=mode,
            permission_mode="dontAsk",
            tools=("Read", "Grep"),
            allowed_tools=(),
            denied_tools=("Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch", "Agent", "Task"),
            settings_path=self.settings,
            mcp_config_paths=(self.mcp,),
            help_text=" ".join(REQUIRED_SANDBOX_FLAGS) + " --setting-sources",
        )
        defaults.update(kwargs)
        return build_runtime_policy(**defaults)

    def test_verified_and_artifact_request_the_fail_closed_sandbox(self):
        for mode in ("verified", "artifact"):
            with self.subTest(mode=mode):
                policy = self.build(mode, tools=("Read", "Bash"), allowed_tools=("Bash(pytest -q)",))
                self.assertTrue(policy.requires_native_sandbox)
                self.assertEqual(policy.settings["sandbox"], SANDBOX_REQUEST)
                self.assertEqual(policy.sandbox_status, "requested-unproven")

    def test_implementation_requests_sandbox_while_retaining_project_writes(self):
        scratch = self.root / "impl-scratch"
        scratch.mkdir()
        project = self.root / "project"
        project.mkdir()
        policy = self.build(
            "implementation",
            permission_mode="acceptEdits",
            tools=("Read", "Bash", "Write", "Edit"),
            denied_tools=("WebFetch", "WebSearch", "Agent", "Task"),
            scratch_dir=scratch,
            project_root=project,
        )
        self.assertTrue(policy.requires_native_sandbox)
        self.assertFalse(policy.settings["sandbox"]["allowUnsandboxedCommands"])
        self.assertEqual(policy.settings["sandbox"]["network"]["deniedDomains"], ["*"])
        self.assertNotIn("Write", policy.settings["permissions"]["deny"])
        self.assertNotIn("Edit", policy.settings["permissions"]["deny"])
        self.assertIn(
            str(scratch.resolve()),
            policy.settings["sandbox"]["filesystem"]["allowWrite"],
        )
        self.assertIn(
            str((project / ".git").resolve()),
            policy.settings["sandbox"]["filesystem"]["denyWrite"],
        )
        self.assertEqual(policy.env["TMPDIR"], str(scratch))

    def test_strict_denies_bash_and_requests_no_sandbox(self):
        policy = self.build("strict", denied_tools=("Bash", "Write", "Edit"))
        self.assertFalse(policy.requires_native_sandbox)
        self.assertNotIn("sandbox", policy.settings)
        self.assertEqual(policy.sandbox_status, "not-requested")
        self.assertIn("Bash", policy.settings["permissions"]["deny"])

    def test_custom_mode_requests_no_sandbox_and_no_profile_permissions_claim(self):
        policy = self.build("custom", permission_mode="acceptEdits")
        self.assertFalse(policy.requires_native_sandbox)
        self.assertEqual(policy.sandbox_status, "not-requested")

    def test_write_edit_notebookedit_web_and_descendants_stay_denied_for_reviews(self):
        policy = self.build("verified", tools=("Read", "Bash"), allowed_tools=("Bash(pytest -q)",))
        deny = policy.settings["permissions"]["deny"]
        for tool in ("Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch", "Agent", "Task"):
            self.assertIn(tool, deny)

    def test_exact_commands_are_allowed_without_auto_approving_arbitrary_bash(self):
        policy = self.build("verified", tools=("Read", "Bash"), allowed_tools=("Bash(pytest -q)",))
        allow = policy.settings["permissions"]["allow"]
        self.assertIn("Bash(pytest -q)", allow)
        self.assertNotIn("Bash", allow)
        self.assertFalse(policy.settings["sandbox"]["autoAllowBashIfSandboxed"])

    def test_mcp_configuration_is_declared_hashed_and_strict(self):
        policy = self.build("verified", tools=("Read", "Bash"), allowed_tools=("Bash(pytest -q)",))
        self.assertIn("--strict-mcp-config", policy.cli_args)
        self.assertIn("--mcp-config", policy.cli_args)
        self.assertIn(str(self.mcp), policy.cli_args)
        self.assertEqual(len(policy.mcp_config_hashes), 1)
        path, digest = policy.mcp_config_hashes[0]
        self.assertEqual(path, str(self.mcp))
        self.assertEqual(len(digest), 64)

    def test_mcp_hashes_carry_no_configuration_contents(self):
        executable = self.root / "codebase-memory-mcp-secret-test"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        secret = self.root / "secret-mcp.json"
        secret.write_text(
            json.dumps({
                "mcpServers": {
                    "codebase-memory-mcp": {
                        "command": str(executable),
                        "description": "SUPER-SECRET-VALUE",
                    }
                }
            }),
            encoding="utf-8",
        )
        policy = self.build(
            "verified",
            tools=("Read", "Bash"),
            allowed_tools=(
                "Bash(pytest -q)",
                "mcp__codebase-memory-mcp__search_graph",
            ),
            mcp_config_paths=(secret,),
        )
        self.assertNotIn("SUPER-SECRET-VALUE", json.dumps(policy.mcp_config_hashes))
        self.assertNotIn("SUPER-SECRET-VALUE", json.dumps(policy.settings))

    def test_allowed_mcp_tool_without_a_declared_server_is_a_prelaunch_error(self):
        with self.assertRaisesRegex(PolicyError, "mcp"):
            self.build(
                "strict",
                allowed_tools=("mcp__codebase-memory-mcp__search_graph",),
                mcp_config_paths=(),
            )

    def test_profiled_mcp_requires_an_absolute_local_executable(self):
        relative = self.root / "relative-mcp.json"
        relative.write_text(
            json.dumps({
                "mcpServers": {
                    "codebase-memory-mcp": {"command": "codebase-memory-mcp"}
                }
            }),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(PolicyError, "absolute local executable"):
            self.build(
                "strict",
                allowed_tools=("mcp__codebase-memory-mcp__search_graph",),
                mcp_config_paths=(relative,),
            )

    def test_profiled_mcp_pins_the_local_executable_hash(self):
        executable = self.root / "codebase-memory-mcp"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        local = self.root / "local-mcp.json"
        local.write_text(
            json.dumps({
                "mcpServers": {
                    "codebase-memory-mcp": {"command": str(executable)}
                }
            }),
            encoding="utf-8",
        )
        policy = self.build(
            "strict",
            allowed_tools=("mcp__codebase-memory-mcp__search_graph",),
            mcp_config_paths=(local,),
        )
        self.assertEqual(policy.mcp_executable_hashes[0][0], "codebase-memory-mcp")
        self.assertEqual(len(policy.mcp_executable_hashes[0][1]), 64)

    def test_settings_path_is_passed_through(self):
        policy = self.build("strict")
        self.assertIn("--settings", policy.cli_args)
        self.assertIn(str(self.settings), policy.cli_args)

    def test_setting_sources_are_suppressed_only_when_advertised(self):
        supported = self.build("strict")
        self.assertIn("--setting-sources", supported.cli_args)
        self.assertTrue(supported.settings_sources_suppressed)
        unsupported = self.build("strict", help_text=" ".join(REQUIRED_SANDBOX_FLAGS))
        self.assertNotIn("--setting-sources", unsupported.cli_args)
        self.assertFalse(unsupported.settings_sources_suppressed)

    def test_scratch_environment_is_redirected_beneath_the_scratch_root(self):
        scratch = self.root / "scratch"
        scratch.mkdir()
        policy = self.build(
            "verified",
            tools=("Read", "Bash"),
            allowed_tools=("Bash(pytest -q)",),
            scratch_dir=scratch,
        )
        for name in ("TMPDIR", "TMP", "TEMP", "XDG_CACHE_HOME"):
            self.assertTrue(policy.env[name].startswith(str(scratch)), name)
        self.assertEqual(policy.env["PYTHONDONTWRITEBYTECODE"], "1")

    def test_policy_hash_is_deterministic_and_ignores_run_local_paths(self):
        first = self.build("verified", tools=("Read", "Bash"), allowed_tools=("Bash(pytest -q)",))
        second = self.build("verified", tools=("Read", "Bash"), allowed_tools=("Bash(pytest -q)",))
        self.assertEqual(first.policy_sha256, second.policy_sha256)
        self.assertEqual(len(first.policy_sha256), 64)
        moved = self.build(
            "verified",
            tools=("Read", "Bash"),
            allowed_tools=("Bash(pytest -q)",),
            settings_path=self.root / "elsewhere.json",
        )
        self.assertEqual(first.policy_sha256, moved.policy_sha256)
        widened = self.build("verified", tools=("Read", "Bash", "Glob"), allowed_tools=("Bash(pytest -q)",))
        self.assertNotEqual(first.policy_sha256, widened.policy_sha256)


class CapabilityPreflightTests(unittest.TestCase):
    def test_all_required_flags_present_yields_no_missing_capability(self):
        help_text = " ".join(REQUIRED_SANDBOX_FLAGS)
        self.assertEqual(missing_capabilities(help_text, requires_native_sandbox=True), ())

    def test_absent_flag_is_reported_when_the_sandbox_is_required(self):
        help_text = "--settings --mcp-config"
        missing = missing_capabilities(help_text, requires_native_sandbox=True)
        self.assertIn("--strict-mcp-config", missing)

    def test_flags_are_not_required_when_the_sandbox_is_not_required(self):
        self.assertEqual(missing_capabilities("", requires_native_sandbox=False), ())


if __name__ == "__main__":
    unittest.main()
