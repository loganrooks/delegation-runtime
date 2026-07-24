from __future__ import annotations

import unittest

from delegate_to_claude.profiles import (
    PINNED_READONLY_MCP_TOOLS,
    BROADER,
    MATCH,
    NARROWER,
    PROFILE_VERSION,
    UNKNOWN,
    ProfileError,
    canonical_profile_id,
    classify_manifest,
    expected_startup_tools,
    resolve_profile,
)


class ProfileResolverTests(unittest.TestCase):
    def test_readonly_review_alias_is_strict_and_warns(self):
        resolved = resolve_profile("readonly-review", None, (), (), (), ())
        self.assertEqual(resolved.profile_id, "strict-readonly")
        self.assertEqual(resolved.profile_requested, "readonly-review")
        self.assertEqual(resolved.permission_mode, "dontAsk")
        self.assertIn("deprecated", resolved.warning)

    def test_implementation_auto_rejects_conflicting_permission(self):
        with self.assertRaisesRegex(ProfileError, "implementation-auto.*auto"):
            resolve_profile("implementation-auto", "acceptEdits", (), (), (), ())

    def test_matching_permission_is_redundant_but_valid(self):
        resolved = resolve_profile("implementation-auto", "auto", (), (), (), ())
        self.assertEqual(resolved.permission_mode, "auto")

    def test_verified_review_requires_a_bounded_command(self):
        with self.assertRaisesRegex(ProfileError, "allowed-command"):
            resolve_profile("verified-review", None, (), (), (), ())

    def test_shell_composition_is_rejected(self):
        for value in ("python3 -m unittest; rm x", "pytest && curl x", "echo $(id)", "echo `id`"):
            with self.subTest(value=value), self.assertRaises(ProfileError):
                resolve_profile("verified-review", None, (), (), (), (value,))

    def test_extra_denies_narrow_without_duplicates(self):
        resolved = resolve_profile("strict-readonly", None, (), (), ("WebFetch", "CustomTool"), ())
        self.assertEqual(resolved.denied_tools.count("WebFetch"), 1)
        self.assertIn("CustomTool", resolved.denied_tools)

    def test_canonical_names_do_not_warn(self):
        for profile_id in (
            "strict-readonly",
            "verified-review",
            "artifact-review",
            "implementation",
            "implementation-auto",
        ):
            with self.subTest(profile_id=profile_id):
                commands = ("python3 -m unittest",) if profile_id in ("verified-review", "artifact-review") else ()
                permission = {
                    "implementation-auto": "auto",
                }.get(profile_id)
                resolved = resolve_profile(profile_id, permission, (), (), (), commands)
                self.assertIsNone(resolved.warning)
                self.assertEqual(resolved.profile_id, profile_id)
                self.assertEqual(resolved.profile_requested, profile_id)

    def test_exact_profile_snapshots(self):
        strict = resolve_profile("strict-readonly", None, (), (), (), ())
        self.assertEqual(strict.permission_mode, "dontAsk")
        self.assertEqual(strict.tools, ("Read", "Grep", "Glob", "Skill"))
        self.assertIn("Bash", strict.denied_tools)
        self.assertIn("Write", strict.denied_tools)
        self.assertIn("Edit", strict.denied_tools)
        self.assertIn("NotebookEdit", strict.denied_tools)
        self.assertIn("WebFetch", strict.denied_tools)
        self.assertIn("WebSearch", strict.denied_tools)
        self.assertIn("mcp__codebase-memory-mcp__delete_project", strict.denied_tools)
        self.assertEqual(strict.version, PROFILE_VERSION)

        verified = resolve_profile("verified-review", None, (), (), (), ("python3 -m unittest",))
        self.assertEqual(verified.permission_mode, "dontAsk")
        self.assertEqual(verified.tools, ("Read", "Grep", "Glob", "Skill", "Bash"))
        self.assertNotIn("Bash", verified.denied_tools)
        self.assertIn("Write", verified.denied_tools)
        self.assertIn("Edit", verified.denied_tools)

        artifact = resolve_profile("artifact-review", None, (), (), (), ("python3 -m unittest",))
        self.assertEqual(artifact.tools, verified.tools)
        self.assertEqual(artifact.denied_tools, verified.denied_tools)

        implementation = resolve_profile("implementation", "acceptEdits", (), (), (), ())
        self.assertEqual(implementation.permission_mode, "acceptEdits")
        self.assertEqual(implementation.tools, ("Read", "Grep", "Glob", "Skill", "Bash", "Write", "Edit"))
        self.assertNotIn("Write", implementation.denied_tools)
        self.assertNotIn("Edit", implementation.denied_tools)

        implementation_auto = resolve_profile("implementation-auto", "auto", (), (), (), ())
        self.assertEqual(implementation_auto.permission_mode, "auto")
        self.assertEqual(implementation_auto.tools, implementation.tools)

    def test_manifest_hash_is_stable_and_snapshot_specific(self):
        first = resolve_profile("strict-readonly", None, (), (), (), ())
        second = resolve_profile("strict-readonly", None, (), (), (), ())
        self.assertEqual(first.manifest_sha256, second.manifest_sha256)
        self.assertEqual(len(first.manifest_sha256), 64)
        verified = resolve_profile("verified-review", None, (), (), (), ("python3 -m unittest",))
        self.assertNotEqual(first.manifest_sha256, verified.manifest_sha256)

    def test_tool_narrowing_accepted_exact_and_subset(self):
        exact = resolve_profile("strict-readonly", None, ("Read", "Grep", "Glob", "Skill"), (), (), ())
        self.assertEqual(exact.tools, ("Read", "Grep", "Glob", "Skill"))
        narrow = resolve_profile("strict-readonly", None, ("Read", "Grep"), (), (), ())
        self.assertEqual(narrow.tools, ("Read", "Grep"))

    def test_tool_broadening_is_rejected(self):
        with self.assertRaises(ProfileError):
            resolve_profile("strict-readonly", None, ("Read", "Bash"), (), (), ())
        with self.assertRaises(ProfileError):
            resolve_profile("strict-readonly", None, ("Read", "CustomTool"), (), (), ())

    def test_allowed_tool_cannot_include_a_denied_tool(self):
        with self.assertRaises(ProfileError):
            resolve_profile("strict-readonly", None, (), ("Bash",), (), ())

    def test_unknown_mcp_tool_is_rejected_by_profiled_modes(self):
        with self.assertRaisesRegex(ProfileError, "pinned read-only"):
            resolve_profile(
                "strict-readonly",
                None,
                (),
                ("mcp__unknown__destructive_operation",),
                (),
                (),
            )

    def test_only_pinned_codebase_memory_mcp_tools_are_admitted(self):
        for tool in PINNED_READONLY_MCP_TOOLS:
            with self.subTest(tool=tool):
                resolved = resolve_profile(
                    "strict-readonly", None, (), (tool,), (), ()
                )
                self.assertIn(tool, resolved.allowed_tools)

    def test_unselected_pinned_mcp_tools_are_explicitly_denied(self):
        selected = "mcp__codebase-memory-mcp__list_projects"
        resolved = resolve_profile(
            "strict-readonly", None, (), (selected,), (), ()
        )
        self.assertNotIn(selected, resolved.denied_tools)
        self.assertTrue(
            set(PINNED_READONLY_MCP_TOOLS) - {selected}
            <= set(resolved.denied_tools)
        )

    def test_real_init_shape_with_unselected_pinned_mcp_exposure_is_not_broader(self):
        selected = "mcp__codebase-memory-mcp__list_projects"
        resolved = resolve_profile(
            "strict-readonly", None, (), (selected,), (), ()
        )
        observed = tuple(resolved.tools) + PINNED_READONLY_MCP_TOOLS
        status, unexpected = classify_manifest(
            resolved.expected_tools,
            resolved.exposed_but_denied,
            observed,
        )
        self.assertEqual(status, MATCH)
        self.assertEqual(unexpected, ())

    def test_allowed_command_converts_to_bash_rule(self):
        resolved = resolve_profile(
            "verified-review", None, (), (), (), ("python3 -m unittest discover",)
        )
        self.assertEqual(resolved.allowed_commands, ("python3 -m unittest discover",))
        self.assertIn("Bash(python3 -m unittest discover)", resolved.allowed_tools)

    def test_allowed_command_rejected_for_profile_without_bash(self):
        with self.assertRaises(ProfileError):
            resolve_profile("strict-readonly", None, (), (), (), ("python3 -m unittest",))

    def test_invalid_profile_id_raises(self):
        with self.assertRaises(ProfileError):
            resolve_profile("not-a-real-profile", None, (), (), (), ())
        with self.assertRaises(ProfileError):
            canonical_profile_id("not-a-real-profile")

    def test_canonical_profile_id_resolves_alias(self):
        self.assertEqual(canonical_profile_id("readonly-review"), "strict-readonly")
        self.assertEqual(canonical_profile_id("strict-readonly"), "strict-readonly")


class ProfileContractVersionThreeTests(unittest.TestCase):
    def test_contract_version_is_three(self):
        self.assertEqual(PROFILE_VERSION, 3)

    def test_descendant_spawning_is_denied_under_both_identifiers(self):
        strict = resolve_profile("strict-readonly", None, (), (), (), ())
        self.assertIn("Task", strict.denied_tools)
        self.assertIn("Agent", strict.denied_tools)
        implementation = resolve_profile("implementation", "acceptEdits", (), (), (), ())
        self.assertIn("Task", implementation.denied_tools)
        self.assertIn("Agent", implementation.denied_tools)

    def test_profile_capability_requirements_are_declared(self):
        strict = resolve_profile("strict-readonly", None, (), (), (), ())
        self.assertFalse(strict.requires_native_sandbox)
        self.assertFalse(strict.uses_scratch_cwd)
        verified = resolve_profile("verified-review", None, (), (), (), ("pytest -q",))
        self.assertTrue(verified.requires_native_sandbox)
        self.assertTrue(verified.uses_scratch_cwd)
        self.assertFalse(verified.requires_artifact_output)
        artifact = resolve_profile("artifact-review", None, (), (), (), ("pytest -q",))
        self.assertTrue(artifact.requires_artifact_output)
        self.assertTrue(artifact.uses_scratch_cwd)
        implementation = resolve_profile("implementation", "acceptEdits", (), (), (), ())
        self.assertTrue(implementation.requires_native_sandbox)
        self.assertTrue(implementation.requires_owned_paths)
        self.assertFalse(implementation.uses_scratch_cwd)
        auto = resolve_profile("implementation-auto", "auto", (), (), (), ())
        self.assertTrue(auto.requires_auto_mode)
        self.assertFalse(implementation.requires_auto_mode)


class ExpectedStartupToolTests(unittest.TestCase):
    def test_requested_builtins_are_expected(self):
        self.assertEqual(
            expected_startup_tools(("Read", "Grep"), ()), ("Grep", "Read")
        )

    def test_explicit_mcp_identifiers_are_expected(self):
        expected = expected_startup_tools(
            ("Read",), ("mcp__codebase-memory-mcp__search_graph",)
        )
        self.assertIn("mcp__codebase-memory-mcp__search_graph", expected)

    def test_permission_rule_normalizes_only_to_a_requested_base_tool(self):
        with_bash = expected_startup_tools(("Read", "Bash"), ("Bash(pytest -q)",))
        self.assertIn("Bash", with_bash)
        self.assertNotIn("Bash(pytest -q)", with_bash)
        without_bash = expected_startup_tools(("Read",), ("Bash(pytest -q)",))
        self.assertNotIn("Bash", without_bash)

    def test_expected_tools_are_sorted_and_deduplicated(self):
        expected = expected_startup_tools(("Read", "Read", "Bash"), ("Bash(pytest -q)", "Bash"))
        self.assertEqual(expected, ("Bash", "Read"))


class ManifestClassificationTests(unittest.TestCase):
    def test_absent_init_event_is_unknown(self):
        status, unexpected = classify_manifest(("Read",), ("Bash",), None)
        self.assertEqual(status, UNKNOWN)
        self.assertEqual(unexpected, ())

    def test_omitted_tool_list_is_unknown_not_empty(self):
        status, _ = classify_manifest(("Read",), (), None)
        self.assertEqual(status, UNKNOWN)

    def test_known_empty_list_is_narrower(self):
        status, unexpected = classify_manifest(("Read", "Grep"), (), ())
        self.assertEqual(status, NARROWER)
        self.assertEqual(unexpected, ())

    def test_exact_observation_is_match(self):
        status, _ = classify_manifest(("Read", "Grep"), (), ("Grep", "Read"))
        self.assertEqual(status, MATCH)

    def test_subset_observation_is_narrower(self):
        status, _ = classify_manifest(("Read", "Grep"), (), ("Read",))
        self.assertEqual(status, NARROWER)

    def test_extra_tool_is_broader_and_named(self):
        status, unexpected = classify_manifest(("Read",), (), ("Read", "SurpriseTool"))
        self.assertEqual(status, BROADER)
        self.assertEqual(unexpected, ("SurpriseTool",))

    def test_exposed_but_denied_tool_is_not_broadening_and_not_allowed(self):
        status, unexpected = classify_manifest(("Read",), ("Bash",), ("Read", "Bash"))
        self.assertEqual(status, MATCH)
        self.assertEqual(unexpected, ())

    def test_denied_exposure_does_not_satisfy_an_expected_allowed_tool(self):
        status, _ = classify_manifest(("Read", "Grep"), ("Bash",), ("Read", "Bash"))
        self.assertEqual(status, NARROWER)


if __name__ == "__main__":
    unittest.main()
