from __future__ import annotations

import copy
import os
import subprocess
import sys
import unittest
from pathlib import Path

from delegation_policy import (
    PolicyValidationError,
    canonical_document,
    normalize_policy,
)

SHARED_SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"


class ImportBoundaryTests(unittest.TestCase):
    def test_shared_package_imports_without_claude_adapter_on_path(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(SHARED_SCRIPTS_DIR)
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import delegation_policy, sys; "
                "assert not any(n == 'delegate_to_claude' or n.startswith('delegate_to_claude.') "
                "for n in sys.modules), 'Claude adapter module imported'",
            ],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class SchemaVersionDispatchTests(unittest.TestCase):
    def test_unknown_schema_version_is_rejected_by_dispatch(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"schema_version": 99})


class DefaultsTests(unittest.TestCase):
    def test_empty_authority_fields_default_to_deny_or_unavailable(self):
        policy = normalize_policy({})
        document = policy.document
        self.assertEqual(document["filesystem"]["defaults"], {"read": "deny", "write": "deny"})
        self.assertEqual(document["mcp"]["mode"], "deny")
        self.assertEqual(document["commands"]["mode"], "deny")
        self.assertEqual(document["network"]["subprocess"], "deny")
        self.assertEqual(document["network"]["mcp_open_world"], "deny")
        self.assertEqual(document["host_effects"]["mode"], "deny")
        self.assertEqual(document["git"]["mutation"], "deny")
        self.assertEqual(document["installation"]["mode"], "deny")
        self.assertEqual(document["descendants"]["mode"], "deny")
        self.assertEqual(
            document["resources"]["memory_bytes"], {"mode": "unavailable", "value": None}
        )
        self.assertEqual(policy.authority_grants, frozenset())
        self.assertEqual(policy.authority_denies, frozenset())


class FieldRejectionTests(unittest.TestCase):
    def test_unknown_top_level_and_nested_fields_are_rejected(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"not_a_real_section": {}})
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"filesystem": {"unknown_nested_field": True}})

    def test_invalid_notice_and_confirmation_modes_are_rejected(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"notices": {"profile_transition": "sometimes"}})
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"confirmation": {"authority_expansion": "sometimes"}})

    def test_confirmation_once_is_rejected(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"confirmation": {"authority_expansion": "once"}})


class FilesystemRuleTests(unittest.TestCase):
    def test_read_and_write_rules_are_independent(self):
        policy = normalize_policy({
            "filesystem": {
                "roots": {"project": {"kind": "project", "binding": "/tmp/project-a"}},
                "rules": [
                    {"operations": ["read"], "scope": "project", "effect": "allow"},
                ],
            }
        })
        self.assertIn("filesystem.read:project", policy.authority_grants)
        self.assertNotIn("filesystem.write:project", policy.authority_grants)

    def test_allow_rule_requires_declared_scope(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({
                "filesystem": {
                    "rules": [
                        {"operations": ["read"], "scope": "undeclared", "effect": "allow"},
                    ],
                }
            })
        with self.assertRaises(PolicyValidationError):
            normalize_policy({
                "filesystem": {
                    "rules": [
                        {"operations": ["read"], "path": "/tmp/raw", "effect": "allow"},
                    ],
                }
            })

    def test_raw_deny_requires_stable_rule_id_and_private_binding(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({
                "filesystem": {
                    "rules": [
                        {"operations": ["read", "write"], "path": "/root/.ssh", "effect": "hard-deny"},
                    ],
                }
            })
        policy = normalize_policy({
            "filesystem": {
                "rules": [
                    {
                        "operations": ["read", "write"],
                        "path": "/root/.ssh",
                        "effect": "hard-deny",
                        "rule_id": "protect-credentials",
                    },
                ],
            }
        })
        self.assertIn("filesystem.read.deny:protect-credentials", policy.authority_denies)
        self.assertIn("filesystem.write.deny:protect-credentials", policy.authority_denies)
        binding = next(b for b in policy.private_bindings if b.binding_id == "protect-credentials")
        self.assertEqual(binding.resolved_path, Path("/root/.ssh"))


class IdentityHashTests(unittest.TestCase):
    def _base(self, binding_path: str) -> dict:
        return {
            "filesystem": {
                "roots": {"project": {"kind": "project", "binding": binding_path}},
                "rules": [
                    {"operations": ["read"], "scope": "project", "effect": "allow"},
                ],
            }
        }

    def test_same_policy_different_absolute_bindings_has_same_semantic_and_authority_hashes(self):
        a = normalize_policy(self._base("/tmp/one"))
        b = normalize_policy(self._base("/tmp/two"))
        self.assertEqual(a.semantic_sha256, b.semantic_sha256)
        self.assertEqual(a.authority_sha256, b.authority_sha256)

    def test_changed_root_roles_change_both_hashes(self):
        a = normalize_policy(self._base("/tmp/one"))
        raw = self._base("/tmp/one")
        raw["filesystem"]["roots"]["project"]["kind"] = "external"
        b = normalize_policy(raw)
        self.assertNotEqual(a.semantic_sha256, b.semantic_sha256)
        self.assertNotEqual(a.authority_sha256, b.authority_sha256)

    def test_binding_identity_stays_private_and_out_of_explainable_document(self):
        policy = normalize_policy(self._base("/tmp/private-sentinel"))
        document = canonical_document(policy)
        import json
        rendered = json.dumps(document, sort_keys=True)
        self.assertNotIn("/tmp/private-sentinel", rendered)
        self.assertEqual(document["filesystem"]["roots"]["project"]["binding"], "bound")

    def test_notice_change_changes_semantic_but_not_authority_hash(self):
        a = normalize_policy({})
        b = normalize_policy({"notices": {"profile_transition": "never"}})
        self.assertNotEqual(a.semantic_sha256, b.semantic_sha256)
        self.assertEqual(a.authority_sha256, b.authority_sha256)
        self.assertEqual(a.authority_grants, b.authority_grants)
        self.assertEqual(a.authority_denies, b.authority_denies)

    def _command_template(self, argv):
        return {
            "id": "adapter-tests",
            "revision": 1,
            "argv": argv,
            "cwd_scope": "project",
            "environment": {"fixed": {}, "pass": []},
            "stdin": "closed",
            "write_scopes": ["scratch"],
            "wall_time_seconds": 180,
            "shared_log_bytes": 16777216,
            "per_file_bytes": 8388608,
            "network": {"mode": "deny", "destinations": []},
            "sandbox": "required",
            "evidence_id": "runner-adapter-tests-v1",
        }

    def _command_policy(self, argv):
        return {
            "filesystem": {
                "roots": {
                    "project": {"kind": "project", "binding": "/tmp/project"},
                    "scratch": {"kind": "scratch", "binding": "/tmp/scratch"},
                },
            },
            "commands": {"mode": "selected", "templates": [self._command_template(argv)]},
        }

    def test_command_template_authority_change_changes_authority_hash(self):
        a = normalize_policy(self._command_policy(["python3", "-m", "unittest"]))
        b = normalize_policy(self._command_policy(["python3", "-m", "pytest"]))
        self.assertNotEqual(a.authority_sha256, b.authority_sha256)

    def test_unsandboxed_template_is_authority_bearing(self):
        outside = self._command_template(["python3", "-m", "unittest"])
        outside["sandbox"] = "outside"
        inside_policy = {
            "filesystem": {
                "roots": {
                    "project": {"kind": "project", "binding": "/tmp/project"},
                    "scratch": {"kind": "scratch", "binding": "/tmp/scratch"},
                },
            },
            "commands": {"mode": "selected", "templates": [outside]},
        }
        a = normalize_policy(inside_policy)
        b_raw = copy.deepcopy(inside_policy)
        b_raw["sandbox"] = {"mode": "off", "unavailable": "run", "unsandboxed_commands": ["adapter-tests"]}
        b = normalize_policy(b_raw)
        self.assertNotEqual(a.authority_sha256, b.authority_sha256)


class ResourceLimitTests(unittest.TestCase):
    def test_omitted_resources_are_unavailable_not_unbounded(self):
        policy = normalize_policy({})
        for name in (
            "wall_time_seconds", "process_count", "memory_bytes",
            "log_bytes", "generated_state_bytes", "generated_state_admission_bytes",
        ):
            self.assertEqual(policy.document["resources"][name], {"mode": "unavailable", "value": None})

    def test_explicit_generated_state_limits_normalize(self):
        policy = normalize_policy({
            "resources": {
                "generated_state_bytes": {"mode": "bounded", "value": 240 * 1024 * 1024},
                "generated_state_admission_bytes": {"mode": "bounded", "value": 192 * 1024 * 1024},
            }
        })
        self.assertEqual(
            policy.document["resources"]["generated_state_bytes"],
            {"mode": "bounded", "value": 240 * 1024 * 1024},
        )
        self.assertEqual(
            policy.document["resources"]["generated_state_admission_bytes"],
            {"mode": "bounded", "value": 192 * 1024 * 1024},
        )

    def test_invalid_limit_mode_value_pairs_are_rejected(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"resources": {"memory_bytes": {"mode": "bounded", "value": None}}})
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"resources": {"memory_bytes": {"mode": "bounded", "value": -1}}})
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"resources": {"memory_bytes": {"mode": "unavailable", "value": 5}}})
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"resources": {"memory_bytes": {"mode": "unbounded", "value": 5}}})


class CrossFieldValidityTests(unittest.TestCase):
    def test_selected_command_mcp_and_network_empty_sets_follow_section_18_2(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"commands": {"mode": "selected", "templates": []}})
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"mcp": {"mode": "selected", "servers": [], "selected_tools": []}})
        policy = normalize_policy({
            "network": {"subprocess": "allowlist", "mcp_open_world": "deny", "allowed_destinations": []}
        })
        self.assertEqual(policy.document["network"]["subprocess"], "deny")

    def test_host_effects_default_to_deny(self):
        policy = normalize_policy({})
        self.assertEqual(policy.document["host_effects"], {"mode": "deny", "grants": []})
        self.assertEqual(policy.authority_grants, frozenset())

    def test_selected_host_effect_requires_known_operation_and_stable_target(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"host_effects": {"mode": "selected", "grants": []}})
        with self.assertRaises(PolicyValidationError):
            normalize_policy({
                "host_effects": {
                    "mode": "selected",
                    "grants": [{"operation": "not-a-real-operation", "target_id": "x"}],
                }
            })
        policy = normalize_policy({
            "host_effects": {
                "mode": "selected",
                "grants": [{"operation": "process-signal", "target_id": "worker-proc"}],
            }
        })
        self.assertIn("host_effect:process-signal:worker-proc", policy.authority_grants)

    def test_system_input_hashes_empty_means_cache_inputs_incomplete(self):
        incomplete = normalize_policy({})
        self.assertFalse(incomplete.cache_inputs_complete)
        complete = normalize_policy({
            "model_inputs": {
                "model": "opus",
                "effort": "high",
                "system_input_hashes": ["abc123"],
            },
            "runtime": {"provider": "claude-code", "version": "2.1.215", "activation": "unavailable"},
        })
        self.assertTrue(complete.cache_inputs_complete)


class C0RemediationCounterexamples(unittest.TestCase):
    """Counterexamples for the provider-neutral contract boundary (C0)."""

    def _command_raw(self, **changes):
        template = {
            "id": "adapter-tests",
            "revision": 1,
            "argv": ["python3", "-m", "unittest"],
            "cwd_scope": "project",
            "environment": {"fixed": {"LANG": "C"}, "pass": []},
            "stdin": "closed",
            "write_scopes": ["scratch"],
            "wall_time_seconds": 180,
            "shared_log_bytes": 1024,
            "per_file_bytes": 512,
            "network": {"mode": "deny", "destinations": []},
            "sandbox": "required",
            "evidence_id": "evidence-v1",
        }
        template.update(changes)
        return {
            "filesystem": {
                "roots": {
                    "project": {"kind": "project", "binding": "unbound"},
                    "scratch": {"kind": "scratch", "binding": "unbound"},
                }
            },
            "commands": {"mode": "selected", "templates": [template]},
        }

    def test_malformed_command_template_values_raise_policy_validation_error(self):
        malformed = {
            "argv": ["python3", 3],
            "cwd_scope": 3,
            "environment": {"fixed": [], "pass": []},
            "stdin": "interactive",
            "write_scopes": "scratch",
            "wall_time_seconds": "180",
            "network": {"mode": "allowlist", "destinations": [3]},
            "sandbox": "maybe",
            "evidence_id": 42,
        }
        for field, value in malformed.items():
            with self.subTest(field=field):
                with self.assertRaises(PolicyValidationError):
                    normalize_policy(self._command_raw(**{field: value}))
        for field, value in (
            ("argv", {"program": "python3"}),
            ("environment", {"fixed": {"LANG": 3}, "pass": []}),
            ("environment", {"fixed": {}, "pass": [3]}),
            ("write_scopes", [3]),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(PolicyValidationError):
                    normalize_policy(self._command_raw(**{field: value}))

    def test_capability_and_proposal_field_enums_and_types_are_validated(self):
        invalid = (
            ({"profile": {"id": 3}}, "profile"),
            ({"model_inputs": {"system_input_hashes": [1]}}, "model_inputs"),
            ({"runtime": {"activation": "maybe"}}, "runtime"),
            ({"filesystem": {"defaults": {"read": "maybe"}}}, "filesystem"),
            ({"tools": {"builtins": [3]}}, "tools"),
            ({"mcp": {"mode": "maybe"}}, "mcp"),
            ({"commands": {"mode": "maybe"}}, "commands"),
            ({"network": {"subprocess": "maybe"}}, "network"),
            ({"host_effects": {"mode": "maybe"}}, "host_effects"),
            ({"git": {"mutation": "maybe"}}, "git"),
            ({"installation": {"mode": "maybe"}}, "installation"),
            ({"descendants": {"mode": "maybe"}}, "descendants"),
            ({"output": {"mode": "maybe"}}, "output"),
            ({"sandbox": {"mode": "maybe"}}, "sandbox"),
            ({"lifecycle": {"resume": "maybe"}}, "lifecycle"),
        )
        for raw, field in invalid:
            with self.subTest(field=field):
                with self.assertRaises(PolicyValidationError):
                    normalize_policy(raw)

    def test_set_like_lists_are_sorted_and_deduplicated_but_argv_order_is_preserved(self):
        raw = self._command_raw(
            argv=["python3", "-m", "unittest"],
            environment={"fixed": {"B": "2", "A": "1"}, "pass": ["Z", "A", "A"]},
            write_scopes=["scratch", "scratch"],
            network={"mode": "allowlist", "destinations": ["b.test", "a.test", "b.test"]},
        )
        raw["tools"] = {"builtins": ["Grep", "Read", "Read"], "deny": ["Write", "Write"]}
        policy = normalize_policy(raw)
        template = policy.document["commands"]["templates"][0]
        self.assertEqual(template["argv"], ["python3", "-m", "unittest"])
        self.assertEqual(template["write_scopes"], ["scratch"])
        self.assertEqual(template["environment"]["pass"], ["A", "Z"])
        self.assertEqual(template["network"]["destinations"], ["a.test", "b.test"])
        self.assertEqual(policy.document["tools"]["builtins"], ["Grep", "Read"])
        self.assertEqual(policy.document["tools"]["deny"], ["Write"])
        reordered = copy.deepcopy(raw)
        reordered["tools"] = {"builtins": ["Read", "Grep"], "deny": ["Write"]}
        reordered["commands"]["templates"][0]["environment"] = {
            "fixed": {"A": "1", "B": "2"}, "pass": ["A", "Z"],
        }
        reordered["commands"]["templates"][0]["write_scopes"] = ["scratch"]
        reordered["commands"]["templates"][0]["network"]["destinations"] = ["a.test", "b.test"]
        other = normalize_policy(reordered)
        self.assertEqual(policy.semantic_sha256, other.semantic_sha256)
        self.assertEqual(policy.authority_sha256, other.authority_sha256)

    def test_filesystem_defaults_are_authority_atoms(self):
        from delegation_policy.diff import compare_policies
        for operation in ("read", "write"):
            before = normalize_policy({})
            after = normalize_policy({"filesystem": {"defaults": {operation: "allow"}}})
            self.assertIn(f"filesystem.default.{operation}:allow", after.authority_grants)
            report = compare_policies(before, after)
            self.assertEqual(report.kind, "broader")
            self.assertIn(f"filesystem.default.{operation}:allow", report.broader_authority)
            reverse = compare_policies(after, before)
            self.assertEqual(reverse.kind, "narrower")

    def test_evidence_only_command_change_does_not_change_authority_hash(self):
        first = normalize_policy(self._command_raw(evidence_id="evidence-v1"))
        second = normalize_policy(self._command_raw(evidence_id="evidence-v2"))
        self.assertNotEqual(first.semantic_sha256, second.semantic_sha256)
        self.assertEqual(first.authority_sha256, second.authority_sha256)

    def test_unavailable_capability_dimensions_are_explicitly_unresolved(self):
        policy = normalize_policy({
            "runtime": {"provider": "claude-code", "version": None, "activation": "unavailable"},
            "commands": {"mode": "unavailable", "templates": []},
            "mcp": {"mode": "unavailable", "servers": [], "selected_tools": []},
        })
        self.assertIn("runtime.activation", policy.unresolved_dimensions)
        self.assertIn("commands.activation", policy.unresolved_dimensions)
        self.assertIn("mcp.activation", policy.unresolved_dimensions)

    def test_structural_resources_and_sandbox_values_raise_policy_validation_error(self):
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"resources": []})
        for value in ([], {"mode": []}, {"unsandboxed_commands": {"id": "diagnostic"}}):
            with self.subTest(value=value):
                with self.assertRaises(PolicyValidationError):
                    normalize_policy({"sandbox": value})

    def test_raw_deny_duplicate_ids_require_one_path_and_dedupe_exact_duplicates(self):
        first = {"operations": ["read"], "path": "/a", "effect": "hard-deny", "rule_id": "credential"}
        second = {"operations": ["write"], "path": "/b", "effect": "hard-deny", "rule_id": "other"}
        ordered = normalize_policy({"filesystem": {"rules": [first, second]}})
        reordered = normalize_policy({"filesystem": {"rules": [second, first]}})
        self.assertEqual(ordered.semantic_sha256, reordered.semantic_sha256)
        self.assertEqual(ordered.authority_sha256, reordered.authority_sha256)
        self.assertEqual(ordered.private_bindings, reordered.private_bindings)

        duplicate = normalize_policy({"filesystem": {"rules": [first, first]}})
        single = normalize_policy({"filesystem": {"rules": [first]}})
        self.assertEqual(duplicate.document, single.document)
        self.assertEqual(duplicate.private_bindings, single.private_bindings)
        with self.assertRaises(PolicyValidationError):
            normalize_policy({"filesystem": {"rules": [first, {**first, "path": "/different"}]}})

    def test_command_template_non_string_sandbox_values_raise_policy_validation_error(self):
        for value in ([], {"mode": "required"}):
            with self.subTest(value=value):
                with self.assertRaises(PolicyValidationError):
                    normalize_policy(self._command_raw(sandbox=value))


if __name__ == "__main__":
    unittest.main()
