from __future__ import annotations

import unittest

from delegation_policy import normalize_policy
from delegation_policy.diff import compare_policies
from delegation_policy.explain import build_explanation


def _policy(**overrides):
    return normalize_policy(overrides)


class ExactNarrowerBroaderMixedTests(unittest.TestCase):
    def test_exact_transition_has_no_changes(self):
        a = _policy()
        b = _policy()
        report = compare_policies(a, b)
        self.assertEqual(report.kind, "exact")
        self.assertEqual(report.known_kind, "exact")
        self.assertEqual(report.broader_authority, ())
        self.assertEqual(report.narrower_authority, ())

    def _rw_policy(self, mode: str):
        rules = [{"operations": ["read"], "scope": "project", "effect": "allow"}]
        if mode == "write":
            rules.append({"operations": ["write"], "scope": "project", "effect": "allow"})
        return _policy(filesystem={
            "roots": {"project": {"kind": "project", "binding": "/tmp/p"}},
            "rules": rules,
        })

    def test_narrower_transition_only_removes_authority(self):
        before = self._rw_policy("write")
        after = self._rw_policy("read")
        report = compare_policies(before, after)
        self.assertEqual(report.kind, "narrower")
        self.assertIn("filesystem.write:project", report.narrower_authority)

    def test_broader_transition_only_adds_authority(self):
        before = self._rw_policy("read")
        after = self._rw_policy("write")
        report = compare_policies(before, after)
        self.assertEqual(report.kind, "broader")
        self.assertIn("filesystem.write:project", report.broader_authority)

    def test_mixed_transition_adds_and_removes(self):
        before = _policy(mcp={"mode": "readonly", "servers": [], "selected_tools": []})
        after = _policy(mcp={"mode": "deny", "servers": [], "selected_tools": []}, network={
            "subprocess": "unrestricted", "mcp_open_world": "deny", "allowed_destinations": [],
        })
        report = compare_policies(before, after)
        self.assertEqual(report.known_kind, "mixed")
        self.assertEqual(report.kind, "unknown")

    def test_unknown_when_unresolved_dimension_could_change_relation(self):
        before = _policy(mcp={"mode": "readonly", "servers": [], "selected_tools": []})
        after = _policy(mcp={"mode": "readonly", "servers": [], "selected_tools": []}, network={
            "subprocess": "unrestricted", "mcp_open_world": "deny", "allowed_destinations": [],
        })
        report = compare_policies(before, after)
        self.assertEqual(report.known_kind, "broader")
        self.assertIn("mcp.registry", report.unresolved_dimensions)

    def test_unresolved_dimension_from_before_policy_is_retained(self):
        before = _policy(commands={"mode": "unavailable", "templates": []})
        after = _policy(tools={"builtins": ["Read"], "deny": []})
        report = compare_policies(before, after)
        self.assertIn("commands.activation", report.unresolved_dimensions)
        self.assertEqual(report.kind, "unknown")

    def test_root_kind_change_with_changed_authority_hash_is_unknown_context(self):
        before = _policy(filesystem={
            "roots": {"project": {"kind": "project", "binding": "unbound"}},
        })
        after = _policy(filesystem={
            "roots": {"project": {"kind": "external", "binding": "unbound"}},
        })
        report = compare_policies(before, after)
        self.assertNotEqual(before.semantic_sha256, after.semantic_sha256)
        self.assertNotEqual(before.authority_sha256, after.authority_sha256)
        self.assertEqual(report.known_kind, "exact")
        self.assertEqual(report.kind, "unknown")
        self.assertIn("filesystem.roots", report.changed_fields)
        self.assertIn("filesystem.roots", report.unresolved_dimensions)
        self.assertIn("authority.projection", report.unresolved_dimensions)
        context_event = next(event for event in report.notice_events if event["category"] == "context_change")
        self.assertTrue(context_event["triggered"])
        self.assertTrue(context_event["display"])
        explanation = build_explanation(before, report)
        self.assertIn("filesystem.roots", explanation["transition"]["unresolved_dimensions"])
        self.assertIn("authority.projection", explanation["transition"]["unresolved_dimensions"])

    def test_root_binding_status_change_is_an_explicit_context_transition(self):
        before = _policy(filesystem={
            "roots": {"project": {"kind": "project", "binding": "unbound"}},
        })
        after = _policy(filesystem={
            "roots": {"project": {"kind": "project", "binding": "/tmp/project"}},
        })
        report = compare_policies(before, after)
        self.assertEqual(report.kind, "unknown")
        context_event = next(event for event in report.notice_events if event["category"] == "context_change")
        self.assertTrue(context_event["triggered"])
        self.assertTrue(context_event["display"])

    def test_resolved_exact_transition_has_equal_authority_hashes(self):
        before = _policy()
        after = _policy()
        report = compare_policies(before, after)
        if report.kind == "exact":
            self.assertEqual(before.authority_sha256, after.authority_sha256)


class GrantDenyDirectionTests(unittest.TestCase):
    def test_grant_addition_and_deny_addition(self):
        before = _policy()
        after = _policy(tools={"builtins": ["Read"], "deny": []})
        report = compare_policies(before, after)
        self.assertEqual(report.kind, "broader")
        self.assertIn("tools.builtin:Read", report.broader_authority)

    def test_deny_removal_broadens(self):
        before = _policy(tools={"builtins": [], "deny": ["Read"]})
        after = _policy(tools={"builtins": [], "deny": []})
        report = compare_policies(before, after)
        self.assertEqual(report.kind, "broader")

    def test_raw_deny_rebinding_is_context_change(self):
        before = _policy(filesystem={
            "rules": [
                {"operations": ["read"], "path": "/a", "effect": "hard-deny", "rule_id": "credential"},
            ],
        })
        after = _policy(filesystem={
            "rules": [
                {"operations": ["read"], "path": "/b", "effect": "hard-deny", "rule_id": "credential"},
            ],
        })
        report = compare_policies(before, after)
        self.assertIn("context_change", [event["category"] for event in report.notice_events])

    def test_allowlist_to_unrestricted_is_broader_not_mixed(self):
        before = _policy(network={
            "subprocess": "allowlist", "mcp_open_world": "deny", "allowed_destinations": ["example.test"],
        })
        after = _policy(network={
            "subprocess": "unrestricted", "mcp_open_world": "deny", "allowed_destinations": [],
        })
        report = compare_policies(before, after)
        self.assertEqual(report.kind, "broader")

    def test_resumes_are_never_rejected_for_broader_or_mixed(self):
        before = _policy()
        after = _policy(tools={"builtins": ["Read"], "deny": []})
        report = compare_policies(before, after)
        self.assertIn(report.kind, {"broader", "mixed", "unknown", "narrower", "exact"})


class DirectionalComparatorTests(unittest.TestCase):
    def test_sandbox_required_to_preferred_to_off_broadens(self):
        required = _policy(sandbox={"mode": "required", "unavailable": "fail", "unsandboxed_commands": []})
        preferred = _policy(sandbox={"mode": "preferred", "unavailable": "fail", "unsandboxed_commands": []})
        off = _policy(sandbox={"mode": "off", "unavailable": "fail", "unsandboxed_commands": []})
        self.assertEqual(compare_policies(required, preferred).kind, "broader")
        self.assertEqual(compare_policies(preferred, off).kind, "broader")
        self.assertEqual(compare_policies(off, required).kind, "narrower")

    def test_sandbox_fallback_fail_to_warn_to_run_broadens(self):
        fail = _policy(sandbox={"mode": "off", "unavailable": "fail", "unsandboxed_commands": []})
        warn = _policy(sandbox={"mode": "off", "unavailable": "warn-and-run", "unsandboxed_commands": []})
        run = _policy(sandbox={"mode": "off", "unavailable": "run", "unsandboxed_commands": []})
        self.assertEqual(compare_policies(fail, warn).kind, "broader")
        self.assertEqual(compare_policies(warn, run).kind, "broader")

    def test_finite_resource_increase_broadens_and_decrease_narrows(self):
        small = _policy(resources={"memory_bytes": {"mode": "bounded", "value": 100}})
        large = _policy(resources={"memory_bytes": {"mode": "bounded", "value": 200}})
        self.assertEqual(compare_policies(small, large).kind, "broader")
        self.assertEqual(compare_policies(large, small).kind, "narrower")

    def test_bounded_to_unbounded_is_broader(self):
        bounded = _policy(resources={"memory_bytes": {"mode": "bounded", "value": 100}})
        unbounded = _policy(resources={"memory_bytes": {"mode": "unbounded", "value": None}})
        self.assertEqual(compare_policies(bounded, unbounded).kind, "broader")

    def test_unavailable_resource_dimension_is_unresolved(self):
        unavailable = _policy()
        bounded = _policy(resources={"memory_bytes": {"mode": "bounded", "value": 100}})
        report = compare_policies(unavailable, bounded)
        self.assertIn("resources.memory_bytes", report.unresolved_dimensions)
        self.assertEqual(report.kind, "unknown")


class CacheAnalysisTests(unittest.TestCase):
    def _model_bound(self, **overrides):
        base = {
            "model_inputs": {"model": "opus", "effort": "high", "system_input_hashes": ["h1"]},
            "runtime": {"provider": "claude-code", "version": "2.1.215", "activation": "unavailable"},
        }
        base.update(overrides)
        return _policy(**base)

    def test_profile_only_change_does_not_claim_cache_miss(self):
        before = _policy(profile={"id": "a", "preset_revision": 1, "legacy_contract_version": None})
        after = _policy(profile={"id": "b", "preset_revision": 1, "legacy_contract_version": None})
        report = compare_policies(before, after)
        self.assertEqual(report.cache_impact, "unknown")

    def test_unchanged_cache_when_all_inputs_bound_and_equal(self):
        before = self._model_bound()
        after = self._model_bound()
        report = compare_policies(before, after)
        self.assertEqual(report.cache_impact, "unchanged")

    def test_tool_change_with_bound_inputs_is_likely_invalidated(self):
        before = self._model_bound(tools={"builtins": ["Read"], "deny": []})
        after = self._model_bound(tools={"builtins": ["Read", "Grep"], "deny": []})
        report = compare_policies(before, after)
        self.assertEqual(report.cache_impact, "likely-invalidated")

    def test_incomplete_cache_inputs_are_unknown(self):
        before = _policy()
        after = _policy()
        report = compare_policies(before, after)
        self.assertEqual(report.cache_impact, "unknown")

    def test_content_change_to_same_command_id_invalidates_cache(self):
        template = {
            "id": "runner",
            "revision": 1,
            "argv": ["python3", "-m", "unittest"],
            "cwd_scope": "project",
            "environment": {"fixed": {}, "pass": []},
            "stdin": "closed",
            "write_scopes": ["scratch"],
            "wall_time_seconds": 180,
            "shared_log_bytes": 1024,
            "per_file_bytes": 512,
            "network": {"mode": "deny", "destinations": []},
            "sandbox": "required",
            "evidence_id": "runner-evidence",
        }
        base = {
            "model_inputs": {"model": "opus", "effort": "high", "system_input_hashes": ["h1"]},
            "runtime": {"provider": "claude-code", "version": "2.1.215", "activation": "unavailable"},
            "filesystem": {
                "roots": {
                    "project": {"kind": "project", "binding": "unbound"},
                    "scratch": {"kind": "scratch", "binding": "unbound"},
                }
            },
            "commands": {"mode": "selected", "templates": [template]},
        }
        before = _policy(**base)
        changed = dict(base)
        changed["commands"] = {"mode": "selected", "templates": [{**template, "argv": ["python3", "-m", "pytest"]}]}
        after = _policy(**changed)
        self.assertEqual(compare_policies(before, after).cache_impact, "likely-invalidated")


class NoticeAndConfirmationEventTests(unittest.TestCase):
    def _outside_command_policy(self, *, unsandboxed: bool, confirmation: dict[str, str]):
        template = {
            "id": "diagnostic",
            "revision": 1,
            "argv": ["python3", "-c", "pass"],
            "cwd_scope": "project",
            "environment": {"fixed": {}, "pass": []},
            "stdin": "closed",
            "write_scopes": [],
            "wall_time_seconds": 10,
            "shared_log_bytes": 1024,
            "per_file_bytes": 512,
            "network": {"mode": "deny", "destinations": []},
            "sandbox": "outside",
            "evidence_id": "evidence",
        }
        return _policy(
            filesystem={"roots": {"project": {"kind": "project", "binding": "unbound"}}},
            commands={"mode": "selected", "templates": [template]},
            sandbox={
                "mode": "off", "unavailable": "run",
                "unsandboxed_commands": ["diagnostic"] if unsandboxed else [],
            },
            confirmation=confirmation,
        )

    def test_same_policy_with_unresolved_dimension_uses_final_unknown_for_notice_and_confirmation(self):
        policy = _policy(commands={"mode": "unavailable", "templates": []})
        report = compare_policies(policy, policy)
        self.assertEqual(report.known_kind, "exact")
        self.assertEqual(report.kind, "unknown")
        authority_events = [event for event in report.notice_events if event["category"] == "authority_change"]
        self.assertEqual(len(authority_events), 1)
        self.assertTrue(authority_events[0]["display"])
        self.assertTrue(authority_events[0]["requires_confirmation"])
        self.assertTrue(any(event["category"] == "authority_change" for event in report.confirmation_events))

    def test_unsandboxed_confirmation_is_independent_of_authority_confirmation(self):
        confirmation = {
            "profile_transition": "never",
            "authority_expansion": "never",
            "unsandboxed_command": "ask",
        }
        before = self._outside_command_policy(unsandboxed=False, confirmation=confirmation)
        after = self._outside_command_policy(unsandboxed=True, confirmation=confirmation)
        report = compare_policies(before, after)
        self.assertTrue(any(event["category"] == "sandbox_change" for event in report.notice_events))
        unsandboxed_events = [
            event for event in report.confirmation_events
            if event["category"] == "unsandboxed_command"
        ]
        self.assertEqual(len(unsandboxed_events), 1)
        self.assertEqual(unsandboxed_events[0]["mode"], "ask")

    def test_unsandboxed_transition_identity_does_not_collide_with_authority_only_change(self):
        confirmation = {
            "profile_transition": "never",
            "authority_expansion": "never",
            "unsandboxed_command": "ask",
        }
        before = self._outside_command_policy(unsandboxed=False, confirmation=confirmation)
        unsandboxed = self._outside_command_policy(unsandboxed=True, confirmation=confirmation)
        authority_only = _policy(
            tools={"builtins": ["Read"], "deny": []}, confirmation=confirmation,
        )
        self.assertNotEqual(
            compare_policies(before, unsandboxed).transition_sha256,
            compare_policies(before, authority_only).transition_sha256,
        )

    def test_every_notice_never_still_records_events(self):
        never_notices = {
            "profile_transition": "never", "cache_impact": "never", "authority_change": "never",
            "context_change": "never", "runtime_change": "never", "sandbox_change": "never",
        }
        before = _policy(notices=never_notices)
        after = _policy(notices=never_notices, tools={"builtins": ["Read"], "deny": []})
        report = compare_policies(before, after)
        authority_events = [e for e in report.notice_events if e["category"] == "authority_change"]
        self.assertTrue(authority_events)
        self.assertFalse(authority_events[0]["display"])

    def test_presentation_change_recorded_but_not_forced_visible(self):
        before = _policy(notices={"profile_transition": "always", "cache_impact": "always",
                                    "authority_change": "always", "context_change": "always",
                                    "runtime_change": "always", "sandbox_change": "always"})
        after = _policy(notices={"profile_transition": "never", "cache_impact": "always",
                                   "authority_change": "always", "context_change": "always",
                                   "runtime_change": "always", "sandbox_change": "always"})
        report = compare_policies(before, after)
        self.assertTrue(any(e["category"] == "presentation_change" for e in report.notice_events))

    def test_operator_current_presentation_precedence_uses_after_policy(self):
        before = _policy(notices={"profile_transition": "always", "cache_impact": "always",
                                    "authority_change": "never", "context_change": "always",
                                    "runtime_change": "always", "sandbox_change": "always"})
        after = _policy(notices={"profile_transition": "always", "cache_impact": "always",
                                   "authority_change": "always", "context_change": "always",
                                   "runtime_change": "always", "sandbox_change": "always"},
                        tools={"builtins": ["Read"], "deny": []})
        report = compare_policies(before, after)
        authority_events = [e for e in report.notice_events if e["category"] == "authority_change"]
        self.assertTrue(authority_events[0]["display"])

    def test_transition_sha256_is_stable_and_deterministic(self):
        before = _policy()
        after = _policy(tools={"builtins": ["Read"], "deny": []})
        first = compare_policies(before, after)
        second = compare_policies(before, after)
        self.assertEqual(first.transition_sha256, second.transition_sha256)

    def test_confirmation_only_change_records_presentation_event_and_changes_identity(self):
        before = _policy(confirmation={
            "profile_transition": "never", "authority_expansion": "ask", "unsandboxed_command": "ask",
        })
        after = _policy(confirmation={
            "profile_transition": "never", "authority_expansion": "never", "unsandboxed_command": "ask",
        })
        report = compare_policies(before, after)
        self.assertTrue(any(e["category"] == "presentation_change" for e in report.notice_events))
        self.assertNotEqual(report.transition_sha256, compare_policies(
            before, _policy(notices={
                "profile_transition": "never", "cache_impact": "always", "authority_change": "always",
                "context_change": "always", "runtime_change": "always", "sandbox_change": "always",
            })
        ).transition_sha256)


if __name__ == "__main__":
    unittest.main()
