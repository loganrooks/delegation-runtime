from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from delegation_policy import PolicyValidationError, normalize_policy
from delegation_policy.diff import compare_policies
from delegation_policy.explain import build_explanation, render_text


def _policy_with_private_path(private_path: str):
    return normalize_policy({
        "profile": {"id": "verified-review", "preset_revision": 1, "legacy_contract_version": None},
        "filesystem": {
            "roots": {
                "project": {"kind": "project", "binding": private_path},
                "scratch": {"kind": "scratch", "binding": "unbound"},
            },
            "rules": [
                {"operations": ["read"], "scope": "project", "effect": "allow"},
                {"operations": ["write"], "scope": "scratch", "effect": "allow"},
            ],
        },
        "sandbox": {"mode": "required", "unavailable": "fail", "unsandboxed_commands": []},
    })


class SanitizedExplanationTests(unittest.TestCase):
    def _unsandboxed_policy(self):
        return normalize_policy({
            "filesystem": {
                "roots": {
                    "project": {"kind": "project", "binding": "unbound"},
                },
            },
            "commands": {
                "mode": "selected",
                "templates": [{
                    "id": "diagnostic",
                    "revision": 1,
                    "argv": ["python3", "-c", "sentinel command text"],
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
                }],
            },
            "sandbox": {
                "mode": "off", "unavailable": "run", "unsandboxed_commands": ["diagnostic"],
            },
        })

    def test_explanation_is_sanitized(self):
        with tempfile.TemporaryDirectory() as tmp:
            private_path = str(Path(tmp) / "private-sentinel")
            explanation = build_explanation(
                _policy_with_private_path(private_path),
                assurance={"built-in-read": "claude-enforced"},
            )
            rendered = json.dumps(explanation, sort_keys=True)
            self.assertNotIn(private_path, rendered)
            self.assertEqual(explanation["stage"], "compiled")

    def test_required_shape_matches_allowlist(self):
        explanation = build_explanation(_policy_with_private_path("/tmp/x"))
        self.assertEqual(explanation["stage"], "compiled")
        self.assertEqual(explanation["schema_version"], 1)
        self.assertIn("id", explanation["profile"])
        self.assertIn("preset_revision", explanation["profile"])
        self.assertIn("legacy_contract_version", explanation["profile"])
        self.assertEqual(len(explanation["semantic_sha256"]), 64)
        self.assertEqual(len(explanation["authority_sha256"]), 64)
        self.assertEqual(explanation["activation"], "unavailable")
        self.assertEqual(explanation["roots"]["read"], [{"id": "project", "binding": "bound"}])
        self.assertEqual(explanation["roots"]["write"], [{"id": "scratch", "binding": "unbound"}])
        self.assertEqual(explanation["capabilities"]["commands"], "deny")
        self.assertEqual(explanation["capabilities"]["mcp"], "deny")
        self.assertEqual(explanation["capabilities"]["host_effects"], "deny")
        self.assertIn("generated_state_bytes", explanation["resources"])
        self.assertEqual(explanation["sandbox"], {
            "mode": "required", "unavailable": "fail", "unsandboxed_commands": [],
        })
        self.assertIsNone(explanation["transition"])
        self.assertEqual(explanation["unresolved"], [])

    def test_assurance_is_supplied_explicitly_and_never_imported(self):
        explanation = build_explanation(_policy_with_private_path("/tmp/x"), assurance=None)
        self.assertEqual(explanation["assurance"], {})
        explanation2 = build_explanation(
            _policy_with_private_path("/tmp/x"), assurance={"built-in-read": "unknown"}
        )
        self.assertEqual(explanation2["assurance"], {"built-in-read": "unknown"})

    def test_assurance_keys_and_values_are_allowlisted(self):
        policy = _policy_with_private_path("/tmp/x")
        for assurance in ({"built-in-read": "maybe"}, {3: "unknown"}):
            with self.subTest(assurance=assurance):
                with self.assertRaises(PolicyValidationError):
                    build_explanation(policy, assurance=assurance)

    def test_explanation_includes_independent_presentation_decisions_and_unsandboxed_ids(self):
        policy = self._unsandboxed_policy()
        explanation = build_explanation(policy)
        self.assertEqual(explanation["presentation"]["notices"], policy.document["notices"])
        self.assertEqual(explanation["presentation"]["confirmation"], policy.document["confirmation"])
        self.assertEqual(explanation["sandbox"]["unsandboxed_commands"], ["diagnostic"])

    def test_explanation_excludes_sentinel_hashes_and_command_content(self):
        policy = self._unsandboxed_policy()
        explanation = build_explanation(policy, assurance={"built-in-read": "unknown"})
        rendered = json.dumps(explanation, sort_keys=True)
        for sentinel in ("sentinel command text", "evidence", "private-sentinel", "objective", "prompt"):
            self.assertNotIn(sentinel, rendered)

    def test_transition_is_included_when_supplied(self):
        before = _policy_with_private_path("/tmp/a")
        after = _policy_with_private_path("/tmp/a")
        transition = compare_policies(before, after)
        explanation = build_explanation(after, transition)
        self.assertIsNotNone(explanation["transition"])
        self.assertIn("known_kind", explanation["transition"])
        self.assertIn("kind", explanation["transition"])
        self.assertIn("cache_impact", explanation["transition"])
        self.assertIn("unresolved_dimensions", explanation["transition"])

    def test_unresolved_dimensions_are_reported(self):
        policy = normalize_policy({"mcp": {"mode": "readonly", "servers": [], "selected_tools": []}})
        explanation = build_explanation(policy)
        self.assertIn("mcp.registry", explanation["unresolved"])

    def test_no_prompt_command_or_secret_text_leaks(self):
        policy = _policy_with_private_path("/tmp/x")
        explanation = build_explanation(policy)
        rendered = json.dumps(explanation)
        for forbidden in ("prompt", "PROMPT", "objective", "argv", "secret"):
            self.assertNotIn(forbidden, rendered)

    def test_deterministic_output(self):
        policy = _policy_with_private_path("/tmp/x")
        first = build_explanation(policy)
        second = build_explanation(policy)
        self.assertEqual(first, second)

    def test_render_text_is_stable_and_labels_unknown_assurance(self):
        policy = _policy_with_private_path("/tmp/x")
        explanation = build_explanation(policy)
        text = render_text(explanation)
        self.assertIsInstance(text, str)
        self.assertIn("compiled", text)
        first = render_text(explanation)
        second = render_text(explanation)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
