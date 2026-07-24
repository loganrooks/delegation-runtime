from __future__ import annotations

import json
import unittest
from pathlib import Path

from delegate_to_claude.profiles import resolve_profile
from delegate_to_claude.policy_presets import (
    PRESET_ASSURANCE,
    PRESET_IDS,
    canonical_preset_id,
    preset_policy,
)
from delegation_policy import PolicyValidationError

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "policy" / "legacy-v3-profiles.json"


class LegacyFixtureCompatibilityTests(unittest.TestCase):
    def test_legacy_v3_fixture_matches_current_candidate(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        for profile_id, expected in fixture["profiles"].items():
            commands = (
                ("python3 -m unittest",)
                if profile_id in {"verified-review", "artifact-review"} else ()
            )
            permission = expected["permission_mode"] if profile_id.startswith("implementation") else None
            actual = resolve_profile(profile_id, permission, (), (), (), commands)
            for field, value in expected.items():
                expected_value = tuple(value) if field == "tools" else value
                self.assertEqual(getattr(actual, field), expected_value)


class PresetPolicyTests(unittest.TestCase):
    def test_all_preset_ids_and_alias_compile(self):
        for preset_id in PRESET_IDS:
            canonical, warning = canonical_preset_id(preset_id)
            policy = preset_policy(preset_id)
            self.assertEqual(policy.document["profile"]["id"], canonical)
            if preset_id == "readonly-review":
                self.assertIsNotNone(warning)
            else:
                self.assertIsNone(warning)

    def test_unknown_preset_id_is_rejected(self):
        with self.assertRaises(PolicyValidationError):
            preset_policy("not-a-real-preset")

    def test_verified_review_is_non_activating_and_sandbox_required(self):
        policy = preset_policy("verified-review").document
        self.assertEqual(policy["sandbox"]["mode"], "required")
        self.assertEqual(policy["sandbox"]["unavailable"], "fail")
        self.assertEqual(policy["commands"]["mode"], "unavailable")
        self.assertEqual(policy["host_effects"]["mode"], "deny")
        self.assertEqual(
            policy["resources"]["generated_state_bytes"],
            {"mode": "bounded", "value": 240 * 1024 * 1024},
        )
        self.assertEqual(
            policy["resources"]["generated_state_admission_bytes"],
            {"mode": "bounded", "value": 192 * 1024 * 1024},
        )
        self.assertEqual(policy["runtime"]["activation"], "unavailable")

    def test_strict_readonly_denies_commands_and_has_no_write_roots(self):
        policy = preset_policy("strict-readonly").document
        self.assertEqual(policy["commands"]["mode"], "unavailable")
        write_roots = [
            rule["scope"] for rule in policy["filesystem"]["rules"]
            if rule["effect"] == "allow" and "write" in rule["operations"]
        ]
        self.assertEqual(write_roots, [])
        read_roots = {
            rule["scope"] for rule in policy["filesystem"]["rules"]
            if rule["effect"] == "allow" and "read" in rule["operations"]
        }
        self.assertIn("project", read_roots)

    def test_verified_review_write_root_is_scratch_only(self):
        policy = preset_policy("verified-review").document
        write_roots = {
            rule["scope"] for rule in policy["filesystem"]["rules"]
            if rule["effect"] == "allow" and "write" in rule["operations"]
        }
        self.assertEqual(write_roots, {"scratch"})

    def test_implementation_presets_allow_owned_project_and_scratch_writes(self):
        for preset_id in ("implementation", "implementation-auto"):
            with self.subTest(preset_id=preset_id):
                policy = preset_policy(preset_id).document
                write_roots = {
                    rule["scope"] for rule in policy["filesystem"]["rules"]
                    if rule["effect"] == "allow" and "write" in rule["operations"]
                }
                self.assertEqual(write_roots, {"owned", "scratch"})
                self.assertIn("project", policy["filesystem"]["roots"])
                self.assertEqual(policy["filesystem"]["roots"]["owned"]["binding"], "unbound")

    def test_generic_mcp_readonly_is_unavailable_until_registry_resolves(self):
        for preset_id in PRESET_IDS:
            with self.subTest(preset_id=preset_id):
                policy = preset_policy(preset_id)
                self.assertEqual(policy.document["mcp"]["mode"], "unavailable")

    def test_notices_and_confirmations_are_independently_configurable_defaults(self):
        policy = preset_policy("strict-readonly").document
        self.assertIn("profile_transition", policy["notices"])
        self.assertIn("authority_expansion", policy["confirmation"])

    def test_preset_assurance_labels_never_claim_os_enforced(self):
        for preset_id, matrix in PRESET_ASSURANCE.items():
            for label in matrix.values():
                self.assertNotEqual(label, "os-enforced")

    def test_preset_revision_and_legacy_contract_version_are_distinct(self):
        policy = preset_policy("strict-readonly").document
        self.assertIsNotNone(policy["profile"]["preset_revision"])
        self.assertNotEqual(
            policy["profile"]["preset_revision"], policy["profile"]["legacy_contract_version"]
        )

    def test_all_presets_are_non_activating(self):
        for preset_id in PRESET_IDS:
            with self.subTest(preset_id=preset_id):
                policy = preset_policy(preset_id)
                self.assertEqual(policy.document["runtime"]["activation"], "unavailable")

    def test_unbound_symbolic_roots_have_no_absolute_paths(self):
        for preset_id in PRESET_IDS:
            with self.subTest(preset_id=preset_id):
                policy = preset_policy(preset_id)
                self.assertEqual(policy.private_bindings, ())
                for root in policy.document["filesystem"]["roots"].values():
                    self.assertEqual(root["binding"], "unbound")


if __name__ == "__main__":
    unittest.main()
