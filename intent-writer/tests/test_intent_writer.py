"""Black-box tests for the driver-side v2 intent/outcome writer (B-7)."""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

import intent_writer
from intent_writer import (
    ATTESTATION,
    CODE_RE,
    DISPOSITION_PAIRINGS,
    DISPOSITIONS,
    EFFORTS,
    IDENTITY_SOURCES,
    LOCK_NAME,
    PROJECTION,
    REGISTERED_CONFOUNDER_CODES,
    REGISTERED_FRICTION_CODES,
    REWORK_ACTORS,
    SURFACES,
    TOOL_PROFILES,
    UNOBSERVABLE_DISPOSITIONS,
    V,
    RecordError,
    load_aliases,
    main,
    normalize_model,
    read_records,
    store_files,
    store_lock,
    store_path,
    summarize,
    ulid,
    ulid_time_ms,
    validate_record,
    write_record,
)


ROOT = Path(__file__).resolve().parents[2]
ENTRYPOINT = ROOT / "intent-writer/scripts/intent_writer.py"
SHA = "b" * 64


def intent(**overrides) -> dict[str, object]:
    record: dict[str, object] = {
        "kind": "intent",
        "run_id": "run-1",
        "session_id": "sess-1",
        "task_class": {"class": None, "class_free": "bounded-implementation"},
        "requested_model": {"id": "anthropic:claude-opus-5", "raw": "opus"},
        "requested_effort": "high",
        "surface": "per-call",
        "harness_contract": {
            "sha256": SHA,
            "label": "implementer v1",
            "features": {"review_gate": True, "claim_tagging": False, "tool_profile": "rw"},
        },
    }
    record.update(overrides)
    return record


def outcome(**overrides) -> dict[str, object]:
    record: dict[str, object] = {
        "kind": "outcome",
        "run_id": "run-1",
        "disposition": "accepted",
        "terminal": True,
        "observed_model": {"id": "anthropic:claude-opus-5", "identity_source": "transcript"},
    }
    record.update(overrides)
    return record


def complete(record: dict[str, object], **overrides) -> dict[str, object]:
    """Fill the writer-stamped envelope so validate_record can be called directly."""
    filled: dict[str, object] = {
        "v": V,
        "event_id": ulid(),
        "ts": "2026-07-26T12:00:00Z",
        "attestation": ATTESTATION,
        "projection": PROJECTION,
        **record,
    }
    if filled["kind"] == "intent":
        filled.setdefault("spawn_ordinal", 0)
    if filled["kind"] == "outcome":
        filled.setdefault("outcome_ordinal", 0)
    filled.update(overrides)
    return filled


class StoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "v2"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        # --home is a per-subcommand flag, so it follows the subcommand name.
        command, rest = argv[0], argv[1:]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([command, "--home", str(self.home), *rest])
        return code, out.getvalue(), err.getvalue()

    def lines(self) -> list[dict[str, object]]:
        records = []
        for path in store_files(self.home):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    records.append(json.loads(line))
        return records


class UlidTests(unittest.TestCase):
    def test_ulid_is_26_crockford_characters(self):
        value = ulid()
        self.assertEqual(len(value), 26)
        self.assertNotIn("I", value)
        self.assertNotIn("L", value)
        self.assertNotIn("U", value)
        validate_record(complete(intent(), event_id=value))

    def test_ulid_prefix_encodes_the_supplied_millisecond(self):
        self.assertEqual(ulid_time_ms(ulid(now_ms=1_782_885_929_454)), 1_782_885_929_454)
        self.assertEqual(ulid_time_ms(ulid(now_ms=0)), 0)

    def test_ulids_sort_in_time_order(self):
        early = ulid(now_ms=1_000_000_000_000)
        late = ulid(now_ms=1_000_000_000_001)
        self.assertLess(early, late)
        self.assertLess(early[:10], late[:10])

    def test_ulid_rejects_a_timestamp_outside_48_bits(self):
        with self.assertRaisesRegex(RecordError, "out of range"):
            ulid(now_ms=1 << 48)

    def test_ulid_time_ms_rejects_a_malformed_id(self):
        for bad in ("", "short", "I" * 26, "a" * 26, "0" * 27):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "ULID"):
                ulid_time_ms(bad)


class EnumTests(unittest.TestCase):
    def test_every_requested_effort_member_is_accepted(self):
        for value in sorted(EFFORTS):
            with self.subTest(effort=value):
                validate_record(complete(intent(requested_effort=value)))

    def test_effort_outside_the_enum_is_rejected(self):
        for bad in ("HIGH", "medium ", "ultra", "", None, 3):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "requested_effort"):
                validate_record(complete(intent(requested_effort=bad)))

    def test_every_surface_member_is_accepted(self):
        for value in sorted(SURFACES):
            with self.subTest(surface=value):
                validate_record(complete(intent(surface=value)))

    def test_surface_outside_the_enum_is_rejected(self):
        for bad in ("api", "Pin", "per_call", None):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "surface"):
                validate_record(complete(intent(surface=bad)))

    def test_every_disposition_member_is_accepted(self):
        for value in sorted(DISPOSITIONS):
            # §3a fixes `terminal` for four of them; supply what the table binds.
            fixed = DISPOSITION_PAIRINGS.get(value, {})
            with self.subTest(disposition=value):
                validate_record(
                    complete(
                        outcome(disposition=value, terminal=fixed.get("terminal", True))
                    )
                )

    def test_disposition_outside_the_enum_is_rejected(self):
        # v0's six-member enum matched 0/96 live S3 values; these are its ghosts.
        for bad in ("accept", "revise", "success", "accepted-after-revision", None):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "disposition"):
                validate_record(complete(outcome(disposition=bad)))

    def test_every_rework_actor_member_is_accepted(self):
        # `accepted-after-rework` is the one disposition §3a leaves free on both
        # axes (three rows map onto it with disagreeing values), so it is where
        # the rework_actor enum can be exercised in full.
        for value in sorted(REWORK_ACTORS):
            with self.subTest(actor=value):
                validate_record(
                    complete(outcome(disposition="accepted-after-rework", rework_actor=value))
                )

    def test_rework_actor_outside_the_enum_is_rejected(self):
        for bad in ("parent", "child", "", True):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "rework_actor"):
                validate_record(
                    complete(outcome(disposition="accepted-after-rework", rework_actor=bad))
                )

    def test_every_identity_source_member_is_accepted(self):
        for value in sorted(IDENTITY_SOURCES):
            with self.subTest(source=value):
                validate_record(
                    complete(
                        outcome(
                            observed_model={
                                "id": "anthropic:claude-opus-5",
                                "identity_source": value,
                            }
                        )
                    )
                )

    def test_identity_source_outside_the_enum_is_rejected(self):
        for bad in ("guess", "UI-label", None):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "identity_source"):
                validate_record(
                    complete(
                        outcome(
                            observed_model={"id": "anthropic:claude-opus-5", "identity_source": bad}
                        )
                    )
                )

    def test_every_tool_profile_member_is_accepted(self):
        for value in sorted(TOOL_PROFILES):
            with self.subTest(profile=value):
                contract = {
                    "sha256": SHA,
                    "label": "x",
                    "features": {"review_gate": True, "claim_tagging": True, "tool_profile": value},
                }
                validate_record(complete(intent(harness_contract=contract)))

    def test_tool_profile_outside_the_enum_is_rejected(self):
        contract = {
            "sha256": SHA,
            "label": "x",
            "features": {"review_gate": True, "claim_tagging": True, "tool_profile": "admin"},
        }
        with self.assertRaisesRegex(RecordError, "tool_profile"):
            validate_record(complete(intent(harness_contract=contract)))

    def test_kind_outside_the_enum_is_rejected(self):
        for bad in ("route_planned", "spawn", "", None):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "kind"):
                validate_record(complete(intent(), kind=bad))

    def test_attestation_and_projection_are_pinned_to_this_writers_tier(self):
        with self.assertRaisesRegex(RecordError, "attestation"):
            validate_record(complete(intent(), attestation="self-reported"))
        with self.assertRaisesRegex(RecordError, "projection"):
            validate_record(complete(intent(), projection="projected-v1"))


class ValueRuleTests(unittest.TestCase):
    def test_unknown_field_names_are_rejected_per_kind(self):
        with self.assertRaisesRegex(RecordError, "unknown fields"):
            validate_record(complete(intent(), notes="free text"))
        # `disposition` is a legal name — on outcomes, not on intents.
        with self.assertRaisesRegex(RecordError, "unknown fields"):
            validate_record(complete(intent(), disposition="accepted"))
        with self.assertRaisesRegex(RecordError, "unknown fields"):
            validate_record(complete(outcome(), surface="per-call"))

    def test_missing_required_fields_are_named(self):
        record = complete(intent())
        del record["harness_contract"]
        with self.assertRaisesRegex(RecordError, "harness_contract"):
            validate_record(record)

    def test_observed_model_is_required_on_outcomes(self):
        # Crosswalk §3 marks it REQ where SPEC.md said optional.
        record = complete(outcome())
        del record["observed_model"]
        with self.assertRaisesRegex(RecordError, "observed_model"):
            validate_record(record)

    def test_observed_model_may_be_null_when_nothing_was_observed(self):
        validate_record(complete(outcome(disposition="error", observed_model=None)))

    def test_requested_model_may_be_null_for_a_session_inherited_spawn(self):
        validate_record(
            complete(intent(requested_model=None, requested_effort="session-inherited"))
        )

    def test_model_bindings_must_be_normalized_vendor_colon_model(self):
        for bad in ("claude-opus-5", "anthropic/claude", "aws:claude", "anthropic:"):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "binding"):
                validate_record(complete(intent(requested_model={"id": bad, "raw": "x"})))

    def test_code_shaped_fields_follow_the_crosswalk_regex(self):
        validate_record(complete(intent(route_id="none-consulted")))
        for bad in ("has space", "-leading", "a" * 129, "semi;colon"):
            with self.subTest(bad=bad):
                self.assertIsNone(CODE_RE.fullmatch(bad))
                with self.assertRaisesRegex(RecordError, "route_id"):
                    validate_record(complete(intent(route_id=bad)))

    def test_warrant_ids_must_be_w_nnn(self):
        validate_record(complete(intent(warrant_ids=["W-001", "W-022"])))
        for bad in (["W-1"], ["w-001"], ["W-0011"], "W-001"):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "warrant_ids"):
                validate_record(complete(intent(warrant_ids=bad)))

    def test_task_class_keeps_class_null_until_the_enum_is_published(self):
        validate_record(complete(intent(task_class={"class_free": "review"})))
        with self.assertRaisesRegex(RecordError, "§2a"):
            validate_record(complete(intent(task_class={"class": "review", "class_free": "review"})))
        with self.assertRaisesRegex(RecordError, "class_free"):
            validate_record(complete(intent(task_class={"class": None, "class_free": "  "})))

    def test_harness_contract_requires_a_sha256_label_and_core_features(self):
        with self.assertRaisesRegex(RecordError, "sha256"):
            validate_record(
                complete(
                    intent(
                        harness_contract={
                            "sha256": "abc",
                            "label": "x",
                            "features": {
                                "review_gate": True,
                                "claim_tagging": True,
                                "tool_profile": "ro",
                            },
                        }
                    )
                )
            )
        with self.assertRaisesRegex(RecordError, "claim_tagging"):
            validate_record(
                complete(
                    intent(
                        harness_contract={
                            "sha256": SHA,
                            "label": "x",
                            "features": {"review_gate": True, "tool_profile": "ro"},
                        }
                    )
                )
            )

    def test_harness_features_reject_free_text_values(self):
        contract = {
            "sha256": SHA,
            "label": "x",
            "features": {
                "review_gate": True,
                "claim_tagging": True,
                "tool_profile": "ro",
                "gate_note": "a sentence that is prose, not a flag",
            },
        }
        with self.assertRaisesRegex(RecordError, "gate_note"):
            validate_record(complete(intent(harness_contract=contract)))

    def test_reason_code_free_is_allowed_only_alongside_other(self):
        validate_record(complete(intent(reason_code="other", reason_code_free="ad-hoc rationale")))
        with self.assertRaisesRegex(RecordError, "reason_code_free"):
            validate_record(
                complete(intent(reason_code_free="ad-hoc rationale")),
            )
        with self.assertRaisesRegex(RecordError, "reason_code"):
            validate_record(complete(intent(reason_code="cheaper")))

    def test_validator_outcome_free_follows_the_same_free_slot_rule(self):
        validate_record(
            complete(outcome(validator={"id": "tests", "outcome": "other", "outcome_free": "3 red"}))
        )
        # No validator vocabulary is registered yet, so `other` is the only legal
        # member today; patching one in is how the free-slot rule gets exercised.
        with unittest.mock.patch.object(
            intent_writer, "REGISTERED_VALIDATOR_OUTCOMES", frozenset({"pass"})
        ):
            validate_record(complete(outcome(validator={"id": "tests", "outcome": "pass"})))
            with self.assertRaisesRegex(RecordError, "outcome_free"):
                validate_record(
                    complete(
                        outcome(validator={"id": "tests", "outcome": "pass", "outcome_free": "3 red"})
                    )
                )

    def test_an_unregistered_validator_outcome_is_rejected_today(self):
        with self.assertRaisesRegex(RecordError, "validator.outcome"):
            validate_record(complete(outcome(validator={"id": "tests", "outcome": "pass"})))

    def test_tokens_accept_nulls_and_reject_non_integers(self):
        validate_record(complete(outcome(tokens={"in": 10, "out": 20, "cache_r": None})))
        with self.assertRaisesRegex(RecordError, "tokens"):
            validate_record(complete(outcome(tokens={"in": 1.5})))
        with self.assertRaisesRegex(RecordError, "unknown fields"):
            validate_record(complete(outcome(tokens={"reasoning": 5})))

    def test_price_lineage_requires_a_binding_two_prices_and_a_date(self):
        validate_record(
            complete(
                intent(
                    price_lineage={
                        "binding": "anthropic:claude-opus-5",
                        "price_per_mtok_in": 15,
                        "price_per_mtok_out": 75,
                        "as_of": "2026-07-24",
                    }
                )
            )
        )
        with self.assertRaisesRegex(RecordError, "as_of"):
            validate_record(
                complete(
                    intent(
                        price_lineage={
                            "binding": "anthropic:claude-opus-5",
                            "price_per_mtok_in": 15,
                            "price_per_mtok_out": 75,
                            "as_of": "24 July 2026",
                        }
                    )
                )
            )

    def test_timestamps_must_be_iso_utc_ending_in_z(self):
        for bad in ("2026-07-26 12:00:00Z", "2026-07-26T12:00:00+00:00", "2026-13-01T00:00:00Z"):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "ts"):
                validate_record(complete(intent(), ts=bad))

    def test_rekey_records_validate_against_the_crosswalk_field_set(self):
        rekey = {
            "v": V,
            "kind": "rekey",
            "event_id": ulid(),
            "ts": "2026-07-26T12:00:00Z",
            "origin": "local",
            "mappings": [{"old_pseudonym": "aa11", "new_pseudonym": "bb22"}],
            "sig": "c2lnbmF0dXJl",
        }
        validate_record(rekey)
        with self.assertRaisesRegex(RecordError, "unknown fields"):
            validate_record({**rekey, "run_id": "run-1"})
        with self.assertRaisesRegex(RecordError, "mappings"):
            validate_record({**rekey, "mappings": []})


class AliasTests(StoreTestCase):
    def test_seed_table_folds_the_measured_terra_spellings_onto_one_binding(self):
        aliases = load_aliases(self.home)
        for spelling in ("terra", "gpt-5.6-terra", "gpt-5-6-terra"):
            with self.subTest(spelling=spelling):
                self.assertEqual(normalize_model(spelling, aliases), "openai:gpt-5.6-terra")

    def test_an_already_normalized_binding_passes_through(self):
        self.assertEqual(
            normalize_model("anthropic:claude-opus-5", load_aliases(self.home)),
            "anthropic:claude-opus-5",
        )

    def test_an_unknown_alias_is_rejected_rather_than_guessed(self):
        with self.assertRaisesRegex(RecordError, "unknown model alias"):
            normalize_model("some-new-model", load_aliases(self.home))

    def test_the_json_data_file_extends_the_table_without_a_code_edit(self):
        self.home.mkdir(parents=True)
        (self.home / "model-aliases.json").write_text(
            json.dumps({"Fable": "anthropic:claude-fable-5"}), encoding="utf-8"
        )
        aliases = load_aliases(self.home)
        self.assertEqual(normalize_model("fable", aliases), "anthropic:claude-fable-5")
        self.assertEqual(normalize_model("terra", aliases), "openai:gpt-5.6-terra")

    def test_a_data_file_mapping_to_a_bad_binding_fails_closed(self):
        self.home.mkdir(parents=True)
        (self.home / "model-aliases.json").write_text(
            json.dumps({"fable": "claude-fable-5"}), encoding="utf-8"
        )
        with self.assertRaisesRegex(RecordError, "binding"):
            load_aliases(self.home)

    def test_aliases_are_applied_when_a_record_is_written(self):
        record = write_record(self.home, intent(requested_model={"id": "terra", "raw": "terra"}))
        self.assertEqual(record["requested_model"]["id"], "openai:gpt-5.6-terra")
        self.assertEqual(record["requested_model"]["raw"], "terra")


class WriteTests(StoreTestCase):
    def test_a_written_intent_is_stamped_with_the_v2_envelope(self):
        record = write_record(self.home, intent())
        self.assertEqual(record["v"], V)
        self.assertEqual(record["attestation"], ATTESTATION)
        self.assertEqual(record["projection"], PROJECTION)
        self.assertEqual(len(record["event_id"]), 26)
        self.assertTrue(str(record["ts"]).endswith("Z"))

    def test_records_land_in_the_month_file_named_by_their_timestamp(self):
        write_record(self.home, intent(ts="2026-07-26T12:00:00Z"))
        write_record(self.home, intent(run_id="run-2", ts="2026-08-02T12:00:00Z"))
        self.assertEqual(
            [path.name for path in store_files(self.home)],
            ["intents-2026-07.jsonl", "intents-2026-08.jsonl"],
        )
        self.assertEqual(
            store_path(self.home, "2026-07-26T12:00:00Z").name, "intents-2026-07.jsonl"
        )

    def test_lines_are_compact_sorted_key_json_one_per_record(self):
        write_record(self.home, intent())
        write_record(self.home, outcome())
        text = store_files(self.home)[0].read_text(encoding="utf-8")
        self.assertEqual(len(text.splitlines()), 2)
        self.assertTrue(text.endswith("\n"))
        self.assertNotIn(", ", text)
        first = text.splitlines()[0]
        self.assertEqual(first, json.dumps(json.loads(first), sort_keys=True, separators=(",", ":")))

    def test_the_store_is_created_private_to_the_user(self):
        write_record(self.home, intent())
        self.assertEqual(self.home.stat().st_mode & 0o777, 0o700)
        self.assertEqual(store_files(self.home)[0].stat().st_mode & 0o777, 0o600)

    def test_a_duplicate_event_id_is_refused(self):
        first = write_record(self.home, intent())
        with self.assertRaisesRegex(RecordError, "duplicate event_id"):
            write_record(self.home, intent(run_id="run-2", event_id=first["event_id"]))
        self.assertEqual(len(self.lines()), 1)

    def test_an_invalid_record_never_reaches_the_store(self):
        with self.assertRaises(RecordError):
            write_record(self.home, intent(requested_effort="ultra"))
        self.assertEqual(store_files(self.home), [])

    def test_spawn_ordinal_counts_up_within_a_session(self):
        for expected in range(3):
            record = write_record(self.home, intent(run_id=f"run-{expected}"))
            self.assertEqual(record["spawn_ordinal"], expected)

    def test_spawn_ordinal_is_counted_per_session_not_globally(self):
        write_record(self.home, intent(run_id="a1", session_id="sess-a"))
        write_record(self.home, intent(run_id="a2", session_id="sess-a"))
        first_b = write_record(self.home, intent(run_id="b1", session_id="sess-b"))
        second_b = write_record(self.home, intent(run_id="b2", session_id="sess-b"))
        third_a = write_record(self.home, intent(run_id="a3", session_id="sess-a"))
        self.assertEqual(first_b["spawn_ordinal"], 0)
        self.assertEqual(second_b["spawn_ordinal"], 1)
        self.assertEqual(third_a["spawn_ordinal"], 2)

    def test_an_explicit_spawn_ordinal_is_preserved(self):
        record = write_record(self.home, intent(spawn_ordinal=7))
        self.assertEqual(record["spawn_ordinal"], 7)

    def test_outcome_ordinals_are_assigned_in_sequence_per_run(self):
        write_record(self.home, intent())
        first = write_record(self.home, outcome(terminal=False, disposition="parked"))
        second = write_record(self.home, outcome(terminal=False, disposition="parked"))
        third = write_record(self.home, outcome(terminal=True))
        self.assertEqual(
            [first["outcome_ordinal"], second["outcome_ordinal"], third["outcome_ordinal"]],
            [0, 1, 2],
        )

    def test_a_second_terminal_outcome_for_one_run_is_refused(self):
        write_record(self.home, intent())
        write_record(self.home, outcome(terminal=True))
        with self.assertRaisesRegex(RecordError, "already carries a terminal outcome"):
            write_record(self.home, outcome(terminal=True, disposition="rejected"))
        self.assertEqual(len(self.lines()), 2)

    def test_two_runs_may_each_carry_their_own_terminal_outcome(self):
        write_record(self.home, intent(run_id="run-1"))
        write_record(self.home, intent(run_id="run-2"))
        write_record(self.home, outcome(run_id="run-1", terminal=True))
        write_record(self.home, outcome(run_id="run-2", terminal=True))
        self.assertEqual(len(self.lines()), 4)

    def test_an_outcome_without_an_intent_is_refused_by_default(self):
        with self.assertRaisesRegex(RecordError, "no intent record"):
            write_record(self.home, outcome(run_id="ghost"))
        self.assertEqual(store_files(self.home), [])

    def test_allow_orphan_records_the_outcome_and_flags_it(self):
        record = write_record(self.home, outcome(run_id="ghost"), allow_orphan=True)
        self.assertIs(record["orphan"], True)

    def test_a_non_orphan_outcome_carries_no_orphan_flag(self):
        write_record(self.home, intent())
        record = write_record(self.home, outcome(), allow_orphan=True)
        self.assertNotIn("orphan", record)

    def test_the_orphan_flag_is_the_writers_finding_not_the_callers_claim(self):
        write_record(self.home, intent())
        record = write_record(self.home, outcome(orphan=True))
        self.assertNotIn("orphan", record)


class LockTests(StoreTestCase):
    def test_the_lock_is_released_when_the_block_exits(self):
        self.home.mkdir(parents=True)
        with store_lock(self.home) as lock:
            self.assertTrue(lock.path.exists())
        self.assertFalse((self.home / LOCK_NAME).exists())

    def test_a_held_lock_makes_a_second_writer_give_up_rather_than_interleave(self):
        self.home.mkdir(parents=True)
        with store_lock(self.home):
            with self.assertRaisesRegex(RecordError, "lock"):
                with store_lock(self.home, timeout=0.05):
                    self.fail("the second writer must not acquire a held lock")

    def test_a_stale_lock_is_reclaimed_rather_than_wedging_the_store(self):
        self.home.mkdir(parents=True)
        stale = self.home / LOCK_NAME
        stale.write_text("", encoding="utf-8")
        import os as _os

        _os.utime(stale, (0, 0))
        with store_lock(self.home, timeout=0.05):
            pass
        self.assertFalse(stale.exists())

    def test_concurrent_writers_produce_whole_lines_and_no_lost_records(self):
        writer = (
            "import sys; sys.path.insert(0, %r)\n"
            "from intent_writer import write_record\n"
            "home = __import__('pathlib').Path(%r)\n"
            "for i in range(15):\n"
            "    write_record(home, {\n"
            "        'kind': 'intent', 'run_id': f'{sys.argv[1]}-{i}',\n"
            "        'session_id': sys.argv[1],\n"
            "        'task_class': {'class': None, 'class_free': 'sweep'},\n"
            "        'requested_model': {'id': 'anthropic:claude-sonnet-5', 'raw': 'sonnet'},\n"
            "        'requested_effort': 'medium', 'surface': 'generic',\n"
            "        'harness_contract': {'sha256': %r, 'label': 'l',\n"
            "            'features': {'review_gate': False, 'claim_tagging': False,\n"
            "                         'tool_profile': 'ro'}},\n"
            "    })\n"
        ) % (str(ENTRYPOINT.parent), str(self.home), SHA)
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", writer, name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for name in ("alpha", "beta")
        ]
        for proc in procs:
            _, err = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0, err.decode())
        records = self.lines()
        self.assertEqual(len(records), 30)
        self.assertEqual(len({record["event_id"] for record in records}), 30)
        read_records(store_files(self.home))


class ValidateAndSummarizeTests(StoreTestCase):
    def _corrupt(self, line: str) -> None:
        path = store_files(self.home)[0]
        with path.open("a", encoding="utf-8") as stream:
            stream.write(line + "\n")

    def test_validate_reports_ok_on_a_clean_store(self):
        write_record(self.home, intent())
        write_record(self.home, outcome())
        code, out, _ = self.run_cli("validate")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["records"], 2)

    def test_validate_fails_closed_on_a_hand_added_unknown_field(self):
        write_record(self.home, intent())
        self._corrupt(json.dumps({**complete(intent(run_id="run-9")), "note": "smuggled"}))
        code, _, err = self.run_cli("validate")
        self.assertEqual(code, 1)
        self.assertIn("line 2", err)
        self.assertIn("unknown fields", err)

    def test_validate_fails_closed_on_a_hand_corrupted_json_line(self):
        write_record(self.home, intent())
        self._corrupt('{"kind": "intent", ')
        code, _, err = self.run_cli("validate")
        self.assertEqual(code, 1)
        self.assertIn("malformed JSON", err)

    def test_validate_fails_closed_on_an_out_of_enum_value(self):
        write_record(self.home, intent())
        self._corrupt(json.dumps(complete(intent(run_id="run-9"), requested_effort="turbo")))
        code, _, err = self.run_cli("validate")
        self.assertEqual(code, 1)
        self.assertIn("requested_effort", err)

    def test_validate_catches_a_duplicate_event_id_written_around_the_writer(self):
        first = write_record(self.home, intent())
        self._corrupt(json.dumps(complete(intent(run_id="run-9"), event_id=first["event_id"])))
        code, _, err = self.run_cli("validate")
        self.assertEqual(code, 1)
        self.assertIn("duplicate event_id", err)

    def test_validate_catches_a_second_terminal_outcome_written_around_the_writer(self):
        write_record(self.home, intent())
        write_record(self.home, outcome(terminal=True))
        self._corrupt(json.dumps(complete(outcome(disposition="rejected"), outcome_ordinal=1)))
        code, _, err = self.run_cli("validate")
        self.assertEqual(code, 1)
        self.assertIn("second terminal outcome", err)

    def test_summarize_counts_by_kind_disposition_surface_and_route(self):
        write_record(self.home, intent(route_id="R15", surface="pin"))
        write_record(self.home, intent(run_id="run-2", route_id="R15", surface="generic"))
        write_record(self.home, intent(run_id="run-3", route_id="none-consulted", surface="pin"))
        write_record(self.home, outcome(run_id="run-2", disposition="rejected"))
        report = summarize(self.home)
        self.assertEqual(report["record_count"], 4)
        self.assertEqual(report["run_count"], 3)
        self.assertEqual(report["by_kind"], {"intent": 3, "outcome": 1})
        self.assertEqual(report["by_disposition"], {"rejected": 1})
        self.assertEqual(report["by_surface"], {"pin": 2, "generic": 1})
        self.assertEqual(report["by_route_id"], {"R15": 2, "none-consulted": 1})

    def test_summarize_on_an_empty_store_reports_zero_rather_than_failing(self):
        report = summarize(self.home)
        self.assertEqual(report["record_count"], 0)
        self.assertEqual(report["by_kind"], {})


class CliTests(StoreTestCase):
    INTENT_ARGV = (
        "record-intent",
        "--run-id",
        "run-1",
        "--session-id",
        "sess-1",
        "--task-class",
        "bounded-implementation",
        "--requested-effort",
        "high",
        "--surface",
        "per-call",
        "--harness-sha256",
        SHA,
        "--harness-label",
        "implementer v1",
        "--harness-review-gate",
        "true",
        "--harness-claim-tagging",
        "false",
        "--harness-tool-profile",
        "rw",
    )

    def test_record_intent_from_flags_prints_the_event_id(self):
        code, out, _ = self.run_cli(*self.INTENT_ARGV, "--requested-model", "terra")
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip()), 26)
        record = self.lines()[0]
        self.assertEqual(record["requested_model"]["id"], "openai:gpt-5.6-terra")
        self.assertEqual(record["task_class"], {"class": None, "class_free": "bounded-implementation"})

    def test_record_intent_requires_a_model_or_the_explicit_inherited_flag(self):
        code, _, err = self.run_cli(*self.INTENT_ARGV)
        self.assertEqual(code, 1)
        self.assertIn("exactly one of", err)

    def test_session_inherited_model_records_a_null_requested_model(self):
        code, _, _ = self.run_cli(*self.INTENT_ARGV, "--session-inherited-model")
        self.assertEqual(code, 0)
        self.assertIsNone(self.lines()[0]["requested_model"])

    def test_missing_required_intent_flags_are_named(self):
        code, _, err = self.run_cli("record-intent", "--run-id", "run-1")
        self.assertEqual(code, 1)
        self.assertIn("--task-class", err)

    def test_json_and_record_flags_may_not_be_combined(self):
        code, _, err = self.run_cli(
            "record-intent", "--json", json.dumps(intent()), "--run-id", "run-1"
        )
        self.assertEqual(code, 1)
        self.assertIn("not both", err)

    def test_record_intent_accepts_a_full_record_as_json(self):
        code, _, _ = self.run_cli(
            "record-intent", "--json", json.dumps(intent(route_id="R15", warrant_ids=["W-001"]))
        )
        self.assertEqual(code, 0)
        self.assertEqual(self.lines()[0]["warrant_ids"], ["W-001"])

    def test_json_with_the_wrong_kind_is_refused(self):
        code, _, err = self.run_cli("record-intent", "--json", json.dumps(outcome()))
        self.assertEqual(code, 1)
        self.assertIn("kind must be", err)

    def test_malformed_json_is_reported_not_raised(self):
        code, _, err = self.run_cli("record-intent", "--json", "{oops")
        self.assertEqual(code, 1)
        self.assertIn("not valid JSON", err)

    def test_record_outcome_requires_exactly_one_terminality_flag(self):
        self.run_cli(*self.INTENT_ARGV, "--requested-model", "terra")
        code, _, err = self.run_cli(
            "record-outcome", "--run-id", "run-1", "--disposition", "accepted"
        )
        self.assertEqual(code, 1)
        self.assertIn("--terminal", err)

    def test_record_outcome_pairs_the_observed_model_with_its_identity_source(self):
        self.run_cli(*self.INTENT_ARGV, "--requested-model", "terra")
        code, _, err = self.run_cli(
            "record-outcome",
            "--run-id",
            "run-1",
            "--disposition",
            "accepted",
            "--terminal",
            "--observed-model",
            "terra",
        )
        self.assertEqual(code, 1)
        self.assertIn("identity-source", err)

    def test_record_outcome_from_flags_writes_a_valid_record(self):
        self.run_cli(*self.INTENT_ARGV, "--requested-model", "terra")
        code, _, _ = self.run_cli(
            "record-outcome",
            "--run-id",
            "run-1",
            "--disposition",
            "accepted",
            "--terminal",
            "--observed-model",
            "gpt-5-6-terra",
            "--observed-identity-source",
            "transcript",
        )
        self.assertEqual(code, 0)
        record = self.lines()[1]
        self.assertEqual(record["observed_model"]["id"], "openai:gpt-5.6-terra")
        self.assertIs(record["terminal"], True)

    def test_record_outcome_without_a_model_records_an_explicit_null(self):
        self.run_cli(*self.INTENT_ARGV, "--requested-model", "terra")
        code, _, _ = self.run_cli(
            "record-outcome", "--run-id", "run-1", "--disposition", "error", "--non-terminal"
        )
        self.assertEqual(code, 0)
        self.assertIn("observed_model", self.lines()[1])
        self.assertIsNone(self.lines()[1]["observed_model"])

    def test_orphan_outcome_is_refused_until_allow_orphan_is_passed(self):
        argv = (
            "record-outcome",
            "--run-id",
            "ghost",
            "--disposition",
            "accepted",
            "--terminal",
            "--observed-model",
            "anthropic:claude-opus-5",
            "--observed-identity-source",
            "transcript",
        )
        code, _, err = self.run_cli(*argv)
        self.assertEqual(code, 1)
        self.assertIn("--allow-orphan", err)
        code, _, _ = self.run_cli(*argv, "--allow-orphan")
        self.assertEqual(code, 0)
        self.assertIs(self.lines()[0]["orphan"], True)

    def test_validate_accepts_a_single_file_argument(self):
        write_record(self.home, intent())
        code, out, _ = self.run_cli("validate", "--file", str(store_files(self.home)[0]))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["files"], 1)

    def test_validate_reports_a_missing_file_instead_of_crashing(self):
        code, _, err = self.run_cli("validate", "--file", str(self.home / "nope.jsonl"))
        self.assertEqual(code, 1)
        self.assertIn("does not exist", err)

    def test_summarize_prints_json(self):
        write_record(self.home, intent())
        code, out, _ = self.run_cli("summarize")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["by_kind"], {"intent": 1})

    def test_the_entrypoint_runs_as_a_script(self):
        result = subprocess.run(
            [sys.executable, str(ENTRYPOINT), "summarize", "--home", str(self.home)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["record_count"], 0)


class FreeCodeRuleTests(unittest.TestCase):
    """R1 F-1: the `reason_code` treatment extended to every free-code field,
    applied at write time so a native store is exportable-by-construction."""

    def test_scalar_free_code_fields_reject_raw_operational_strings(self):
        # The exact values the R1 probe smuggled through: a repo-relative test
        # path and a merge-state sentence.
        for field, value in (
            ("validation_oracle", "tests/test_gate2_slice_a.py::test_budget"),
            ("closure_target", "PR-441-merged-and-green"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(RecordError, field):
                validate_record(complete(intent(**{field: value})))

    def test_scalar_free_code_fields_accept_the_free_slot_pair(self):
        for field in ("validation_oracle", "closure_target"):
            with self.subTest(field=field):
                validate_record(
                    complete(intent(**{field: "other", f"{field}_free": "tests/test_x.py"}))
                )

    def test_scalar_free_slot_requires_the_base_field_to_be_other(self):
        for field in ("validation_oracle", "closure_target"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(RecordError, f"{field}_free"):
                    validate_record(complete(intent(**{f"{field}_free": "anything"})))

    def test_a_registered_scalar_member_is_accepted_once_a_vocabulary_exists(self):
        with unittest.mock.patch.object(
            intent_writer, "REGISTERED_VALIDATION_ORACLES", frozenset({"unit-tests"})
        ):
            validate_record(complete(intent(validation_oracle="unit-tests")))
            with self.assertRaisesRegex(RecordError, "validation_oracle_free"):
                validate_record(
                    complete(intent(validation_oracle="unit-tests", validation_oracle_free="x"))
                )

    def test_list_free_code_fields_reject_raw_elements(self):
        for field, value in (
            ("friction_codes", "reviewer-disagreed-on-scope-in-round-2"),
            ("confounder_codes", "ran/under/gateway@cliproxy:8317"),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(RecordError, field):
                validate_record(complete(outcome(**{field: [value]})))

    def test_list_free_code_fields_accept_other_with_an_aligned_free_list(self):
        validate_record(
            complete(
                outcome(
                    friction_codes=["other"],
                    friction_codes_free=["reviewer disagreed on scope in round 2"],
                )
            )
        )

    def test_a_free_list_must_match_its_base_list_length(self):
        for free in ([], ["a", "b"]):
            with self.subTest(free=free):
                with self.assertRaisesRegex(RecordError, "same length"):
                    validate_record(
                        complete(outcome(friction_codes=["other"], friction_codes_free=free))
                    )

    def test_a_free_list_without_its_base_list_is_rejected(self):
        with self.assertRaisesRegex(RecordError, "requires friction_codes"):
            validate_record(complete(outcome(friction_codes_free=["x"])))

    def test_a_free_slot_is_null_where_the_element_is_not_other(self):
        with unittest.mock.patch.object(
            intent_writer, "REGISTERED_FRICTION_CODES", frozenset({"rate-limit"})
        ):
            validate_record(
                complete(
                    outcome(
                        friction_codes=["rate-limit", "other"],
                        friction_codes_free=[None, "something local"],
                    )
                )
            )
            with self.assertRaisesRegex(RecordError, r"friction_codes_free\[0\]"):
                validate_record(
                    complete(
                        outcome(
                            friction_codes=["rate-limit", "other"],
                            friction_codes_free=["leaked", "something local"],
                        )
                    )
                )

    def test_the_write_path_applies_the_rule_not_just_validate(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        home = Path(temp.name) / "v2"
        with self.assertRaisesRegex(RecordError, "validation_oracle"):
            write_record(home, intent(validation_oracle="tests/test_budget.py::test_x"))
        self.assertEqual(store_files(home), [])


class ObservedModelGateTests(StoreTestCase):
    """R1 F-3 / F-10."""

    def test_null_is_legal_only_on_the_four_unobservable_dispositions(self):
        self.assertEqual(
            sorted(UNOBSERVABLE_DISPOSITIONS), ["abandoned", "blocked", "error", "interrupted"]
        )
        for value in sorted(UNOBSERVABLE_DISPOSITIONS):
            fixed = DISPOSITION_PAIRINGS.get(value, {})
            with self.subTest(disposition=value):
                validate_record(
                    complete(
                        outcome(
                            disposition=value,
                            terminal=fixed.get("terminal", True),
                            observed_model=None,
                        )
                    )
                )

    def test_null_is_rejected_on_every_other_disposition(self):
        for value in sorted(DISPOSITIONS - UNOBSERVABLE_DISPOSITIONS):
            fixed = DISPOSITION_PAIRINGS.get(value, {})
            with self.subTest(disposition=value):
                with self.assertRaisesRegex(RecordError, "observed_model may be null"):
                    validate_record(
                        complete(
                            outcome(
                                disposition=value,
                                terminal=fixed.get("terminal", True),
                                observed_model=None,
                            )
                        )
                    )

    def test_the_bare_flag_path_errors_instead_of_writing_null(self):
        self.run_cli(*CliTests.INTENT_ARGV, "--requested-model", "terra")
        code, _, err = self.run_cli(
            "record-outcome", "--run-id", "run-1", "--disposition", "accepted", "--terminal"
        )
        self.assertEqual(code, 1)
        self.assertIn("--observed-model is required", err)
        self.assertEqual(len(self.lines()), 1)

    def test_the_flag_path_still_allows_omission_on_an_unobservable_disposition(self):
        self.run_cli(*CliTests.INTENT_ARGV, "--requested-model", "terra")
        code, _, _ = self.run_cli(
            "record-outcome", "--run-id", "run-1", "--disposition", "blocked", "--terminal"
        )
        self.assertEqual(code, 0)
        self.assertIsNone(self.lines()[1]["observed_model"])

    def test_observed_model_accepts_an_optional_raw_spelling(self):
        validate_record(
            complete(
                outcome(
                    observed_model={
                        "id": "openai:gpt-5.6-terra",
                        "identity_source": "transcript",
                        "raw": "terra",
                    }
                )
            )
        )

    def test_observed_model_raw_must_be_bounded_text(self):
        with self.assertRaisesRegex(RecordError, "observed_model.raw"):
            validate_record(
                complete(
                    outcome(
                        observed_model={
                            "id": "openai:gpt-5.6-terra",
                            "identity_source": "transcript",
                            "raw": "x" * 129,
                        }
                    )
                )
            )

    def test_the_flag_path_preserves_the_typed_spelling_as_raw(self):
        self.run_cli(*CliTests.INTENT_ARGV, "--requested-model", "terra")
        self.run_cli(
            "record-outcome", "--run-id", "run-1", "--disposition", "accepted", "--terminal",
            "--observed-model", "gpt-5-6-terra", "--observed-identity-source", "transcript",
        )
        observed = self.lines()[1]["observed_model"]
        self.assertEqual(observed["id"], "openai:gpt-5.6-terra")
        self.assertEqual(observed["raw"], "gpt-5-6-terra")


class DispositionPairingTests(unittest.TestCase):
    """R1 F-11: crosswalk §3a binds native records."""

    def test_the_bound_dispositions_are_exactly_the_single_row_ones(self):
        self.assertEqual(
            sorted(DISPOSITION_PAIRINGS), ["accepted", "interrupted", "parked", "rejected"]
        )

    def test_each_bound_disposition_accepts_its_fixed_pair(self):
        for value, fixed in DISPOSITION_PAIRINGS.items():
            with self.subTest(disposition=value):
                validate_record(
                    complete(
                        outcome(
                            disposition=value,
                            terminal=fixed["terminal"],
                            rework_actor=fixed["rework_actor"],
                            observed_model=None
                            if value in UNOBSERVABLE_DISPOSITIONS
                            else {"id": "anthropic:claude-opus-5", "identity_source": "api"},
                        )
                    )
                )

    def test_a_contradicting_terminal_flag_is_rejected(self):
        for value, fixed in DISPOSITION_PAIRINGS.items():
            with self.subTest(disposition=value):
                with self.assertRaisesRegex(RecordError, "§3a fixes terminal"):
                    validate_record(
                        complete(
                            outcome(
                                disposition=value,
                                terminal=not fixed["terminal"],
                                observed_model=None
                                if value in UNOBSERVABLE_DISPOSITIONS
                                else {"id": "anthropic:claude-opus-5", "identity_source": "api"},
                            )
                        )
                    )

    def test_a_contradicting_rework_actor_is_rejected(self):
        with self.assertRaisesRegex(RecordError, "§3a fixes rework_actor"):
            validate_record(complete(outcome(disposition="accepted", rework_actor="delegate")))

    def test_accepted_after_rework_is_left_free_on_both_axes(self):
        # Three §3a rows map onto it with disagreeing values, so it fixes nothing.
        for terminal, actor in ((False, "unknown"), (True, "delegate"), (True, "root")):
            with self.subTest(terminal=terminal, actor=actor):
                validate_record(
                    complete(
                        outcome(
                            disposition="accepted-after-rework",
                            terminal=terminal,
                            rework_actor=actor,
                        )
                    )
                )

    def test_dispositions_absent_from_the_table_are_unconstrained(self):
        for value in ("blocked", "error", "abandoned", "completed-unknown"):
            for terminal in (True, False):
                with self.subTest(disposition=value, terminal=terminal):
                    validate_record(
                        complete(
                            outcome(
                                disposition=value,
                                terminal=terminal,
                                rework_actor="delegate",
                                # `completed-unknown` is outside the §3a table
                                # but also outside the null carve-out.
                                observed_model=None
                                if value in UNOBSERVABLE_DISPOSITIONS
                                else {
                                    "id": "anthropic:claude-opus-5",
                                    "identity_source": "transcript",
                                },
                            )
                        )
                    )


class ClosedShapeTests(unittest.TestCase):
    """R1 F-6, F-9, F-12."""

    def test_harness_features_reject_any_key_outside_the_three(self):
        contract = {
            "sha256": SHA,
            "label": "x",
            "features": {
                "review_gate": True,
                "claim_tagging": True,
                "tool_profile": "ro",
                "client_codename": "projectX",
            },
        }
        with self.assertRaisesRegex(RecordError, "client_codename"):
            validate_record(complete(intent(harness_contract=contract)))

    def test_harness_features_accept_exactly_the_three(self):
        validate_record(complete(intent()))

    def test_note_hash_accepts_a_sha256_digest(self):
        validate_record(complete(intent(reason_code="other", note_hash="a" * 64)))

    def test_note_hash_rejects_anything_that_is_not_a_digest(self):
        for bad in ("nope", "A" * 64, "a" * 63, 12345):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "note_hash"):
                validate_record(complete(intent(note_hash=bad)))

    def test_router_model_accepts_the_human_literal(self):
        validate_record(complete(intent(router_model="human")))

    def test_router_model_still_requires_a_binding_otherwise(self):
        for bad in ("Human", "a person", "claude-opus-5"):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "router_model"):
                validate_record(complete(intent(router_model=bad)))


class JoinKeyTests(StoreTestCase):
    """R1 F-5."""

    def test_an_explicit_duplicate_join_key_is_refused_at_write(self):
        write_record(self.home, intent())
        write_record(self.home, outcome(terminal=False, disposition="parked", outcome_ordinal=0))
        with self.assertRaisesRegex(RecordError, "already carries outcome_ordinal"):
            write_record(self.home, outcome(terminal=True, outcome_ordinal=0))
        self.assertEqual(len(self.lines()), 2)

    def test_the_same_ordinal_under_a_different_run_is_fine(self):
        write_record(self.home, intent(run_id="run-1"))
        write_record(self.home, intent(run_id="run-2"))
        write_record(self.home, outcome(run_id="run-1", outcome_ordinal=0))
        write_record(self.home, outcome(run_id="run-2", outcome_ordinal=0))
        self.assertEqual(len(self.lines()), 4)

    def test_validate_catches_a_duplicate_join_key_written_around_the_writer(self):
        write_record(self.home, intent())
        write_record(self.home, outcome(terminal=False, disposition="parked", outcome_ordinal=0))
        path = store_files(self.home)[0]
        with path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(complete(outcome(terminal=False, disposition="parked"), outcome_ordinal=0))
                + "\n"
            )
        code, _, err = self.run_cli("validate")
        self.assertEqual(code, 1)
        self.assertIn("duplicate (run_id, outcome_ordinal)", err)


class SpawnOrdinalAcrossMonthsTests(StoreTestCase):
    """R1 F-4."""

    def test_the_counter_does_not_restart_at_a_month_boundary(self):
        first = write_record(self.home, intent(run_id="r1", ts="2026-06-30T23:59:59Z"))
        second = write_record(self.home, intent(run_id="r2", ts="2026-07-01T00:00:01Z"))
        third = write_record(self.home, intent(run_id="r3", ts="2026-07-01T00:00:02Z"))
        self.assertEqual(
            [first["spawn_ordinal"], second["spawn_ordinal"], third["spawn_ordinal"]], [0, 1, 2]
        )
        self.assertEqual(len(store_files(self.home)), 2)

    def test_sessions_stay_independent_across_month_files(self):
        write_record(self.home, intent(run_id="a1", session_id="a", ts="2026-06-30T23:00:00Z"))
        other = write_record(
            self.home, intent(run_id="b1", session_id="b", ts="2026-07-01T01:00:00Z")
        )
        self.assertEqual(other["spawn_ordinal"], 0)


class DurableWriteTests(StoreTestCase):
    """R1 F-7, F-8."""

    def test_a_short_append_is_rolled_back_and_the_store_stays_readable(self):
        write_record(self.home, intent())
        path = store_files(self.home)[0]
        before = path.stat().st_size
        real_write = os.write

        def short_write(fd, data):
            # Only truncate record lines; the lock sentinel must write in full.
            if data.endswith(b"\n"):
                return real_write(fd, data[: len(data) // 2])
            return real_write(fd, data)

        with unittest.mock.patch.object(intent_writer.os, "write", short_write):
            with self.assertRaisesRegex(RecordError, "short append"):
                write_record(self.home, intent(run_id="short"))
        self.assertEqual(path.stat().st_size, before)
        self.assertEqual(len(read_records(store_files(self.home))), 1)

    def test_a_writer_does_not_release_a_sentinel_it_no_longer_owns(self):
        self.home.mkdir(parents=True)
        first = store_lock(self.home)
        first.__enter__()
        os.utime(self.home / LOCK_NAME, (0, 0))
        second = store_lock(self.home, timeout=0.5)
        second.__enter__()
        try:
            first.__exit__()
            self.assertTrue((self.home / LOCK_NAME).exists())
            with self.assertRaisesRegex(RecordError, "lock"):
                store_lock(self.home, timeout=0.05).__enter__()
        finally:
            second.__exit__()
        self.assertFalse((self.home / LOCK_NAME).exists())

    def test_the_sentinel_carries_a_pid_and_nonce(self):
        self.home.mkdir(parents=True)
        with store_lock(self.home) as lock:
            token = lock.path.read_text(encoding="utf-8")
        pid, _, nonce = token.partition(":")
        self.assertEqual(int(pid), os.getpid())
        self.assertEqual(len(nonce), 16)

    def test_two_locks_in_the_same_process_get_distinct_tokens(self):
        self.assertNotEqual(store_lock(self.home).token, store_lock(self.home).token)


class CliSurfaceTests(StoreTestCase):
    """Crosswalk v0.2.2: `surface` gains `cli`."""

    def test_cli_is_a_surface_member(self):
        self.assertIn("cli", SURFACES)

    def test_a_cli_surface_intent_validates_and_writes(self):
        record = write_record(self.home, intent(surface="cli"))
        self.assertEqual(record["surface"], "cli")

    def test_near_misses_are_still_rejected(self):
        for bad in ("CLI", "shell", "cli ", "command-line"):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "surface"):
                validate_record(complete(intent(surface=bad)))

    def test_the_cli_flag_offers_the_new_surface(self):
        argv = list(CliTests.INTENT_ARGV)
        argv[argv.index("--surface") + 1] = "cli"
        code, _, err = self.run_cli(*argv, "--requested-model", "terra")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.lines()[0]["surface"], "cli")

    def test_summarize_counts_the_new_surface(self):
        write_record(self.home, intent(surface="cli"))
        self.assertEqual(summarize(self.home)["by_surface"], {"cli": 1})


class RegisteredFrictionCodeTests(unittest.TestCase):
    """Crosswalk v0.2.2: the first three registered friction-code members."""

    def test_the_three_severe_failure_classes_are_registered(self):
        self.assertEqual(
            sorted(REGISTERED_FRICTION_CODES),
            ["fabricated-completion", "silent-scope-violation", "undetected-omission"],
        )

    def test_each_registered_member_is_accepted_bare(self):
        for code in sorted(REGISTERED_FRICTION_CODES):
            with self.subTest(code=code):
                validate_record(complete(outcome(friction_codes=[code])))

    def test_registered_members_mix_with_the_free_slot(self):
        validate_record(
            complete(
                outcome(
                    friction_codes=["fabricated-completion", "other"],
                    friction_codes_free=[None, "something not yet registered"],
                )
            )
        )

    def test_a_free_slot_beside_a_registered_member_is_still_rejected(self):
        with self.assertRaisesRegex(RecordError, r"friction_codes_free\[0\]"):
            validate_record(
                complete(
                    outcome(
                        friction_codes=["fabricated-completion"],
                        friction_codes_free=["leaked text"],
                    )
                )
            )

    def test_an_unregistered_friction_code_is_still_rejected(self):
        for bad in ("fabricated_completion", "Fabricated-Completion", "slow-reviewer"):
            with self.subTest(bad=bad), self.assertRaisesRegex(RecordError, "friction_codes"):
                validate_record(complete(outcome(friction_codes=[bad])))

    def test_the_confounder_registry_stays_empty_on_the_narrow_reading(self):
        # The §3 row groups the two fields because they share the RULE; it does
        # not say the three members belong to both vocabularies. If that reading
        # is widened, this test is the one that should fail first.
        self.assertEqual(REGISTERED_CONFOUNDER_CODES, frozenset())
        with self.assertRaisesRegex(RecordError, "confounder_codes"):
            validate_record(complete(outcome(confounder_codes=["fabricated-completion"])))
        validate_record(
            complete(
                outcome(
                    confounder_codes=["other"],
                    confounder_codes_free=["fabricated completion, as a confounder"],
                )
            )
        )

    def test_the_attestation_tier_rule_is_not_enforced_by_this_writer(self):
        # The crosswalk pairs these members with a >= third-party-verified
        # requirement. This writer's attestation is the fixed literal
        # `driver-attested`, so enforcing it here would make them unwritable
        # rather than gated; the rule binds the record set consumers read.
        record = validate_record(complete(outcome(friction_codes=["fabricated-completion"])))
        self.assertEqual(record["attestation"], ATTESTATION)


class AliasDataFileTests(StoreTestCase):
    """The shipped `model-aliases.json` payload, exercised against a temp home."""

    PAYLOAD = {
        "terra": "openai:gpt-5.6-terra",
        "gpt-5.6-terra": "openai:gpt-5.6-terra",
        "gpt-5-6-terra": "openai:gpt-5.6-terra",
        "flash": "google:gemini-3.6-flash-high",
    }

    def setUp(self):
        super().setUp()
        self.home.mkdir(parents=True)
        (self.home / "model-aliases.json").write_text(
            json.dumps(self.PAYLOAD), encoding="utf-8"
        )

    def test_every_shipped_alias_resolves_to_its_binding(self):
        aliases = load_aliases(self.home)
        for spelling, binding in self.PAYLOAD.items():
            with self.subTest(spelling=spelling):
                self.assertEqual(normalize_model(spelling, aliases), binding)

    def test_flash_resolves_to_the_served_high_binding(self):
        self.assertEqual(
            normalize_model("flash", load_aliases(self.home)), "google:gemini-3.6-flash-high"
        )

    def test_the_bare_flash_id_is_deliberately_absent_but_still_a_legal_binding(self):
        # W-026: the bare id is not served (gateway README, verified 2026-07-26),
        # so no alias points at it — but it is shape-valid, so a caller who
        # passes it explicitly is not second-guessed by the writer.
        self.assertNotIn("google:gemini-3.6-flash", self.PAYLOAD.values())
        validate_record(
            complete(intent(requested_model={"id": "google:gemini-3.6-flash", "raw": "flash"}))
        )

    def test_an_aliased_flash_spawn_writes_end_to_end(self):
        record = write_record(
            self.home, intent(surface="cli", requested_model={"id": "flash", "raw": "flash"})
        )
        self.assertEqual(record["requested_model"]["id"], "google:gemini-3.6-flash-high")
        self.assertEqual(record["requested_model"]["raw"], "flash")


if __name__ == "__main__":
    unittest.main()
