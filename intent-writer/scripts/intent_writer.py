#!/usr/bin/env python3
"""Driver-side writer for v2 intent/outcome records (crosswalk v0.2, B-7)."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import time


V = "2"
ATTESTATION = "driver-attested"
PROJECTION = "native"
KINDS = ("intent", "outcome", "rekey")
EFFORTS = frozenset(
    {
        "low",
        "medium",
        "high",
        "xhigh",
        "max",
        "session-inherited",
        "unspecified",
        "unknown",
    }
)
SURFACES = frozenset({"pin", "per-call", "generic", "teams", "cowork"})
DISPOSITIONS = frozenset(
    {
        "accepted",
        "accepted-after-rework",
        "rejected",
        "parked",
        "interrupted",
        "blocked",
        "error",
        "abandoned",
        "completed-unknown",
    }
)
REWORK_ACTORS = frozenset({"root", "delegate", "none", "unknown"})
IDENTITY_SOURCES = frozenset({"transcript", "api", "ui-label"})
TOOL_PROFILES = frozenset({"ro", "rw"})
VENDORS = ("anthropic", "openai", "google", "other")
FREE_SLOT = "other"
# Crosswalk §2/§3: the closed vocabularies are unpublished, so `other` + an
# origin-local free slot is the only honest member today.
REGISTERED_REASON_CODES: frozenset[str] = frozenset()
REGISTERED_VALIDATOR_OUTCOMES: frozenset[str] = frozenset()
SEED_MODEL_ALIASES = {
    "terra": "openai:gpt-5.6-terra",
    "gpt-5.6-terra": "openai:gpt-5.6-terra",
    "gpt-5-6-terra": "openai:gpt-5.6-terra",
}
ALIAS_FILE = "model-aliases.json"
STORE_PREFIX = "intents-"
LOCK_NAME = ".intents.lock"
LOCK_TIMEOUT_SECONDS = 5.0
LOCK_POLL_SECONDS = 0.02
STALE_LOCK_SECONDS = 30.0

CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
BINDING_RE = re.compile(rf"^({'|'.join(VENDORS)}):[A-Za-z0-9][A-Za-z0-9._+-]{{0,63}}$")
ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
WARRANT_RE = re.compile(r"^W-\d{3}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
SIG_RE = re.compile(r"^[A-Za-z0-9+/=_-]{1,512}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

COMMON = {
    "v",
    "kind",
    "event_id",
    "ts",
    "origin",
    "run_id",
    "session_id",
    "attestation",
    "projection",
}
INTENT_FIELDS = COMMON | {
    "spawn_ordinal",
    "task_class",
    "requested_model",
    "requested_effort",
    "surface",
    "harness_contract",
    "route_id",
    "warrant_ids",
    "rung",
    "router_effort",
    "router_model",
    "reason_code",
    "reason_code_free",
    "price_lineage",
    "reversibility",
    "consequence",
    "ambiguity",
    "validation_oracle",
    "closure_target",
    "write_scope_count",
}
OUTCOME_FIELDS = COMMON | {
    "outcome_ordinal",
    "terminal",
    "orphan",
    "disposition",
    "observed_model",
    "observed_effort",
    "tokens",
    "cost_usd",
    "rework_actor",
    "rework_count",
    "validator",
    "friction_codes",
    "confounder_codes",
}
# Crosswalk §1 enumerates the rekey field set exactly; it carries no run_id,
# attestation, or projection.
REKEY_FIELDS = {"v", "kind", "event_id", "ts", "origin", "mappings", "sig"}
ALLOWED = {
    "intent": frozenset(INTENT_FIELDS),
    "outcome": frozenset(OUTCOME_FIELDS),
    "rekey": frozenset(REKEY_FIELDS),
}
REQUIRED = {
    "intent": frozenset(
        {
            "v",
            "kind",
            "event_id",
            "ts",
            "run_id",
            "attestation",
            "projection",
            "spawn_ordinal",
            "task_class",
            "requested_model",
            "requested_effort",
            "surface",
            "harness_contract",
        }
    ),
    "outcome": frozenset(
        {
            "v",
            "kind",
            "event_id",
            "ts",
            "run_id",
            "attestation",
            "projection",
            "outcome_ordinal",
            "terminal",
            "disposition",
            # Crosswalk §3 marks this REQ; SPEC.md listed it optional. The
            # crosswalk is the authority, so the key must be stated — null is a
            # legal statement, silence is not.
            "observed_model",
        }
    ),
    "rekey": frozenset(REKEY_FIELDS),
}


class RecordError(ValueError):
    """A fail-closed rejection of a record, a store line, or a CLI invocation."""


def _b32(value: int, length: int) -> str:
    chars = []
    for _ in range(length):
        chars.append(CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(chars))


def ulid(now_ms: int | None = None) -> str:
    """Crockford base32 ULID: 48-bit millisecond prefix + 80 random bits."""
    stamp = int(time.time() * 1000) if now_ms is None else now_ms
    if not 0 <= stamp < (1 << 48):
        raise RecordError("ulid timestamp out of range")
    return _b32(stamp, 10) + _b32(int.from_bytes(os.urandom(10), "big"), 16)


def ulid_time_ms(value: str) -> int:
    if not ULID_RE.fullmatch(value):
        raise RecordError("event_id must be a 26-character Crockford base32 ULID")
    stamp = 0
    for char in value[:10]:
        stamp = stamp * 32 + CROCKFORD.index(char)
    return stamp


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def home_path(raw: str | None = None) -> Path:
    value = raw or os.environ.get("DELEGATION_V2_HOME")
    return Path(value).expanduser() if value else Path.home() / ".delegation" / "v2"


def ensure_home(home: Path) -> None:
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(home, 0o700)


def store_path(home: Path, ts: str) -> Path:
    _check_ts(ts)
    return home / f"{STORE_PREFIX}{ts[:7]}.jsonl"


def store_files(home: Path) -> list[Path]:
    return sorted(home.glob(f"{STORE_PREFIX}*.jsonl"))


def _check_literal(value: object, field: str, expected: str) -> None:
    if value != expected:
        raise RecordError(f"{field} must be {expected!r}")


def _check_enum(value: object, field: str, allowed) -> None:
    if not isinstance(value, str) or value not in allowed:
        raise RecordError(f"{field} must be one of {sorted(allowed)}")


def _check_code(value: object, field: str) -> None:
    if not isinstance(value, str) or not CODE_RE.fullmatch(value):
        raise RecordError(f"{field} must be a bounded operational code")


def _check_text(value: object, field: str, *, maxlen: int) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RecordError(f"{field} must be a nonempty string")
    if len(value) > maxlen:
        raise RecordError(f"{field} exceeds {maxlen} characters")
    if CONTROL_RE.search(value):
        raise RecordError(f"{field} must not contain control characters")


def _check_bool(value: object, field: str) -> None:
    if type(value) is not bool:
        raise RecordError(f"{field} must be boolean")


def _check_int(value: object, field: str, *, minimum: int = 0) -> None:
    if type(value) is not int or value < minimum:
        raise RecordError(f"{field} must be an integer >= {minimum}")


def _check_number(value: object, field: str, *, minimum: float = 0.0) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < minimum:
        raise RecordError(f"{field} must be a number >= {minimum}")


def _check_pattern(value: object, field: str, pattern: re.Pattern[str], hint: str) -> None:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise RecordError(f"{field} must be {hint}")


def _check_ts(value: object, field: str = "ts") -> None:
    _check_pattern(value, field, TS_RE, "ISO-8601 UTC ending in Z")
    try:
        datetime.fromisoformat(str(value)[:-1])
    except ValueError as exc:
        raise RecordError(f"{field} is not a real timestamp") from exc


def _check_object(value: object, field: str, required=(), optional=()) -> dict:
    if not isinstance(value, dict):
        raise RecordError(f"{field} must be an object")
    unknown = set(value) - set(required) - set(optional)
    if unknown:
        raise RecordError(f"{field}: unknown fields rejected: {sorted(unknown)}")
    missing = set(required) - set(value)
    if missing:
        raise RecordError(f"{field}: missing fields: {sorted(missing)}")
    return value


def _check_registered(value: object, field: str, registered) -> None:
    if not isinstance(value, str) or (value != FREE_SLOT and value not in registered):
        raise RecordError(
            f"{field} must be a registered vocabulary member or {FREE_SLOT!r}"
        )


def _check_code_list(value: object, field: str, *, limit: int = 16) -> None:
    if not isinstance(value, list) or len(value) > limit or len(set(map(repr, value))) != len(value):
        raise RecordError(f"{field} must be a unique list of at most {limit} codes")
    for item in value:
        _check_code(item, field)


def _check_warrant_ids(value: object) -> None:
    if not isinstance(value, list) or len(value) > 32 or len(set(map(repr, value))) != len(value):
        raise RecordError("warrant_ids must be a unique list of at most 32 W-IDs")
    for item in value:
        _check_pattern(item, "warrant_ids", WARRANT_RE, "a W-NNN warrant id")


def _check_task_class(value: object) -> None:
    task_class = _check_object(value, "task_class", ("class_free",), ("class",))
    _check_text(task_class["class_free"], "task_class.class_free", maxlen=128)
    if task_class.get("class") is not None:
        raise RecordError(
            "task_class.class stays null until the closed enum is published (crosswalk §2a)"
        )


HARNESS_CORE_FEATURES = ("review_gate", "claim_tagging", "tool_profile")


def _check_harness_contract(value: object) -> None:
    contract = _check_object(value, "harness_contract", ("sha256", "label", "features"))
    _check_pattern(contract["sha256"], "harness_contract.sha256", SHA256_RE, "64 hex characters")
    _check_text(contract["label"], "harness_contract.label", maxlen=80)
    features = contract["features"]
    if not isinstance(features, dict):
        raise RecordError("harness_contract.features must be an object")
    missing = set(HARNESS_CORE_FEATURES) - set(features)
    if missing:
        raise RecordError(f"harness_contract.features: missing fields: {sorted(missing)}")
    _check_bool(features["review_gate"], "harness_contract.features.review_gate")
    _check_bool(features["claim_tagging"], "harness_contract.features.claim_tagging")
    _check_enum(
        features["tool_profile"], "harness_contract.features.tool_profile", TOOL_PROFILES
    )
    for name, item in features.items():
        if name in HARNESS_CORE_FEATURES:
            continue
        _check_code(name, "harness_contract.features key")
        if type(item) is bool:
            continue
        if not isinstance(item, str) or len(item) > 32 or not CODE_RE.fullmatch(item):
            raise RecordError(
                f"harness_contract.features.{name} must be a bool or a short enum string"
            )


def _check_binding(value: object, field: str) -> None:
    _check_pattern(value, field, BINDING_RE, "a normalized vendor:model binding")


def _check_requested_model(value: object) -> None:
    # Null is the session-inherited spawn: the driver requested no model at all
    # (crosswalk §2 — S2's 330/724 null `model_requested`). Recording that
    # honestly is the point of a driver-side writer, so the key stays REQ and
    # only the value may be absent.
    if value is None:
        return
    model = _check_object(value, "requested_model", ("id", "raw"))
    _check_binding(model["id"], "requested_model.id")
    _check_text(model["raw"], "requested_model.raw", maxlen=128)


def _check_observed_model(value: object) -> None:
    # REQ per crosswalk §3, nullable for the run where nothing was observed
    # (error / blocked before any model answered) — see README.
    if value is None:
        return
    model = _check_object(value, "observed_model", ("id", "identity_source"))
    _check_binding(model["id"], "observed_model.id")
    _check_enum(model["identity_source"], "observed_model.identity_source", IDENTITY_SOURCES)


def _check_tokens(value: object) -> None:
    tokens = _check_object(value, "tokens", (), ("in", "out", "cache_r", "cache_w"))
    for name, item in tokens.items():
        if item is None:
            continue
        _check_int(item, f"tokens.{name}")


def _check_validator(value: object) -> None:
    validator = _check_object(value, "validator", ("id", "outcome"), ("outcome_free",))
    _check_code(validator["id"], "validator.id")
    _check_registered(validator["outcome"], "validator.outcome", REGISTERED_VALIDATOR_OUTCOMES)
    if "outcome_free" in validator:
        if validator["outcome"] != FREE_SLOT:
            raise RecordError(
                f"validator.outcome_free is allowed only when validator.outcome is {FREE_SLOT!r}"
            )
        _check_text(validator["outcome_free"], "validator.outcome_free", maxlen=256)


def _check_price_lineage(value: object) -> None:
    price = _check_object(
        value,
        "price_lineage",
        ("binding", "price_per_mtok_in", "price_per_mtok_out", "as_of"),
    )
    _check_binding(price["binding"], "price_lineage.binding")
    _check_number(price["price_per_mtok_in"], "price_lineage.price_per_mtok_in")
    _check_number(price["price_per_mtok_out"], "price_lineage.price_per_mtok_out")
    _check_pattern(price["as_of"], "price_lineage.as_of", DATE_RE, "an ISO date (YYYY-MM-DD)")


def _check_mappings(value: object) -> None:
    if not isinstance(value, list) or not value or len(value) > 1024:
        raise RecordError("mappings must be a nonempty list of at most 1024 entries")
    for item in value:
        entry = _check_object(item, "mappings[]", ("old_pseudonym", "new_pseudonym"))
        _check_code(entry["old_pseudonym"], "mappings[].old_pseudonym")
        _check_code(entry["new_pseudonym"], "mappings[].new_pseudonym")


FIELD_CHECKS = {
    "v": lambda value: _check_literal(value, "v", V),
    "kind": lambda value: _check_enum(value, "kind", KINDS),
    "event_id": lambda value: _check_pattern(
        value, "event_id", ULID_RE, "a 26-character Crockford base32 ULID"
    ),
    "ts": _check_ts,
    "origin": lambda value: _check_code(value, "origin"),
    "run_id": lambda value: _check_code(value, "run_id"),
    "session_id": lambda value: _check_code(value, "session_id"),
    "attestation": lambda value: _check_literal(value, "attestation", ATTESTATION),
    "projection": lambda value: _check_literal(value, "projection", PROJECTION),
    "spawn_ordinal": lambda value: _check_int(value, "spawn_ordinal"),
    "task_class": _check_task_class,
    "requested_model": _check_requested_model,
    "requested_effort": lambda value: _check_enum(value, "requested_effort", EFFORTS),
    "surface": lambda value: _check_enum(value, "surface", SURFACES),
    "harness_contract": _check_harness_contract,
    "route_id": lambda value: _check_code(value, "route_id"),
    "warrant_ids": _check_warrant_ids,
    "rung": lambda value: _check_code(value, "rung"),
    "router_effort": lambda value: _check_enum(value, "router_effort", EFFORTS),
    "router_model": lambda value: _check_binding(value, "router_model"),
    "reason_code": lambda value: _check_registered(
        value, "reason_code", REGISTERED_REASON_CODES
    ),
    "reason_code_free": lambda value: _check_text(value, "reason_code_free", maxlen=256),
    "price_lineage": _check_price_lineage,
    "reversibility": lambda value: _check_code(value, "reversibility"),
    "consequence": lambda value: _check_code(value, "consequence"),
    "ambiguity": lambda value: _check_code(value, "ambiguity"),
    "validation_oracle": lambda value: _check_code(value, "validation_oracle"),
    "closure_target": lambda value: _check_code(value, "closure_target"),
    "write_scope_count": lambda value: _check_int(value, "write_scope_count"),
    "outcome_ordinal": lambda value: _check_int(value, "outcome_ordinal"),
    "terminal": lambda value: _check_bool(value, "terminal"),
    "orphan": lambda value: _check_bool(value, "orphan"),
    "disposition": lambda value: _check_enum(value, "disposition", DISPOSITIONS),
    "observed_model": _check_observed_model,
    "observed_effort": lambda value: _check_enum(value, "observed_effort", EFFORTS),
    "tokens": _check_tokens,
    "cost_usd": lambda value: _check_number(value, "cost_usd"),
    "rework_actor": lambda value: _check_enum(value, "rework_actor", REWORK_ACTORS),
    "rework_count": lambda value: _check_int(value, "rework_count"),
    "validator": _check_validator,
    "friction_codes": lambda value: _check_code_list(value, "friction_codes"),
    "confounder_codes": lambda value: _check_code_list(value, "confounder_codes"),
    "mappings": _check_mappings,
    "sig": lambda value: _check_pattern(value, "sig", SIG_RE, "a bounded signature string"),
}


def validate_record(raw: object) -> dict[str, object]:
    """Reject on field name AND field value; this writer is fail-closed by design."""
    if not isinstance(raw, dict):
        raise RecordError("record must be a JSON object")
    kind = raw.get("kind")
    if kind not in KINDS:
        raise RecordError(f"kind must be one of {sorted(KINDS)}")
    unknown = set(raw) - ALLOWED[kind]
    if unknown:
        raise RecordError(f"unknown fields rejected: {sorted(unknown)}")
    missing = REQUIRED[kind] - set(raw)
    if missing:
        raise RecordError(f"missing required fields: {sorted(missing)}")
    for field, value in raw.items():
        FIELD_CHECKS[field](value)
    if "reason_code_free" in raw and raw.get("reason_code") != FREE_SLOT:
        raise RecordError(
            f"reason_code_free is allowed only when reason_code is {FREE_SLOT!r}"
        )
    return dict(raw)


def load_aliases(home: Path | None = None) -> dict[str, str]:
    """Seed table from the crosswalk's measured drift; extended by a JSON data file."""
    table = dict(SEED_MODEL_ALIASES)
    path = home / ALIAS_FILE if home is not None else None
    if path is None or not path.exists():
        return table
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RecordError(f"{ALIAS_FILE} is not valid JSON") from exc
    if not isinstance(data, dict):
        raise RecordError(f"{ALIAS_FILE} must be a JSON object of alias -> binding")
    for key, value in data.items():
        if not isinstance(key, str) or not key.strip():
            raise RecordError(f"{ALIAS_FILE} keys must be nonempty strings")
        _check_binding(value, f"{ALIAS_FILE}[{key}]")
        table[key.strip().lower()] = value
    return table


def normalize_model(raw: object, aliases: dict[str, str]) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise RecordError("model must be a nonempty string")
    value = raw.strip()
    if BINDING_RE.fullmatch(value):
        return value
    mapped = aliases.get(value.lower())
    if mapped is None:
        raise RecordError(
            f"unknown model alias {raw!r}; pass a normalized vendor:model binding"
        )
    return mapped


def _normalize_bindings(record: dict[str, object], aliases: dict[str, str]) -> None:
    for field in ("router_model",):
        value = record.get(field)
        if isinstance(value, str) and not BINDING_RE.fullmatch(value):
            record[field] = aliases.get(value.strip().lower(), value)
    for field in ("requested_model", "observed_model", "price_lineage"):
        holder = record.get(field)
        key = "binding" if field == "price_lineage" else "id"
        if not isinstance(holder, dict):
            continue
        value = holder.get(key)
        if isinstance(value, str) and not BINDING_RE.fullmatch(value):
            holder = dict(holder)
            holder[key] = aliases.get(value.strip().lower(), value)
            record[field] = holder


class store_lock:
    """Advisory whole-store lock: an `O_EXCL` sentinel file beside the store.

    The store is a single append-only file per month, so one writer at a time is
    the whole requirement — the sentinel is claimed for the duration of a write
    and released in `__exit__`. A sentinel older than `STALE_LOCK_SECONDS` is
    treated as abandoned, because a writer killed mid-write must not wedge every
    later spawn; that window is far longer than any honest write takes.
    """

    def __init__(self, home: Path, timeout: float = LOCK_TIMEOUT_SECONDS) -> None:
        self.path = home / LOCK_NAME
        self.timeout = timeout

    def _claim(self) -> bool:
        try:
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        except FileExistsError:
            return False
        return True

    def _age_seconds(self) -> float:
        try:
            return time.time() - self.path.stat().st_mtime
        except FileNotFoundError:
            # Released between our failed claim and this check — retry at once.
            return float("inf")

    def __enter__(self) -> store_lock:
        deadline = time.monotonic() + self.timeout
        waited = 0
        while not self._claim():
            if self._age_seconds() > STALE_LOCK_SECONDS:
                self.path.unlink(missing_ok=True)
                continue
            if time.monotonic() >= deadline:
                raise RecordError(
                    f"record store lock held by another writer: gave up after "
                    f"{self.timeout:g}s ({waited} retries)"
                )
            waited += 1
            time.sleep(LOCK_POLL_SECONDS)
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self.path.unlink(missing_ok=True)
        return False


def scan_records(paths):
    """Parse stored lines without field validation: JSON damage is loud, schema drift is not."""
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise RecordError(f"{path} does not exist") from None
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RecordError(f"{path.name} line {number}: malformed JSON") from exc
            if not isinstance(item, dict):
                raise RecordError(f"{path.name} line {number}: record must be a JSON object")
            yield path, number, item


def read_records(paths) -> list[dict[str, object]]:
    """Strict read: every line validated, ids unique, one terminal outcome per run."""
    records: list[dict[str, object]] = []
    seen: set[object] = set()
    terminals: set[object] = set()
    for path, number, item in scan_records(paths):
        try:
            record = validate_record(item)
        except RecordError as exc:
            raise RecordError(f"{path.name} line {number}: {exc}") from exc
        if record["event_id"] in seen:
            raise RecordError(f"{path.name} line {number}: duplicate event_id")
        seen.add(record["event_id"])
        if record["kind"] == "outcome" and record["terminal"] is True:
            if record["run_id"] in terminals:
                raise RecordError(
                    f"{path.name} line {number}: second terminal outcome for run_id"
                )
            terminals.add(record["run_id"])
        records.append(record)
    return records


def _next_spawn_ordinal(home: Path, record: dict[str, object]) -> int:
    path = store_path(home, str(record["ts"]))
    if not path.exists():
        return 0
    session = record.get("session_id")
    count = 0
    for _, _, item in scan_records([path]):
        if item.get("kind") == "intent" and item.get("session_id") == session:
            count += 1
    return count


def _resolve_outcome(home: Path, record: dict[str, object], *, allow_orphan: bool) -> None:
    run_id = record.get("run_id")
    intents = 0
    ordinals: list[int] = []
    terminals = 0
    for _, _, item in scan_records(store_files(home)):
        if item.get("run_id") != run_id:
            continue
        if item.get("kind") == "intent":
            intents += 1
        elif item.get("kind") == "outcome":
            ordinal = item.get("outcome_ordinal")
            if type(ordinal) is int:
                ordinals.append(ordinal)
            if item.get("terminal") is True:
                terminals += 1
    # `orphan` states what the store showed at write time, so the writer owns it
    # outright — a caller-supplied value would be an unverifiable claim.
    record.pop("orphan", None)
    if not intents:
        if not allow_orphan:
            raise RecordError(
                f"no intent record for run_id {run_id!r}; pass --allow-orphan to record it anyway"
            )
        record["orphan"] = True
    if "outcome_ordinal" not in record:
        record["outcome_ordinal"] = max(ordinals) + 1 if ordinals else 0
    if record.get("terminal") is True and terminals:
        raise RecordError(f"run_id {run_id!r} already carries a terminal outcome")


def _prepare(
    home: Path, raw: dict[str, object], *, aliases: dict[str, str], allow_orphan: bool
) -> dict[str, object]:
    record = dict(raw)
    record.setdefault("v", V)
    record.setdefault("event_id", ulid())
    record.setdefault("ts", utc_now())
    _check_ts(record["ts"])
    kind = record.get("kind")
    if kind in ("intent", "outcome"):
        record.setdefault("attestation", ATTESTATION)
        record.setdefault("projection", PROJECTION)
        _normalize_bindings(record, aliases)
    if kind == "intent" and "spawn_ordinal" not in record:
        record["spawn_ordinal"] = _next_spawn_ordinal(home, record)
    if kind == "outcome":
        _resolve_outcome(home, record, allow_orphan=allow_orphan)
    return record


def _append(path: Path, record: dict[str, object]) -> None:
    """One line, one `os.write`, then fsync — no buffering layer to flush wrong."""
    line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
    payload = line.encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        written = os.write(fd, payload)
        if written != len(payload):
            raise RecordError(f"short append to {path.name}: {written}/{len(payload)} bytes")
        os.fsync(fd)
    finally:
        os.close(fd)


def write_record(
    home: Path,
    raw: object,
    *,
    allow_orphan: bool = False,
    timeout: float = LOCK_TIMEOUT_SECONDS,
) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise RecordError("record must be a JSON object")
    ensure_home(home)
    aliases = load_aliases(home)
    with store_lock(home, timeout):
        record = _prepare(home, raw, aliases=aliases, allow_orphan=allow_orphan)
        record = validate_record(record)
        for _, _, item in scan_records(store_files(home)):
            if item.get("event_id") == record["event_id"]:
                raise RecordError("duplicate event_id")
        _append(store_path(home, str(record["ts"])), record)
    return record


def summarize(home: Path) -> dict[str, object]:
    records = read_records(store_files(home))
    return {
        "v": V,
        "record_count": len(records),
        "run_count": len({record["run_id"] for record in records if "run_id" in record}),
        "by_kind": dict(Counter(str(record["kind"]) for record in records)),
        "by_disposition": dict(
            Counter(str(record["disposition"]) for record in records if "disposition" in record)
        ),
        "by_surface": dict(
            Counter(str(record["surface"]) for record in records if "surface" in record)
        ),
        "by_route_id": dict(
            Counter(str(record["route_id"]) for record in records if "route_id" in record)
        ),
    }


def _with_kind(raw: object, kind: str) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise RecordError("record must be a JSON object")
    if raw.get("kind", kind) != kind:
        raise RecordError(f"kind must be {kind!r} for this subcommand")
    return {**raw, "kind": kind}


def _parse_json(text: str) -> object:
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise RecordError(f"--json is not valid JSON: {exc}") from exc


def _require_flags(args: argparse.Namespace, names) -> None:
    missing = [f"--{name.replace('_', '-')}" for name in names if getattr(args, name) is None]
    if missing:
        raise RecordError(f"missing required flags: {sorted(missing)}")


def _reject_mixed_input(args: argparse.Namespace, names) -> None:
    if args.json is None:
        return
    used = [f"--{name.replace('_', '-')}" for name in names if getattr(args, name) is not None]
    if used:
        raise RecordError(f"pass --json or record flags, not both: {sorted(used)}")


INTENT_FLAGS = (
    "run_id",
    "session_id",
    "origin",
    "spawn_ordinal",
    "task_class",
    "requested_model",
    "requested_effort",
    "surface",
    "harness_sha256",
    "harness_label",
    "harness_review_gate",
    "harness_claim_tagging",
    "harness_tool_profile",
    "route_id",
)
# store_true flags read as False, not None, so they are checked separately.
INTENT_BOOL_FLAGS = ("session_inherited_model",)
INTENT_REQUIRED_FLAGS = (
    "run_id",
    "task_class",
    "requested_effort",
    "surface",
    "harness_sha256",
    "harness_label",
    "harness_review_gate",
    "harness_claim_tagging",
    "harness_tool_profile",
)
OUTCOME_FLAGS = (
    "run_id",
    "session_id",
    "origin",
    "outcome_ordinal",
    "disposition",
    "observed_model",
    "observed_identity_source",
)
OUTCOME_REQUIRED_FLAGS = ("run_id", "disposition")


def _intent_from_flags(args: argparse.Namespace, aliases: dict[str, str]) -> dict[str, object]:
    _require_flags(args, INTENT_REQUIRED_FLAGS)
    # A generic spawn requests no model at all. That has to be sayable, but not
    # by accident — hence an explicit flag rather than an absent one.
    if (args.requested_model is None) == (not args.session_inherited_model):
        raise RecordError(
            "pass exactly one of --requested-model / --session-inherited-model"
        )
    requested: dict[str, object] | None = None
    if args.requested_model is not None:
        requested = {
            "id": normalize_model(args.requested_model, aliases),
            "raw": args.requested_model,
        }
    record: dict[str, object] = {
        "kind": "intent",
        "run_id": args.run_id,
        "task_class": {"class": None, "class_free": args.task_class},
        "requested_model": requested,
        "requested_effort": args.requested_effort,
        "surface": args.surface,
        "harness_contract": {
            "sha256": args.harness_sha256,
            "label": args.harness_label,
            "features": {
                "review_gate": args.harness_review_gate == "true",
                "claim_tagging": args.harness_claim_tagging == "true",
                "tool_profile": args.harness_tool_profile,
            },
        },
    }
    for field in ("session_id", "origin", "route_id", "spawn_ordinal"):
        value = getattr(args, field)
        if value is not None:
            record[field] = value
    if args.warrant_id:
        record["warrant_ids"] = args.warrant_id
    return record


def _outcome_from_flags(args: argparse.Namespace, aliases: dict[str, str]) -> dict[str, object]:
    _require_flags(args, OUTCOME_REQUIRED_FLAGS)
    if (args.observed_model is None) != (args.observed_identity_source is None):
        raise RecordError(
            "--observed-model and --observed-identity-source are given together or not at all"
        )
    observed: dict[str, object] | None = None
    if args.observed_model is not None:
        observed = {
            "id": normalize_model(args.observed_model, aliases),
            "identity_source": args.observed_identity_source,
        }
    record: dict[str, object] = {
        "kind": "outcome",
        "run_id": args.run_id,
        "disposition": args.disposition,
        "terminal": bool(args.terminal),
        # Stated either way: crosswalk §3 REQ, null when nothing was observed.
        "observed_model": observed,
    }
    for field in ("session_id", "origin", "outcome_ordinal"):
        value = getattr(args, field)
        if value is not None:
            record[field] = value
    return record


def command_record_intent(args: argparse.Namespace, home: Path) -> int:
    _reject_mixed_input(args, INTENT_FLAGS)
    if args.json is not None:
        clashes = [
            f"--{name.replace('_', '-')}" for name in INTENT_BOOL_FLAGS if getattr(args, name)
        ]
        if args.warrant_id:
            clashes.append("--warrant-id")
        if clashes:
            raise RecordError(f"pass --json or record flags, not both: {sorted(clashes)}")
        raw = _parse_json(args.json)
    else:
        raw = _intent_from_flags(args, load_aliases(home))
    record = write_record(home, _with_kind(raw, "intent"))
    print(record["event_id"])
    return 0


def command_record_outcome(args: argparse.Namespace, home: Path) -> int:
    _reject_mixed_input(args, OUTCOME_FLAGS)
    if args.json is not None:
        clashes = [
            name
            for name, used in (("--terminal", args.terminal), ("--non-terminal", args.non_terminal))
            if used
        ]
        if clashes:
            raise RecordError(f"pass --json or record flags, not both: {clashes}")
        raw = _parse_json(args.json)
    else:
        if args.terminal == args.non_terminal:
            raise RecordError("pass exactly one of --terminal / --non-terminal")
        raw = _outcome_from_flags(args, load_aliases(home))
    record = write_record(home, _with_kind(raw, "outcome"), allow_orphan=args.allow_orphan)
    print(record["event_id"])
    return 0


def command_validate(args: argparse.Namespace, home: Path) -> int:
    paths = [Path(args.file).expanduser()] if args.file else store_files(home)
    records = read_records(paths)
    print(
        json.dumps(
            {"status": "ok", "files": len(paths), "records": len(records)}, sort_keys=True
        )
    )
    return 0


def command_summarize(args: argparse.Namespace, home: Path) -> int:
    print(json.dumps(summarize(home), sort_keys=True))
    return 0


def _add_home(command: argparse.ArgumentParser) -> None:
    command.add_argument("--home", help="record store directory (default ~/.delegation/v2)")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    intent = commands.add_parser("record-intent")
    _add_home(intent)
    intent.add_argument("--json", help="a complete intent record as JSON")
    intent.add_argument("--run-id")
    intent.add_argument("--session-id")
    intent.add_argument("--origin")
    intent.add_argument("--spawn-ordinal", type=int)
    intent.add_argument("--task-class", help="native task term (task_class.class_free)")
    intent.add_argument("--requested-model")
    intent.add_argument(
        "--session-inherited-model",
        action="store_true",
        help="record requested_model as null (a generic spawn requested no model)",
    )
    intent.add_argument("--requested-effort", choices=sorted(EFFORTS))
    intent.add_argument("--surface", choices=sorted(SURFACES))
    intent.add_argument("--harness-sha256")
    intent.add_argument("--harness-label")
    intent.add_argument("--harness-review-gate", choices=("true", "false"))
    intent.add_argument("--harness-claim-tagging", choices=("true", "false"))
    intent.add_argument("--harness-tool-profile", choices=sorted(TOOL_PROFILES))
    intent.add_argument("--route-id")
    intent.add_argument("--warrant-id", action="append", default=[])
    intent.set_defaults(handler=command_record_intent)

    outcome = commands.add_parser("record-outcome")
    _add_home(outcome)
    outcome.add_argument("--json", help="a complete outcome record as JSON")
    outcome.add_argument("--run-id")
    outcome.add_argument("--session-id")
    outcome.add_argument("--origin")
    outcome.add_argument("--outcome-ordinal", type=int)
    outcome.add_argument("--disposition", choices=sorted(DISPOSITIONS))
    outcome.add_argument("--observed-model", help="model actually observed (alias or binding)")
    outcome.add_argument("--observed-identity-source", choices=sorted(IDENTITY_SOURCES))
    outcome.add_argument("--terminal", action="store_true")
    outcome.add_argument("--non-terminal", action="store_true")
    outcome.add_argument("--allow-orphan", action="store_true")
    outcome.set_defaults(handler=command_record_outcome)

    validate = commands.add_parser("validate")
    _add_home(validate)
    validate.add_argument("--file", help="validate one store file instead of the whole home")
    validate.set_defaults(handler=command_validate)

    summary = commands.add_parser("summarize")
    _add_home(summary)
    summary.set_defaults(handler=command_summarize)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    home = home_path(args.home)
    try:
        return args.handler(args, home)
    except (OSError, json.JSONDecodeError, RecordError) as exc:
        print(f"intent-writer: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
