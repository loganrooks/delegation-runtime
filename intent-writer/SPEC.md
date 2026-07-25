# intent-writer — driver-side v2 intent/outcome record writer (B-7)

**Authority:** delegation-triage crosswalk v0.2 (RATIFIED 2026-07-24, D-B3-1/D-B3-2) —
`delegation-triage:docs/proposals/2026-07-24-intent-outcome-record-crosswalk.md`. This module
is the "one NEW writer" its §6.3 names: driver-side, `driver-attested`, carrying the four
fields no existing capture source supplies (`route_id`, `warrant_ids`, `surface`,
`harness_contract`). It writes NEW v2 records only — it is NOT a projector (projectors over
S1/S2/S3 are a separate item, C-5-adjacent).

## Scope

A stdlib-only Python library + CLI the driver session invokes per spawn. **No daemon, no
hooks, no background process.** Two operations:

- `record-intent` — at the routing decision point, before/at spawn.
- `record-outcome` — at completion/adjudication; N outcomes per intent are legal.

## Store

- Append-only JSONL: `~/.delegation/v2/intents-YYYY-MM.jsonl` (dir configurable via
  `--home` / `DELEGATION_V2_HOME`; default as stated). One record per line, sorted keys,
  compact separators.
- **Never** append to any v1 store (crosswalk §6.0-b: a v2 line bricks S3's v1 readers).
- Write pattern per S3's proven approach: lock file with bounded retry, `O_APPEND|O_CREAT`
  0o600, fsync, duplicate-`event_id` rejection.

## Record shapes (from crosswalk v0.2 §§1–4 — the spec of record; on any conflict, the
crosswalk wins and this file has a bug)

### Common envelope (both record kinds)

| field | REQ | rule |
|---|---|---|
| `v` | ✓ | literal `"2"` |
| `kind` | ✓ | `intent` \| `outcome` \| `rekey` (rekey: accept and validate the shape from crosswalk §1; no CLI needed yet) |
| `event_id` | ✓ | ULID (Crockford base32, 26 chars, time-prefixed — implement in-module, stdlib only) |
| `ts` | ✓ | ISO-8601 UTC with `Z` |
| `origin` | | omitted ⇒ implied `local` |
| `run_id` | ✓ | caller-supplied; unique within origin; local records keep native value |
| `session_id` | | opaque |
| `spawn_ordinal` | ✓ intent | int; per-session counter derived by scanning the current month file for that `session_id` (correctness over speed at current volumes) |
| `attestation` | ✓ | literal `driver-attested` (this writer's tier); reject others |
| `projection` | ✓ | literal `native` (this writer never projects); reject others |

### Intent (`kind: intent`)

REQ: `task_class` (object: `class` nullable until the closed enum is published per crosswalk
§2a; `class_free` required non-empty), `requested_model` (object: `id` normalized
`vendor:model`, `raw` preserved), `requested_effort` (enum:
`low|medium|high|xhigh|max|session-inherited|unspecified|unknown`), `surface` (enum:
`pin|per-call|generic|teams|cowork`), `harness_contract` (object: `sha256` 64-hex, `label`
str ≤80, `features` object with only bool/short-enum values — at minimum `review_gate: bool`,
`claim_tagging: bool`, `tool_profile: "ro"|"rw"`).

Optional: `route_id` (str; `none-consulted` legal), `warrant_ids` (list of `W-NNN` strings),
`rung` (str), `router_effort` (same effort enum), `router_model` (normalized binding),
`reason_code` (registered vocab member or `other`; `reason_code_free` allowed ONLY when
`reason_code` is `other` — origin-local, flagged non-exportable), `price_lineage` (object:
`binding`, `price_per_mtok_in`, `price_per_mtok_out` numbers, `as_of` ISO date), riders
`reversibility|consequence|ambiguity|validation_oracle|closure_target` (str, CODE_RE-shaped)
+ `write_scope_count` (int).

### Outcome (`kind: outcome`)

REQ: `run_id` matching an existing intent in the store (else exit non-zero with a clear
error; `--allow-orphan` overrides, record flagged `orphan: true`), `outcome_ordinal` (int
≥0; auto-assigned as max+1 for that run_id if omitted), `terminal` (bool; **at most one
terminal outcome per run_id — enforce**), `disposition` (enum: `accepted|
accepted-after-rework|rejected|parked|interrupted|blocked|error|abandoned|
completed-unknown`).

Optional: `observed_model` (object: `id` normalized, `identity_source`:
`transcript|api|ui-label`), `observed_effort` (effort enum), `tokens` (object of ints:
`in|out|cache_r|cache_w`, each nullable), `cost_usd` (number), `rework_actor`
(`root|delegate|none|unknown`), `rework_count` (int), `validator` (object: `id` str,
`outcome` registered-vocab-or-`other` + free slot rule as above), `friction_codes`/
`confounder_codes` (lists, CODE_RE-shaped).

## Validation — fail closed (crosswalk §5)

- Allowlist over field NAMES per kind; unknown fields ⇒ reject (S3's mechanism).
- Value rules per the tables above — enum membership checked, not just shape. This is the
  name-AND-value discipline the crosswalk added over S3.
- `CODE_RE = ^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$` for code-shaped strings.
- Model normalization: `vendor:model` where vendor ∈ `anthropic|openai|google|other`; a
  small alias table maps observed drift (`terra`→`openai:gpt-5.6-terra`; seed table from the
  crosswalk's measured aliases, extendable via a JSON data file, not code edits).
- A `validate` CLI subcommand: read a store file, exit non-zero on first bad line (this is
  the §5.5 machine-check seed).

## CLI

`python3 intent-writer/scripts/intent_writer.py {record-intent|record-outcome|validate|summarize} [--home DIR] [--json '{...}' | flags]`
— accept a full record as `--json` (primary interface for drivers) and individual `--field`
flags for the REQ fields (human/manual use). `summarize`: counts by kind, disposition,
surface, route_id — read-only.

## Layout + tests (match repo conventions)

- `intent-writer/scripts/intent_writer.py`, `intent-writer/tests/test_*.py` (unittest,
  discoverable exactly like the existing suites), plus `intent-writer/README.md` (short:
  what/why/authority pointer).
- Add a CI step to `.github/workflows/ci.yml` mirroring the existing three.
- Tests MUST cover: ULID shape+monotonic-time prefix; every enum's accept AND reject cases;
  unknown-field rejection; duplicate event_id; one-terminal-per-run enforcement; orphan
  outcome behavior; spawn_ordinal derivation across sessions; alias normalization; the
  `reason_code_free`-only-with-`other` rule; lock contention (two writers, no interleaved
  corruption); `validate` failing closed on a hand-corrupted line.
- Target: the existing suites stay green; new suite ≥25 tests.

## Non-goals

No projectors, no export/share path, no HMAC pseudonymization (export-time concerns — the
writer records locally with native values), no S1/S2/S3 reads, no daemon, no schema for the
closed `task_class.class` enum (blocked on crosswalk §2a publication).
