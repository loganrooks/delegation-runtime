# intent-writer — driver-side v2 intent/outcome record writer (B-7)

**Authority:** delegation-triage crosswalk **v0.2.2** (ratified v0.2 2026-07-24, D-B3-1/D-B3-2;
amended v0.2.1 2026-07-26 after this module's R1 conformance review, then v0.2.2 after the
Flash-pilot panel) —
`delegation-triage:docs/proposals/2026-07-24-intent-outcome-record-crosswalk.md`. The seven
v0.2.1 areas are marked **[v0.2.1]** below and the three additive v0.2.2 changes **[v0.2.2]**;
both syncs followed their implementing commit in the same pass. This module
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
- Write pattern reimplementing S3's proven approach: lock file with bounded retry,
  `O_APPEND|O_CREAT` 0o600, fsync, duplicate-`event_id` rejection. The sentinel carries
  pid+nonce and is released only by its owner (a writer whose lock was stale-reclaimed must not
  unlink the new holder's), and a short append is rolled back to the pre-write size inside the
  lock so a partial line cannot wedge the store.

## Record shapes (from crosswalk v0.2.1 §§1–4 — the spec of record; on any conflict, the
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
| `spawn_ordinal` | ✓ intent | int; per-session counter derived by scanning **the whole store** for that `session_id` **[v0.2.1]** — a month-file-only scan restarts the count at a month boundary and collides with the session's own earlier spawns (correctness over speed at current volumes) |
| `attestation` | ✓ | literal `driver-attested` (this writer's tier); reject others |
| `projection` | ✓ | literal `native` (this writer never projects); reject others |

### Intent (`kind: intent`)

REQ: `task_class` (object: `class` **MUST be null** until the closed enum is published per
crosswalk §2a — writers fail closed on any non-null value **[v0.2.1]**, there being no
vocabulary to validate against; `class_free` required non-empty), `requested_model` (object:
`id` normalized `vendor:model`, `raw` preserved — **or `null`** for a session-inherited spawn,
which requests no model at all; the key is REQ either way), `requested_effort` (enum:
`low|medium|high|xhigh|max|session-inherited|unspecified|unknown`), `surface` (enum:
`pin|per-call|generic|teams|cowork|`**`cli` [v0.2.2]** — a native shell CLI invocation, e.g.
`agy -p`, outside any Claude Code surface; recording one as `pin`/`generic` would falsify the
axis), `harness_contract` (object: `sha256` 64-hex, `label`
str ≤80, `features` object closed to **exactly** `review_gate: bool`, `claim_tagging: bool`,
`tool_profile: "ro"|"rw"` **[v0.2.1]** — unknown keys rejected; extension is by crosswalk
amendment, since an open map smuggles operator-chosen keys and values past a name-level export
check).

Optional: `route_id` (str; a ROUTES/overlay row, **or a registered CANDIDATE lane id
[v0.2.2]** — registered = named in a committed package doc + a W-record, the Flash pilot's
FP-A/B/C being the first; `none-consulted` legal). No code change was needed for the v0.2.2
widening: `route_id` is CODE_RE-validated and lane ids like `FP-A` already satisfy it — the
amendment widened what the field *means*, not what it accepts. `warrant_ids` (list of `W-NNN`
strings),
`rung` (str), `router_effort` (same effort enum), `router_model` (normalized binding **or the
literal `human` [v0.2.1]** — the field's own semantics name a human router, so `other:human`
was a workaround), `reason_code` (registered vocab member or `other`; `reason_code_free`
allowed ONLY when `reason_code` is `other` — origin-local, flagged non-exportable),
`note_hash` (sha256 hex digest of the origin-local note **[v0.2.1]**; the note itself never
enters the record), `price_lineage` (object: `binding`, `price_per_mtok_in`,
`price_per_mtok_out` numbers, `as_of` ISO date), riders `reversibility|consequence|ambiguity`
(str, CODE_RE-shaped), `validation_oracle|closure_target` (**registered-vocab-or-`other` with a
`*_free` sibling gated on `other` [v0.2.1]** — same treatment as `reason_code`; see Validation)
+ `write_scope_count` (int).

### Outcome (`kind: outcome`)

REQ: `run_id` matching an existing intent in the store (else exit non-zero with a clear
error; `--allow-orphan` overrides, record flagged `orphan: true` — a bool that is
**native-v2 only, WRITER-stamped and never caller-asserted, origin-local and non-exportable**
**[v0.2.1]**; a caller-supplied value is discarded), `outcome_ordinal` (int ≥0; auto-assigned
as max+1 for that run_id if omitted; **`(run_id, outcome_ordinal)` is unique — reject a
duplicate pair at write AND at validate [v0.2.1]**, since a silent collision fans out the §3
join), `terminal` (bool; **at most one terminal outcome per run_id — enforce**), `disposition`
(enum: `accepted|accepted-after-rework|rejected|parked|interrupted|blocked|error|abandoned|
completed-unknown`), `observed_model` (object: `id` normalized, `identity_source`:
`transcript|api|ui-label`, optional `raw` preserved spelling **[v0.2.1]**) — REQ per crosswalk
§3 (this spec originally listed it optional; the build followed the crosswalk per the conflict
rule, and the spec is corrected here). **A null value is legal ONLY when `disposition ∈
{error, blocked, interrupted, abandoned}` [v0.2.1]** — nothing answered, so nothing was
observable; on every other disposition the key AND value are REQ, and the CLI flag path must
error rather than default to null.

**§3a pairings bind native records [v0.2.1].** Where the crosswalk's §3a table fixes `terminal`
and/or `rework_actor` for a disposition, the writer enforces it: `accepted`, `rejected`,
`interrupted` ⇒ `terminal: true` + `rework_actor: none`; `parked` ⇒ `terminal: false` +
`rework_actor: none`. `accepted-after-rework` is **unconstrained** on both axes — three §3a
rows map onto it with disagreeing values, so the table fixes nothing for it — as are
`blocked|error|abandoned|completed-unknown`, which appear in no §3a row.

Optional: `observed_effort` (effort enum), `tokens` (object of ints:
`in|out|cache_r|cache_w`, each nullable), `cost_usd` (number), `rework_actor`
(`root|delegate|none|unknown`), `rework_count` (int), `validator` (object: `id` str,
`outcome` registered-vocab-or-`other` + free slot rule as above), `friction_codes`/
`confounder_codes` (lists whose **every element** is registered-vocab-or-`other`
**[v0.2.1]**, with an index-aligned `*_free` sibling list — text where the element is `other`,
`null` elsewhere).

**First registered vocabulary members [v0.2.2].** `fabricated-completion` (unhedged completion
claim contradicted by the oracle), `silent-scope-violation` (write outside stated scope,
undisclosed), `undetected-omission` (failure invisible at the time, found later) — severe-failure
classes, accepted bare alongside `other`+free. **`friction_codes` ONLY:** the two fields share
the *rule*, not the *vocabulary*, and a severe-failure class as a *confounder* is a category
error, so `REGISTERED_CONFOUNDER_CODES` stays empty and separate. The crosswalk pairs these
members with a "requires ≥ `third-party-verified` attestation" rule — **not validated by this
writer, deliberately.** Its `attestation` is the fixed literal `driver-attested`, so enforcing
the tier here would make the three unwritable by this module rather than gated; the rule binds
the record SET a consumer reads across writers.

## Validation — fail closed (crosswalk §5)

- Allowlist over field NAMES per kind; unknown fields ⇒ reject (S3's mechanism).
- Value rules per the tables above — enum membership checked, not just shape. This is the
  name-AND-value discipline the crosswalk added over S3.
- `CODE_RE = ^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$` for code-shaped strings. **CODE_RE alone
  is not enough for free-code fields [v0.2.1]:** it is a character class, not a vocabulary, and
  a repo-relative test path or a `host:port` passes it cleanly. So `reason_code`,
  `validation_oracle`, `closure_target`, and every element of `friction_codes` /
  `confounder_codes` take the registered-member-or-`other` rule with a `*_free` sibling legal
  only where the base is `other`. **Applied at WRITE time, not only at export** (crosswalk
  §5.3), so a native store is exportable-by-construction rather than needing a scrub at
  projection. **[v0.2.2]** `friction_codes` now has three registered members (above); every
  other free-code field still has an empty registry, so `other` + free slot remains the only
  honest form for them. The registries are module constants resolved at call time, so
  publishing a vocabulary is a one-binding change.
- Model normalization: `vendor:model` where vendor ∈ `anthropic|openai|google|other`; a
  small alias table maps observed drift (`terra`→`openai:gpt-5.6-terra`; seed table from the
  crosswalk's measured aliases, extendable via a JSON data file, not code edits).
- A `validate` CLI subcommand: read a store file, exit non-zero on first bad line (this is
  the §5.5 machine-check seed). Cross-record invariants (duplicate `event_id`, duplicate
  `(run_id, outcome_ordinal)`, one-terminal-per-run) hold only across the lines it reads, so
  `--file` checks them **within that file only** — prefer the whole-home form for conformance.

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
- **[v0.2.1]** Plus, from the R1 fix list: the free-code rule on all four newly-covered fields
  (raw values rejected, `other`+`*_free` accepted, free slot without `other` rejected, free-list
  length and per-position alignment); the `observed_model` null carve-out on both sides and the
  flag path erroring rather than defaulting; `spawn_ordinal` continuity across a month boundary;
  duplicate `(run_id, outcome_ordinal)` at write and at validate; `features` rejecting unlisted
  keys; short-append rollback leaving the store readable; a stale-reclaimed writer not releasing
  the new holder's sentinel; `note_hash` shape; `observed_model.raw`; the §3a pairings including
  the deliberately-free `accepted-after-rework`; `router_model: human`.
- **[v0.2.2]** Plus: `cli` accepted as a surface (validate, write, CLI flag, summarize bucket)
  with near-misses (`CLI`, `shell`, `command-line`) still rejected; each registered friction
  code accepted bare; registered members mixing with `other`+free; a free slot beside a
  registered member still rejected; unregistered codes still rejected; the severe-failure
  classes rejected as `confounder_codes` (the friction-only reading, asserted so it fails first
  if widened); and the shipped alias payload resolving against a temp home — never the real one.
- Target: the existing suites stay green; new suite ≥25 tests.

## Non-goals

No projectors, no export/share path, no HMAC pseudonymization (export-time concerns — the
writer records locally with native values), no S1/S2/S3 reads, no daemon, no schema for the
closed `task_class.class` enum (blocked on crosswalk §2a publication).
