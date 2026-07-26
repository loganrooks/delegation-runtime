# intent-writer — driver-side v2 intent/outcome record writer (B-7)

**Authority:** delegation-triage crosswalk **v0.2.2** (ratified v0.2 2026-07-24, D-B3-1/D-B3-2;
amended v0.2.1 2026-07-26 after this module's R1 conformance review, then v0.2.2 after the
Flash-pilot panel) —
`delegation-triage:docs/proposals/2026-07-24-intent-outcome-record-crosswalk.md`. The seven
v0.2.1 areas are marked **[v0.2.1]** below and the three additive v0.2.2 changes **[v0.2.2]**;
both syncs followed their implementing commit in the same pass.

Items marked **[SC]** come from the cross-vendor (gpt-5.6-sol) code review of `b1a8646`
(adjudication: `delegation-triage:docs/reviews/2026-07-26-sol-design-wave1-adjudication.md`,
10/10 accepted). **These are implementation hardening, not schema change** — the crosswalk
stays at v0.2.2 and no field changed meaning. Several are the crosswalk's own rules finally
being *enforced* (§1's "`run_id` unique within origin" was previously keyed globally). This
module
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
- **Mutual exclusion is `fcntl.flock` on `<home>/.intents.lock` [SC-1].** The kernel owns the
  lock, so it releases on close AND on process death. **No lease, no stale-lock reclaim, no
  owner token** — the previous sentinel protocol (mtime lease + pid+nonce, itself the R1 F-8
  fix) could not make reclaim atomic: two writers observing one stale sentinel could both
  unlink and both claim, and the release-time `holds?`/`unlink` pair was its own TOCTOU. The
  lock file is never unlinked; removing it would let a later writer lock a different inode
  while a holder still has the old one.
- Append with `O_APPEND|O_CREAT|O_NOFOLLOW` 0o600 + fsync. A short append is rolled back to the
  pre-write size inside the lock, so a partial line cannot wedge the store.
- **Filesystem posture [SC-8]:** the store is opened `O_NOFOLLOW`, confirmed a regular file by
  `fstat` before any byte is read or written, and `fchmod`ed to 0600 on every append —
  `0o600`-on-create alone leaves a pre-existing 0644 file permissive, and a planted symlink
  would redirect the append outside the home. `O_NONBLOCK` is set on both opens and cleared
  after the regular-file check: opening a planted FIFO otherwise *blocks the writer forever*
  instead of rejecting it, since the check necessarily runs after the open.
- **Trailing-newline preflight [SC-3]:** a non-empty store whose last line lacks `\n` is
  refused on read and before any append, rather than having the next record glued onto it as
  `}{`. Checked under the lock, before a byte is written.
- **One scan per write [SC-6].** The lock is taken, the store is parsed ONCE into an index
  carrying every invariant the write needs (duplicate ids, both ordinal sequences, identity
  uniqueness), then the record is appended. Formerly three separate whole-store scans. This is
  still O(store) per write — O(N²) to build N records — which is accepted at current volumes
  and stated rather than hidden; a durable index is deferred, and the trigger to build one is
  write latency becoming noticeable, not a record count.
- **`fsync` failure after a complete write is an `UNKNOWN COMMIT` [SC-10]:** the bytes are in
  the file but may not be durable and the writer cannot tell. The error carries the
  `event_id` and the CLI exits **3** — deliberately distinct from the ordinary failure code 1,
  so a wrapper that retries failures does not blindly mint a second record for one delegation.
  A retry must reuse the returned `event_id`.

## Record shapes (from crosswalk v0.2.1 §§1–4 — the spec of record; on any conflict, the
crosswalk wins and this file has a bug)

### Common envelope (both record kinds)

| field | REQ | rule |
|---|---|---|
| `v` | ✓ | literal `"2"` |
| `kind` | ✓ | `intent` \| `outcome` \| `rekey` (rekey: accept and validate the shape from crosswalk §1; no CLI needed yet) |
| `event_id` | ✓ | ULID (Crockford base32, 26 chars, time-prefixed — implement in-module, stdlib only). **Overflow forms rejected [SC-7]:** 26 Crockford chars carry 130 bits and a ULID is 128, so the first character must be `0`–`7`; `"Z"*26` decodes to a time prefix past the 48-bit maximum |
| `ts` | ✓ | ISO-8601 UTC with `Z` |
| `origin` | | omitted ⇒ implied `local`. **[SC-4]** That implication is applied when KEYING (see below), never by stamping the record — §1 says local records may omit it, so it stays omitted on disk |
| `run_id` | ✓ | caller-supplied; **unique within origin** — so every join and invariant is keyed `(origin, run_id)` **[SC-4]**, never `run_id` alone. Two origins may each carry a run named `r`, each with its own ordinals and its own terminal outcome. Local records keep the native value |
| `session_id` | | opaque. **Absent `session_id` is a real bucket, not a missing one [SC-5]:** unsessioned intents share one per-origin bucket keyed `None`, counted and uniqueness-checked exactly like a named session, and distinct from every named session |
| `spawn_ordinal` | ✓ intent | int; per-session counter derived by scanning **the whole store** for that `(origin, session_id)` **[v0.2.1][SC-4]** — a month-file-only scan restarts the count at a month boundary and collides with the session's own earlier spawns (correctness over speed at current volumes) |
| `attestation` | ✓ | literal `driver-attested` (this writer's tier); reject others |
| `projection` | ✓ | literal `native` (this writer never projects); reject others |

**Record identity — enforced at write AND at validate [SC-5]:**

- **One intent per `(origin, run_id)`.** A second is either a re-spawn needing its own `run_id`
  or a double-write; both are refused rather than silently fanning out the §3 join.
- **One intent per `(origin, session_id, spawn_ordinal)`**, including the unsessioned `None`
  bucket. An explicitly-supplied ordinal is collision-checked, not trusted.
- **One outcome per `(origin, run_id, outcome_ordinal)`**, and one `terminal: true` per
  `(origin, run_id)`.

**`event_id` ordering [SC-7]:** the generator is monotonic **within a process** —
same-millisecond calls increment the entropy instead of re-randomizing, a backwards wall clock
is clamped to the last issued millisecond, and entropy exhaustion rolls into the next
millisecond. **This does not extend across processes:** two concurrent writers can issue
same-millisecond ids that sort arbitrarily against each other. Consumers order by `ts` and
append position; `event_id` is an identifier, not the sort key.

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
- **Numerics must be finite [SC-2].** `NaN`/`Infinity` serialize as bare `NaN`/`Infinity`,
  which is not JSON — one such line makes a strict reader reject the entire store. `NaN` also
  defeats every range check silently, since all comparisons against it are false. Enforced with
  `math.isfinite` per value plus `json.dumps(..., allow_nan=False)` at the serializer.
- **Dates are checked semantically, not just by shape [SC-9].** `2026-99-99` matches the
  regex; `date.fromisoformat` is what rejects it.
- **Display-bearing text rejects lone surrogates and bidi format controls [SC-9].** A lone
  surrogate survives `json.dumps` (escaped) but is not encodable UTF-8, so it breaks strict
  consumers; a bidi override (U+202E and relatives) makes a label render as something other
  than what was recorded. Applies to labels, `raw` spellings, `class_free`, and every `*_free`
  slot. Ordinary non-ASCII text is unaffected.
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
- **[SC]** Plus the review's 12-item test-gap list: simultaneous lock contenders and
  release-by-process-death; a lock held longer than any former lease; non-finite floats plus a
  strict-JSON round-trip of the written store; a store whose final line lacks `\n`, on both
  read and write; cross-origin joins, ordinals and terminals; duplicate `(origin, run_id)` and
  duplicate session ordinals, at write and at validate; ordinal derivation with no
  `session_id`; same-ms ULID bursts, clock regression, entropy rollover, overflow first
  character, and id/`ts` consistency; one-scan-per-write and a few-hundred-record run;
  pre-existing permissive modes, symlinks and FIFOs in the store position; semantic dates,
  lone surrogates, bidi controls, and strict UTF-8 round-trip; and `fsync` failure after a
  complete write surfacing the id and exit code 3.
- Target: the existing suites stay green; new suite ≥25 tests.

## Non-goals

No projectors, no export/share path, no HMAC pseudonymization (export-time concerns — the
writer records locally with native values), no S1/S2/S3 reads, no daemon, no schema for the
closed `task_class.class` enum (blocked on crosswalk §2a publication).
