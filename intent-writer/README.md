# intent-writer — driver-side v2 intent/outcome record writer (B-7)

A stdlib-only library and CLI the **routing driver** invokes per spawn: one `intent` record at
the routing decision point, and 0..N `outcome` records at completion. It is the "one NEW
writer" the crosswalk names — the only source that can supply `route_id`, `warrant_ids`,
`surface`, and `harness_contract`, which are `∅` in all three existing capture systems (the
Claude Code OTel stream, the spawn ledger, and Codex orchestration-learning v1).

**Authority:** the ratified crosswalk, now **v0.2.1** (amended 2026-07-26 after this module's
R1 conformance review) — delegation-triage
`docs/proposals/2026-07-24-intent-outcome-record-crosswalk.md`. Local build contract:
[`SPEC.md`](SPEC.md). **Where the two disagree the crosswalk governs.** SPEC.md predates
v0.2.1, so on `observed_model`, `harness_contract.features`, the free-code rule, `orphan`,
`note_hash`, `router_model`, and the §3a pairings, read the crosswalk.

This is not a projector. It writes native v2 records only (`projection: native`,
`attestation: driver-attested`); projecting S1/S2/S3 history into v2 is a separate item.

## Use it

```bash
S=intent-writer/scripts/intent_writer.py

python3 $S record-intent --run-id run-a --session-id sess-1 \
  --task-class bounded-implementation --requested-model terra --requested-effort high \
  --surface per-call --route-id R15 --warrant-id W-001 \
  --harness-sha256 "$SHA" --harness-label 'implementer v1' \
  --harness-review-gate true --harness-claim-tagging false --harness-tool-profile rw

python3 $S record-outcome --run-id run-a --disposition accepted --terminal \
  --observed-model anthropic:claude-opus-5 --observed-identity-source transcript

python3 $S validate      # exit 1 on the first bad line
python3 $S summarize     # counts by kind / disposition / surface / route_id
```

Drivers should prefer `--json '{...}'` — it reaches every optional field, where the flags cover
only the required ones. Each subcommand takes `--home DIR`; otherwise `DELEGATION_V2_HOME`, else
`~/.delegation/v2`.

## Store

Append-only JSONL at `<home>/intents-YYYY-MM.jsonl`, one sorted-key compact record per line,
mode 0600 under a 0700 directory. **Nothing here ever touches a v1 store** — a single v2 line
appended to Codex's `events.jsonl` bricks that reader's `audit`, `summarize`, and all
subsequent writes (crosswalk §6.0-b).

Writes serialize on an `fcntl.flock` over `<home>/.intents.lock`, then append with
`O_APPEND|O_CREAT|O_NOFOLLOW` and fsync. The kernel owns the lock, so it is released both on
close and on process death — there is no lease to expire and no stale-lock reclaim, because a
reclaim protocol is inherently racy (two writers can observe the same stale lock and both take
it). The lock file itself is never unlinked: removing it would let a later writer lock a
different inode while a holder still has the old one.

Every write takes the lock, scans the store **once** to build the index it needs (duplicate ids,
both ordinal sequences, every uniqueness invariant), then appends. That is still O(store) work
per write, so building N records is O(N²) parsing overall — fine at the volumes this sees
(tens to thousands), and deliberately not optimized yet. A durable index is the fix when it
matters; the trigger to do it is write latency becoming noticeable, not a record count.

The store is opened `O_NOFOLLOW` and confirmed a regular file before any byte is written or
read, and its mode is forced to 0600 on every append — a store file planted as a symlink would
otherwise redirect the append outside the home, and one left at an inherited 0644 would stay
world-readable.

## Validation is fail-closed

Field **names** are allowlisted per kind and **values** are checked against the enum, pattern,
or numeric rule the crosswalk states — the name-AND-value discipline §5 added over S3's
name-only allowlist. Unknown field, wrong enum member, malformed ULID, duplicate `event_id`, a
second `terminal: true` for one `run_id`, an outcome whose `run_id` has no intent: all rejected,
nothing written. `validate` applies the same rules to a stored file and is the §5.5 machine-check
seed.

Model ids normalize to `vendor:model`. The alias table seeds from the crosswalk's measured drift
(`terra` / `gpt-5.6-terra` / `gpt-5-6-terra` are one binding in three spellings) and extends via
`<home>/model-aliases.json` — a data file, not a code edit. An unrecognized alias is **rejected,
never guessed**.

The deployed `~/.delegation/v2/model-aliases.json` carries those three spellings plus
`flash` → `google:gemini-3.6-flash-high`. **The bare `google:gemini-3.6-flash` is deliberately
absent**: that id is not served (gateway README, verified 2026-07-26 — delegation-triage W-026),
so no alias resolves to it. It remains a shape-valid binding, so a caller who passes it
explicitly is recorded as asking for it rather than silently corrected — the writer records what
was requested, it does not adjudicate what is servable.

## The rules that bite most often

- **Free-code fields never take raw operational strings.** `reason_code`, `validation_oracle`,
  `closure_target` and every element of `friction_codes` / `confounder_codes` must be a
  registered vocabulary member or the literal `other`; the origin-local text goes in a
  `*_free` sibling that is legal *only* where the base is `other`. For the two list fields the
  sibling is an index-aligned list — text at positions where the element is `other`, `null`
  everywhere else. No vocabulary is registered yet, so in practice everything is
  `other` + free today. This is applied at **write** time (crosswalk §5.3), so a native store
  is exportable-by-construction rather than needing a scrub later.
- **`observed_model` is REQUIRED on outcomes, and null is gated.** A null value is legal only
  when `disposition` is `error`, `blocked`, `interrupted`, or `abandoned` — nothing answered, so
  nothing was observable. On any other disposition the CLI refuses rather than writing a
  silently un-joinable record. Optional `raw` preserves the spelling you typed.
- **Crosswalk §3a binds native records.** `accepted` and `rejected` and `interrupted` are
  terminal with `rework_actor: none`; `parked` is non-terminal with `rework_actor: none`.
  `accepted-after-rework` is free on both axes (three §3a rows map onto it with disagreeing
  values), as are `blocked` / `error` / `abandoned` / `completed-unknown`, which appear in no
  §3a row.
- **`harness_contract.features` is exactly three keys** — `review_gate`, `claim_tagging`,
  `tool_profile`. Extension is by crosswalk amendment, not by writing a new key: an open map
  would smuggle operator-chosen keys past a name-level export check.
- **`requested_model` may be `null`** for a session-inherited (generic) spawn — said out loud
  with `--session-inherited-model`, never by omission. **`router_model`** takes a normalized
  binding or the literal `human`. **`note_hash`** (optional, intents) is a sha256 hex digest of
  an origin-local note; the note itself never enters the record.
- **`orphan` is writer-stamped, never caller-asserted**, and is origin-local/non-exportable.
- **Every join and invariant is keyed by `(origin, run_id)`**, with an omitted `origin` read as
  `local` (crosswalk §1). `run_id` is unique *within* an origin, so two origins may each carry a
  run named `r`, each with its own ordinals and its own terminal outcome. The canonicalization is
  for keying only — an omitted origin stays omitted on disk, because §1 says it may be.
- **One intent per `(origin, run_id)`**, and one intent per
  `(origin, session_id, spawn_ordinal)`. A second intent for a run is either a re-spawn that
  needs its own `run_id` or a double-write; both are refused. **Intents with no `session_id`
  share a single per-origin bucket keyed `None`** — "unsessioned" counts as one session for
  ordinal derivation, and the uniqueness rule applies to it unchanged.
- **Numbers must be finite.** `NaN` and `Infinity` serialize as bare `NaN`/`Infinity`, which is
  not JSON — one such line makes a strict reader reject the whole store.
- **Display-bearing text rejects lone surrogates and bidi format controls.** A lone surrogate
  survives `json.dumps` but is not encodable UTF-8; a bidi override makes a label render as
  something other than what was recorded. Ordinary non-ASCII text is unaffected.
- **The first three friction codes are registered** (crosswalk v0.2.2): `fabricated-completion`,
  `silent-scope-violation`, `undetected-omission` — severe-failure classes, accepted bare
  alongside `other`+free. The crosswalk pairs them with a "requires ≥ `third-party-verified`
  attestation" rule; **this writer does not validate that rule, deliberately.** Its
  `attestation` is the fixed literal `driver-attested`, so enforcing the tier here would make
  the three members unwritable by this module rather than gating them. The tier rule binds the
  record *set* a consumer reads across writers — it is documented here, not validated here.
  Registered for `friction_codes` only; `confounder_codes` has no registered members yet (the
  §3 row groups the two fields because they share the *rule*, not the vocabulary).
- **`surface` includes `cli`** (v0.2.2) — a native shell CLI invocation such as `agy -p`,
  outside any Claude Code surface. Recording one as `pin` or `generic` would falsify the axis.

## Limits worth knowing

- **`validate --file` checks cross-record invariants only within that file.** Duplicate
  `event_id`, duplicate `(run_id, outcome_ordinal)`, and the one-terminal-per-run rule are
  enforced across the lines it reads — so a collision whose two halves sit in different month
  files is caught by a bare `validate` (whole home) and missed by `validate --file`. Prefer the
  whole-home form for conformance checks.
- A **pre-existing** malformed line blocks further writes, because every write scans the store
  for duplicate ids. The writer will not create one — a short append is rolled back to the
  pre-write size inside the lock — but damage from outside the writer needs manual repair. The
  same applies to a store whose last line is missing its newline: reads and writes both refuse
  it, rather than letting the next append glue two records onto one line.
- **`fsync` can fail after the bytes are already in the file.** That is reported as an
  `UNKNOWN COMMIT` error carrying the `event_id`, with CLI exit code **3** (distinct from the
  ordinary failure code 1, precisely so a wrapper does not retry it blindly). The line may or
  may not be durable and the writer cannot tell; inspect the store, and if you retry, reuse the
  returned `event_id` rather than minting a new one.
- **`event_id` ordering is monotonic within a process, not across processes.** Same-millisecond
  ids from one writer increase, and a backwards clock is clamped rather than emitting a
  decreasing id — but two concurrent writers can issue same-millisecond ids that sort
  arbitrarily against each other. Order the store by `ts` and append position, not by
  `event_id`.
- `task_class.class` must stay `null` until the closed enum is published (crosswalk §2a, made
  explicit in v0.2.1): there is no vocabulary to validate against, so the writer fails closed
  and `class_free` carries the native term meanwhile.
- No vocabulary is registered for any free-code field yet, so `other` + a `*_free` slot is the
  only honest form today. Those slots are origin-local and non-exportable.
- Ordinal derivation and the duplicate-id check scan the whole store, not just the current
  month, and share a single pass: correctness over speed at current volumes (see Store).
- No projectors, no export path, no HMAC pseudonymization, no daemon. Records are local and
  carry native values; export-time concerns are §5's, not this module's.
