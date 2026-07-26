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
mode 0600 under a 0700 directory. Writes take an advisory lock file, append with
`O_APPEND|O_CREAT`, and fsync. **Nothing here ever touches a v1 store** — a single v2 line
appended to Codex's `events.jsonl` bricks that reader's `audit`, `summarize`, and all
subsequent writes (crosswalk §6.0-b).

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

## Limits worth knowing

- **`validate --file` checks cross-record invariants only within that file.** Duplicate
  `event_id`, duplicate `(run_id, outcome_ordinal)`, and the one-terminal-per-run rule are
  enforced across the lines it reads — so a collision whose two halves sit in different month
  files is caught by a bare `validate` (whole home) and missed by `validate --file`. Prefer the
  whole-home form for conformance checks.
- A **pre-existing** malformed line blocks further writes, because every write scans the store
  for duplicate ids. The writer will not create one — a short append is rolled back to the
  pre-write size inside the lock — but damage from outside the writer needs manual repair.
- `task_class.class` must stay `null` until the closed enum is published (crosswalk §2a, made
  explicit in v0.2.1): there is no vocabulary to validate against, so the writer fails closed
  and `class_free` carries the native term meanwhile.
- No vocabulary is registered for any free-code field yet, so `other` + a `*_free` slot is the
  only honest form today. Those slots are origin-local and non-exportable.
- `spawn_ordinal` and the duplicate-id check both scan the whole store, not just the current
  month: correctness over speed at current volumes.
- No projectors, no export path, no HMAC pseudonymization, no daemon. Records are local and
  carry native values; export-time concerns are §5's, not this module's.
