# intent-writer — driver-side v2 intent/outcome record writer (B-7)

A stdlib-only library and CLI the **routing driver** invokes per spawn: one `intent` record at
the routing decision point, and 0..N `outcome` records at completion. It is the "one NEW
writer" the crosswalk names — the only source that can supply `route_id`, `warrant_ids`,
`surface`, and `harness_contract`, which are `∅` in all three existing capture systems (the
Claude Code OTel stream, the spawn ledger, and Codex orchestration-learning v1).

**Authority:** the ratified crosswalk v0.2 —
delegation-triage `docs/proposals/2026-07-24-intent-outcome-record-crosswalk.md` (RATIFIED
2026-07-24, D-B3-1/D-B3-2). Local build contract: [`SPEC.md`](SPEC.md). **Where the two
disagree the crosswalk governs**; the deviations that follow from that rule are listed below.

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

## Deviations from SPEC.md (crosswalk governs)

- **`observed_model` is REQUIRED on outcomes.** Crosswalk §3 marks it REQ; SPEC.md listed it
  optional. The key must be stated — but the value may be `null`, because a run that errored
  before any model answered has nothing to observe, and silence and "nothing ran" must not look
  alike.
- **`requested_model` may be `null`.** Crosswalk §2 records the session-inherited spawn as
  `requested_model: null` (330/724 measured S2 spawn requests). SPEC.md required an object.
  Recording generic spawns is the point of a driver-side writer, so the CLI says it out loud
  with `--session-inherited-model` rather than by omission.

## Limits worth knowing

- `task_class.class` must stay `null`. The closed enum is unpublished (crosswalk §2a), so any
  value would be unvalidatable; `class_free` carries the native term meanwhile.
- `reason_code` and `validator.outcome` accept only `other` today — no vocabulary is registered
  yet. The free-text slot is origin-local and non-exportable.
- `spawn_ordinal` is derived by scanning the current month file, so a session spanning a month
  boundary restarts its count.
- Every write scans the store for duplicate ids: correctness over speed, per spec, at current
  volumes.
- No projectors, no export path, no HMAC pseudonymization, no daemon. Records are local and
  carry native values; export-time concerns are §5's, not this module's.
