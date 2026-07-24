# delegation-runtime

Cross-runtime delegation machinery: programs a host harness (currently Codex) runs to spawn,
govern, and reconcile delegated worker sessions on other providers' agents — today
delegate-to-claude (Claude sessions) and delegate-to-antigravity (Gemini Flash via the
Antigravity bridge), sharing a `delegation_policy` schema/diff/explain core.

**Status: pre-validation.** 307 passing tests (223 claude + 10 antigravity + 74 policy),
**zero completed real worker turns**. The first milestone is one attested end-to-end worker
turn (registered in delegation-triage's 2026-07-24 portfolio review as item C-3, parked
pending operator-authorized spend). Until then, nothing here is a validated route.

## Relationship to delegation-triage

This repo is **Product 2** of the two-product split decided 2026-07-24 (delegation-triage,
`docs/reviews/2026-07-24-portfolio-decomposition-fable-review.md`, decision D-3: own repo).

- **delegation-triage** (Product 1) owns doctrine: routes, warrants, state, probes, epistemics.
  It is consumed *by reading*, and it cites this repo via its WARRANTS KNOWN-REPOS prefix key.
- **delegation-runtime** (this repo) *consumes* that doctrine as versioned data. It never
  defines routes; it executes and reports against them. Delegation outcomes produced here are
  candidate evidence for delegation-triage's probe loop, graded by that repo's rules.

## Provenance

Developed 2026-07-17 → 2026-07-20 by Codex sessions working inside the delegation-triage
worktree under `adapters/codex/`, where it remained **untracked** (in no commit) until
2026-07-24. Moved here byte-identically (rsync + `diff -rq` verified, `__pycache__`/`.DS_Store`
excluded) and first committed in this repository. Design lineage: the cross-runtime routing
proposal and the composable policy proposal, both in delegation-triage `docs/proposals/`.

**Layout note:** the `adapters/codex/` prefix was vestigial — preserved through the move so the
move commit could be byte-identical and the test suites (which computed the repo root as
`parents[4]` of the test file and hardcoded `adapters/codex/...` entrypoint paths) passed
unmodified. That prefix was **flattened on 2026-07-24** — this repo's first registered refactor:
the four trees (`delegate-to-claude/`, `delegate-to-antigravity/`, `scripts/`, `tests/`) now sit
at the repository root, `adapters/` is gone, and the dependent root computation, entrypoint
path, CI `PYTHONPATH`s and discovery roots, and the commands below were updated in the same pass.

## Running the tests

```bash
PYTHONPATH=delegate-to-claude/scripts:scripts \
  python3 -m unittest discover -s delegate-to-claude/tests -p 'test_*.py'
PYTHONPATH=delegate-to-antigravity/scripts:scripts \
  python3 -m unittest discover -s delegate-to-antigravity/tests -p 'test_*.py'
PYTHONPATH=scripts \
  python3 -m unittest discover -s tests -p 'test_*.py'
```

CI (`.github/workflows/ci.yml`) runs all three; the delegate-to-claude step is the one that
formerly sat, uncommitted, in delegation-triage's `ci.yml` (its D-6 coupling — resolved
"neither" by this move).

## Charter register (operator vision, 2026-07-24 — candidates, not commitments)

Recorded so design work can be held against them; none of these is authorized work until the
first-worker-turn milestone lands and delegation-triage's decomposition schedules them.

1. **Multi-target delegation from any host.** A session in one harness (Codex today; others
   later) routes work across provider boundaries — Claude, Antigravity/Gemini, further
   targets — under one policy core. Targets as *bindings*: transport + capability declaration
   + cost model + evidence hooks, pluggable without touching the policy core.
2. **Fleet-affordance profile.** A user's "fleet" is the set of bindings their subscriptions,
   API keys, and gateways actually afford. The runtime should be able to *profile* it:
   coverage map of demand classes → evidenced bindings, surfacing gaps ("no strong UI lane",
   "no cross-vendor review lane — consider a GPT-class reviewer") and stale/Contested
   evidence, rather than only routing within the fleet as given.
3. **Minimal-roster projections.** Small evidenced core rosters (≈5–10 bindings) as the
   recommended default; large fleets (20–30) are an evidence problem before a plumbing
   problem — each routable binding needs per-demand-class evidence someone has to sustain.
   Support projections: a 3–5 row minimal table for constrained users, fuller tables where
   the evidence exists.
4. **Epistemic discipline inherited, not reimplemented.** Attestation, grading, flip
   thresholds, and record formats come from delegation-triage (and the evidence-commons
   north star's interchange-format work); this repo emits records in that format.
