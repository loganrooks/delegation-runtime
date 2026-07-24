---
name: delegate-to-antigravity
description: Use when Codex should delegate a bounded review, investigation, or implementation task to Gemini Flash through the local Antigravity CLI, especially to use separate Gemini account limits while keeping Codex responsible for task ownership and verification.
---

# Delegate to Antigravity

Use the temporary adapter as an explicit worker surface. Codex retains routing, integration, and
verification. This MVP is manual and intentionally smaller than the deferred provider-neutral
router.

**Required:** use `delegation-triage` first. Define the objective, non-goals, owned files, allowed
effects, validation, return shape, and escalation conditions. Give one writer a checkout.

## Workflow

1. Run `agy_delegate.py models` and select an exact model line.
2. Put the bounded task packet in a private prompt file (`0600`, at most 64 KiB). Do not include
   secrets. Antigravity 1.1.4 requires the prompt in its process argv, so another same-user process
   may observe it while the worker runs.
3. Select a profile explicitly:
   - `review`: plan mode plus native sandbox; no auto-approval flag.
   - `implementation-auto`: accept-edits plus native sandbox and Antigravity's
     `--dangerously-skip-permissions`. Use only with exact write ownership.
4. Run `agy_delegate.py run --help`, then invoke `run` with the profile, exact model, absolute
   workspace, and prompt file.
5. Let the foreground command finish. Inspect its stdout, stderr status, and private run directory
   before retrying. Inspect edits and run fresh project verification before accepting the result.

The adapter refuses new work once its user-level state reaches 192 MiB and has an absolute 240 MiB
ceiling. It never deletes old state. This MVP has no resume, recovery daemon, capability record,
full-workspace reconciliation, automatic routing, recursive delegation, installation, download,
monitoring, or Dionysus integration.

## Common mistakes

- Using `implementation-auto` for a read-only task.
- Passing an approximate model alias instead of the exact `models` line.
- Letting two implementation workers share a checkout or accepting undeclared edits.
- Retrying an odd result without first preserving and inspecting its partial evidence.
- Treating the native sandbox as proof that network, external writes, or provider-global state were
  independently certified; this temporary adapter makes no such claim.
