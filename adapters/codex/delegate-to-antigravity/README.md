# Codex → Antigravity Gemini Flash adapter (temporary MVP)

This manual adapter lets Codex run one bounded Gemini worker through the already-installed `agy`
CLI. It is a temporary bridge to the deferred provider-neutral router, not a certified isolation
boundary.

## Use it

List exact model names:

```bash
python3 scripts/agy_delegate.py models
```

Create a private task packet, then run a read-only investigation:

```bash
chmod 600 /private/path/task.txt
python3 scripts/agy_delegate.py run \
  --profile review \
  --model 'Gemini 3.5 Flash (Medium)' \
  --workspace /absolute/project/path \
  --prompt-file /private/path/task.txt
```

Use `--profile implementation-auto` only after assigning exact file ownership. It enables
Antigravity's accept-edits mode, native sandbox, and automatic permission approval. The `review`
profile uses plan mode and the native sandbox without auto approval.

Run `python3 scripts/agy_delegate.py run --help` for optional timeout, state-root, and binary
bindings.

## Boundaries

- The adapter validates the selected model against a fresh `agy models` result.
- Commands use argument lists, never a shell.
- Private run evidence defaults to `~/.codex/state/delegate-to-antigravity`; admission stops at
  192 MiB and the configured absolute ceiling is 240 MiB. The adapter never deletes evidence.
- Antigravity 1.1.4 accepts the print prompt through argv. Do not put secrets in task packets.
- No resume, retry, full-workspace reconciliation, materialization, automatic routing,
  installation, download, monitoring, or Dionysus integration is implemented.
- A successful run is worker evidence, not integration proof. Inspect edits and run project checks.
