# ParaEGOX Agent Rules

ParaEGOX is in a clean-slate architecture stage. Read these files before changing the
repository:

1. `CONTRIBUTING.md`
2. `governance.toml`
3. the admitted contracts, source, and tests for the touched boundary

## Mandatory rules

- Do not treat Draft, Proposed, Research, plans, diagrams, or target file trees as implemented
  behavior.
- Do not create a package, public contract, service, controller, registry, daemon, compatibility
  layer, or public term without satisfying the admission rules in `CONTRIBUTING.md`.
- A test, document, registry row, wrapper, or second abstraction created only to reference the
  first abstraction is evidence, not an independent consumer.
- Keep new implementation internal by default. Public surfaces must be registered in
  `governance.toml` together with owner, consumers, compatibility policy, and tests.
- Do not create placeholder packages or directories from architecture diagrams.
- Do not introduce a second writer, hidden fallback, implicit retry, unmanaged background work,
  process-global mutable state, or a parallel source of truth.
- Do not use renaming to preserve an obsolete abstraction. Compatibility and deprecation entries
  require an owner and removal date.
- Every lint suppression, skipped/expected-failure test, CI soft failure, or temporary exception
  requires a live waiver entry and an inline `GOV-WAIVER-NNNN` reference.
- Do not perform unrelated refactors, repository-wide formatting, or edits outside the declared
  change boundary.
- Preserve user and other-agent changes. Re-read affected authority files if the worktree changes
  while you are working.

## Required validation

Run from the repository root:

```bash
cargo fmt --all --check
cargo metadata --format-version 1 --locked
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked

uv sync --locked
uv run --frozen ruff check .
uv run --frozen python scripts/check_governance.py
uv run --frozen pytest
```

If a command cannot run, report it as blocked; do not claim it passed.
