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
- A strategic CoreService explicitly named by an Accepted ADR or authoritative roadmap may be
  admitted before it has a real running consumer, but only as `experimental`/`enabler`: it must
  record owner and non-owner boundaries, contain a non-placeholder contract and mechanism with
  focused semantic evidence, name the near-term integration batch, avoid any running-capability
  claim, and carry a batch-end fold-back/remove/merge review checkpoint. This exception does not
  apply to ordinary helpers, wrappers, or provider adapters.
- Keep new implementation internal by default. Public surfaces must be registered in
  `governance.toml` together with owner, consumers, compatibility policy, and tests.
- Do not create placeholder packages or directories from architecture diagrams.
- Keep implementation colocated with its existing logical owner by default. Do not split a new
  crate, module, source file, wrapper, or helper merely to mirror an architecture layer, shorten a
  file, or give one caller its own name. Separation requires a concrete dependency/compile,
  lifecycle/deployment, security/isolation, language-neutral contract, or independently reused
  ownership boundary; otherwise extend the existing implementation coherently.
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
- Parallel agents may edit disjoint write sets, but Rust workspace validation is centrally
  coordinated and serial by default. Reuse the repository target cache; do not create concurrent
  per-agent target directories that rebuild the same heavy dependency graph.
- The Mac repository is the sole writable source authority for the current development workflow.
  Agents edit source only there. The build server is a disposable validation consumer, never a
  second source tree or merge authority.
- Prefer transferring source to the build server as Git commits, refs, or patches produced from the
  Mac repository. If Git transport is unavailable and the user explicitly authorizes the fallback,
  send only the required uncompressed files or bounded file chunks from Mac to a remote temporary
  path, verify each complete file against its Mac SHA-256 digest, and atomically replace the remote
  validation copy. Never use tar archives or compressed source snapshots for this fallback.
- Source movement is one-way: Mac to build server. Never copy, extract, fetch, or merge source files
  from the build server back into the Mac worktree. In particular, do not run a mutating formatter
  remotely and import its result; run remote formatters in check mode and make any correction in
  the Mac source authority.
- Before remote validation, pin the exact Git object or patch being tested and verify its write set.
  An explicitly authorized direct-file fallback must additionally record the local and remote
  SHA-256 digests for every transferred file. Remote builds use `--locked`; server-side
  dependency/cache artifacts and source edits are not returned to the Mac repository.

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
