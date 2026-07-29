# Contributing to ParaEGOX

ParaEGOX accepts small, evidence-linked changes that preserve explicit ownership and dependency
boundaries. Architecture documents describe targets; code, tests, and runtime evidence describe
implemented behavior.

## Classify the change

Use the narrowest applicable class. Higher classes include the requirements of lower classes.

| Class | Examples | Required evidence |
| --- | --- | --- |
| Local | Internal implementation with no public or ownership change | Focused test and lint |
| Public contract | Public Rust/Python API, language-neutral Schema, CLI, configuration field, protocol | Admission record, consumers, compatibility rule, contract test |
| Architecture | New owner, package boundary, dependency direction, persistent format | Accepted or explicitly authorized decision, migration/removal path |
| Runtime/state | Lifecycle, background work, retry, persistence, recovery | Failure, cancellation, restart, and cleanup evidence |
| Safety/security | Authority, physical effect, Secret, sandbox, trust boundary | Independent review and fail-closed evidence |

Do not make every change architectural. A local reversible implementation choice does not need a
new ADR.

## Admit new surfaces

Before adding a top-level package, public contract, service, controller, registry, daemon, public
term, or compatibility layer, record:

- the logical owner and mutation authority;
- existing owners considered and why they are insufficient;
- producer and independent consumer;
- runtime or developer entrypoint;
- first functional or contract test;
- lifecycle and failure boundary;
- compatibility, migration, or removal condition.

Register implementation packages and public APIs in `governance.toml`. A consumer must be an
executable call path, runtime binding, or independently owned/lived integration. The following do
not independently prove consumption:

- a unit test or example;
- documentation, an ADR, a plan, or a future UI;
- a wrapper in the same ownership boundary;
- registration without a runtime call path;
- another abstraction introduced only to consume the first one.

An unconsumed prerequisite may be admitted as `experimental` or `enabler`, but it must remain
internal, identify the bounded batch that will connect it, and include a removal condition. It is
not a completed capability.

## Keep ownership smaller than deployment

A logical owner is not automatically a package, class, process, service, store, or manager. Keep
mutation authority explicit, but colocate implementation until isolation, lifecycle, or independent
consumption requires separation. New generic `common`, `shared`, `utils`, `base`, `core`,
`helpers`, `managers`, `registry`, or `framework` boundaries require explicit justification and at
least two independent consumers.

## Keep public surfaces intentional

- New code is internal unless listed in `registry.public_apis`.
- Avoid convenience re-exports from a Rust crate root/prelude or Python package `__init__.py`.
- Do not make deep implementation imports an accidental compatibility promise.
- Public Schema, configuration, CLI, and protocol changes need a version/compatibility rule.
- Cross-process and cross-language contracts must be defined by their Schema, canonical encoding,
  version and compatibility tests, not by Rust memory layout, trait objects, Python objects, or a
  language-specific serializer default.
- Unknown configuration fields fail validation; environment variables must not create a parallel
  configuration authority.

## Control exceptions and legacy

Every suppression, skipped or expected-failure test, CI soft failure, compatibility shim, feature
flag, TODO/FIXME exception, or deprecated surface must have:

- an owner;
- a reason and narrow scope;
- an expiry or removal date;
- a replacement or removal condition.

Waivers live in `registry.waivers`, deprecations in `registry.deprecations`, and feature flags in
`registry.feature_flags` inside `governance.toml`. Reference waivers inline as
`GOV-WAIVER-NNNN`. CI rejects missing, unknown, out-of-scope, unused, or expired waivers.

Compatibility adapters do not own state, form a second runtime entrypoint, silently fall back,
or dual-write. Retry/reconcile likewise has one owner and one budget per operation.

## Work safely with other contributors and agents

- State the intended write set before a multi-file change.
- Only one active change should own a public contract or authority document at a time.
- Re-read changed ADRs, terminology, and package rules before merging.
- Do not overwrite unrelated dirty work or hide it with formatting churn.
- Keep generated artifacts identifiable and reproducible; never edit generated and authoritative
  sources as if both were truth.

## Validate locally

The repository has a pinned Rust workspace for admitted core slices and Python 3.11/`uv`
governance tooling. The commands below validate those current surfaces; they are not evidence that
a production RuntimeHost exists, and they are not a claim about the eventual ROS2, Jetson,
hardware, or production runtime support matrix.

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

Cargo is the authority for Rust dependencies, builds and tests, while `uv`, Python
`pyproject.toml` and `uv.lock` remain
the authority for Python governance tooling, SDKs and workloads. Neither tool may maintain a second
lock or dependency truth for the other ecosystem. `cargo metadata --locked` failure is a hard
governance failure; do not skip Rust checks when Cargo or the pinned toolchain is unavailable.

Hardware, external-service, or manually authorized checks remain separate and must not be reported
as passing based on local mocks.
