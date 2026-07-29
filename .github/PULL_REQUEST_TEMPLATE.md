## Outcome

What observable repository behavior or rule changes?

## Change class

- [ ] Local
- [ ] Public contract
- [ ] Architecture
- [ ] Runtime/state
- [ ] Safety/security

## Ownership and admission

- Existing owners considered:
- Logical owner / mutation authority:
- Producer:
- Independent consumer:
- Entrypoint:
- First functional or contract test:
- Lifecycle and removal condition:

Use `N/A` with a reason for a Local change. A test, document, registry row, wrapper, or a second
abstraction created only for this change is not independently sufficient consumer evidence.

## Public, compatibility, and debt review

- [ ] No unregistered package, public API, public term, feature flag, compatibility layer, waiver,
      or deprecation was added.
- [ ] Or, all introduced surfaces are registered in `governance.toml` with owners and expiry or
      removal conditions.
- [ ] No hidden fallback, second writer, unmanaged background work, or parallel source of truth was
      introduced.

## Validation

- [ ] `cargo fmt --all --check`
- [ ] `cargo metadata --format-version 1 --locked`
- [ ] `cargo check --workspace --all-targets --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo test --workspace --all-targets --locked`
- [ ] `uv sync --locked`
- [ ] `uv run --frozen ruff check .`
- [ ] `uv run --frozen python scripts/check_governance.py`
- [ ] `uv run --frozen pytest`

Additional evidence or explicitly blocked checks:
