from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT_ROOT = REPO_ROOT / "crates" / "paraegox-deployment"
DEPLOYMENT_SRC = DEPLOYMENT_ROOT / "src"
RUNTIME_ROOT = REPO_ROOT / "crates" / "paraegox-runtime"
RUNTIME_SRC = RUNTIME_ROOT / "src"

INTERNAL_DEPLOYMENT_MODULES = (
    "controller_initializer",
    "controller_journal",
    "controller_store",
    "tenure_authority",
    "tenure_client",
    "tenure_protocol",
)
PUBLIC_AUTHORITY_SYMBOLS = {
    "TenureAuthorityProcessError",
    "run_tenure_authority_process",
}


def _read_required(path: Path) -> str:
    assert path.is_file(), f"required S7-D source is missing: {path.relative_to(REPO_ROOT)}"
    return path.read_text(encoding="utf-8")


def _load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(_read_required(path))


def test_only_the_real_authority_process_is_promoted() -> None:
    library = _read_required(DEPLOYMENT_SRC / "lib.rs")
    for module in INTERNAL_DEPLOYMENT_MODULES:
        source = (
            DEPLOYMENT_SRC / module / "mod.rs"
            if module == "tenure_authority"
            else DEPLOYMENT_SRC / f"{module}.rs"
        )
        _read_required(source)
        assert re.search(rf"(?m)^\s*mod\s+{module}\s*;\s*$", library)
        assert not re.search(
            rf"(?m)^\s*pub(?:\s*\([^)]*\))?\s+mod\s+{module}\s*;\s*$",
            library,
        )
        assert not re.search(
            rf"(?m)^\s*pub(?:\s*\([^)]*\))?\s+use\s+[^;]*\b{module}\s*::",
            library,
        )

    assert re.search(r"(?m)^\s*mod\s+tenure_authority_process\s*;\s*$", library)
    exported = re.search(
        r"(?ms)pub\s+use\s+tenure_authority_process\s*::\s*\{(?P<symbols>[^}]*)\}\s*;",
        library,
    )
    assert exported is not None
    symbols = {
        symbol.strip()
        for symbol in exported.group("symbols").split(",")
        if symbol.strip()
    }
    assert symbols == PUBLIC_AUTHORITY_SYMBOLS


def test_governance_claims_w1_foundations_but_not_executable_vertical() -> None:
    governance = _load_toml(REPO_ROOT / "governance.toml")["registry"]
    packages = [
        package
        for package in governance["packages"]
        if package.get("cargo_package") == "paraegox-deployment"
    ]
    assert len(packages) == 1
    package = packages[0]
    assert package["status"] == "experimental"
    assert package["public_entrypoints"] == [
        "paraegox_deployment::run_tenure_authority_process"
    ]
    assert package["consumers"] == ["paraegox-tenure-authority"]

    public_rows = [
        api
        for api in governance["public_apis"]
        if str(api["module"]).replace("-", "_") == "paraegox_deployment"
    ]
    assert len(public_rows) == 1
    assert {str(symbol) for symbol in public_rows[0]["symbols"]} == PUBLIC_AUTHORITY_SYMBOLS

    forbidden_claims = {
        "AcquireTenureRequestV1",
        "AcquireTenureResponseV1",
        "ControllerJournal",
        "RuntimeJournal",
        "DeploymentController",
        "RuntimeApplyEndpoint",
        "run_deploymentd_process",
    }
    all_symbols = {
        str(symbol)
        for row in governance["public_apis"]
        for symbol in row["symbols"]
    }
    assert all_symbols.isdisjoint(forbidden_claims)


def test_authority_cli_has_no_environment_secret_or_production_test_backdoor() -> None:
    process_source = _read_required(DEPLOYMENT_SRC / "tenure_authority_process.rs")
    production_source = process_source.split("#[cfg(test)]", maxsplit=1)[0]
    forbidden = (
        "std::env::var(",
        "std::env::var_os(",
        "PARAEGOX_",
        "--fault",
        "--failpoint",
        "--max-requests",
    )
    for marker in forbidden:
        assert marker not in production_source

    binary = _read_required(DEPLOYMENT_SRC / "bin" / "paraegox-tenure-authority.rs")
    assert "run_tenure_authority_process" in binary
    assert "AcquireTenureRequestV1" not in binary
    assert "AcquireTenureResponseV1" not in binary


def test_s7_e_w1_does_not_create_deploymentd_or_runtime_apply_executables() -> None:
    binaries = sorted(path.name for path in (DEPLOYMENT_SRC / "bin").glob("*.rs"))
    assert binaries == ["paraegox-tenure-authority.rs"]
    assert not (DEPLOYMENT_SRC / "bin" / "paraegox-deploymentd.rs").exists()
    assert not (DEPLOYMENT_SRC / "deployment_controller_process.rs").exists()


def test_s7_e_runtime_store_foundation_remains_crate_private_and_unwired() -> None:
    runtime_library = _read_required(RUNTIME_SRC / "lib.rs")
    _read_required(RUNTIME_SRC / "runtime_journal.rs")
    _read_required(RUNTIME_SRC / "runtime_store.rs")
    assert re.search(r"(?m)^\s*mod\s+runtime_journal\s*;\s*$", runtime_library)
    assert re.search(r"(?m)^\s*mod\s+runtime_store\s*;\s*$", runtime_library)
    assert not re.search(
        r"(?m)^\s*pub(?:\s*\([^)]*\))?\s+mod\s+runtime_journal\s*;\s*$",
        runtime_library,
    )
    assert not re.search(
        r"(?m)^\s*pub(?:\s*\([^)]*\))?\s+mod\s+runtime_store\s*;\s*$",
        runtime_library,
    )
    assert "run_runtime_apply_endpoint" not in runtime_library

    governance = _load_toml(REPO_ROOT / "governance.toml")["registry"]
    runtime_packages = [
        package
        for package in governance["packages"]
        if package.get("cargo_package") == "paraegox-runtime"
    ]
    assert len(runtime_packages) == 1
    runtime_package = runtime_packages[0]
    assert "crates/paraegox-runtime/src/runtime_journal.rs" in runtime_package[
        "first_tests"
    ]
    assert "crates/paraegox-runtime/src/runtime_store.rs" in runtime_package[
        "first_tests"
    ]
    assert "Runtime one-shot initializer" in runtime_package[
        "responsibility"
    ]
    assert "not implemented" in runtime_package["responsibility"]

    public_symbols = {
        str(symbol)
        for row in governance["public_apis"]
        for symbol in row["symbols"]
    }
    assert public_symbols.isdisjoint(
        {
            "RuntimeJournal",
            "RuntimeJournalSnapshot",
            "RuntimeApplyEndpoint",
            "run_runtime_apply_endpoint",
        }
    )
