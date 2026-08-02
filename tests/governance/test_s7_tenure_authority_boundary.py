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
    "controller_tenure",
    "manifest_ingress",
    "tenure_authority",
    "tenure_client",
    "tenure_protocol",
)
PUBLIC_AUTHORITY_SYMBOLS = {
    "TenureAuthorityProcessError",
    "run_tenure_authority_process",
}
PUBLIC_DEPLOYMENTD_SYMBOLS = {
    "DeploymentdProcessError",
    "run_deploymentd_process",
}


def _read_required(path: Path) -> str:
    assert path.is_file(), f"required S7-D source is missing: {path.relative_to(REPO_ROOT)}"
    return path.read_text(encoding="utf-8")


def _load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(_read_required(path))


def test_only_the_two_real_process_facades_are_promoted() -> None:
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
    symbols = {symbol.strip() for symbol in exported.group("symbols").split(",") if symbol.strip()}
    assert symbols == PUBLIC_AUTHORITY_SYMBOLS

    assert re.search(r"(?m)^\s*mod\s+deployment_process\s*;\s*$", library)
    exported = re.search(
        r"(?ms)pub\s+use\s+deployment_process\s*::\s*\{(?P<symbols>[^}]*)\}\s*;",
        library,
    )
    assert exported is not None
    symbols = {symbol.strip() for symbol in exported.group("symbols").split(",") if symbol.strip()}
    assert symbols == PUBLIC_DEPLOYMENTD_SYMBOLS


def test_governance_claims_exact_one_shot_controller_vertical_without_future_recovery() -> None:
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
        "paraegox_deployment::run_tenure_authority_process",
        "paraegox_deployment::run_deploymentd_process",
        (
            "paraegox-deploymentd initialize-reference-v1/commit-reference-loop-v1/"
            "commit-reference-empty-v1/acquire-tenure-v1/bootstrap-runtime-v1/"
            "apply-reference-v1 CLI"
        ),
    ]
    assert package["consumers"] == [
        "paraegox-tenure-authority",
        "paraegox-deploymentd",
    ]
    assert "one-shot DeploymentController" in package["responsibility"]
    for command in (
        "initialize-reference-v1",
        "commit-reference-loop-v1",
        "commit-reference-empty-v1",
        "acquire-tenure-v1",
        "bootstrap-runtime-v1",
        "apply-reference-v1",
    ):
        assert command in package["responsibility"]
    assert "exact signed PXAR before one direct Runtime send" in package["responsibility"]
    assert "strictly correlated Runtime-signed PXRT" in package["responsibility"]
    assert "Tenure, terminal apply, and committed Empty-plan replays" in package[
        "responsibility"
    ]
    assert "Loop-plan replay is byte-identical only while" in package["responsibility"]
    assert "bootstrap refresh may legitimately pin a newer Runtime epoch" in package[
        "responsibility"
    ]
    assert "committed at 1ed704c" in package["responsibility"]
    assert "verified by Ubuntu CI run 30748840399" in package["responsibility"]
    assert "Runtime query, Controller reconciliation" in package["responsibility"]
    assert "production restart reassembly/recovery" in package["responsibility"]
    assert "remain absent" in package["responsibility"]
    assert "does not constitute general live-state reassembly or recovery" in package[
        "responsibility"
    ]

    public_rows = [
        api
        for api in governance["public_apis"]
        if str(api["module"]).replace("-", "_") == "paraegox_deployment"
    ]
    assert len(public_rows) == 1
    assert {str(symbol) for symbol in public_rows[0]["symbols"]} == (
        PUBLIC_AUTHORITY_SYMBOLS | PUBLIC_DEPLOYMENTD_SYMBOLS
    )
    compatibility = public_rows[0]["compatibility"]
    for command in (
        "initialize-reference-v1",
        "commit-reference-loop-v1",
        "commit-reference-empty-v1",
        "acquire-tenure-v1",
        "bootstrap-runtime-v1",
        "apply-reference-v1",
    ):
        assert command in compatibility
    assert "no Runtime query, restart reassembly/recovery" in compatibility
    assert "Controller reconcile loop" in compatibility
    assert "communicate over a real strict versioned wire" in compatibility

    waiver_reasons = {
        waiver["id"]: waiver["reason"] for waiver in governance["waivers"]
    }
    assert "exact one-shot deploymentd consumers" in waiver_reasons["GOV-WAIVER-0002"]
    assert "cross-process wires are executable" in waiver_reasons["GOV-WAIVER-0002"]
    assert "three distinct non-root Runtime, Controller, and Authority" in waiver_reasons[
        "GOV-WAIVER-0009"
    ]
    assert "Ubuntu CI run 30748840399 at commit 1ed704c verified" in waiver_reasons[
        "GOV-WAIVER-0009"
    ]
    assert "372 pytest passes and no skips" in waiver_reasons["GOV-WAIVER-0009"]

    forbidden_claims = {
        "AcquireTenureRequestV1",
        "AcquireTenureResponseV1",
        "ControllerJournal",
        "RuntimeJournal",
        "DeploymentController",
        "RuntimeApplyEndpoint",
    }
    all_symbols = {str(symbol) for row in governance["public_apis"] for symbol in row["symbols"]}
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


def test_s7_f_query_contracts_are_registered_without_claiming_an_endpoint() -> None:
    governance = _load_toml(REPO_ROOT / "governance.toml")["registry"]
    package = next(
        package
        for package in governance["packages"]
        if package.get("cargo_package") == "paraegox-runtime-contracts"
    )
    assert "canonical authenticated PXQR/PXQS query owner" in package["responsibility"]
    assert "never infers a missing `SourcePlanRef`" in package["responsibility"]
    assert "do not by themselves create a Runtime query endpoint" in package["responsibility"]

    api = next(
        row
        for row in governance["public_apis"]
        if row["module"] == "paraegox_runtime_contracts::reference_control"
    )
    symbols = {str(symbol) for symbol in api["symbols"]}
    assert {
        "REFERENCE_QUERY_VERSION",
        "MAX_REFERENCE_RUNTIME_PLAN_SLICE_BYTES",
        "verify_reference_durable_slice_v1",
        "ReferenceQueryRequestV1",
        "ReferenceQueryResponseV1",
        "ReferenceQueryFactsV1",
    }.issubset(symbols)
    assert "cannot recover or fabricate missing provenance" in api["compatibility"]
    assert "do not claim that a Runtime endpoint" in api["compatibility"]


def test_exact_process_binaries_are_thin_and_runtime_control_stays_behind_runtimehost() -> None:
    binaries = sorted(path.name for path in (DEPLOYMENT_SRC / "bin").glob("*.rs"))
    assert binaries == ["paraegox-deploymentd.rs", "paraegox-tenure-authority.rs"]

    deploymentd = _read_required(DEPLOYMENT_SRC / "bin" / "paraegox-deploymentd.rs")
    assert "run_deploymentd_process" in deploymentd
    for private_symbol in (
        "ControllerJournal",
        "ControllerStore",
        "DeckCompiler",
        "DeploymentPlanner",
        "AcquireTenureRequestV1",
        "ReferenceApplyRequestV1",
    ):
        assert private_symbol not in deploymentd

    assert not (DEPLOYMENT_SRC / "deployment_controller_process.rs").exists()
    assert not (RUNTIME_SRC / "runtime_apply_endpoint.rs").exists()
    runtime_control = _read_required(RUNTIME_SRC / "runtime_control_endpoint.rs")
    assert "run_runtime_bootstrap_process" in runtime_control
    assert "ReferenceApplyRequestV1" in runtime_control
    assert "ReferenceApplyTerminalReceiptV1" in runtime_control


def test_s7_e_runtime_store_and_initializer_stay_private_behind_real_install_entrypoint() -> None:
    runtime_library = _read_required(RUNTIME_SRC / "lib.rs")
    private_modules = (
        "runtime_journal",
        "runtime_store",
        "runtime_initializer",
        "runtime_artifact",
        "runtime_build_metadata",
        "runtime_install_files",
        "runtime_host_entrypoint",
        "runtime_provisioning",
        "runtime_control_endpoint",
        "runtime_control_state",
    )
    for module in private_modules:
        _read_required(RUNTIME_SRC / f"{module}.rs")
        assert re.search(rf"(?m)^\s*mod\s+{module}\s*;\s*$", runtime_library)
        assert not re.search(
            rf"(?m)^\s*pub(?:\s*\([^)]*\))?\s+mod\s+{module}\s*;\s*$",
            runtime_library,
        )
    control_state = _read_required(RUNTIME_SRC / "runtime_control_state.rs")
    for child in ("runtime_reference_apply", "runtime_reference_owner"):
        _read_required(RUNTIME_SRC / f"{child}.rs")
        assert f'#[path = "{child}.rs"]' in control_state
        assert re.search(rf"(?m)^\s*pub\(crate\)\s+mod\s+{child}\s*;\s*$", control_state)
    assert "run_runtime_apply_endpoint" not in runtime_library
    assert "run_runtime_host_entrypoint" in runtime_library

    governance = _load_toml(REPO_ROOT / "governance.toml")["registry"]
    runtime_packages = [
        package
        for package in governance["packages"]
        if package.get("cargo_package") == "paraegox-runtime"
    ]
    assert len(runtime_packages) == 1
    runtime_package = runtime_packages[0]
    assert "crates/paraegox-runtime/src/runtime_journal.rs" in runtime_package["first_tests"]
    assert "crates/paraegox-runtime/src/runtime_store.rs" in runtime_package["first_tests"]
    assert "real one-shot Runtime initializer" in runtime_package["responsibility"]
    assert "release-descriptor-v1" in runtime_package["responsibility"]
    assert "install-v1" in runtime_package["responsibility"]
    assert "same four-byte-framed channel" in runtime_package["responsibility"]
    assert "canonical PXBR bootstrap and PXAR v5 apply requests" in runtime_package[
        "responsibility"
    ]
    assert "canonical Runtime-signed PXRT terminal Receipt" in runtime_package["responsibility"]
    assert "Runtime query, production restart reassembly/recovery" in runtime_package[
        "responsibility"
    ]
    assert "remain unimplemented" in runtime_package["responsibility"]

    public_symbols = {str(symbol) for row in governance["public_apis"] for symbol in row["symbols"]}
    assert public_symbols.isdisjoint(
        {
            "RuntimeJournal",
            "RuntimeJournalSnapshot",
            "RuntimeApplyEndpoint",
            "run_runtime_apply_endpoint",
        }
    )
    assert {
        "run_runtime_host_entrypoint",
        "RuntimeHostEntrypointError",
    }.issubset(public_symbols)
