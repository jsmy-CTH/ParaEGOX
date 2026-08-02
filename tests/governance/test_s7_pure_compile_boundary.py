from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATES_ROOT = REPO_ROOT / "crates"
DEPLOYMENT_ROOT = CRATES_ROOT / "paraegox-deployment"
DEPLOYMENT_SRC = DEPLOYMENT_ROOT / "src"
PURE_COMPILE_SOURCES = (
    DEPLOYMENT_SRC / "deck.rs",
    DEPLOYMENT_SRC / "planner.rs",
)

DEPENDENCY_TABLES = {"dependencies", "dev-dependencies", "build-dependencies"}
FORBIDDEN_RUNTIME_DEPENDENCIES = {"paraegox-deployment", "paraegox-decks"}
FORBIDDEN_GRAPH_NAMES = {
    "graph",
    "graph-foundation",
    "graph_foundation",
    "paraegox-graph",
    "paraegox-graph-foundation",
}


def _read_required(path: Path) -> str:
    assert path.is_file(), f"required S7-C source is missing: {path.relative_to(REPO_ROOT)}"
    return path.read_text(encoding="utf-8")


def _load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(_read_required(path))


def _normalized_dependency_names(manifest: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            for key, nested in value.items():
                if key in DEPENDENCY_TABLES and isinstance(nested, Mapping):
                    for alias, specification in nested.items():
                        names.add(str(alias).replace("_", "-"))
                        if isinstance(specification, Mapping):
                            package = specification.get("package")
                            if isinstance(package, str):
                                names.add(package.replace("_", "-"))
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(manifest)
    return names


def test_deck_and_planner_stay_crate_private() -> None:
    library = _read_required(DEPLOYMENT_SRC / "lib.rs")
    for source_path in PURE_COMPILE_SOURCES:
        _read_required(source_path)
        module = source_path.stem
        assert re.search(rf"(?m)^\s*mod\s+{module}\s*;\s*$", library)

    assert not re.search(
        r"(?m)^\s*pub(?:\s*\([^)]*\))?\s+mod\s+(?:deck|planner)\s*;\s*$",
        library,
    )
    assert not re.search(
        r"\bpub(?:\s*\([^)]*\))?\s+use\s+[^;]*\b(?:deck|planner)\s*::",
        library,
    )


def test_no_graph_foundation_crate_or_generic_module_is_admitted() -> None:
    workspace = _load_toml(REPO_ROOT / "Cargo.toml")
    members = workspace["workspace"]["members"]
    assert isinstance(members, list)

    for member in members:
        member_path = REPO_ROOT / str(member)
        member_name = member_path.name
        package_name = _load_toml(member_path / "Cargo.toml")["package"]["name"]
        assert member_name not in FORBIDDEN_GRAPH_NAMES
        assert package_name not in FORBIDDEN_GRAPH_NAMES
        assert not member_name.startswith("paraegox-graph")
        assert not package_name.startswith("paraegox-graph")

    for path in CRATES_ROOT.rglob("*"):
        relative_parts = path.relative_to(CRATES_ROOT).parts
        assert not any(part in FORBIDDEN_GRAPH_NAMES for part in relative_parts)

    graph_module = re.compile(
        r"(?m)^\s*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?:graph|graph_foundation)\s*;"
    )
    for crate_root in (*CRATES_ROOT.glob("*/src/lib.rs"), *CRATES_ROOT.rglob("mod.rs")):
        assert not graph_module.search(crate_root.read_text(encoding="utf-8"))


def test_runtime_layers_do_not_depend_on_deployment_compile_layers() -> None:
    for crate_name in ("paraegox-runtime", "paraegox-runtime-host"):
        manifest = _load_toml(CRATES_ROOT / crate_name / "Cargo.toml")
        dependencies = _normalized_dependency_names(manifest)
        assert dependencies.isdisjoint(FORBIDDEN_RUNTIME_DEPENDENCIES), (
            f"{crate_name} reverses the Runtime-to-Deployment dependency boundary: "
            f"{sorted(dependencies & FORBIDDEN_RUNTIME_DEPENDENCIES)}"
        )


def test_pure_compile_sources_do_not_reimplement_manifest_or_side_effects() -> None:
    forbidden_literals = (
        "PXCM",
        "paraegox.runtime.artifact-compatibility-manifest.sha256.v1",
        "decode_compatibility_manifest",
        "decode_compatibility_projection",
        "build_manifest_wire",
        "build_projection_wire",
        "append_manifest_target_row",
        "decode_manifest_target_row",
    )
    forbidden_patterns = {
        "manifest type definition": re.compile(
            r"\b(?:struct|enum|union|type|trait)\s+"
            r"RuntimeArtifactCompatibilityManifestV1\b"
        ),
        "manifest codec implementation": re.compile(
            r"\bimpl(?:\s*<[^>]*>)?\s+RuntimeArtifactCompatibilityManifestV1\b"
        ),
        "manifest framing constant": re.compile(
            r"\bconst\s+(?:COMPATIBILITY_)?MANIFEST_"
            r"(?:MAGIC|DIGEST_DOMAIN|VERSION|BYTES)\b"
        ),
        "filesystem/network/process/thread access": re.compile(
            r"\bstd\s*::\s*(?:fs|net|process|thread)\s*::"
        ),
        "side-effect module import": re.compile(
            r"(?m)^\s*use\s+std\s*::\s*(?:fs|net|process|thread)\s*;"
        ),
        "grouped side-effect import": re.compile(
            r"(?m)^\s*use\s+std\s*::\s*\{[^}\n]*\b(?:fs|net|process|thread)\b"
        ),
        "async runtime access": re.compile(r"\b(?:tokio|async_std)\s*::"),
        "async function": re.compile(
            r"(?m)^\s*(?:pub(?:\s*\([^)]*\))?\s+)?async\s+fn\b"
        ),
        "await point": re.compile(r"\.await\b"),
        "mutable static": re.compile(
            r"(?m)^\s*(?:pub(?:\s*\([^)]*\))?\s+)?static\s+mut\s+[A-Za-z_]\w*"
        ),
        "interior-mutable static": re.compile(
            r"(?m)^\s*(?:pub(?:\s*\([^)]*\))?\s+)?static\s+[A-Za-z_]\w*\s*:"
            r"[^=;\n]*\b(?:Atomic\w*|Mutex|OnceLock|RwLock)\b"
        ),
        "thread-local state": re.compile(r"\bthread_local\s*!"),
    }

    for path in PURE_COMPILE_SOURCES:
        source = _read_required(path)
        for literal in forbidden_literals:
            assert literal not in source, (
                f"{path.relative_to(REPO_ROOT)} duplicates manifest authority: {literal}"
            )
        for mechanism, pattern in forbidden_patterns.items():
            assert not pattern.search(source), (
                f"{path.relative_to(REPO_ROOT)} violates pure-compile boundary: {mechanism}"
            )


def test_s7_c_pure_compile_owners_remain_private_after_s7_d() -> None:
    governance = _load_toml(REPO_ROOT / "governance.toml")
    registry = governance["registry"]

    deployment_rows = [
        package
        for package in registry["packages"]
        if package.get("cargo_package") == "paraegox-deployment"
    ]
    assert len(deployment_rows) == 1
    deployment_row = deployment_rows[0]
    assert deployment_row["status"] == "experimental"
    assert deployment_row["public_entrypoints"] == [
        "paraegox_deployment::run_tenure_authority_process"
    ]
    assert deployment_row["consumers"] == ["paraegox-tenure-authority"]

    for api in registry["public_apis"]:
        module = str(api["module"]).replace("-", "_")
        symbols = {str(symbol) for symbol in api["symbols"]}
        if module == "paraegox_deployment":
            assert symbols == {
                "TenureAuthorityProcessError",
                "run_tenure_authority_process",
            }
            continue
        assert not module.startswith(("paraegox_deployment", "paraegox_decks"))

    deployment_manifest = _load_toml(DEPLOYMENT_ROOT / "Cargo.toml")
    assert "bin" not in deployment_manifest
    assert not (DEPLOYMENT_SRC / "main.rs").exists()
    executable_sources = sorted(
        path.name for path in (DEPLOYMENT_SRC / "bin").glob("*.rs")
    )
    assert executable_sources == ["paraegox-tenure-authority.rs"]
