from __future__ import annotations

import datetime as dt
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "check_governance.py"
SPEC = importlib.util.spec_from_file_location("paraegox_check_governance", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
governance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = governance
SPEC.loader.exec_module(governance)


def base_config() -> dict:
    return {
        "schema_version": 1,
        "repository": {
            "source_root": "src/paraegox",
            "term_scan_roots": ["src"],
            "exception_scan_roots": ["src", "tests", ".github"],
            "documentation_roots": ["docs"],
            "allowed_top_level_directories": [".github", "docs", "src", "tests"],
            "ignored_top_level_directories": [],
        },
        "registry": {
            "packages": [],
            "public_apis": [],
            "waivers": [],
            "deprecations": [],
            "feature_flags": [],
        },
        "architecture": {
            "rules": [
                {
                    "id": "ARCH-TEST",
                    "source": "paraegox.kernel",
                    "forbid": ["paraegox.runtime"],
                    "reason": "test boundary",
                }
            ]
        },
        "terminology": {
            "rules": [
                {
                    "id": "TERM-TEST",
                    "identifier": "OldContract",
                    "replacement": "NewContract",
                }
            ]
        },
    }


def validate(root: Path, config: dict) -> list:
    return governance.validate_repository(root, config, today=dt.date(2026, 7, 29))


def rule_ids(findings: list) -> set[str]:
    return {finding.rule_id for finding in findings}


def test_repository_configuration_passes_current_tree() -> None:
    config = governance.load_config(REPO_ROOT / "governance.toml")
    assert governance.validate_repository(REPO_ROOT, config, today=dt.date(2026, 7, 29)) == []


def test_unadmitted_top_level_directory_is_rejected(tmp_path: Path) -> None:
    config = base_config()
    (tmp_path / "mystery").mkdir()

    findings = validate(tmp_path, config)

    assert "DIR-001" in rule_ids(findings)


def test_implementation_package_requires_registry_entry(tmp_path: Path) -> None:
    config = base_config()
    package = tmp_path / "src" / "paraegox" / "kernel"
    package.mkdir(parents=True)
    (package / "identity.py").write_text("VALUE = 1\n", encoding="utf-8")

    findings = validate(tmp_path, config)

    assert "PKG-006" in rule_ids(findings)


def test_forbidden_dependency_is_rejected(tmp_path: Path) -> None:
    config = base_config()
    package = tmp_path / "src" / "paraegox" / "kernel"
    package.mkdir(parents=True)
    (package / "bad.py").write_text("import paraegox.runtime\n", encoding="utf-8")
    config["registry"]["packages"] = [
        {
            "path": "src/paraegox/kernel",
            "owner": "kernel",
            "responsibility": "mechanisms",
            "status": "internal",
            "public_entrypoints": [],
            "consumers": [],
            "first_tests": [],
            "removal_condition": "remove with the package",
        }
    ]

    findings = validate(tmp_path, config)

    assert "ARCH-TEST" in rule_ids(findings)


def test_forbidden_terminology_is_rejected(tmp_path: Path) -> None:
    config = base_config()
    package = tmp_path / "src" / "paraegox"
    package.mkdir(parents=True)
    (package / "contract.py").write_text("class OldContract: pass\n", encoding="utf-8")

    findings = validate(tmp_path, config)

    assert "TERM-TEST" in rule_ids(findings)


def test_unregistered_suppression_is_rejected(tmp_path: Path) -> None:
    config = base_config()
    package = tmp_path / "src" / "paraegox"
    package.mkdir(parents=True)
    suppression = "# no" + "qa: F401\n"
    (package / "suppressed.py").write_text("import os  " + suppression, encoding="utf-8")

    findings = validate(tmp_path, config)

    assert "WAIVER-001" in rule_ids(findings)


def test_expired_waiver_is_rejected_even_when_referenced(tmp_path: Path) -> None:
    config = base_config()
    package = tmp_path / "src" / "paraegox"
    package.mkdir(parents=True)
    waiver_id = "GOV-WAIVER-0001"
    suppression = "# no" + f"qa: F401  # {waiver_id}\n"
    (package / "suppressed.py").write_text("import os  " + suppression, encoding="utf-8")
    config["registry"]["waivers"] = [
        {
            "id": waiver_id,
            "rule_id": "ruff:F401",
            "scope": "src/paraegox/suppressed.py",
            "owner": "kernel",
            "reason": "test fixture",
            "expires_at": "2026-07-28",
        }
    ]

    findings = validate(tmp_path, config)

    assert {"GOV-007", "WAIVER-004"} <= rule_ids(findings)


def test_broken_local_markdown_link_is_rejected(tmp_path: Path) -> None:
    config = base_config()
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "README.md").write_text("[missing](absent.md)\n", encoding="utf-8")

    findings = validate(tmp_path, config)

    assert "DOC-001" in rule_ids(findings)


def test_forbidden_workspace_dependency_is_rejected(tmp_path: Path) -> None:
    kernel = tmp_path / "crates" / "paraegox-kernel"
    runtime = tmp_path / "crates" / "paraegox-runtime"
    kernel.mkdir(parents=True)
    runtime.mkdir(parents=True)
    kernel_manifest = kernel / "Cargo.toml"
    runtime_manifest = runtime / "Cargo.toml"
    kernel_manifest.write_text("[package]\nname = 'paraegox-kernel'\n", encoding="utf-8")
    runtime_manifest.write_text("[package]\nname = 'paraegox-runtime'\n", encoding="utf-8")
    config = base_config()
    config["cargo"] = {
        "crate_root": "crates",
        "rules": [
            {
                "id": "CARGO-ARCH-TEST",
                "source": "paraegox-kernel",
                "allow_workspace_dependencies": [],
            },
            {
                "id": "CARGO-ARCH-RUNTIME",
                "source": "paraegox-runtime",
                "allow_workspace_dependencies": [],
            },
        ],
    }
    config["registry"]["packages"] = [
        {
            "path": "crates/paraegox-kernel",
            "cargo_package": "paraegox-kernel",
        },
        {
            "path": "crates/paraegox-runtime",
            "cargo_package": "paraegox-runtime",
        },
    ]
    metadata = {
        "workspace_members": ["kernel-id", "runtime-id"],
        "packages": [
            {
                "id": "kernel-id",
                "name": "paraegox-kernel",
                "manifest_path": str(kernel_manifest),
                "dependencies": [{"name": "paraegox-runtime", "kind": "dev"}],
            },
            {
                "id": "runtime-id",
                "name": "paraegox-runtime",
                "manifest_path": str(runtime_manifest),
                "dependencies": [],
            },
        ],
    }

    findings = governance._validate_cargo_metadata(tmp_path, config, metadata)

    assert "CARGO-ARCH-TEST" in rule_ids(findings)


def test_missing_cargo_is_a_hard_failure(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    (tmp_path / "Cargo.lock").write_text("version = 4\n", encoding="utf-8")
    config = base_config()
    config["cargo"] = {"manifest_path": "Cargo.toml", "crate_root": "crates", "rules": []}

    def missing_cargo(*_args, **_kwargs):
        raise FileNotFoundError("cargo not found")

    monkeypatch.setattr(governance.subprocess, "run", missing_cargo)

    findings = governance.check_cargo_workspace(tmp_path, config)

    assert "CARGO-002" in rule_ids(findings)


def test_missing_cargo_lock_is_a_hard_failure(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
    config = base_config()
    config["cargo"] = {"manifest_path": "Cargo.toml", "crate_root": "crates", "rules": []}

    findings = governance.check_cargo_workspace(tmp_path, config)

    assert "CARGO-011" in rule_ids(findings)


def test_unregistered_rust_suppression_is_rejected(tmp_path: Path) -> None:
    config = base_config()
    config["repository"]["exception_scan_roots"] = ["crates"]
    source = tmp_path / "crates" / "example" / "src"
    source.mkdir(parents=True)
    (source / "lib.rs").write_text("#[allow(dead_code)]\nfn hidden() {}\n", encoding="utf-8")

    findings = governance.check_exceptions(
        tmp_path, config, today=dt.date(2026, 7, 29)
    )

    assert "WAIVER-001" in rule_ids(findings)


def test_rust_inner_attribute_cfg_attr_and_block_debt_are_scanned(tmp_path: Path) -> None:
    config = base_config()
    config["repository"]["exception_scan_roots"] = ["crates"]
    source = tmp_path / "crates" / "example" / "src"
    source.mkdir(parents=True)
    (source / "lib.rs").write_text(
        "#![allow(dead_code)]\n"
        "#![cfg_attr(test, allow(unused_imports))]\n"
        "/* TODO: remove compatibility branch */\n",
        encoding="utf-8",
    )

    findings = governance.check_exceptions(
        tmp_path, config, today=dt.date(2026, 7, 29)
    )

    assert sum(finding.rule_id == "WAIVER-001" for finding in findings) == 3


def test_rust_exception_text_inside_string_is_not_scanned(tmp_path: Path) -> None:
    config = base_config()
    config["repository"]["exception_scan_roots"] = ["crates"]
    source = tmp_path / "crates" / "example" / "src"
    source.mkdir(parents=True)
    (source / "lib.rs").write_text(
        'const MESSAGE: &str = "todo!() TODO #[allow(dead_code)]";\n',
        encoding="utf-8",
    )

    findings = governance.check_exceptions(
        tmp_path, config, today=dt.date(2026, 7, 29)
    )

    assert findings == []


def test_waiver_rule_must_match_detected_exception(tmp_path: Path) -> None:
    config = base_config()
    config["repository"]["exception_scan_roots"] = ["crates"]
    source = tmp_path / "crates" / "example" / "src"
    source.mkdir(parents=True)
    waiver_id = "GOV-WAIVER-0001"
    (source / "lib.rs").write_text(
        f"#[allow(dead_code)] // {waiver_id}\nfn hidden() {{}}\n",
        encoding="utf-8",
    )
    config["registry"]["waivers"] = [
        {
            "id": waiver_id,
            "rule_id": "rust:expect",
            "scope": "crates/example/src/lib.rs",
            "owner": "kernel",
            "reason": "negative test",
            "expires_at": "2026-08-01",
        }
    ]

    findings = governance.check_exceptions(
        tmp_path, config, today=dt.date(2026, 7, 29)
    )

    assert {"WAIVER-006", "WAIVER-007"} <= rule_ids(findings)


def test_cargo_member_requires_workspace_lints_and_external_admission(
    tmp_path: Path,
) -> None:
    crate = tmp_path / "crates" / "paraegox-kernel"
    crate.mkdir(parents=True)
    manifest = crate / "Cargo.toml"
    manifest.write_text("[package]\nname = 'paraegox-kernel'\n", encoding="utf-8")
    config = base_config()
    config["cargo"] = {
        "crate_root": "crates",
        "rules": [
            {
                "id": "CARGO-ARCH-TEST",
                "source": "paraegox-kernel",
                "allow_workspace_dependencies": [],
                "allow_external_dependencies": [],
            }
        ],
    }
    config["registry"]["packages"] = [
        {
            "path": "crates/paraegox-kernel",
            "cargo_package": "paraegox-kernel",
        }
    ]
    metadata = {
        "workspace_members": ["kernel-id"],
        "packages": [
            {
                "id": "kernel-id",
                "name": "paraegox-kernel",
                "manifest_path": str(manifest),
                "dependencies": [{"name": "tokio"}],
            }
        ],
    }

    findings = governance._validate_cargo_metadata(tmp_path, config, metadata)

    assert {"CARGO-013", "CARGO-ARCH-TEST"} <= rule_ids(findings)
