#!/usr/bin/env python3
"""Validate ParaEGOX's executable repository-governance rules."""

from __future__ import annotations

import argparse
import ast
import datetime as dt
import fnmatch
import json
import re
import subprocess
import sys
import tokenize
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

VALID_PACKAGE_STATUSES = {"internal", "experimental", "enabler", "public"}
VALID_DOCUMENT_STATUSES = {
    "Accepted",
    "Current",
    "Draft",
    "Proposed",
    "Rejected",
    "Research Complete",
    "Superseded",
}
WAIVER_ID_RE = re.compile(r"\bGOV-WAIVER-\d{4}\b")
MARKDOWN_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
DOCUMENT_STATUS_RE = re.compile(r"^> 状态：(.+)$", re.MULTILINE)
ADR_NAME_RE = re.compile(r"^ADR-(\d{4})-")
COMMENT_EXCEPTION_RE = re.compile(r"\b(?:noqa|type:\s*ignore|TODO|FIXME)\b", re.IGNORECASE)
YAML_EXCEPTION_RE = re.compile(r"(?:continue-on-error\s*:\s*true|\|\|\s*true)", re.IGNORECASE)
PYTEST_EXCEPTION_RE = re.compile(r"(?:pytest\.mark\.(?:skip|xfail)|pytest\.skip\s*\()")
RUST_ATTRIBUTE_EXCEPTION_RE = re.compile(
    r"(?:#\s*!?\s*\[\s*(?:allow|expect|ignore)\b|"
    r"#\s*!?\s*\[\s*cfg_attr\b[^\]]*\b(?:allow|expect)\s*\()",
    re.IGNORECASE,
)
RUST_MACRO_EXCEPTION_RE = re.compile(r"\b(?:todo|unimplemented)!\s*\(", re.IGNORECASE)
DEBT_MARKER_RE = re.compile(r"\b(?:TODO|FIXME)\b", re.IGNORECASE)
NOQA_RE = re.compile(r"#\s*noqa(?:\s*:\s*([A-Za-z0-9_,\s]+))?", re.IGNORECASE)
RUST_QUOTED_LITERAL_RE = re.compile(
    r'(?:br|r)#{0,16}".*?"#{0,16}|b?"(?:\\.|[^"\\])*"'
)


@dataclass(frozen=True)
class Finding:
    rule_id: str
    path: str
    message: str
    line: int | None = None

    def render(self) -> str:
        location = self.path
        if self.line is not None:
            location = f"{location}:{self.line}"
        return f"{location}: [{self.rule_id}] {self.message}"


def load_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def validate_repository(root: Path, config: dict[str, Any], *, today: dt.date) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(check_config(config, today=today))
    findings.extend(check_top_level_directories(root, config))
    findings.extend(check_package_registry(root, config))
    findings.extend(check_cargo_workspace(root, config))
    findings.extend(check_architecture_imports(root, config))
    findings.extend(check_terminology(root, config))
    findings.extend(check_exceptions(root, config, today=today))
    findings.extend(check_documentation(root, config))
    return sorted(findings, key=lambda item: (item.path, item.line or 0, item.rule_id))


def check_config(config: dict[str, Any], *, today: dt.date) -> list[Finding]:
    findings: list[Finding] = []
    if config.get("schema_version") != 1:
        findings.append(Finding("GOV-001", "governance.toml", "schema_version must be 1"))

    registry = _table(config, "registry")
    for name in ("packages", "public_apis", "waivers", "deprecations", "feature_flags"):
        if not isinstance(registry.get(name), list):
            findings.append(
                Finding("GOV-002", "governance.toml", f"registry.{name} must be an array")
            )

    seen_ids: set[str] = set()
    for kind in ("waivers", "deprecations", "feature_flags"):
        for index, raw_entry in enumerate(_list(registry, kind)):
            entry = _entry(raw_entry)
            entry_id = str(entry.get("id", ""))
            if not entry_id:
                findings.append(
                    Finding("GOV-003", "governance.toml", f"registry.{kind}[{index}] needs id")
                )
            elif entry_id in seen_ids:
                findings.append(
                    Finding("GOV-004", "governance.toml", f"duplicate registry id {entry_id}")
                )
            else:
                seen_ids.add(entry_id)

    for index, raw_entry in enumerate(_list(registry, "waivers")):
        entry = _entry(raw_entry)
        findings.extend(
            _require_fields(
                entry,
                "governance.toml",
                f"registry.waivers[{index}]",
                ("id", "rule_id", "scope", "owner", "reason", "expires_at"),
            )
        )
        if entry.get("id") and not WAIVER_ID_RE.fullmatch(str(entry["id"])):
            findings.append(
                Finding("GOV-005", "governance.toml", f"invalid waiver id {entry['id']!r}")
            )
        findings.extend(_check_expiry(entry, "expires_at", today=today))

    for kind, date_field, required in (
        (
            "deprecations",
            "remove_by",
            ("id", "surface", "replacement", "owner", "remove_by", "remaining_consumers"),
        ),
        (
            "feature_flags",
            "remove_by",
            ("id", "name", "owner", "default", "remove_by", "removal_condition"),
        ),
    ):
        for index, raw_entry in enumerate(_list(registry, kind)):
            entry = _entry(raw_entry)
            findings.extend(
                _require_fields(
                    entry,
                    "governance.toml",
                    f"registry.{kind}[{index}]",
                    required,
                )
            )
            findings.extend(_check_expiry(entry, date_field, today=today))

    return findings


def check_top_level_directories(root: Path, config: dict[str, Any]) -> list[Finding]:
    repository = _table(config, "repository")
    allowed = set(_strings(repository.get("allowed_top_level_directories")))
    ignored = set(_strings(repository.get("ignored_top_level_directories")))
    findings: list[Finding] = []
    for path in sorted(item for item in root.iterdir() if item.is_dir()):
        if path.name not in allowed and path.name not in ignored:
            findings.append(
                Finding(
                    "DIR-001",
                    path.name,
                    "top-level directory is not admitted in governance.toml",
                )
            )
    return findings


def check_package_registry(root: Path, config: dict[str, Any]) -> list[Finding]:
    repository = _table(config, "repository")
    registry = _table(config, "registry")
    source_root = root / str(repository.get("source_root", "src/paraegox"))
    raw_entries = _list(registry, "packages")
    entries = [_entry(item) for item in raw_entries]
    findings: list[Finding] = []
    registered_paths: set[str] = set()

    required = (
        "path",
        "owner",
        "responsibility",
        "status",
        "public_entrypoints",
        "consumers",
        "first_tests",
        "removal_condition",
    )
    for index, entry in enumerate(entries):
        label = f"registry.packages[{index}]"
        findings.extend(_require_fields(entry, "governance.toml", label, required))
        path_value = str(entry.get("path", ""))
        if path_value:
            if path_value in registered_paths:
                findings.append(
                    Finding("PKG-001", "governance.toml", f"duplicate package path {path_value}")
                )
            registered_paths.add(path_value)
            if not (root / path_value).is_dir():
                findings.append(
                    Finding("PKG-002", path_value, "registered package directory does not exist")
                )
        status = str(entry.get("status", ""))
        if status and status not in VALID_PACKAGE_STATUSES:
            findings.append(
                Finding("PKG-003", "governance.toml", f"invalid package status {status!r}")
            )
        if status == "public" and not _strings(entry.get("consumers")):
            findings.append(
                Finding("PKG-004", "governance.toml", f"{label} public package needs consumers")
            )
        if status == "public" and not _strings(entry.get("public_entrypoints")):
            findings.append(
                Finding(
                    "PKG-007",
                    "governance.toml",
                    f"{label} public package needs public_entrypoints",
                )
            )
        if not _strings(entry.get("first_tests")):
            findings.append(
                Finding("PKG-008", "governance.toml", f"{label} needs first_tests")
            )
        for test_path in _strings(entry.get("first_tests")):
            if not (root / test_path).is_file():
                findings.append(Finding("PKG-005", test_path, "registered first test is missing"))

    if source_root.is_dir():
        for package in sorted(path for path in source_root.iterdir() if path.is_dir()):
            if package.name == "__pycache__":
                continue
            relative = package.relative_to(root).as_posix()
            if relative not in registered_paths:
                findings.append(
                    Finding(
                        "PKG-006",
                        relative,
                        "implementation package is not registered in registry.packages",
                    )
                )

    for index, raw_entry in enumerate(_list(registry, "public_apis")):
        entry = _entry(raw_entry)
        label = f"registry.public_apis[{index}]"
        findings.extend(
            _require_fields(
                entry,
                "governance.toml",
                label,
                ("module", "symbols", "owner", "consumers", "compatibility", "tests"),
            )
        )
        if entry.get("module") and not _strings(entry.get("consumers")):
            findings.append(
                Finding("API-001", "governance.toml", f"{label} needs independent consumers")
            )
        if entry.get("module") and not _strings(entry.get("symbols")):
            findings.append(
                Finding("API-003", "governance.toml", f"{label} needs symbols")
            )
        if entry.get("module") and not _strings(entry.get("tests")):
            findings.append(
                Finding("API-004", "governance.toml", f"{label} needs compatibility tests")
            )
        for test_path in _strings(entry.get("tests")):
            if not (root / test_path).is_file():
                findings.append(Finding("API-002", test_path, "public API test is missing"))
    return findings


def check_architecture_imports(root: Path, config: dict[str, Any]) -> list[Finding]:
    source_root_value = str(_table(config, "repository").get("source_root", "src/paraegox"))
    source_root = root / source_root_value
    source_parent = source_root.parent
    rules = [_entry(item) for item in _list(_table(config, "architecture"), "rules")]
    findings: list[Finding] = []
    if not source_root.is_dir():
        return findings

    for path in sorted(source_root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except SyntaxError as exc:
            findings.append(
                Finding(
                    "ARCH-000",
                    path.relative_to(root).as_posix(),
                    f"cannot inspect imports: {exc.msg}",
                    exc.lineno,
                )
            )
            continue
        module = _module_name(path, source_parent)
        imports = _imported_modules(tree)
        for rule in rules:
            source = str(rule.get("source", ""))
            if not _module_matches(module, source):
                continue
            for imported, line in imports:
                for forbidden in _strings(rule.get("forbid")):
                    if _module_matches(imported, forbidden):
                        findings.append(
                            Finding(
                                str(rule.get("id", "ARCH")),
                                path.relative_to(root).as_posix(),
                                f"{module} must not import {imported}: {rule.get('reason', '')}",
                                line,
                            )
                        )
    return findings


def check_cargo_workspace(root: Path, config: dict[str, Any]) -> list[Finding]:
    cargo_config = _table(config, "cargo")
    manifest_value = str(cargo_config.get("manifest_path", ""))
    if not manifest_value:
        return []

    manifest_path = root / manifest_value
    if not manifest_path.is_file():
        return [Finding("CARGO-001", manifest_value, "Cargo workspace manifest is missing")]
    lockfile_value = str(cargo_config.get("lockfile_path", "Cargo.lock"))
    if not (root / lockfile_value).is_file():
        return [Finding("CARGO-011", lockfile_value, "Cargo lockfile is missing")]

    command = [
        "cargo",
        "metadata",
        "--format-version",
        "1",
        "--locked",
        "--manifest-path",
        str(manifest_path),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError as exc:
        return [Finding("CARGO-002", manifest_value, f"cannot execute cargo metadata: {exc}")]

    if completed.returncode != 0:
        detail = _first_nonempty_line(completed.stderr) or "cargo metadata failed"
        return [Finding("CARGO-003", manifest_value, detail)]

    try:
        metadata = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        return [Finding("CARGO-004", manifest_value, f"invalid cargo metadata JSON: {exc.msg}")]
    if not isinstance(metadata, dict):
        return [Finding("CARGO-004", manifest_value, "cargo metadata root must be an object")]

    return _validate_cargo_metadata(root, config, metadata)


def _validate_cargo_metadata(
    root: Path, config: dict[str, Any], metadata: dict[str, Any]
) -> list[Finding]:
    cargo_config = _table(config, "cargo")
    crate_root_value = str(cargo_config.get("crate_root", "crates"))
    crate_root = root / crate_root_value
    packages = [item for item in metadata.get("packages", []) if isinstance(item, dict)]
    workspace_members = {str(item) for item in metadata.get("workspace_members", [])}
    workspace_packages = {
        str(package.get("name")): package
        for package in packages
        if str(package.get("id")) in workspace_members and package.get("name")
    }
    findings: list[Finding] = []

    registry_entries = [
        _entry(item) for item in _list(_table(config, "registry"), "packages")
    ]
    registered_by_path = {
        str(entry.get("path")): entry for entry in registry_entries if entry.get("path")
    }
    workspace_manifest_paths: set[Path] = set()

    for package_name, package in sorted(workspace_packages.items()):
        raw_manifest = package.get("manifest_path")
        if not isinstance(raw_manifest, str):
            findings.append(
                Finding("CARGO-005", "Cargo.toml", f"{package_name} has no manifest path")
            )
            continue
        manifest = Path(raw_manifest).resolve()
        workspace_manifest_paths.add(manifest)
        try:
            package_path = manifest.parent.relative_to(root.resolve()).as_posix()
        except ValueError:
            findings.append(
                Finding(
                    "CARGO-006",
                    raw_manifest,
                    f"workspace package {package_name} is outside the repository",
                )
            )
            continue
        try:
            manifest.parent.relative_to(crate_root.resolve())
        except ValueError:
            findings.append(
                Finding(
                    "CARGO-012",
                    package_path,
                    f"workspace package {package_name} must live under {crate_root_value}",
                )
            )
        entry = registered_by_path.get(package_path)
        if entry is None:
            findings.append(
                Finding(
                    "CARGO-007",
                    package_path,
                    f"workspace package {package_name} is not registered",
                )
            )
        elif str(entry.get("cargo_package", "")) != package_name:
            findings.append(
                Finding(
                    "CARGO-008",
                    "governance.toml",
                    f"{package_path} must register cargo_package = {package_name!r}",
                )
            )

        try:
            with manifest.open("rb") as handle:
                member_manifest = tomllib.load(handle)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            findings.append(
                Finding(
                    "CARGO-013",
                    package_path,
                    f"cannot inspect workspace lint inheritance: {exc}",
                )
            )
        else:
            lints = member_manifest.get("lints")
            if not isinstance(lints, dict) or lints.get("workspace") is not True:
                findings.append(
                    Finding(
                        "CARGO-013",
                        manifest.relative_to(root).as_posix(),
                        "workspace package must declare [lints] workspace = true",
                    )
                )
    if crate_root.is_dir():
        for manifest in sorted(crate_root.rglob("Cargo.toml")):
            if manifest.resolve() not in workspace_manifest_paths:
                findings.append(
                    Finding(
                        "CARGO-009",
                        manifest.relative_to(root).as_posix(),
                        "crate manifest is not an admitted workspace member",
                    )
                )

    rules = [_entry(item) for item in _list(cargo_config, "rules")]
    rules_by_source: dict[str, dict[str, Any]] = {}
    for rule in rules:
        source = str(rule.get("source", ""))
        if not source:
            findings.append(
                Finding("CARGO-014", "governance.toml", "Cargo dependency rule needs source")
            )
        elif source in rules_by_source:
            findings.append(
                Finding(
                    "CARGO-014",
                    "governance.toml",
                    f"duplicate Cargo dependency rule for {source}",
                )
            )
        else:
            rules_by_source[source] = rule
    workspace_names = set(workspace_packages)
    for source in sorted(set(rules_by_source) - workspace_names):
        findings.append(
            Finding(
                "CARGO-015",
                "governance.toml",
                f"Cargo dependency rule targets missing workspace package {source}",
            )
        )
    for package_name, package in sorted(workspace_packages.items()):
        rule = rules_by_source.get(package_name)
        if rule is None:
            findings.append(
                Finding(
                    "CARGO-010",
                    "governance.toml",
                    f"workspace package {package_name} has no Cargo dependency rule",
                )
            )
            continue
        allowed = set(_strings(rule.get("allow_workspace_dependencies")))
        actual = {
            str(dependency.get("name"))
            for dependency in package.get("dependencies", [])
            if isinstance(dependency, dict)
            and str(dependency.get("name")) in workspace_names
        }
        for dependency in sorted(actual - allowed):
            findings.append(
                Finding(
                    str(rule.get("id", "CARGO-ARCH")),
                    str(package.get("manifest_path", "Cargo.toml")),
                    f"{package_name} must not depend on workspace package {dependency}",
                )
            )
        allowed_external = set(_strings(rule.get("allow_external_dependencies")))
        actual_external = {
            str(dependency.get("name"))
            for dependency in package.get("dependencies", [])
            if isinstance(dependency, dict)
            and dependency.get("name")
            and str(dependency.get("name")) not in workspace_names
        }
        for dependency in sorted(actual_external - allowed_external):
            findings.append(
                Finding(
                    str(rule.get("id", "CARGO-ARCH")),
                    str(package.get("manifest_path", "Cargo.toml")),
                    f"{package_name} must not depend on external package {dependency}",
                )
            )
    return findings


def check_terminology(root: Path, config: dict[str, Any]) -> list[Finding]:
    repository = _table(config, "repository")
    rules = [_entry(item) for item in _list(_table(config, "terminology"), "rules")]
    findings: list[Finding] = []
    for path in _iter_scannable_files(root, _strings(repository.get("term_scan_roots"))):
        text = path.read_text(encoding="utf-8", errors="replace")
        for rule in rules:
            identifier = str(rule.get("identifier", ""))
            if not identifier:
                continue
            pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(identifier)}(?![A-Za-z0-9_])")
            for line_number, line in enumerate(text.splitlines(), 1):
                if pattern.search(line):
                    findings.append(
                        Finding(
                            str(rule.get("id", "TERM")),
                            path.relative_to(root).as_posix(),
                            f"forbidden identifier {identifier!r}; use {rule.get('replacement')!r}",
                            line_number,
                        )
                    )
    return findings


def check_exceptions(root: Path, config: dict[str, Any], *, today: dt.date) -> list[Finding]:
    repository = _table(config, "repository")
    registry = _table(config, "registry")
    waivers = {
        str(entry.get("id")): entry
        for entry in (_entry(item) for item in _list(registry, "waivers"))
        if entry.get("id")
    }
    used_waivers: set[str] = set()
    findings: list[Finding] = []

    for path in _iter_scannable_files(root, _strings(repository.get("exception_scan_roots"))):
        relative = path.relative_to(root).as_posix()
        candidates = _exception_lines(path)
        for line_number, line in candidates:
            detected_rules = _exception_rule_ids(path, line)
            references = WAIVER_ID_RE.findall(line)
            if not references:
                findings.append(
                    Finding(
                        "WAIVER-001",
                        relative,
                        "temporary exception needs an inline GOV-WAIVER-NNNN reference",
                        line_number,
                    )
                )
                continue
            covered_rules: set[str] = set()
            for waiver_id in references:
                used_waivers.add(waiver_id)
                waiver = waivers.get(waiver_id)
                if waiver is None:
                    findings.append(
                        Finding(
                            "WAIVER-002",
                            relative,
                            f"{waiver_id} is not registered",
                            line_number,
                        )
                    )
                    continue
                waiver_rule = str(waiver.get("rule_id", ""))
                if waiver_rule not in detected_rules:
                    findings.append(
                        Finding(
                            "WAIVER-006",
                            relative,
                            f"{waiver_id} rule {waiver_rule!r} does not match "
                            f"{sorted(detected_rules)!r}",
                            line_number,
                        )
                    )
                else:
                    covered_rules.add(waiver_rule)
                scope = str(waiver.get("scope", ""))
                if scope and not fnmatch.fnmatch(relative, scope):
                    findings.append(
                        Finding(
                            "WAIVER-003",
                            relative,
                            f"{waiver_id} does not cover this path (scope {scope!r})",
                            line_number,
                        )
                    )
                expiry = _date_value(waiver.get("expires_at"))
                if expiry is not None and expiry < today:
                    findings.append(
                        Finding(
                            "WAIVER-004",
                            relative,
                            f"{waiver_id} expired on {expiry}",
                            line_number,
                        )
                    )
            for uncovered_rule in sorted(detected_rules - covered_rules):
                findings.append(
                    Finding(
                        "WAIVER-007",
                        relative,
                        f"temporary exception rule {uncovered_rule!r} has no matching waiver",
                        line_number,
                    )
                )

    for waiver_id in sorted(set(waivers) - used_waivers):
        findings.append(
            Finding("WAIVER-005", "governance.toml", f"registered waiver {waiver_id} is unused")
        )
    return findings


def check_documentation(root: Path, config: dict[str, Any]) -> list[Finding]:
    repository = _table(config, "repository")
    markdown_files: list[Path] = []
    for value in _strings(repository.get("documentation_roots")):
        path = root / value
        if path.is_file() and path.suffix == ".md":
            markdown_files.append(path)
        elif path.is_dir():
            markdown_files.extend(path.rglob("*.md"))

    findings: list[Finding] = []
    adr_ids: dict[str, Path] = {}
    for path in sorted(set(markdown_files)):
        relative = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for raw_target in MARKDOWN_LINK_RE.findall(text):
            target = raw_target.split("#", 1)[0].replace("%20", " ")
            if not target or re.match(r"^(?:https?://|mailto:)", target):
                continue
            resolved = (path.parent / target).resolve()
            if not resolved.exists():
                findings.append(
                    Finding(
                        "DOC-001",
                        relative,
                        f"local Markdown target does not exist: {raw_target}",
                    )
                )

        if _requires_document_status(path, root):
            match = DOCUMENT_STATUS_RE.search(text)
            if match is None:
                findings.append(Finding("DOC-002", relative, "core document has no status"))
            else:
                status = _base_document_status(match.group(1))
                if status not in VALID_DOCUMENT_STATUSES:
                    findings.append(
                        Finding("DOC-003", relative, f"unknown document status {match.group(1)!r}")
                    )
                if status == "Current" and ("src/" not in text or "tests/" not in text):
                    findings.append(
                        Finding(
                            "DOC-004",
                            relative,
                            "Current document must reference implementation and tests",
                        )
                    )

        adr_match = ADR_NAME_RE.match(path.name)
        if adr_match:
            adr_id = adr_match.group(1)
            previous = adr_ids.get(adr_id)
            if previous is not None:
                findings.append(
                    Finding(
                        "DOC-005",
                        relative,
                        f"ADR-{adr_id} duplicates {previous.relative_to(root).as_posix()}",
                    )
                )
            adr_ids[adr_id] = path
    return findings


def _exception_lines(path: Path) -> list[tuple[int, str]]:
    if path.suffix == ".py":
        return _python_exception_lines(path)
    if path.suffix == ".rs":
        return _rust_exception_lines(path)
    text = path.read_text(encoding="utf-8", errors="replace")
    return [
        (line_number, line)
        for line_number, line in enumerate(text.splitlines(), 1)
        if YAML_EXCEPTION_RE.search(line)
    ]


def _rust_exception_lines(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    candidates: list[tuple[int, str]] = []
    in_block_comment = False
    for line_number, line in enumerate(text.splitlines(), 1):
        code, comments, in_block_comment = _rust_line_parts(line, in_block_comment)
        has_debt_marker = any(DEBT_MARKER_RE.search(comment) for comment in comments)
        if (
            RUST_ATTRIBUTE_EXCEPTION_RE.search(code)
            or RUST_MACRO_EXCEPTION_RE.search(code)
            or has_debt_marker
        ):
            normalized = " ".join((code, *comments))
            candidates.append((line_number, normalized))
    return candidates


def _rust_line_parts(line: str, in_block_comment: bool) -> tuple[str, list[str], bool]:
    line = RUST_QUOTED_LITERAL_RE.sub("", line)
    code: list[str] = []
    comments: list[str] = []
    cursor = 0
    while cursor < len(line):
        if in_block_comment:
            end = line.find("*/", cursor)
            if end == -1:
                comments.append(line[cursor:])
                return "".join(code), comments, True
            comments.append(line[cursor:end])
            cursor = end + 2
            in_block_comment = False
            continue

        line_comment = line.find("//", cursor)
        block_comment = line.find("/*", cursor)
        if line_comment != -1 and (block_comment == -1 or line_comment < block_comment):
            code.append(line[cursor:line_comment])
            comments.append(line[line_comment + 2 :])
            return "".join(code), comments, False
        if block_comment == -1:
            code.append(line[cursor:])
            return "".join(code), comments, False
        code.append(line[cursor:block_comment])
        cursor = block_comment + 2
        in_block_comment = True
    return "".join(code), comments, in_block_comment


def _exception_rule_ids(path: Path, line: str) -> set[str]:
    rules: set[str] = set()
    if path.suffix == ".py":
        noqa = NOQA_RE.search(line)
        if noqa:
            codes = [code.strip().upper() for code in (noqa.group(1) or "").split(",")]
            rules.update(f"ruff:{code}" for code in codes if code)
            if not any(codes):
                rules.add("python:noqa")
        if re.search(r"#.*\btype:\s*ignore\b", line, re.IGNORECASE):
            rules.add("python:type-ignore")
        if PYTEST_EXCEPTION_RE.search(line):
            if "xfail" in line:
                rules.add("pytest:xfail")
            else:
                rules.add("pytest:skip")
    elif path.suffix == ".rs":
        if re.search(r"\ballow\s*\(", line, re.IGNORECASE):
            rules.add("rust:allow")
        if re.search(r"\bexpect\s*\(", line, re.IGNORECASE):
            rules.add("rust:expect")
        if re.search(r"#\s*!?\s*\[\s*ignore\b", line, re.IGNORECASE):
            rules.add("rust:ignore")
        if re.search(r"\btodo!\s*\(", line, re.IGNORECASE):
            rules.add("rust:todo")
        if re.search(r"\bunimplemented!\s*\(", line, re.IGNORECASE):
            rules.add("rust:unimplemented")
    else:
        if re.search(r"continue-on-error\s*:\s*true", line, re.IGNORECASE):
            rules.add("ci:continue-on-error")
        if re.search(r"\|\|\s*true", line, re.IGNORECASE):
            rules.add("ci:or-true")

    if re.search(r"\bTODO\b", line, re.IGNORECASE):
        rules.add("debt:TODO")
    if re.search(r"\bFIXME\b", line, re.IGNORECASE):
        rules.add("debt:FIXME")
    return rules or {"exception:unknown"}


def _python_exception_lines(path: Path) -> list[tuple[int, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    candidates: dict[int, str] = {}
    try:
        for token in tokenize.generate_tokens(iter(lines).__next__):
            if token.type == tokenize.COMMENT and COMMENT_EXCEPTION_RE.search(token.string):
                candidates[token.start[0]] = lines[token.start[0] - 1]
    except (IndentationError, tokenize.TokenError):
        pass
    for line_number, line in enumerate(lines, 1):
        if PYTEST_EXCEPTION_RE.search(line):
            context = " ".join(lines[line_number - 1 : min(line_number + 2, len(lines))])
            candidates[line_number] = context
    return sorted(candidates.items())


def _iter_scannable_files(root: Path, roots: list[str]) -> list[Path]:
    allowed_suffixes = {".cue", ".json", ".py", ".rs", ".toml", ".yaml", ".yml"}
    result: list[Path] = []
    for value in roots:
        path = root / value
        if path.is_file() and path.suffix in allowed_suffixes:
            result.append(path)
        elif path.is_dir():
            result.extend(
                item
                for item in path.rglob("*")
                if item.is_file()
                and item.suffix in allowed_suffixes
                and not any(part in {".venv", "__pycache__"} for part in item.parts)
            )
    return sorted(set(result))


def _requires_document_status(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return (
        len(relative.parts) >= 3
        and relative.parts[0] == "docs"
        and relative.parts[1] in {"adr", "architecture", "concepts", "plans", "research"}
        and path.name != "README.md"
        and path.name != "ADR-template.md"
    )


def _base_document_status(value: str) -> str:
    return re.split(r"[，,；;]", value, maxsplit=1)[0].strip()


def _module_name(path: Path, source_parent: Path) -> str:
    relative = path.relative_to(source_parent).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _imported_modules(tree: ast.AST) -> list[tuple[str, int]]:
    imports: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.append((node.module, node.lineno))
    return imports


def _module_matches(module: str, prefix: str) -> bool:
    return module == prefix or module.startswith(f"{prefix}.")


def _first_nonempty_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped[:500]
    return ""


def _check_expiry(entry: dict[str, Any], field: str, *, today: dt.date) -> list[Finding]:
    value = entry.get(field)
    parsed = _date_value(value)
    if value in (None, ""):
        return []
    if parsed is None:
        return [Finding("GOV-006", "governance.toml", f"invalid {field} date {value!r}")]
    if parsed < today:
        return [
            Finding(
                "GOV-007",
                "governance.toml",
                f"{entry.get('id', 'entry')} expired on {parsed}",
            )
        ]
    return []


def _date_value(value: Any) -> dt.date | None:
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            return None
    return None


def _require_fields(
    entry: dict[str, Any], path: str, label: str, fields: tuple[str, ...]
) -> list[Finding]:
    return [
        Finding("GOV-008", path, f"{label} is missing {field}")
        for field in fields
        if field not in entry or entry[field] in (None, "")
    ]


def _table(config: dict[str, Any], name: str) -> dict[str, Any]:
    value = config.get(name, {})
    return value if isinstance(value, dict) else {}


def _list(config: dict[str, Any], name: str) -> list[Any]:
    value = config.get(name, [])
    return value if isinstance(value, list) else []


def _entry(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "governance.toml",
        help="Path to governance.toml; repository root is its parent",
    )
    parser.add_argument("--quiet", action="store_true", help="Only use the exit status")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    config_path = args.config.resolve()
    root = config_path.parent
    try:
        config = load_config(config_path)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        if not args.quiet:
            print(f"{config_path}: [GOV-000] cannot load governance configuration: {exc}")
        return 2

    findings = validate_repository(root, config, today=dt.date.today())
    if not args.quiet:
        if findings:
            for finding in findings:
                print(finding.render())
            print(f"FAILED: {len(findings)} governance finding(s)")
        else:
            print("OK: repository governance checks passed")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
