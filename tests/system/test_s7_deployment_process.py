from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from test_s7_runtime_install_process import (
    AUTHORITY_PRINCIPAL,
    CONTROLLER_KEY_REF,
    CONTROLLER_PRINCIPAL,
    CONTROLLER_SEED,
    REPO_ROOT,
    RUNTIME_PRINCIPAL,
    RUNTIME_RESPONSE_KEY_REF,
    SOURCE_SCOPE,
    TARGET,
    TENURE_AUTHORITY_REF,
    TENURE_KEY_REF,
    TENURE_SEED,
    WRITER,
    InstalledRuntime,
    ServiceIdentity,
    _install_receipt,
    _root_read,
    _run_checked,
    _run_text,
)
from test_s7_runtime_install_process import service_identities as service_identities

pytest_plugins = ("test_s7_runtime_install_process",)

pytestmark = pytest.mark.skipif(  # GOV-WAIVER-0009
    sys.platform != "linux",
    reason=(
        "the DeploymentController process profile requires Linux ext4 and a non-root "
        "fixture identity distinct from the test runner"
    ),
)

SCOPE = SOURCE_SCOPE
PLAN = bytes.fromhex("72" * 16)
REQUEST_AUTH_KEY = CONTROLLER_KEY_REF
DECK_KEY = bytes.fromhex("74" * 16)
CARD_USE_KEY = bytes.fromhex("75" * 16)
OPERATION_ID = bytes.fromhex("76" * 16)
AUTHORITY_SERVICE_PRINCIPAL = bytes.fromhex("77" * 16)
AUTHORITY_OWNER_ID = bytes.fromhex("78" * 16)
EMPTY_OPERATION_ID = bytes.fromhex("7b" * 16)


@dataclass(frozen=True)
class ProcessBinaries:
    deploymentd: Path
    tenure_authority: Path


@dataclass(frozen=True)
class InstalledControllerProfile:
    service: ServiceIdentity
    root: Path
    deploymentd: Path
    tenure_authority: Path
    manifest_path: Path
    manifest_digest: bytes
    state_directory: Path
    public_key_path: Path
    private_seed_path: Path
    runtime_response_public_key_path: Path
    authority_public_key_path: Path
    alternate_authority_public_key_path: Path
    authority_state_directory: Path
    authority_socket_path: Path
    authority_private_seed_path: Path
    authority_service_public_key_path: Path
    authority_controller_public_key_path: Path
    authority_store_id: bytes
    runtime: InstalledRuntime
    runtime_store_id: bytes

    def initialize_command(self) -> list[str]:
        return [
            *self.service.command_prefix,
            os.fspath(self.deploymentd),
            "initialize-reference-v1",
            os.fspath(self.state_directory),
            os.fspath(self.manifest_path),
            self.manifest_digest.hex(),
            SCOPE.hex(),
            PLAN.hex(),
            REQUEST_AUTH_KEY.hex(),
            os.fspath(self.public_key_path),
            str(self.service.uid),
            str(self.service.gid),
        ]

    def commit_command(
        self,
        store_instance_id: bytes,
        *,
        definition_version: int,
        operation_id: bytes = OPERATION_ID,
    ) -> list[str]:
        return [
            *self.service.command_prefix,
            os.fspath(self.deploymentd),
            "commit-reference-loop-v1",
            os.fspath(self.state_directory),
            store_instance_id.hex(),
            SCOPE.hex(),
            PLAN.hex(),
            REQUEST_AUTH_KEY.hex(),
            os.fspath(self.public_key_path),
            str(self.service.uid),
            str(self.service.gid),
            DECK_KEY.hex(),
            CARD_USE_KEY.hex(),
            str(definition_version),
            operation_id.hex(),
            "10",
            "20",
            "30",
        ]

    def bootstrap_command(self, store_instance_id: bytes) -> list[str]:
        provisioning = self.runtime.provisioning
        identities = provisioning.identities
        return [
            *self.service.command_prefix,
            os.fspath(self.deploymentd),
            "bootstrap-runtime-v1",
            os.fspath(self.state_directory),
            store_instance_id.hex(),
            SCOPE.hex(),
            PLAN.hex(),
            REQUEST_AUTH_KEY.hex(),
            os.fspath(self.public_key_path),
            os.fspath(self.private_seed_path),
            str(self.service.uid),
            str(self.service.gid),
            CONTROLLER_PRINCIPAL.hex(),
            WRITER.hex(),
            AUTHORITY_PRINCIPAL.hex(),
            str(identities.authority.uid),
            str(identities.authority.gid),
            TENURE_AUTHORITY_REF.hex(),
            TENURE_KEY_REF.hex(),
            os.fspath(self.authority_public_key_path),
            os.fspath(provisioning.socket_path),
            RUNTIME_PRINCIPAL.hex(),
            RUNTIME_RESPONSE_KEY_REF.hex(),
            os.fspath(self.runtime_response_public_key_path),
            str(identities.runtime.uid),
            str(identities.runtime.gid),
        ]

    def apply_command(
        self,
        store_instance_id: bytes,
        *,
        runtime_socket_path: Path | None = None,
        runtime_uid: int | None = None,
        runtime_gid: int | None = None,
    ) -> list[str]:
        provisioning = self.runtime.provisioning
        identities = provisioning.identities
        runtime_socket_path = (
            provisioning.socket_path
            if runtime_socket_path is None
            else runtime_socket_path
        )
        runtime_uid = identities.runtime.uid if runtime_uid is None else runtime_uid
        runtime_gid = identities.runtime.gid if runtime_gid is None else runtime_gid
        return [
            *self.service.command_prefix,
            os.fspath(self.deploymentd),
            "apply-reference-v1",
            os.fspath(self.state_directory),
            store_instance_id.hex(),
            SCOPE.hex(),
            PLAN.hex(),
            REQUEST_AUTH_KEY.hex(),
            os.fspath(self.public_key_path),
            os.fspath(self.private_seed_path),
            str(self.service.uid),
            str(self.service.gid),
            CONTROLLER_PRINCIPAL.hex(),
            WRITER.hex(),
            AUTHORITY_PRINCIPAL.hex(),
            str(identities.authority.uid),
            str(identities.authority.gid),
            TENURE_AUTHORITY_REF.hex(),
            TENURE_KEY_REF.hex(),
            os.fspath(self.authority_public_key_path),
            os.fspath(runtime_socket_path),
            RUNTIME_PRINCIPAL.hex(),
            RUNTIME_RESPONSE_KEY_REF.hex(),
            os.fspath(self.runtime_response_public_key_path),
            str(runtime_uid),
            str(runtime_gid),
        ]

    def commit_empty_command(
        self,
        store_instance_id: bytes,
        *,
        operation_id: bytes = EMPTY_OPERATION_ID,
    ) -> list[str]:
        return [
            *self.service.command_prefix,
            os.fspath(self.deploymentd),
            "commit-reference-empty-v1",
            os.fspath(self.state_directory),
            store_instance_id.hex(),
            SCOPE.hex(),
            PLAN.hex(),
            REQUEST_AUTH_KEY.hex(),
            os.fspath(self.public_key_path),
            str(self.service.uid),
            str(self.service.gid),
            operation_id.hex(),
        ]

    def authority_common_arguments(self) -> list[str]:
        authority = self.runtime.provisioning.identities.authority
        controller = self.service
        return [
            "--state-dir",
            os.fspath(self.authority_state_directory),
            "--socket-path",
            os.fspath(self.authority_socket_path),
            "--authority-public-key",
            os.fspath(self.authority_service_public_key_path),
            "--controller-public-key",
            os.fspath(self.authority_controller_public_key_path),
            "--source-scope",
            SCOPE.hex(),
            "--writer-ref",
            WRITER.hex(),
            "--authority-ref",
            TENURE_AUTHORITY_REF.hex(),
            "--tenure-key-ref",
            TENURE_KEY_REF.hex(),
            "--controller-principal-ref",
            CONTROLLER_PRINCIPAL.hex(),
            "--controller-key-ref",
            CONTROLLER_KEY_REF.hex(),
            "--service-principal-ref",
            AUTHORITY_SERVICE_PRINCIPAL.hex(),
            "--owner-id",
            AUTHORITY_OWNER_ID.hex(),
            "--expected-authority-uid",
            str(authority.uid),
            "--expected-authority-gid",
            str(authority.gid),
            "--expected-peer-uid",
            str(controller.uid),
            "--expected-peer-gid",
            str(controller.gid),
        ]

    def authority_serve_command(self) -> list[str]:
        authority = self.runtime.provisioning.identities.authority
        return [
            *authority.command_prefix,
            os.fspath(self.tenure_authority),
            "serve",
            *self.authority_common_arguments(),
            "--expected-store-id",
            self.authority_store_id.hex(),
            "--private-seed",
            os.fspath(self.authority_private_seed_path),
        ]

    def acquire_tenure_command(
        self,
        store_instance_id: bytes,
        *,
        tenure_authority_ref: bytes = TENURE_AUTHORITY_REF,
        tenure_key_ref: bytes = TENURE_KEY_REF,
        authority_public_key_path: Path | None = None,
        authority_socket_path: Path | None = None,
        authority_uid: int | None = None,
        authority_gid: int | None = None,
    ) -> list[str]:
        authority = self.runtime.provisioning.identities.authority
        authority_public_key_path = (
            self.authority_public_key_path
            if authority_public_key_path is None
            else authority_public_key_path
        )
        authority_socket_path = (
            self.authority_socket_path
            if authority_socket_path is None
            else authority_socket_path
        )
        authority_uid = authority.uid if authority_uid is None else authority_uid
        authority_gid = authority.gid if authority_gid is None else authority_gid
        return [
            *self.service.command_prefix,
            os.fspath(self.deploymentd),
            "acquire-tenure-v1",
            os.fspath(self.state_directory),
            store_instance_id.hex(),
            SCOPE.hex(),
            PLAN.hex(),
            REQUEST_AUTH_KEY.hex(),
            os.fspath(self.public_key_path),
            os.fspath(self.private_seed_path),
            str(self.service.uid),
            str(self.service.gid),
            CONTROLLER_PRINCIPAL.hex(),
            WRITER.hex(),
            tenure_authority_ref.hex(),
            tenure_key_ref.hex(),
            os.fspath(authority_public_key_path),
            os.fspath(authority_socket_path),
            str(authority_uid),
            str(authority_gid),
        ]

    def runtime_serve_command(self) -> list[str]:
        return [
            *self.runtime.service.command_prefix,
            os.fspath(self.runtime.installed_binary),
            "serve-v1",
            os.fspath(self.runtime.state_directory),
            self.runtime_store_id.hex(),
            *self.runtime.provisioning.command_arguments(),
        ]


def _debug_binary(name: str) -> Path:
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", REPO_ROOT / "target"))
    if not target_root.is_absolute():
        target_root = REPO_ROOT / target_root
    binary = (target_root / "debug" / name).resolve()
    assert binary.is_file() and not binary.is_symlink()
    return binary


@pytest.fixture(scope="module")
def process_binaries() -> ProcessBinaries:
    for command in (
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "paraegox-runtime-host",
            "--bin",
            "paraegox-runtime-host",
        ],
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "paraegox-deployment",
            "--bin",
            "paraegox-deploymentd",
        ],
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "paraegox-deployment",
            "--bin",
            "paraegox-tenure-authority",
        ],
    ):
        completed = _run_text(command, timeout=180)
        assert completed.returncode == 0, completed.stdout + completed.stderr
    return ProcessBinaries(
        deploymentd=_debug_binary("paraegox-deploymentd"),
        tenure_authority=_debug_binary("paraegox-tenure-authority"),
    )


@pytest.fixture
def installed_controller_profile(
    process_binaries: ProcessBinaries,
    installed_runtime: InstalledRuntime,
) -> Iterator[InstalledControllerProfile]:
    runtime = installed_runtime
    installed = _run_text(runtime.install_command(), cwd=runtime.working_directory)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    assert installed.stderr == ""
    runtime_receipt = _install_receipt(installed.stdout)
    service = runtime.provisioning.identities.controller
    root = runtime.working_directory
    installed_deploymentd = root / "bin" / "paraegox-deploymentd"
    installed_tenure_authority = root / "bin" / "paraegox-tenure-authority"
    controller_state = root / "controller-state"
    controller_manifest_parent = root / "controller-manifest"
    controller_manifest = controller_manifest_parent / "runtime.pxcm"
    key_parent = root / "controller-keys"
    public_key_path = key_parent / "controller.pub"
    private_seed_path = key_parent / "controller.seed"
    runtime_response_public_key_path = key_parent / "runtime-response.pub"
    authority_public_key_path = key_parent / "authority.pub"
    alternate_authority_public_key_path = key_parent / "authority-alternate.pub"
    authority = runtime.provisioning.identities.authority
    authority_state = root / "authority-state"
    authority_key_parent = root / "authority-keys"
    authority_socket_parent = root / "authority-control"
    authority_socket_path = authority_socket_parent / "authority.sock"
    authority_private_seed_path = authority_key_parent / "authority.seed"
    authority_service_public_key_path = authority_key_parent / "authority.pub"
    authority_controller_public_key_path = authority_key_parent / "controller.pub"

    _run_checked(
        [
            "sudo",
            "-n",
            "install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0555",
            os.fspath(process_binaries.deploymentd),
            os.fspath(installed_deploymentd),
        ]
    )
    _run_checked(
        [
            "sudo",
            "-n",
            "install",
            "-o",
            "root",
            "-g",
            "root",
            "-m",
            "0555",
            os.fspath(process_binaries.tenure_authority),
            os.fspath(installed_tenure_authority),
        ]
    )
    _run_checked(
        [
            "sudo",
            "-n",
            "install",
            "-d",
            "-o",
            str(service.uid),
            "-g",
            str(service.gid),
            "-m",
            "0700",
            os.fspath(controller_state),
            os.fspath(controller_manifest_parent),
            os.fspath(key_parent),
        ]
    )
    _run_checked(
        [
            "sudo",
            "-n",
            "install",
            "-d",
            "-o",
            str(authority.uid),
            "-g",
            str(authority.gid),
            "-m",
            "0700",
            os.fspath(authority_state),
            os.fspath(authority_key_parent),
        ]
    )
    _run_checked(
        [
            "sudo",
            "-n",
            "install",
            "-d",
            "-o",
            str(authority.uid),
            "-g",
            str(service.gid),
            "-m",
            "2750",
            os.fspath(authority_socket_parent),
        ]
    )
    _run_checked(
        [
            "sudo",
            "-n",
            "install",
            "-o",
            str(service.uid),
            "-g",
            str(service.gid),
            "-m",
            "0600",
            os.fspath(runtime.manifest_path),
            os.fspath(controller_manifest),
        ]
    )

    with tempfile.TemporaryDirectory(prefix="pxdc-keys-", dir="/tmp") as key_source_path:
        key_source = Path(key_source_path).resolve()
        key_source.chmod(0o700)
        key_values = {
            "controller.pub": runtime.provisioning.controller_public_key,
            "controller.seed": CONTROLLER_SEED,
            "runtime-response.pub": runtime.provisioning.runtime_response_public_key,
            "authority.pub": runtime.provisioning.tenure_public_key,
            "authority-alternate.pub": runtime.provisioning.runtime_response_public_key,
        }
        destinations = {
            "controller.pub": public_key_path,
            "controller.seed": private_seed_path,
            "runtime-response.pub": runtime_response_public_key_path,
            "authority.pub": authority_public_key_path,
            "authority-alternate.pub": alternate_authority_public_key_path,
        }
        for name, value in key_values.items():
            source = key_source / name
            source.write_bytes(value)
            source.chmod(0o600)
            _run_checked(
                [
                    "sudo",
                    "-n",
                    "install",
                    "-o",
                    str(service.uid),
                    "-g",
                    str(service.gid),
                    "-m",
                    "0400",
                    os.fspath(source),
                    os.fspath(destinations[name]),
                ]
            )

        authority_key_values = {
            authority_private_seed_path: (TENURE_SEED, 0o600),
            authority_service_public_key_path: (
                runtime.provisioning.tenure_public_key,
                0o644,
            ),
            authority_controller_public_key_path: (
                runtime.provisioning.controller_public_key,
                0o644,
            ),
        }
        for index, (destination, (value, mode)) in enumerate(
            authority_key_values.items()
        ):
            source = key_source / f"authority-service-{index}.key"
            source.write_bytes(value)
            source.chmod(0o600)
            _run_checked(
                [
                    "sudo",
                    "-n",
                    "install",
                    "-o",
                    str(authority.uid),
                    "-g",
                    str(authority.gid),
                    "-m",
                    f"{mode:o}",
                    os.fspath(source),
                    os.fspath(destination),
                ]
            )

        profile = InstalledControllerProfile(
            service=service,
            root=root,
            deploymentd=installed_deploymentd,
            tenure_authority=installed_tenure_authority,
            manifest_path=controller_manifest,
            manifest_digest=runtime_receipt["manifest_digest"],
            state_directory=controller_state,
            public_key_path=public_key_path,
            private_seed_path=private_seed_path,
            runtime_response_public_key_path=runtime_response_public_key_path,
            authority_public_key_path=authority_public_key_path,
            alternate_authority_public_key_path=alternate_authority_public_key_path,
            authority_state_directory=authority_state,
            authority_socket_path=authority_socket_path,
            authority_private_seed_path=authority_private_seed_path,
            authority_service_public_key_path=authority_service_public_key_path,
            authority_controller_public_key_path=authority_controller_public_key_path,
            authority_store_id=bytes.fromhex("01" * 32),
            runtime=runtime,
            runtime_store_id=runtime_receipt["store_instance_id"],
        )
        authority_initialized = _run_text(
            [
                *authority.command_prefix,
                os.fspath(installed_tenure_authority),
                "initialize",
                *profile.authority_common_arguments(),
            ],
            cwd=root,
        )
        assert authority_initialized.returncode == 0, (
            authority_initialized.stdout + authority_initialized.stderr
        )
        assert authority_initialized.stderr == ""
        authority_initialization = _plain_facts(authority_initialized.stdout)
        authority_store_id = _hex_field(
            authority_initialization, "store_instance_id", 32
        )
        yield replace(profile, authority_store_id=authority_store_id)


def _receipt(stdout: str, header: str) -> dict[str, str]:
    assert stdout.endswith("\n")
    lines = stdout[:-1].splitlines()
    assert lines and lines[0] == header
    parsed: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition("=")
        assert separator == "=" and name and name not in parsed and value
        parsed[name] = value
    return parsed


def _plain_facts(stdout: str) -> dict[str, str]:
    assert stdout.endswith("\n")
    parsed: dict[str, str] = {}
    for line in stdout[:-1].splitlines():
        name, separator, value = line.partition("=")
        assert separator == "=" and name and name not in parsed and value
        parsed[name] = value
    return parsed


def _hex_field(fields: dict[str, str], name: str, length: int) -> bytes:
    encoded = fields[name]
    assert len(encoded) == length * 2
    assert all(character in "0123456789abcdef" for character in encoded)
    value = bytes.fromhex(encoded)
    assert any(value)
    return value


def _controller_store_bytes(profile: InstalledControllerProfile) -> dict[str, bytes]:
    return {
        "controller.lock": _root_read(profile.state_directory / "controller.lock"),
        "controller.snapshot": _root_read(profile.state_directory / "controller.snapshot"),
    }


def _assert_only_controller_store_files(profile: InstalledControllerProfile) -> None:
    observed = _run_checked(
        [
            "sudo",
            "-n",
            "find",
            os.fspath(profile.state_directory),
            "-mindepth",
            "1",
            "-maxdepth",
            "1",
            "-printf",
            "%f\n",
        ]
    )
    assert set(observed.stdout.splitlines()) == {"controller.lock", "controller.snapshot"}


def _run_controller(
    command: Sequence[str],
    profile: InstalledControllerProfile,
) -> subprocess.CompletedProcess[str]:
    return _run_text(command, cwd=profile.root)


def _wait_for_runtime_socket(
    process: subprocess.Popen[str], profile: InstalledControllerProfile
) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                f"Runtime exited before bootstrap readiness: {process.returncode}; "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        observed = subprocess.run(
            [
                *profile.service.command_prefix,
                "test",
                "-S",
                os.fspath(profile.runtime.provisioning.socket_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        if observed.returncode == 0:
            return
        time.sleep(0.02)
    pytest.fail("Runtime bootstrap socket did not become ready")


def _wait_for_authority_socket(
    process: subprocess.Popen[str], profile: InstalledControllerProfile
) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            pytest.fail(
                f"Authority exited before readiness: {process.returncode}; "
                f"stdout={stdout!r} stderr={stderr!r}"
            )
        observed = subprocess.run(
            [
                *profile.service.command_prefix,
                "test",
                "-S",
                os.fspath(profile.authority_socket_path),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=2,
        )
        if observed.returncode == 0:
            return
        time.sleep(0.02)
    pytest.fail("Tenure Authority socket did not become ready")


@contextmanager
def _runtime_server(
    profile: InstalledControllerProfile,
) -> Iterator[subprocess.Popen[str]]:
    process = subprocess.Popen(
        profile.runtime_serve_command(),
        cwd=profile.root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        close_fds=True,
    )
    try:
        _wait_for_runtime_socket(process, profile)
        yield process
    finally:
        if process.poll() is None:
            subprocess.run(
                [
                    "sudo",
                    "-n",
                    "/bin/kill",
                    "-s",
                    signal.SIGTERM.name,
                    "--",
                    f"-{process.pid}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            subprocess.run(
                [
                    "sudo",
                    "-n",
                    "/bin/kill",
                    "-s",
                    signal.SIGKILL.name,
                    "--",
                    f"-{process.pid}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            process.kill()
            process.wait(timeout=5)


@contextmanager
def _authority_server(
    profile: InstalledControllerProfile,
) -> Iterator[subprocess.Popen[str]]:
    process = subprocess.Popen(
        profile.authority_serve_command(),
        cwd=profile.root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        close_fds=True,
    )
    try:
        _wait_for_authority_socket(process, profile)
        yield process
    finally:
        if process.poll() is None:
            subprocess.run(
                [
                    "sudo",
                    "-n",
                    "/bin/kill",
                    "-s",
                    signal.SIGTERM.name,
                    "--",
                    f"-{process.pid}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            subprocess.run(
                [
                    "sudo",
                    "-n",
                    "/bin/kill",
                    "-s",
                    signal.SIGKILL.name,
                    "--",
                    f"-{process.pid}",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            process.kill()
            process.wait(timeout=5)


def test_real_deployment_process_initializes_commits_replays_and_rejects_conflict_without_mutation(
    installed_controller_profile: InstalledControllerProfile,
) -> None:
    profile = installed_controller_profile
    initialized = _run_controller(profile.initialize_command(), profile)
    assert initialized.returncode == 0, initialized.stdout + initialized.stderr
    assert initialized.stderr == ""
    initialization = _receipt(initialized.stdout, "controller_initialize_v1")
    assert set(initialization) == {
        "store_instance_id",
        "owner_identity_fingerprint",
        "snapshot_sequence",
        "initialized_snapshot_digest",
        "receipt_digest",
        "receipt_bytes",
    }
    store_instance_id = _hex_field(initialization, "store_instance_id", 32)
    _hex_field(initialization, "owner_identity_fingerprint", 32)
    _hex_field(initialization, "initialized_snapshot_digest", 32)
    _hex_field(initialization, "receipt_digest", 32)
    initialization_receipt_bytes = _hex_field(
        initialization,
        "receipt_bytes",
        len(bytes.fromhex(initialization["receipt_bytes"])),
    )
    assert initialization_receipt_bytes[:10] == b"PXCINIT\0\0\x01"
    assert initialization_receipt_bytes[10:42] == store_instance_id
    assert initialization["snapshot_sequence"] == "1"
    _assert_only_controller_store_files(profile)
    initialized_store = _controller_store_bytes(profile)
    assert initialized_store["controller.lock"] == b""
    initialized_snapshot = initialized_store["controller.snapshot"]
    assert initialized_snapshot[:4] == b"PXJR"
    assert initialized_snapshot[14:46] == store_instance_id
    assert int.from_bytes(initialized_snapshot[78:86], "big") == 1

    committed = _run_controller(
        profile.commit_command(store_instance_id, definition_version=7), profile
    )
    assert committed.returncode == 0, committed.stdout + committed.stderr
    assert committed.stderr == ""
    commit = _receipt(committed.stdout, "controller_commit_reference_loop_v1")
    assert set(commit) == {
        "store_instance_id",
        "snapshot_sequence",
        "plan_revision",
        "operation_id",
        "plan_digest",
        "manifest_digest",
        "snapshot_digest",
        "receipt_digest",
        "receipt_bytes",
    }
    assert _hex_field(commit, "store_instance_id", 32) == store_instance_id
    assert _hex_field(commit, "operation_id", 16) == OPERATION_ID
    assert _hex_field(commit, "manifest_digest", 32) == profile.manifest_digest
    for field in ("plan_digest", "snapshot_digest", "receipt_digest"):
        _hex_field(commit, field, 32)
    commit_receipt_bytes = _hex_field(
        commit, "receipt_bytes", len(bytes.fromhex(commit["receipt_bytes"]))
    )
    assert commit_receipt_bytes[:12] == b"PXDCOMMIT\0\0\x01"
    assert commit_receipt_bytes[12:44] == store_instance_id
    assert int.from_bytes(commit_receipt_bytes[44:52], "big") == 3
    assert int.from_bytes(commit_receipt_bytes[52:60], "big") == 1
    assert commit_receipt_bytes[60:76] == OPERATION_ID
    assert commit["snapshot_sequence"] == "3"
    assert commit["plan_revision"] == "1"
    committed_store = _controller_store_bytes(profile)
    assert committed_store["controller.lock"] == b""
    committed_snapshot = committed_store["controller.snapshot"]
    assert committed_snapshot[:4] == b"PXJR"
    assert committed_snapshot[14:46] == store_instance_id
    assert int.from_bytes(committed_snapshot[78:86], "big") == 3

    retried = _run_controller(
        profile.commit_command(store_instance_id, definition_version=7), profile
    )
    assert retried.returncode == 0, retried.stdout + retried.stderr
    assert retried.stderr == ""
    assert retried.stdout == committed.stdout
    assert _controller_store_bytes(profile) == committed_store
    _assert_only_controller_store_files(profile)

    conflicted = _run_controller(
        profile.commit_command(store_instance_id, definition_version=8), profile
    )
    assert conflicted.returncode != 0
    assert conflicted.stdout == ""
    assert conflicted.stderr == (
        "paraegox-deploymentd failed closed; code=PXDC-COMMIT-FAILED-CLOSED "
        "stage=commit_reference_plan\n"
    )
    assert _controller_store_bytes(profile) == committed_store
    _assert_only_controller_store_files(profile)

    with _runtime_server(profile):
        bootstrapped = _run_controller(
            profile.bootstrap_command(store_instance_id), profile
        )
        assert bootstrapped.returncode == 0, bootstrapped.stdout + bootstrapped.stderr
        assert bootstrapped.stderr == ""
        bootstrap = _receipt(
            bootstrapped.stdout, "controller_bootstrap_runtime_v1"
        )
        assert set(bootstrap) == {
            "controller_store_instance_id",
            "controller_snapshot_sequence",
            "target",
            "runtime_store_instance_id",
            "runtime_host_epoch",
            "channel_policy_fingerprint",
            "bootstrap_response_digest",
            "bootstrap_response_bytes",
        }
        assert (
            _hex_field(bootstrap, "controller_store_instance_id", 32)
            == store_instance_id
        )
        assert _hex_field(bootstrap, "target", 16) == TARGET
        assert (
            _hex_field(bootstrap, "runtime_store_instance_id", 32)
            == profile.runtime_store_id
        )
        assert bootstrap["controller_snapshot_sequence"] == "4"
        assert int(bootstrap["runtime_host_epoch"]) > 0
        _hex_field(bootstrap, "channel_policy_fingerprint", 32)
        _hex_field(bootstrap, "bootstrap_response_digest", 32)
        response_bytes = _hex_field(
            bootstrap,
            "bootstrap_response_bytes",
            len(bytes.fromhex(bootstrap["bootstrap_response_bytes"])),
        )
        assert response_bytes
        bootstrapped_store = _controller_store_bytes(profile)
        assert int.from_bytes(
            bootstrapped_store["controller.snapshot"][78:86], "big"
        ) == 4

        replayed_bootstrap = _run_controller(
            profile.bootstrap_command(store_instance_id), profile
        )
        assert replayed_bootstrap.returncode == 0, (
            replayed_bootstrap.stdout + replayed_bootstrap.stderr
        )
        assert replayed_bootstrap.stderr == ""
        assert replayed_bootstrap.stdout == bootstrapped.stdout
        assert _controller_store_bytes(profile) == bootstrapped_store
        _assert_only_controller_store_files(profile)

    with _authority_server(profile):
        acquired = _run_controller(
            profile.acquire_tenure_command(store_instance_id), profile
        )
        assert acquired.returncode == 0, acquired.stdout + acquired.stderr
        assert acquired.stderr == ""
        tenure = _receipt(acquired.stdout, "controller_acquire_tenure_v1")
        assert set(tenure) == {
            "controller_store_instance_id",
            "authority_domain_fingerprint",
            "operation_id",
            "request_digest",
            "source_scope",
            "writer_ref",
            "writer_epoch",
            "supersedes_through_epoch",
            "tenure_authority_ref",
            "tenure_key_ref",
            "proof_algorithm",
            "proof_algorithm_version",
            "proof_nonce",
            "proof_signature",
            "proof_digest",
            "acquire_response_digest",
            "acquire_response_bytes",
        }
        assert (
            _hex_field(tenure, "controller_store_instance_id", 32)
            == store_instance_id
        )
        _hex_field(tenure, "authority_domain_fingerprint", 32)
        assert _hex_field(tenure, "source_scope", 16) == SCOPE
        assert _hex_field(tenure, "writer_ref", 16) == WRITER
        assert int(tenure["writer_epoch"]) == 1
        assert int(tenure["supersedes_through_epoch"]) == 0
        assert _hex_field(tenure, "tenure_authority_ref", 16) == TENURE_AUTHORITY_REF
        assert _hex_field(tenure, "tenure_key_ref", 16) == TENURE_KEY_REF
        assert tenure["proof_algorithm"] == "1"
        assert tenure["proof_algorithm_version"] == "1"
        _hex_field(tenure, "operation_id", 16)
        _hex_field(tenure, "request_digest", 32)
        _hex_field(tenure, "proof_signature", 64)
        _hex_field(tenure, "proof_digest", 32)
        _hex_field(tenure, "acquire_response_digest", 32)
        proof_nonce = _hex_field(
            tenure, "proof_nonce", len(bytes.fromhex(tenure["proof_nonce"]))
        )
        assert proof_nonce
        acquire_response = _hex_field(
            tenure,
            "acquire_response_bytes",
            len(bytes.fromhex(tenure["acquire_response_bytes"])),
        )
        assert acquire_response[:8] == b"PXATRSP\0"
        tenure_store = _controller_store_bytes(profile)
        assert int.from_bytes(tenure_store["controller.snapshot"][78:86], "big") == 6

    removed_socket = _run_text(
        [
            *profile.service.command_prefix,
            "test",
            "!",
            "-e",
            os.fspath(profile.authority_socket_path),
        ],
        cwd=profile.root,
    )
    assert removed_socket.returncode == 0, removed_socket.stdout + removed_socket.stderr

    changed_domains = [
        {"tenure_authority_ref": bytes.fromhex("79" * 16)},
        {"tenure_key_ref": bytes.fromhex("7a" * 16)},
        {"authority_public_key_path": profile.alternate_authority_public_key_path},
        {
            "authority_socket_path": profile.authority_socket_path.with_name(
                "changed-authority.sock"
            )
        },
        {
            "authority_uid": (
                profile.runtime.provisioning.identities.authority.uid + 10_000
            )
        },
        {
            "authority_gid": (
                profile.runtime.provisioning.identities.authority.gid + 10_000
            )
        },
    ]
    for changed_domain in changed_domains:
        rejected = _run_controller(
            profile.acquire_tenure_command(store_instance_id, **changed_domain),
            profile,
        )
        assert rejected.returncode != 0
        assert rejected.stdout == ""
        assert rejected.stderr == (
            "paraegox-deploymentd failed closed; code=PXDC-TENURE-FAILED-CLOSED "
            "stage=acquire_tenure\n"
        )
        assert _controller_store_bytes(profile) == tenure_store

    with _runtime_server(profile):
        refreshed = _run_controller(profile.bootstrap_command(store_instance_id), profile)
        assert refreshed.returncode == 0, refreshed.stdout + refreshed.stderr
        assert refreshed.stderr == ""
        successor_store = _controller_store_bytes(profile)
        assert successor_store != tenure_store

        replayed_tenure = _run_controller(
            profile.acquire_tenure_command(store_instance_id), profile
        )
        assert replayed_tenure.returncode == 0, (
            replayed_tenure.stdout + replayed_tenure.stderr
        )
        assert replayed_tenure.stderr == ""
        assert replayed_tenure.stdout == acquired.stdout
        assert _controller_store_bytes(profile) == successor_store

        for changed_runtime_domain in (
            {
                "runtime_socket_path": profile.runtime.provisioning.socket_path.with_name(
                    "changed-runtime.sock"
                )
            },
            {
                "runtime_uid": (
                    profile.runtime.provisioning.identities.runtime.uid + 10_000
                )
            },
            {
                "runtime_gid": (
                    profile.runtime.provisioning.identities.runtime.gid + 10_000
                )
            },
        ):
            rejected_apply = _run_controller(
                profile.apply_command(store_instance_id, **changed_runtime_domain),
                profile,
            )
            assert rejected_apply.returncode != 0
            assert rejected_apply.stdout == ""
            assert rejected_apply.stderr == (
                "paraegox-deploymentd failed closed; "
                "code=PXDC-PROVISIONING-REJECTED "
                "stage=build_controller_identity\n"
            )
            assert _controller_store_bytes(profile) == successor_store

        premature_empty = _run_controller(
            profile.commit_empty_command(store_instance_id), profile
        )
        assert premature_empty.returncode != 0
        assert premature_empty.stdout == ""
        assert premature_empty.stderr == (
            "paraegox-deploymentd failed closed; code=PXDC-COMMIT-FAILED-CLOSED "
            "stage=commit_reference_plan\n"
        )
        assert _controller_store_bytes(profile) == successor_store

        runtime_socket = profile.runtime.provisioning.socket_path
        _run_checked(["sudo", "-n", "chmod", "0600", os.fspath(runtime_socket)])
        not_sent = _run_controller(profile.apply_command(store_instance_id), profile)
        assert not_sent.returncode != 0
        assert not_sent.stdout == ""
        assert not_sent.stderr == (
            "paraegox-deploymentd failed closed; code=PXDC-APPLY-FAILED-CLOSED "
            "stage=apply_reference\n"
        )
        prepared_store = _controller_store_bytes(profile)
        assert prepared_store != successor_store
        assert (
            int.from_bytes(prepared_store["controller.snapshot"][78:86], "big")
            == int.from_bytes(successor_store["controller.snapshot"][78:86], "big")
            + 1
        )

        repeated_not_sent = _run_controller(
            profile.apply_command(store_instance_id), profile
        )
        assert repeated_not_sent.returncode != 0
        assert repeated_not_sent.stdout == ""
        assert repeated_not_sent.stderr == not_sent.stderr
        assert _controller_store_bytes(profile) == prepared_store

        _run_checked(["sudo", "-n", "chmod", "0660", os.fspath(runtime_socket)])
        applied = _run_controller(profile.apply_command(store_instance_id), profile)
        assert applied.returncode == 0, applied.stdout + applied.stderr
        assert applied.stderr == ""
        apply_receipt = _receipt(applied.stdout, "controller_apply_reference_v1")
        assert set(apply_receipt) == {
            "controller_store_instance_id",
            "target",
            "runtime_store_instance_id",
            "source_scope",
            "source_plan",
            "source_plan_revision",
            "source_plan_digest",
            "writer_ref",
            "writer_epoch",
            "apply_operation_id",
            "target_slice_digest",
            "apply_request_digest",
            "request_time_channel_binding_digest",
            "apply_request_bytes",
            "terminal_result_ref",
            "terminal_outcome",
            "terminal_lifecycle_effect",
            "terminal_head",
            "desired_head_digest",
            "resource_census_digest",
            "raw_outcome_digest",
            "completion_runtime_host_epoch",
            "completion_snapshot_sequence",
            "selection_clock_generation",
            "selection_observed_at_nanos",
            "runtime_peer",
            "runtime_response_key_ref",
            "runtime_response_algorithm",
            "runtime_response_algorithm_version",
            "terminal_receipt_digest",
            "terminal_receipt_bytes",
        }
        assert (
            _hex_field(apply_receipt, "controller_store_instance_id", 32)
            == store_instance_id
        )
        assert _hex_field(apply_receipt, "target", 16) == TARGET
        assert (
            _hex_field(apply_receipt, "runtime_store_instance_id", 32)
            == profile.runtime_store_id
        )
        assert _hex_field(apply_receipt, "source_scope", 16) == SCOPE
        assert _hex_field(apply_receipt, "source_plan", 16) == PLAN
        assert apply_receipt["source_plan_revision"] == "1"
        _hex_field(apply_receipt, "source_plan_digest", 32)
        assert _hex_field(apply_receipt, "writer_ref", 16) == WRITER
        assert apply_receipt["writer_epoch"] == "1"
        _hex_field(apply_receipt, "apply_operation_id", 16)
        target_slice_digest = _hex_field(
            apply_receipt, "target_slice_digest", 32
        )
        assert (
            _hex_field(apply_receipt, "desired_head_digest", 32)
            == target_slice_digest
        )
        _hex_field(apply_receipt, "apply_request_digest", 32)
        _hex_field(apply_receipt, "request_time_channel_binding_digest", 32)
        apply_request_bytes = _hex_field(
            apply_receipt,
            "apply_request_bytes",
            len(bytes.fromhex(apply_receipt["apply_request_bytes"])),
        )
        assert apply_request_bytes[:4] == b"PXAR"
        _hex_field(apply_receipt, "terminal_result_ref", 16)
        assert apply_receipt["terminal_outcome"] == "1"
        assert apply_receipt["terminal_lifecycle_effect"] == "2"
        assert apply_receipt["terminal_head"] == "3"
        _hex_field(apply_receipt, "resource_census_digest", 32)
        _hex_field(apply_receipt, "raw_outcome_digest", 32)
        assert int(apply_receipt["completion_runtime_host_epoch"]) > 0
        assert int(apply_receipt["completion_snapshot_sequence"]) > 0
        assert int(apply_receipt["selection_clock_generation"]) > 0
        assert int(apply_receipt["selection_observed_at_nanos"]) > 0
        assert _hex_field(apply_receipt, "runtime_peer", 16) == RUNTIME_PRINCIPAL
        assert (
            _hex_field(apply_receipt, "runtime_response_key_ref", 16)
            == RUNTIME_RESPONSE_KEY_REF
        )
        assert apply_receipt["runtime_response_algorithm"] == "1"
        assert apply_receipt["runtime_response_algorithm_version"] == "1"
        _hex_field(apply_receipt, "terminal_receipt_digest", 32)
        terminal_receipt_bytes = _hex_field(
            apply_receipt,
            "terminal_receipt_bytes",
            len(bytes.fromhex(apply_receipt["terminal_receipt_bytes"])),
        )
        assert terminal_receipt_bytes[:4] == b"PXRT"
        applied_store = _controller_store_bytes(profile)
        assert applied_store != prepared_store

        # A terminal replay must not touch the endpoint. Keeping the same
        # socket inode but making its ACL invalid proves success is returned
        # from the exact durable PXRT before any transport validation/send.
        _run_checked(["sudo", "-n", "chmod", "0600", os.fspath(runtime_socket)])
        terminal_replay = _run_controller(
            profile.apply_command(store_instance_id), profile
        )
        assert terminal_replay.returncode == 0, (
            terminal_replay.stdout + terminal_replay.stderr
        )
        assert terminal_replay.stderr == ""
        assert terminal_replay.stdout == applied.stdout
        assert _controller_store_bytes(profile) == applied_store
        _run_checked(["sudo", "-n", "chmod", "0660", os.fspath(runtime_socket)])

        committed_empty = _run_controller(
            profile.commit_empty_command(store_instance_id), profile
        )
        assert committed_empty.returncode == 0, (
            committed_empty.stdout + committed_empty.stderr
        )
        assert committed_empty.stderr == ""
        empty_commit = _receipt(
            committed_empty.stdout, "controller_commit_reference_empty_v1"
        )
        assert set(empty_commit) == {
            "controller_store_instance_id",
            "source_scope",
            "source_plan",
            "plan_revision",
            "operation_id",
            "target",
            "plan_digest",
            "manifest_digest",
            "allocation_generation",
            "expected_active_target_slice_digest",
            "receipt_digest",
            "receipt_bytes",
        }
        assert (
            _hex_field(empty_commit, "controller_store_instance_id", 32)
            == store_instance_id
        )
        assert _hex_field(empty_commit, "source_scope", 16) == SCOPE
        assert _hex_field(empty_commit, "source_plan", 16) == PLAN
        assert empty_commit["plan_revision"] == "2"
        assert _hex_field(empty_commit, "operation_id", 16) == EMPTY_OPERATION_ID
        assert _hex_field(empty_commit, "target", 16) == TARGET
        _hex_field(empty_commit, "plan_digest", 32)
        assert _hex_field(empty_commit, "manifest_digest", 32) == profile.manifest_digest
        assert empty_commit["allocation_generation"] == "2"
        assert (
            _hex_field(
                empty_commit, "expected_active_target_slice_digest", 32
            )
            == target_slice_digest
        )
        _hex_field(empty_commit, "receipt_digest", 32)
        empty_commit_receipt = _hex_field(
            empty_commit,
            "receipt_bytes",
            len(bytes.fromhex(empty_commit["receipt_bytes"])),
        )
        assert empty_commit_receipt[:12] == b"PXDCEMPTY\0\0\x01"
        assert empty_commit_receipt[12:44] == store_instance_id
        assert empty_commit_receipt[44:60] == SCOPE
        assert empty_commit_receipt[60:76] == PLAN
        assert int.from_bytes(empty_commit_receipt[76:84], "big") == 2
        assert empty_commit_receipt[84:100] == EMPTY_OPERATION_ID
        assert empty_commit_receipt[100:116] == TARGET
        assert empty_commit_receipt[148:180] == profile.manifest_digest
        assert int.from_bytes(empty_commit_receipt[180:188], "big") == 2
        assert empty_commit_receipt[188:220] == target_slice_digest
        empty_committed_store = _controller_store_bytes(profile)
        assert empty_committed_store != applied_store
        assert (
            int.from_bytes(
                empty_committed_store["controller.snapshot"][78:86], "big"
            )
            == int.from_bytes(applied_store["controller.snapshot"][78:86], "big") + 2
        )

        replayed_empty_commit = _run_controller(
            profile.commit_empty_command(store_instance_id), profile
        )
        assert replayed_empty_commit.returncode == 0, (
            replayed_empty_commit.stdout + replayed_empty_commit.stderr
        )
        assert replayed_empty_commit.stderr == ""
        assert replayed_empty_commit.stdout == committed_empty.stdout
        assert _controller_store_bytes(profile) == empty_committed_store

        conflicting_empty = _run_controller(
            profile.commit_empty_command(
                store_instance_id, operation_id=bytes.fromhex("7c" * 16)
            ),
            profile,
        )
        assert conflicting_empty.returncode != 0
        assert conflicting_empty.stdout == ""
        assert conflicting_empty.stderr == premature_empty.stderr
        assert _controller_store_bytes(profile) == empty_committed_store

        applied_empty = _run_controller(profile.apply_command(store_instance_id), profile)
        assert applied_empty.returncode == 0, applied_empty.stdout + applied_empty.stderr
        assert applied_empty.stderr == ""
        empty_apply_receipt = _receipt(
            applied_empty.stdout, "controller_apply_reference_v1"
        )
        assert set(empty_apply_receipt) == set(apply_receipt)
        assert empty_apply_receipt["source_plan_revision"] == "2"
        assert _hex_field(empty_apply_receipt, "source_scope", 16) == SCOPE
        assert _hex_field(empty_apply_receipt, "source_plan", 16) == PLAN
        assert _hex_field(empty_apply_receipt, "writer_ref", 16) == WRITER
        empty_target_slice_digest = _hex_field(
            empty_apply_receipt, "target_slice_digest", 32
        )
        assert empty_target_slice_digest != target_slice_digest
        assert (
            _hex_field(empty_apply_receipt, "desired_head_digest", 32)
            == empty_target_slice_digest
        )
        assert empty_apply_receipt["terminal_outcome"] == "2"
        assert empty_apply_receipt["terminal_lifecycle_effect"] in {"1", "2"}
        assert empty_apply_receipt["terminal_head"] == "3"
        empty_apply_request = _hex_field(
            empty_apply_receipt,
            "apply_request_bytes",
            len(bytes.fromhex(empty_apply_receipt["apply_request_bytes"])),
        )
        assert empty_apply_request[:4] == b"PXAR"
        empty_terminal_receipt = _hex_field(
            empty_apply_receipt,
            "terminal_receipt_bytes",
            len(bytes.fromhex(empty_apply_receipt["terminal_receipt_bytes"])),
        )
        assert empty_terminal_receipt[:4] == b"PXRT"
        empty_applied_store = _controller_store_bytes(profile)
        assert empty_applied_store != empty_committed_store

        # Both ensure-once commands must now replay without touching Runtime
        # or the Controller journal. An invalid live ACL makes any accidental
        # second connect observable.
        _run_checked(["sudo", "-n", "chmod", "0600", os.fspath(runtime_socket)])
        replayed_empty_apply = _run_controller(
            profile.apply_command(store_instance_id), profile
        )
        assert replayed_empty_apply.returncode == 0, (
            replayed_empty_apply.stdout + replayed_empty_apply.stderr
        )
        assert replayed_empty_apply.stderr == ""
        assert replayed_empty_apply.stdout == applied_empty.stdout
        assert _controller_store_bytes(profile) == empty_applied_store
        replayed_empty_commit_after_apply = _run_controller(
            profile.commit_empty_command(store_instance_id), profile
        )
        assert replayed_empty_commit_after_apply.returncode == 0, (
            replayed_empty_commit_after_apply.stdout
            + replayed_empty_commit_after_apply.stderr
        )
        assert replayed_empty_commit_after_apply.stderr == ""
        assert replayed_empty_commit_after_apply.stdout == committed_empty.stdout
        assert _controller_store_bytes(profile) == empty_applied_store
        _run_checked(["sudo", "-n", "chmod", "0660", os.fspath(runtime_socket)])

    # Only already-terminal Empty operations are replayed after Runtime exits;
    # restart reassembly belongs to S7-F and is not assumed here.
    offline_terminal_replay = _run_controller(
        profile.apply_command(store_instance_id), profile
    )
    assert offline_terminal_replay.returncode == 0, (
        offline_terminal_replay.stdout + offline_terminal_replay.stderr
    )
    assert offline_terminal_replay.stderr == ""
    assert offline_terminal_replay.stdout == applied_empty.stdout
    assert _controller_store_bytes(profile) == empty_applied_store
    offline_empty_commit_replay = _run_controller(
        profile.commit_empty_command(store_instance_id), profile
    )
    assert offline_empty_commit_replay.returncode == 0, (
        offline_empty_commit_replay.stdout + offline_empty_commit_replay.stderr
    )
    assert offline_empty_commit_replay.stderr == ""
    assert offline_empty_commit_replay.stdout == committed_empty.stdout
    assert _controller_store_bytes(profile) == empty_applied_store
    _assert_only_controller_store_files(profile)
