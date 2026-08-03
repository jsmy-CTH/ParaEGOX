from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.skipif(  # GOV-WAIVER-0008
    sys.platform != "linux",
    reason=(
        "the Runtime install system profile requires Linux ext4, a root-controlled "
        "executable, and a distinct non-root service identity"
    ),
)

DIGEST_MAGIC = b"ParaEGOX\0canonical-digest"
DIGEST_VERSION = 1
DIGEST_FIELD = b"\x01"
DIGEST_END = b"\xff"
BUILD_DESCRIPTOR_DIGEST_DOMAIN = b"paraegox.runtime.build-descriptor.sha256.v1"
COMPATIBILITY_MANIFEST_DIGEST_DOMAIN = (
    b"paraegox.runtime.artifact-compatibility-manifest.sha256.v1"
)
INITIALIZED_SNAPSHOT_DIGEST_DOMAIN = b"paraegox.runtime.initialized-snapshot.sha256.v1"
OWNER_TARGET_FINGERPRINT_DOMAIN = b"paraegox.runtime.owner-target.sha256.v1"
ADMISSION_POLICY_FINGERPRINT_DOMAIN = (
    b"paraegox.runtime.apply-admission-policy.sha256.v1"
)
CHANNEL_POLICY_FINGERPRINT_DOMAIN = (
    b"paraegox.runtime.bootstrap-channel-policy.sha256.v1"
)
CONTROL_KEY_FINGERPRINT_DOMAIN = (
    b"paraegox.runtime.control-auth.ed25519-public-key.sha256.v1"
)

TARGET = bytes.fromhex("11" * 16)
SOURCE_SCOPE = bytes.fromhex("12" * 16)
WRITER = bytes.fromhex("13" * 16)
RUNTIME_PRINCIPAL = bytes.fromhex("21" * 16)
CONTROLLER_PRINCIPAL = bytes.fromhex("22" * 16)
AUTHORITY_PRINCIPAL = bytes.fromhex("23" * 16)
CONTROLLER_KEY_REF = bytes.fromhex("31" * 16)
RUNTIME_RESPONSE_KEY_REF = bytes.fromhex("32" * 16)
TENURE_AUTHORITY_REF = bytes.fromhex("33" * 16)
TENURE_KEY_REF = bytes.fromhex("34" * 16)
CONTROLLER_SEED = bytes.fromhex("41" * 32)
RUNTIME_RESPONSE_SEED = bytes.fromhex("42" * 32)
TENURE_SEED = bytes.fromhex("43" * 32)
MAX_REFERENCE_LIFECYCLE_NANOS = 86_400_000_000_000
REFERENCE_ADMISSION_CAPACITY = 256
CONTROL_SOCKET_DIRECTORY_MODE = 0o2750
CONTROL_SOCKET_MODE = 0o660


@dataclass(frozen=True)
class ServiceIdentity:
    uid: int
    gid: int
    command_prefix: tuple[str, ...]


@dataclass(frozen=True)
class ProvisionedServiceIdentities:
    runtime: ServiceIdentity
    controller: ServiceIdentity
    authority: ServiceIdentity


@dataclass(frozen=True)
class RuntimeProvisioningFacts:
    socket_path: Path
    controller_public_key_path: Path
    runtime_response_public_key_path: Path
    runtime_response_private_seed_path: Path
    tenure_public_key_path: Path
    identities: ProvisionedServiceIdentities
    controller_public_key: bytes
    runtime_response_public_key: bytes
    tenure_public_key: bytes

    def command_arguments(self) -> list[str]:
        runtime = self.identities.runtime
        controller = self.identities.controller
        authority = self.identities.authority
        return [
            os.fspath(self.socket_path),
            TARGET.hex(),
            SOURCE_SCOPE.hex(),
            WRITER.hex(),
            RUNTIME_PRINCIPAL.hex(),
            str(runtime.uid),
            str(runtime.gid),
            CONTROLLER_PRINCIPAL.hex(),
            str(controller.uid),
            str(controller.gid),
            CONTROLLER_KEY_REF.hex(),
            os.fspath(self.controller_public_key_path),
            RUNTIME_RESPONSE_KEY_REF.hex(),
            os.fspath(self.runtime_response_public_key_path),
            os.fspath(self.runtime_response_private_seed_path),
            AUTHORITY_PRINCIPAL.hex(),
            str(authority.uid),
            str(authority.gid),
            TENURE_AUTHORITY_REF.hex(),
            TENURE_KEY_REF.hex(),
            os.fspath(self.tenure_public_key_path),
        ]


@dataclass(frozen=True)
class InstalledRuntime:
    source_binary: Path
    installed_binary: Path
    descriptor_path: Path
    descriptor_bytes: bytes
    descriptor_digest: bytes
    manifest_parent: Path
    manifest_path: Path
    state_directory: Path
    service: ServiceIdentity
    provisioning: RuntimeProvisioningFacts
    working_directory: Path

    def install_command(self) -> list[str]:
        return [
            *self.service.command_prefix,
            os.fspath(self.installed_binary),
            "install-v1",
            os.fspath(self.descriptor_path),
            self.descriptor_digest.hex(),
            os.fspath(self.manifest_path),
            os.fspath(self.state_directory),
            *self.provisioning.command_arguments(),
        ]


def _canonical_digest_fields(domain: bytes, fields: Sequence[bytes]) -> bytes:
    digest = hashlib.sha256()
    digest.update(DIGEST_MAGIC)
    digest.update(DIGEST_VERSION.to_bytes(2, "big"))
    digest.update(len(domain).to_bytes(4, "big"))
    digest.update(domain)
    for ordinal, field in enumerate(fields, start=1):
        digest.update(DIGEST_FIELD)
        digest.update(ordinal.to_bytes(4, "big"))
        digest.update(len(field).to_bytes(8, "big"))
        digest.update(field)
    digest.update(DIGEST_END)
    digest.update(len(fields).to_bytes(4, "big"))
    return digest.digest()


def _canonical_digest(domain: bytes, field: bytes) -> bytes:
    return _canonical_digest_fields(domain, [field])


def _u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _owner_target_fingerprint(provisioning: RuntimeProvisioningFacts) -> bytes:
    runtime = provisioning.identities.runtime
    return _canonical_digest_fields(
        OWNER_TARGET_FINGERPRINT_DOMAIN,
        [TARGET, RUNTIME_PRINCIPAL, _u64(runtime.uid), _u64(runtime.gid)],
    )


def _admission_policy_fingerprint(provisioning: RuntimeProvisioningFacts) -> bytes:
    authority = provisioning.identities.authority
    return _canonical_digest_fields(
        ADMISSION_POLICY_FINGERPRINT_DOMAIN,
        [
            _u16(1),
            _u64(MAX_REFERENCE_LIFECYCLE_NANOS),
            _u64(REFERENCE_ADMISSION_CAPACITY),
            _u64(REFERENCE_ADMISSION_CAPACITY),
            _u64(REFERENCE_ADMISSION_CAPACITY),
            _u64(1),
            SOURCE_SCOPE,
            AUTHORITY_PRINCIPAL,
            _u64(authority.uid),
            _u64(authority.gid),
            TENURE_AUTHORITY_REF,
            TENURE_KEY_REF,
            _u16(1),
            _u16(1),
            provisioning.tenure_public_key,
            _u64(1),
            SOURCE_SCOPE,
            TARGET,
            CONTROLLER_PRINCIPAL,
            WRITER,
            CONTROLLER_KEY_REF,
            _u16(1),
            _u16(1),
            provisioning.controller_public_key,
        ],
    )


def _channel_policy_fingerprint(provisioning: RuntimeProvisioningFacts) -> bytes:
    runtime = provisioning.identities.runtime
    controller = provisioning.identities.controller
    return _canonical_digest_fields(
        CHANNEL_POLICY_FINGERPRINT_DOMAIN,
        [
            TARGET,
            os.fsencode(provisioning.socket_path),
            SOURCE_SCOPE,
            CONTROLLER_PRINCIPAL,
            CONTROLLER_KEY_REF,
            provisioning.controller_public_key,
            _u64(runtime.uid),
            _u64(runtime.gid),
            _u64(controller.uid),
            _u64(controller.gid),
            RUNTIME_PRINCIPAL,
            RUNTIME_RESPONSE_KEY_REF,
            provisioning.runtime_response_public_key,
            _u64(CONTROL_SOCKET_DIRECTORY_MODE),
            _u64(CONTROL_SOCKET_MODE),
        ],
    )


def _controller_key_fingerprint(provisioning: RuntimeProvisioningFacts) -> bytes:
    return _canonical_digest_fields(
        CONTROL_KEY_FINGERPRINT_DOMAIN,
        [_u16(1), b"Ed25519", provisioning.controller_public_key],
    )


def _run_text(
    command: Sequence[str],
    *,
    cwd: Path = REPO_ROOT,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _run_checked(
    command: Sequence[str],
    *,
    cwd: Path = REPO_ROOT,
    timeout: int = 30,
) -> subprocess.CompletedProcess[str]:
    completed = _run_text(command, cwd=cwd, timeout=timeout)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed


def _service_identity_command_prefix(
    setpriv_path: Path, uid: int, gid: int
) -> tuple[str, ...]:
    return (
        "sudo",
        "-n",
        "--",
        os.fspath(setpriv_path),
        f"--reuid={uid}",
        f"--regid={gid}",
        "--clear-groups",
        "--",
    )


def _service_identity(setpriv_path: Path, uid: int, gid: int) -> ServiceIdentity:
    prefix = _service_identity_command_prefix(setpriv_path, uid, gid)
    observed_uid = _run_checked([*prefix, "id", "-u"])
    observed_gid = _run_checked([*prefix, "id", "-g"])
    observed_groups = _run_checked([*prefix, "id", "-G"])
    assert int(observed_uid.stdout.strip()) == uid
    assert int(observed_gid.stdout.strip()) == gid
    assert observed_groups.stdout.split() == [str(gid)]
    return ServiceIdentity(uid, gid, prefix)


def _linux_distinct_service_identities() -> ProvisionedServiceIdentities:
    assert sys.platform == "linux"
    _run_checked(["sudo", "-n", "true"])
    discovered_setpriv = shutil.which("setpriv")
    assert discovered_setpriv is not None
    setpriv_path = Path(discovered_setpriv).resolve(strict=True)
    assert setpriv_path.is_absolute() and setpriv_path.is_file()
    setpriv_version = _run_checked(
        ["sudo", "-n", "--", os.fspath(setpriv_path), "--version"]
    )
    assert setpriv_version.stderr == ""
    assert setpriv_version.stdout.startswith("setpriv from util-linux ")
    import pwd

    preferred_names = ("nobody", "daemon", "www-data", "bin", "sys", "sync")
    preferred = []
    for name in preferred_names:
        try:
            preferred.append(pwd.getpwnam(name))
        except KeyError:
            pass
    candidates = [*preferred, *pwd.getpwall()]
    selected = []
    selected_uids: set[int] = set()
    for account in candidates:
        if (
            account.pw_uid in {0, os.getuid()}
            or account.pw_uid in selected_uids
            or account.pw_gid == 0
        ):
            continue
        selected.append(account)
        selected_uids.add(account.pw_uid)
        if len(selected) == 3:
            break
    if len(selected) != 3:
        pytest.fail("three distinct non-root Runtime/Controller/Authority accounts are required")

    runtime_account, controller_account, authority_account = selected
    runtime = _service_identity(
        setpriv_path, runtime_account.pw_uid, runtime_account.pw_gid
    )
    # Controller runs with its own distinct UID and the Runtime socket group.
    controller = _service_identity(setpriv_path, controller_account.pw_uid, runtime.gid)
    authority = _service_identity(
        setpriv_path, authority_account.pw_uid, authority_account.pw_gid
    )
    assert len({runtime.uid, controller.uid, authority.uid}) == 3
    return ProvisionedServiceIdentities(runtime, controller, authority)


def _mode_bits(path: Path) -> int:
    return path.stat().st_mode & 0o7777


def _sha256_file(path: Path) -> bytes:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").digest()


def _ed25519_public_key(seed: bytes) -> bytes:
    return (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _root_file_metadata(path: Path) -> tuple[int, int, int, int, int]:
    completed = _run_checked(
        ["sudo", "-n", "stat", "-c", "%u %g %a %h %s", "--", os.fspath(path)]
    )
    uid, gid, mode, links, length = completed.stdout.split()
    return int(uid), int(gid), int(mode, 8), int(links), int(length)


def _root_read(path: Path) -> bytes:
    completed = subprocess.run(
        ["sudo", "-n", "cat", "--", os.fspath(path)],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return completed.stdout


def _root_directory_entries(path: Path) -> set[str]:
    completed = _run_checked(
        [
            "sudo",
            "-n",
            "find",
            os.fspath(path),
            "-mindepth",
            "1",
            "-maxdepth",
            "1",
            "-printf",
            "%f\n",
        ]
    )
    return set(completed.stdout.splitlines())


def _single_hex_fact(stdout: str, name: str) -> bytes:
    assert stdout.endswith("\n") and "\n" not in stdout[:-1]
    key, separator, encoded = stdout[:-1].partition("=")
    assert key == name and separator == "="
    assert len(encoded) == 64
    assert all(character in "0123456789abcdef" for character in encoded)
    value = bytes.fromhex(encoded)
    assert any(value)
    return value


def _install_receipt(stdout: str) -> dict[str, bytes]:
    assert stdout.endswith("\n") and "\n" not in stdout[:-1]
    fields = stdout[:-1].split()
    assert fields[0] == "runtime_install_v1"
    parsed: dict[str, bytes] = {}
    for field in fields[1:]:
        name, separator, encoded = field.partition("=")
        assert separator == "=" and name not in parsed
        assert len(encoded) == 64
        assert all(character in "0123456789abcdef" for character in encoded)
        parsed[name] = bytes.fromhex(encoded)
    assert set(parsed) == {
        "manifest_digest",
        "store_instance_id",
        "initialized_snapshot_digest",
    }
    assert all(any(value) for value in parsed.values())
    return parsed


@pytest.fixture(scope="module")
def runtime_host_binary() -> Path:
    completed = _run_text(
        [
            "cargo",
            "build",
            "--locked",
            "-p",
            "paraegox-runtime-host",
            "--bin",
            "paraegox-runtime-host",
        ],
        timeout=180,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", REPO_ROOT / "target"))
    if not target_root.is_absolute():
        target_root = REPO_ROOT / target_root
    binary = (target_root / "debug" / "paraegox-runtime-host").resolve()
    assert binary.is_file() and not binary.is_symlink()
    return binary


@pytest.fixture(scope="module")
def service_identities() -> ProvisionedServiceIdentities:
    return _linux_distinct_service_identities()


@pytest.fixture
def installed_runtime(
    runtime_host_binary: Path,
    service_identities: ProvisionedServiceIdentities,
) -> Iterator[InstalledRuntime]:
    identities = service_identities
    service = identities.runtime
    with tempfile.TemporaryDirectory(prefix="pxr-release-", dir="/tmp") as release_path:
        release_directory = Path(release_path).resolve()
        release_directory.chmod(0o700)
        staged_release_binary = release_directory / "paraegox-runtime-host"
        assert not staged_release_binary.exists()
        shutil.copyfile(runtime_host_binary, staged_release_binary)
        staged_release_binary.chmod(0o755)
        staged_metadata = staged_release_binary.lstat()
        build_metadata = runtime_host_binary.stat()
        assert staged_release_binary.is_file() and not staged_release_binary.is_symlink()
        assert staged_metadata.st_nlink == 1
        assert (staged_metadata.st_dev, staged_metadata.st_ino) != (
            build_metadata.st_dev,
            build_metadata.st_ino,
        )
        assert _mode_bits(staged_release_binary) == 0o755
        assert staged_metadata.st_size == build_metadata.st_size
        assert _sha256_file(staged_release_binary) == _sha256_file(runtime_host_binary)
        release_descriptor = release_directory / "runtime.pxbd"
        released = _run_text(
            [
                os.fspath(staged_release_binary),
                "release-descriptor-v1",
                os.fspath(release_descriptor),
            ]
        )
        assert released.returncode == 0, released.stdout + released.stderr
        assert released.stderr == ""
        descriptor_digest = _single_hex_fact(released.stdout, "descriptor_digest")
        descriptor_bytes = release_descriptor.read_bytes()
        assert descriptor_digest == _canonical_digest(
            BUILD_DESCRIPTOR_DIGEST_DOMAIN, descriptor_bytes
        )
        controller_public_key = _ed25519_public_key(CONTROLLER_SEED)
        runtime_response_public_key = _ed25519_public_key(RUNTIME_RESPONSE_SEED)
        tenure_public_key = _ed25519_public_key(TENURE_SEED)
        assert len({controller_public_key, runtime_response_public_key, tenure_public_key}) == 3
        key_sources = {
            "controller.pub": controller_public_key,
            "runtime.pub": runtime_response_public_key,
            "runtime.seed": RUNTIME_RESPONSE_SEED,
            "authority.pub": tenure_public_key,
        }
        for name, value in key_sources.items():
            source = release_directory / name
            source.write_bytes(value)
            source.chmod(0o600)

        with tempfile.TemporaryDirectory(prefix="pxr-install-", dir="/tmp") as install_path:
            root = Path(install_path).resolve()
            binary_directory = root / "bin"
            descriptor_parent = root / "descriptor"
            manifest_parent = root / "manifest"
            state_directory = root / "state"
            key_directory = root / "keys"
            socket_directory = root / "control"
            socket_path = socket_directory / "bootstrap.sock"
            installed_binary = binary_directory / "paraegox-runtime-host"
            descriptor_path = descriptor_parent / "runtime.pxbd"
            manifest_path = manifest_parent / "runtime.pxcm"
            try:
                _run_checked(
                    [
                        "sudo",
                        "-n",
                        "install",
                        "-d",
                        "-o",
                        "root",
                        "-g",
                        "root",
                        "-m",
                        "0755",
                        os.fspath(root),
                        os.fspath(binary_directory),
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
                        os.fspath(descriptor_parent),
                        os.fspath(manifest_parent),
                        os.fspath(state_directory),
                        os.fspath(key_directory),
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
                        "2750",
                        os.fspath(socket_directory),
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
                        os.fspath(staged_release_binary),
                        os.fspath(installed_binary),
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
                        os.fspath(release_descriptor),
                        os.fspath(descriptor_path),
                    ]
                )
                provisioned_key_paths: dict[str, Path] = {}
                for name in key_sources:
                    destination = key_directory / name
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
                            os.fspath(release_directory / name),
                            os.fspath(destination),
                        ]
                    )
                    provisioned_key_paths[name] = destination
                _run_checked(
                    [*service.command_prefix, "test", "-x", os.fspath(installed_binary)],
                    cwd=root,
                )
                yield InstalledRuntime(
                    source_binary=staged_release_binary,
                    installed_binary=installed_binary,
                    descriptor_path=descriptor_path,
                    descriptor_bytes=descriptor_bytes,
                    descriptor_digest=descriptor_digest,
                    manifest_parent=manifest_parent,
                    manifest_path=manifest_path,
                    state_directory=state_directory,
                    service=service,
                    provisioning=RuntimeProvisioningFacts(
                        socket_path=socket_path,
                        controller_public_key_path=provisioned_key_paths["controller.pub"],
                        runtime_response_public_key_path=provisioned_key_paths["runtime.pub"],
                        runtime_response_private_seed_path=provisioned_key_paths["runtime.seed"],
                        tenure_public_key_path=provisioned_key_paths["authority.pub"],
                        identities=identities,
                        controller_public_key=controller_public_key,
                        runtime_response_public_key=runtime_response_public_key,
                        tenure_public_key=tenure_public_key,
                    ),
                    working_directory=root,
                )
            finally:
                if root.exists():
                    _run_checked(
                        [
                            "sudo",
                            "-n",
                            "chown",
                            "-R",
                            f"{os.getuid()}:{os.getgid()}",
                            os.fspath(root),
                        ]
                    )


def _installed_bytes(runtime: InstalledRuntime) -> dict[str, bytes]:
    return {
        "descriptor": _root_read(runtime.descriptor_path),
        "manifest": _root_read(runtime.manifest_path),
        "runtime.lock": _root_read(runtime.state_directory / "runtime.lock"),
        "runtime.snapshot": _root_read(runtime.state_directory / "runtime.snapshot"),
    }


def test_service_identity_fixture_uses_exact_setpriv_drop_grammar(
    service_identities: ProvisionedServiceIdentities,
) -> None:
    identities = (
        service_identities.runtime,
        service_identities.controller,
        service_identities.authority,
    )
    assert len({identity.uid for identity in identities}) == 3
    assert service_identities.controller.gid == service_identities.runtime.gid
    assert len({identity.command_prefix[3] for identity in identities}) == 1
    for identity in identities:
        assert identity.command_prefix == _service_identity_command_prefix(
            Path(identity.command_prefix[3]), identity.uid, identity.gid
        )
        assert "-u" not in identity.command_prefix
        assert "-g" not in identity.command_prefix


def test_real_installed_runtime_process_initializes_sequence_one_exactly_once(
    installed_runtime: InstalledRuntime,
) -> None:
    runtime = installed_runtime
    descriptor = runtime.descriptor_bytes
    source_metadata = runtime.source_binary.lstat()
    assert runtime.source_binary.is_file() and not runtime.source_binary.is_symlink()
    assert source_metadata.st_nlink == 1
    installed_length = runtime.installed_binary.stat().st_size
    installed_sha256 = _sha256_file(runtime.installed_binary)

    assert installed_length == runtime.source_binary.stat().st_size
    assert installed_sha256 == _sha256_file(runtime.source_binary)
    assert descriptor[:6] == b"PXBD\x00\x01"
    assert len(descriptor) >= 113
    assert any(descriptor[6:38])
    assert int.from_bytes(descriptor[38:46], "big") == installed_length
    assert descriptor[46:78] == installed_sha256
    target_length = int.from_bytes(descriptor[78:80], "big")
    assert 0 < target_length <= 255
    assert 80 + target_length + 32 == len(descriptor)
    target_triple = descriptor[80 : 80 + target_length].decode("ascii")
    assert target_triple.endswith("-unknown-linux-gnu")
    assert runtime.descriptor_digest == _canonical_digest(
        BUILD_DESCRIPTOR_DIGEST_DOMAIN, descriptor
    )
    assert _root_read(runtime.descriptor_path) == descriptor
    assert len(
        {
            runtime.provisioning.identities.runtime.uid,
            runtime.provisioning.identities.controller.uid,
            runtime.provisioning.identities.authority.uid,
        }
    ) == 3
    assert RUNTIME_RESPONSE_SEED.hex() not in runtime.install_command()

    binary_metadata = runtime.installed_binary.stat()
    assert binary_metadata.st_uid == 0
    assert binary_metadata.st_gid == 0
    assert _mode_bits(runtime.installed_binary) == 0o555
    assert binary_metadata.st_nlink == 1
    for directory in (runtime.manifest_parent, runtime.state_directory):
        metadata = directory.stat()
        assert metadata.st_uid == runtime.service.uid
        assert metadata.st_gid == runtime.service.gid
        assert _mode_bits(directory) == 0o700
    key_directory = runtime.provisioning.controller_public_key_path.parent
    assert _root_file_metadata(key_directory)[:3] == (
        runtime.service.uid,
        runtime.service.gid,
        0o700,
    )
    assert _root_file_metadata(runtime.provisioning.socket_path.parent)[:3] == (
        runtime.service.uid,
        runtime.service.gid,
        CONTROL_SOCKET_DIRECTORY_MODE,
    )
    for key_path in (
        runtime.provisioning.controller_public_key_path,
        runtime.provisioning.runtime_response_public_key_path,
        runtime.provisioning.runtime_response_private_seed_path,
        runtime.provisioning.tenure_public_key_path,
    ):
        uid, gid, mode, links, length = _root_file_metadata(key_path)
        assert (uid, gid, mode, links, length) == (
            runtime.service.uid,
            runtime.service.gid,
            0o400,
            1,
            32,
        )

    installed = _run_text(runtime.install_command(), cwd=runtime.working_directory)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    assert installed.stderr == ""
    receipt = _install_receipt(installed.stdout)

    assert _root_directory_entries(runtime.manifest_parent) == {runtime.manifest_path.name}
    assert _root_directory_entries(runtime.state_directory) == {"runtime.lock", "runtime.snapshot"}
    manifest = _root_read(runtime.manifest_path)
    marker = _root_read(runtime.state_directory / "runtime.lock")
    snapshot = _root_read(runtime.state_directory / "runtime.snapshot")

    assert len(manifest) == 266
    assert manifest[:6] == b"PXCM\x00\x01"
    assert manifest[6:22] == TARGET
    assert receipt["manifest_digest"] == _canonical_digest(
        COMPATIBILITY_MANIFEST_DIGEST_DOMAIN, manifest
    )
    assert marker == b""

    assert snapshot[:14] == b"PXJR\x00\x01\x00\x03\x00\x05\x00\x01\x00\x01"
    assert snapshot[14:46] == receipt["store_instance_id"]
    assert snapshot[46:78] == _owner_target_fingerprint(runtime.provisioning)
    assert int.from_bytes(snapshot[78:86], "big") == 1
    payload_length = int.from_bytes(snapshot[86:94], "big")
    assert len(snapshot) == 126 + payload_length
    assert descriptor in snapshot
    assert manifest in snapshot
    assert _admission_policy_fingerprint(runtime.provisioning) in snapshot
    assert _channel_policy_fingerprint(runtime.provisioning) in snapshot
    assert _controller_key_fingerprint(runtime.provisioning) in snapshot
    assert RUNTIME_RESPONSE_SEED not in snapshot
    assert receipt["initialized_snapshot_digest"] == _canonical_digest(
        INITIALIZED_SNAPSHOT_DIGEST_DOMAIN, snapshot
    )

    for path, expected_length in (
        (runtime.descriptor_path, len(descriptor)),
        (runtime.manifest_path, len(manifest)),
        (runtime.state_directory / "runtime.lock", 0),
        (runtime.state_directory / "runtime.snapshot", len(snapshot)),
    ):
        uid, gid, mode, links, length = _root_file_metadata(path)
        assert (uid, gid, mode, links, length) == (
            runtime.service.uid,
            runtime.service.gid,
            0o600,
            1,
            expected_length,
        )

    before_retry = _installed_bytes(runtime)
    retried = _run_text(runtime.install_command(), cwd=runtime.working_directory)
    assert retried.returncode != 0
    assert retried.stdout == ""
    assert retried.stderr == (
        "RuntimeHost entrypoint failed: Runtime store preflight: Runtime initializer cannot "
        "begin: MarkerConsumed(InitializerMarkerAlreadyPresent)\n"
    )
    assert _root_directory_entries(runtime.manifest_parent) == {runtime.manifest_path.name}
    assert _root_directory_entries(runtime.state_directory) == {"runtime.lock", "runtime.snapshot"}
    assert _installed_bytes(runtime) == before_retry
