from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NODE_READY = b"paraegox: node ready\n"
DEPLOYMENT_READY = b"paraegox: deployment ready\n"
PROCESS_TIMEOUT_SECONDS = 120.0

INSTALLATION_ID = "01" * 16
TARGET = "02" * 16
SOURCE_SCOPE = "03" * 16
WRITER = "04" * 16
RUNTIME_PRINCIPAL = "05" * 16
CONTROLLER_PRINCIPAL = "06" * 16
AUTHORITY_PRINCIPAL = "07" * 16
CONTROLLER_REQUEST_KEY_REF = "08" * 16
RUNTIME_RESPONSE_KEY_REF = "09" * 16
TENURE_AUTHORITY_REF = "0a" * 16
TENURE_KEY_REF = "0b" * 16
ENROLLMENT_ISSUER_REF = "0c" * 16
RUNTIME_ENDPOINT_REF = "0d" * 16
RUNTIME_TRUST_DOMAIN_REF = "0e" * 16
RUNTIME_TRUST_ANCHOR_REF = "0f" * 16
RUNTIME_CONTROLLER_CREDENTIAL_REF = "10" * 16
RUNTIME_LISTENER_CREDENTIAL_REF = "11" * 16
RUNTIME_TRANSPORT_PROFILE_REF = "12" * 16
NODE_ENDPOINT_REF = "13" * 16
NODE_TRUST_DOMAIN_REF = "14" * 16
NODE_TRUST_ANCHOR_REF = "15" * 16
NODE_CONTROLLER_CREDENTIAL_REF = "16" * 16
NODE_LISTENER_CREDENTIAL_REF = "17" * 16
NODE_TRANSPORT_PROFILE_REF = "18" * 16
NODE_PRINCIPAL = "19" * 16


@dataclass
class RunningProcess:
    process: subprocess.Popen[bytes]
    stdout_path: Path
    stderr_path: Path
    stdout_file: BinaryIO
    stderr_file: BinaryIO

    def close_logs(self) -> None:
        self.stdout_file.close()
        self.stderr_file.close()


def _mkdir_owned(path: Path, mode: int, uid: int, gid: int) -> None:
    path.mkdir()
    os.chown(path, uid, gid)
    path.chmod(mode)


def _write_owned(path: Path, payload: bytes, mode: int, uid: int, gid: int) -> None:
    with path.open("xb") as target:
        target.write(payload)
        target.flush()
        os.fsync(target.fileno())
    os.chown(path, uid, gid)
    path.chmod(mode)
    metadata = path.stat()
    assert metadata.st_uid == uid and metadata.st_gid == gid
    assert metadata.st_nlink == 1
    assert metadata.st_mode & 0o7777 == mode


def _ed25519_public_key(seed: bytes) -> bytes:
    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _non_loopback_ipv4(ip_command: str) -> str:
    completed = subprocess.run(
        [ip_command, "-o", "-4", "addr", "show", "scope", "global"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    for line in completed.stdout.splitlines():
        fields = line.split()
        if "inet" not in fields:
            continue
        candidate = fields[fields.index("inet") + 1].split("/", 1)[0]
        address = ipaddress.ip_address(candidate)
        if (
            isinstance(address, ipaddress.IPv4Address)
            and not address.is_loopback
            and not address.is_unspecified
            and not address.is_multicast
        ):
            return candidate
    pytest.fail("one bindable non-loopback global IPv4 address is required")


def _free_port(address: str, excluded: set[int]) -> int:
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((address, 0))
            port = listener.getsockname()[1]
        if port not in excluded:
            return port


def _certificate_name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _make_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    name = _certificate_name("ParaEGOX public deployment smoke CA")
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _make_leaf(
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    common_name: str,
    *,
    server_address: str | None,
) -> tuple[bytes, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_certificate_name(common_name))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if server_address is None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    else:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(server_address))]
            ),
            critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    certificate = builder.sign(ca_key, hashes.SHA256())
    return (
        certificate.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _copy_public_binary(source: Path, target: Path, uid: int, gid: int) -> None:
    assert source.is_absolute() and source.is_file() and not source.is_symlink()
    shutil.copyfile(source, target)
    os.chown(target, uid, gid)
    target.chmod(0o755)
    metadata = target.stat()
    assert metadata.st_uid == uid and metadata.st_gid == gid
    assert metadata.st_nlink == 1
    assert metadata.st_mode & 0o7777 == 0o755


def _spawn(
    command: list[str],
    *,
    name: str,
    root: Path,
    environment: dict[str, str],
) -> RunningProcess:
    stdout_path = root / f"{name}.stdout"
    stderr_path = root / f"{name}.stderr"
    stdout_file = stdout_path.open("wb", buffering=0)
    stderr_file = stderr_path.open("wb", buffering=0)
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            start_new_session=True,
        )
    except BaseException:
        stdout_file.close()
        stderr_file.close()
        raise
    return RunningProcess(process, stdout_path, stderr_path, stdout_file, stderr_file)


@contextmanager
def _temporary_root() -> Iterator[Path]:
    root = Path(tempfile.mkdtemp(prefix="pg2.", dir="/tmp"))
    try:
        yield root
    finally:
        if os.environ.get("PARAEGOX_PRESERVE_PUBLIC_DEPLOYMENT_SMOKE") == "1":
            print(f"preserved public Deployment smoke root: {root}", file=sys.stderr)
        else:
            shutil.rmtree(root)


def _logs(process: RunningProcess) -> tuple[bytes, bytes]:
    process.stdout_file.flush()
    process.stderr_file.flush()
    return process.stdout_path.read_bytes(), process.stderr_path.read_bytes()


def _inventory(root: Path) -> list[tuple[str, int, int, int, int, int]]:
    observed = []
    for path in sorted(root.rglob("*")):
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        observed.append(
            (
                str(path.relative_to(root)),
                metadata.st_mode & 0o7777,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
                metadata.st_size,
            )
        )
    return observed


def _wait_for_marker(
    process: RunningProcess, marker: bytes, *, timeout: float = PROCESS_TIMEOUT_SECONDS
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        stdout, stderr = _logs(process)
        if marker in stdout:
            assert stdout.count(marker) == 1, stdout
            assert stdout == marker, stdout
            assert process.process.poll() is None, (stdout, stderr)
            time.sleep(0.1)
            assert process.process.poll() is None, (stdout, stderr)
            return
        return_code = process.process.poll()
        if return_code is not None:
            pytest.fail(
                f"process exited {return_code} before {marker!r}; "
                f"stdout={stdout!r}; stderr={stderr!r}; "
                f"inventory={_inventory(process.stdout_path.parent)!r}"
            )
        time.sleep(0.05)
    stdout, stderr = _logs(process)
    pytest.fail(
        f"process timed out before {marker!r}; stdout={stdout!r}; stderr={stderr!r}; "
        f"inventory={_inventory(process.stdout_path.parent)!r}"
    )


def _wait_for_exit(
    process: RunningProcess, *, timeout: float = PROCESS_TIMEOUT_SECONDS
) -> int:
    try:
        return process.process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stdout, stderr = _logs(process)
        pytest.fail(
            f"process did not exit in {timeout}s; stdout={stdout!r}; stderr={stderr!r}"
        )


def _stop_process(process: RunningProcess) -> None:
    if process.process.poll() is None:
        process.process.send_signal(signal.SIGTERM)
        try:
            process.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass
    try:
        os.killpg(process.process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.process.poll() is None:
        process.process.wait(timeout=10)
    process.close_logs()


def _node_document(
    *,
    state_root: Path,
    credentials: Path,
    address: str,
    runtime_port: int,
    node_port: int,
    controller_public_key: bytes,
    authority_public_key: bytes,
) -> str:
    return f'''schema_version = 2
state_root = "{state_root}"

[control]
installation_id = "{INSTALLATION_ID}"
target = "{TARGET}"
source_scope = "{SOURCE_SCOPE}"
writer = "{WRITER}"
runtime_principal = "{RUNTIME_PRINCIPAL}"
controller_principal = "{CONTROLLER_PRINCIPAL}"
authority_principal = "{AUTHORITY_PRINCIPAL}"
controller_request_key_ref = "{CONTROLLER_REQUEST_KEY_REF}"
runtime_response_key_ref = "{RUNTIME_RESPONSE_KEY_REF}"
tenure_authority_ref = "{TENURE_AUTHORITY_REF}"
tenure_key_ref = "{TENURE_KEY_REF}"
enrollment_issuer_ref = "{ENROLLMENT_ISSUER_REF}"
controller_request_verification_key = "{controller_public_key.hex()}"
tenure_verification_key = "{authority_public_key.hex()}"

[restricted_runtime_apply]
endpoint_ref = "{RUNTIME_ENDPOINT_REF}"
endpoint_generation = 1
tls_listener_locator = "tls/{address}:{runtime_port}"
route = "paraegox/runtime/{TARGET}/apply"
trust_domain_ref = "{RUNTIME_TRUST_DOMAIN_REF}"
trust_anchor_ref = "{RUNTIME_TRUST_ANCHOR_REF}"
controller_connector_credential_ref = "{RUNTIME_CONTROLLER_CREDENTIAL_REF}"
runtime_listener_credential_ref = "{RUNTIME_LISTENER_CREDENTIAL_REF}"
control_transport_profile_ref = "{RUNTIME_TRANSPORT_PROFILE_REF}"
root_ca_certificate_file = "{credentials / 'runtime-ca.pem'}"
runtime_listener_certificate_file = "{credentials / 'runtime.pem'}"
runtime_listener_private_key_file = "{credentials / 'runtime-key.pem'}"

[node_control]
endpoint_ref = "{NODE_ENDPOINT_REF}"
endpoint_generation = 1
tls_listener_locator = "tls/{address}:{node_port}"
route = "paraegox/node/control/v1"
trust_domain_ref = "{NODE_TRUST_DOMAIN_REF}"
trust_anchor_ref = "{NODE_TRUST_ANCHOR_REF}"
controller_connector_credential_ref = "{NODE_CONTROLLER_CREDENTIAL_REF}"
node_listener_credential_ref = "{NODE_LISTENER_CREDENTIAL_REF}"
control_transport_profile_ref = "{NODE_TRANSPORT_PROFILE_REF}"
node_certificate_principal = "{NODE_PRINCIPAL}"
root_ca_certificate_file = "{credentials / 'node-ca.pem'}"
node_listener_certificate_file = "{credentials / 'node.pem'}"
node_listener_private_key_file = "{credentials / 'node-key.pem'}"
'''


def _deployment_document(
    *,
    state_root: Path,
    artifact: Path,
    artifact_sha256: bytes,
    controller_seed: Path,
    authority_seed: Path,
    authority_state: Path,
    authority_socket: Path,
    credentials: Path,
) -> str:
    return f'''schema_version = 1
state_root = "{state_root}"
enrollment_artifact_file = "{artifact}"
enrollment_artifact_sha256 = "{artifact_sha256.hex()}"
controller_signing_seed_file = "{controller_seed}"
authority_signing_seed_file = "{authority_seed}"
authority_state_directory = "{authority_state}"
authority_socket_path = "{authority_socket}"

[runtime_connector]
root_ca_certificate_file = "{credentials / 'runtime-ca.pem'}"
client_certificate_file = "{credentials / 'runtime-client.pem'}"
client_private_key_file = "{credentials / 'runtime-client-key.pem'}"

[node_connector]
root_ca_certificate_file = "{credentials / 'node-ca.pem'}"
client_certificate_file = "{credentials / 'node-client.pem'}"
client_private_key_file = "{credentials / 'node-client-key.pem'}"
'''


def test_public_deployment_fresh_restart_and_sha_pin_fail_closed() -> None:
    if sys.platform != "linux":
        pytest.skip("the public Deployment process smoke is Linux-only")
    if os.geteuid() != 0:
        pytest.skip("the harness requires root only to prepare and drop to a non-root uid")
    binary_value = os.environ.get("PARAEGOX_PUBLIC_CLI_BINARY")
    if binary_value is None:
        pytest.skip("set PARAEGOX_PUBLIC_CLI_BINARY to an already built exact-ref binary")
    source_binary = Path(binary_value).resolve(strict=True)
    setpriv = shutil.which("setpriv")
    assert setpriv is not None
    ip_command = shutil.which("ip")
    assert ip_command is not None
    account = pwd.getpwnam("nobody")
    uid, gid = account.pw_uid, account.pw_gid
    assert uid != 0 and gid != 0

    with _temporary_root() as root:
        os.chown(root, uid, gid)
        root.chmod(0o700)
        directories = {
            "bin": 0o700,
            "cfg": 0o700,
            "tmp": 0o700,
            "node": 0o700,
            "deployment": 0o700,
            "authority": 0o700,
            "authority-socket": 0o2750,
            "deployment-wrong-sha": 0o700,
            "authority-wrong-sha": 0o700,
            "authority-wrong-sha-socket": 0o2750,
            "deployment-node-down": 0o700,
            "authority-node-down": 0o700,
            "authority-node-down-socket": 0o2750,
            "input": 0o700,
            "secrets": 0o700,
            "deployment-credentials": 0o700,
        }
        for name, mode in directories.items():
            _mkdir_owned(root / name, mode, uid, gid)
        node_credentials = root / "node" / "credentials"
        _mkdir_owned(node_credentials, 0o700, uid, gid)

        binary = root / "bin" / "paraegox"
        _copy_public_binary(source_binary, binary, uid, gid)
        controller_seed_bytes = os.urandom(32)
        authority_seed_bytes = os.urandom(32)
        controller_seed = root / "secrets" / "controller.seed"
        authority_seed = root / "secrets" / "authority.seed"
        _write_owned(controller_seed, controller_seed_bytes, 0o600, uid, gid)
        _write_owned(authority_seed, authority_seed_bytes, 0o600, uid, gid)
        controller_public_key = _ed25519_public_key(controller_seed_bytes)
        authority_public_key = _ed25519_public_key(authority_seed_bytes)
        assert controller_public_key != authority_public_key

        address = _non_loopback_ipv4(ip_command)
        runtime_port = _free_port(address, set())
        node_port = _free_port(address, {runtime_port})
        ca_key, ca_certificate = _make_ca()
        ca_pem = ca_certificate.public_bytes(serialization.Encoding.PEM)
        runtime_certificate, runtime_key = _make_leaf(
            ca_key,
            ca_certificate,
            f"paraegox-principal-{RUNTIME_PRINCIPAL}",
            server_address=address,
        )
        node_certificate, node_key = _make_leaf(
            ca_key,
            ca_certificate,
            f"paraegox-principal-{NODE_PRINCIPAL}",
            server_address=address,
        )
        runtime_client_certificate, runtime_client_key = _make_leaf(
            ca_key,
            ca_certificate,
            f"paraegox-principal-{CONTROLLER_PRINCIPAL}",
            server_address=None,
        )
        node_client_certificate, node_client_key = _make_leaf(
            ca_key,
            ca_certificate,
            f"paraegox-principal-{CONTROLLER_PRINCIPAL}",
            server_address=None,
        )
        for name, payload, mode in (
            ("runtime-ca.pem", ca_pem, 0o444),
            ("runtime.pem", runtime_certificate, 0o444),
            ("runtime-key.pem", runtime_key, 0o600),
            ("node-ca.pem", ca_pem, 0o444),
            ("node.pem", node_certificate, 0o444),
            ("node-key.pem", node_key, 0o600),
        ):
            _write_owned(node_credentials / name, payload, mode, uid, gid)
        deployment_credentials = root / "deployment-credentials"
        for name, payload, mode in (
            ("runtime-ca.pem", ca_pem, 0o444),
            ("runtime-client.pem", runtime_client_certificate, 0o444),
            ("runtime-client-key.pem", runtime_client_key, 0o600),
            ("node-ca.pem", ca_pem, 0o444),
            ("node-client.pem", node_client_certificate, 0o444),
            ("node-client-key.pem", node_client_key, 0o600),
        ):
            _write_owned(deployment_credentials / name, payload, mode, uid, gid)

        node_config = root / "cfg" / "node.toml"
        _write_owned(
            node_config,
            _node_document(
                state_root=root / "node",
                credentials=node_credentials,
                address=address,
                runtime_port=runtime_port,
                node_port=node_port,
                controller_public_key=controller_public_key,
                authority_public_key=authority_public_key,
            ).encode(),
            0o600,
            uid,
            gid,
        )
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(root),
                "TMPDIR": str(root / "tmp"),
                "RUST_MIN_STACK": "16777216",
            }
        )
        command_prefix = [
            setpriv,
            f"--reuid={uid}",
            f"--regid={gid}",
            "--clear-groups",
            "--",
        ]
        node = _spawn(
            [*command_prefix, str(binary), "node", "--config", str(node_config)],
            name="node",
            root=root,
            environment=environment,
        )
        deployment: RunningProcess | None = None
        deployment_restart: RunningProcess | None = None
        wrong_pin: RunningProcess | None = None
        node_down: RunningProcess | None = None
        try:
            _wait_for_marker(node, NODE_READY)
            artifact_source = root / "node" / "node" / "enrollment-v1.pxea"
            assert artifact_source.is_file() and artifact_source.stat().st_size > 0
            artifact = root / "input" / "enrollment-v1.pxea"
            _write_owned(artifact, artifact_source.read_bytes(), 0o400, uid, gid)
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).digest()
            wrong_digest = bytes([artifact_sha256[0] ^ 1]) + artifact_sha256[1:]
            wrong_config = root / "cfg" / "deployment-wrong-sha.toml"
            _write_owned(
                wrong_config,
                _deployment_document(
                    state_root=root / "deployment-wrong-sha",
                    artifact=artifact,
                    artifact_sha256=wrong_digest,
                    controller_seed=controller_seed,
                    authority_seed=authority_seed,
                    authority_state=root / "authority-wrong-sha",
                    authority_socket=root
                    / "authority-wrong-sha-socket"
                    / "authority.sock",
                    credentials=deployment_credentials,
                ).encode(),
                0o600,
                uid,
                gid,
            )
            wrong_pin = _spawn(
                [
                    *command_prefix,
                    str(binary),
                    "deployment",
                    "--config",
                    str(wrong_config),
                ],
                name="deployment-wrong-sha",
                root=root,
                environment=environment,
            )
            assert _wait_for_exit(wrong_pin, timeout=30) != 0
            wrong_stdout, _ = _logs(wrong_pin)
            assert DEPLOYMENT_READY not in wrong_stdout
            assert not any((root / "deployment-wrong-sha").iterdir())
            assert not any((root / "authority-wrong-sha").iterdir())
            assert not (root / "authority-wrong-sha-socket" / "authority.sock").exists()
            wrong_pin.close_logs()
            wrong_pin = None

            deployment_config = root / "cfg" / "deployment.toml"
            deployment_text = _deployment_document(
                state_root=root / "deployment",
                artifact=artifact,
                artifact_sha256=artifact_sha256,
                controller_seed=controller_seed,
                authority_seed=authority_seed,
                authority_state=root / "authority",
                authority_socket=root / "authority-socket" / "authority.sock",
                credentials=deployment_credentials,
            )
            _write_owned(
                deployment_config, deployment_text.encode(), 0o600, uid, gid
            )
            assert controller_seed_bytes not in deployment_text.encode()
            assert authority_seed_bytes not in deployment_text.encode()

            deployment = _spawn(
                [
                    *command_prefix,
                    str(binary),
                    "deployment",
                    "--config",
                    str(deployment_config),
                ],
                name="deployment-fresh",
                root=root,
                environment=environment,
            )
            _wait_for_marker(deployment, DEPLOYMENT_READY)
            assert deployment.process.poll() is None
            deployment.process.send_signal(signal.SIGTERM)
            assert _wait_for_exit(deployment) == 0, _logs(deployment)
            deployment.close_logs()
            deployment = None

            deployment_restart = _spawn(
                [
                    *command_prefix,
                    str(binary),
                    "deployment",
                    "--config",
                    str(deployment_config),
                ],
                name="deployment-restart",
                root=root,
                environment=environment,
            )
            _wait_for_marker(deployment_restart, DEPLOYMENT_READY)
            assert deployment_restart.process.poll() is None
            deployment_restart.process.send_signal(signal.SIGTERM)
            assert _wait_for_exit(deployment_restart) == 0, _logs(deployment_restart)
            deployment_restart.close_logs()
            deployment_restart = None

            assert node.process.poll() is None
            node.process.send_signal(signal.SIGTERM)
            assert _wait_for_exit(node) == 0, _logs(node)

            node_down_config = root / "cfg" / "deployment-node-down.toml"
            node_down_socket = root / "authority-node-down-socket" / "authority.sock"
            _write_owned(
                node_down_config,
                _deployment_document(
                    state_root=root / "deployment-node-down",
                    artifact=artifact,
                    artifact_sha256=artifact_sha256,
                    controller_seed=controller_seed,
                    authority_seed=authority_seed,
                    authority_state=root / "authority-node-down",
                    authority_socket=node_down_socket,
                    credentials=deployment_credentials,
                ).encode(),
                0o600,
                uid,
                gid,
            )
            node_down = _spawn(
                [
                    *command_prefix,
                    str(binary),
                    "deployment",
                    "--config",
                    str(node_down_config),
                ],
                name="deployment-node-down",
                root=root,
                environment=environment,
            )
            assert _wait_for_exit(node_down, timeout=90) != 0
            node_down_stdout, _ = _logs(node_down)
            assert DEPLOYMENT_READY not in node_down_stdout
            assert not node_down_socket.exists()
            node_down.close_logs()
            node_down = None
        finally:
            for process in (node_down, wrong_pin, deployment_restart, deployment, node):
                if process is not None:
                    _stop_process(process)
