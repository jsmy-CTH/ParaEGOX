from __future__ import annotations

import hashlib
import os
import pwd
import shutil
import signal
import sys
from pathlib import Path

import pytest
import test_g2_public_deployment_cli as g2

DEPLOYMENT_AGENT_BOOTSTRAP_READY = b"paraegox: deployment agent bootstrap ready\n"
FABRIC_SERVICE_ID = "20" * 16
AGENT_SERVICE_ID = "21" * 16


def _node_v3_document(
    *,
    state_root: Path,
    credentials: Path,
    address: str,
    runtime_port: int,
    node_port: int,
    controller_public_key: bytes,
    authority_public_key: bytes,
) -> str:
    base = g2._node_document(
        state_root=state_root,
        credentials=credentials,
        address=address,
        runtime_port=runtime_port,
        node_port=node_port,
        controller_public_key=controller_public_key,
        authority_public_key=authority_public_key,
    )
    assert base.startswith("schema_version = 2\n")
    return (
        base.replace("schema_version = 2\n", "schema_version = 3\n", 1)
        + "\n[managed_agent_bootstrap]\n"
        + 'provider = "deterministic-echo-v1"\n'
    )


def _deployment_v2_document(
    *,
    state_root: Path,
    artifact: Path,
    artifact_sha256: bytes,
    controller_seed: Path,
    authority_seed: Path,
    authority_state: Path,
    authority_socket: Path,
    credentials: Path,
    fabric_port: int,
) -> str:
    base = g2._deployment_document(
        state_root=state_root,
        artifact=artifact,
        artifact_sha256=artifact_sha256,
        controller_seed=controller_seed,
        authority_seed=authority_seed,
        authority_state=authority_state,
        authority_socket=authority_socket,
        credentials=credentials,
    )
    assert base.startswith("schema_version = 1\n")
    return (
        base.replace("schema_version = 1\n", "schema_version = 2\n", 1)
        + "\n[managed_agent_bootstrap]\n"
        + f'fabric_service_id = "{FABRIC_SERVICE_ID}"\n'
        + f'agent_service_id = "{AGENT_SERVICE_ID}"\n'
        + f'fabric_listen = "tcp/127.0.0.1:{fabric_port}"\n'
        + 'limits_profile = "developer-agent-bootstrap-v1"\n'
    )


def _assert_ready_and_no_error(
    process: g2.RunningProcess, marker: bytes = DEPLOYMENT_AGENT_BOOTSTRAP_READY
) -> None:
    g2._wait_for_marker(process, marker)
    stdout, stderr = g2._logs(process)
    assert stdout == marker
    assert stderr == b""


def _assert_joined_sigterm(
    process: g2.RunningProcess, marker: bytes = DEPLOYMENT_AGENT_BOOTSTRAP_READY
) -> None:
    assert process.process.poll() is None
    process.process.send_signal(signal.SIGTERM)
    assert g2._wait_for_exit(process) == 0, g2._logs(process)
    stdout, stderr = g2._logs(process)
    assert stdout == marker
    assert stderr == b""


def _assert_failed_without_ready(process: g2.RunningProcess, *, timeout: float) -> None:
    assert g2._wait_for_exit(process, timeout=timeout) != 0
    stdout, _stderr = g2._logs(process)
    assert stdout == b""
    assert DEPLOYMENT_AGENT_BOOTSTRAP_READY not in stdout
    assert g2.DEPLOYMENT_READY not in stdout


def _assert_logs_do_not_contain_secrets(root: Path, secrets: tuple[bytes, ...]) -> None:
    for path in (*root.glob("*.stdout"), *root.glob("*.stderr")):
        payload = path.read_bytes()
        for secret in secrets:
            assert secret not in payload, path
        assert b"-----BEGIN PRIVATE KEY-----" not in payload, path


def test_public_agent_bootstrap_fresh_resume_and_fail_closed() -> None:
    """Proves only the public managed-Agent bootstrap descriptor lifecycle.

    A Ready marker here does not prove Agent access, Echo, conversation, reconnect,
    remote TUI, or distributed readiness.
    """
    if sys.platform != "linux":
        pytest.skip(  # GOV-WAIVER-0013
            "the public managed-Agent bootstrap smoke is Linux-only"
        )
    if os.geteuid() != 0:
        pytest.skip(  # GOV-WAIVER-0013
            "the harness requires root only to prepare and drop to a non-root uid"
        )
    binary_value = os.environ.get("PARAEGOX_PUBLIC_CLI_BINARY")
    if binary_value is None:
        pytest.skip(  # GOV-WAIVER-0013
            "set PARAEGOX_PUBLIC_CLI_BINARY to an already built exact-ref binary"
        )
    source_binary = Path(binary_value).resolve(strict=True)
    setpriv = shutil.which("setpriv")
    assert setpriv is not None
    ip_command = shutil.which("ip")
    assert ip_command is not None
    account = pwd.getpwnam("nobody")
    uid, gid = account.pw_uid, account.pw_gid
    assert uid != 0 and gid != 0

    with g2._temporary_root() as root:
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
            g2._mkdir_owned(root / name, mode, uid, gid)
        node_credentials = root / "node" / "credentials"
        g2._mkdir_owned(node_credentials, 0o700, uid, gid)

        binary = root / "bin" / "paraegox"
        g2._copy_public_binary(source_binary, binary, uid, gid)
        controller_seed_bytes = os.urandom(32)
        authority_seed_bytes = os.urandom(32)
        controller_seed = root / "secrets" / "controller.seed"
        authority_seed = root / "secrets" / "authority.seed"
        g2._write_owned(controller_seed, controller_seed_bytes, 0o600, uid, gid)
        g2._write_owned(authority_seed, authority_seed_bytes, 0o600, uid, gid)
        controller_public_key = g2._ed25519_public_key(controller_seed_bytes)
        authority_public_key = g2._ed25519_public_key(authority_seed_bytes)
        assert controller_public_key != authority_public_key

        address = g2._non_loopback_ipv4(ip_command)
        runtime_port = g2._free_port(address, set())
        node_port = g2._free_port(address, {runtime_port})
        fabric_port = g2._free_port("127.0.0.1", {runtime_port, node_port})
        ca_key, ca_certificate = g2._make_ca()
        ca_pem = ca_certificate.public_bytes(g2.serialization.Encoding.PEM)
        runtime_certificate, runtime_key = g2._make_leaf(
            ca_key,
            ca_certificate,
            f"paraegox-principal-{g2.RUNTIME_PRINCIPAL}",
            server_address=address,
        )
        node_certificate, node_key = g2._make_leaf(
            ca_key,
            ca_certificate,
            f"paraegox-principal-{g2.NODE_PRINCIPAL}",
            server_address=address,
        )
        runtime_client_certificate, runtime_client_key = g2._make_leaf(
            ca_key,
            ca_certificate,
            f"paraegox-principal-{g2.CONTROLLER_PRINCIPAL}",
            server_address=None,
        )
        node_client_certificate, node_client_key = g2._make_leaf(
            ca_key,
            ca_certificate,
            f"paraegox-principal-{g2.CONTROLLER_PRINCIPAL}",
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
            g2._write_owned(node_credentials / name, payload, mode, uid, gid)
        deployment_credentials = root / "deployment-credentials"
        for name, payload, mode in (
            ("runtime-ca.pem", ca_pem, 0o444),
            ("runtime-client.pem", runtime_client_certificate, 0o444),
            ("runtime-client-key.pem", runtime_client_key, 0o600),
            ("node-ca.pem", ca_pem, 0o444),
            ("node-client.pem", node_client_certificate, 0o444),
            ("node-client-key.pem", node_client_key, 0o600),
        ):
            g2._write_owned(deployment_credentials / name, payload, mode, uid, gid)

        node_config = root / "cfg" / "node-v3.toml"
        node_text = _node_v3_document(
            state_root=root / "node",
            credentials=node_credentials,
            address=address,
            runtime_port=runtime_port,
            node_port=node_port,
            controller_public_key=controller_public_key,
            authority_public_key=authority_public_key,
        )
        g2._write_owned(node_config, node_text.encode(), 0o600, uid, gid)
        assert controller_seed_bytes not in node_text.encode()
        assert authority_seed_bytes not in node_text.encode()

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
        node: g2.RunningProcess | None = g2._spawn(
            [*command_prefix, str(binary), "node", "--config", str(node_config)],
            name="t1-node-fresh",
            root=root,
            environment=environment,
        )
        deployment: g2.RunningProcess | None = None
        deployment_restart: g2.RunningProcess | None = None
        node_restart: g2.RunningProcess | None = None
        wrong_pin: g2.RunningProcess | None = None
        node_down: g2.RunningProcess | None = None
        try:
            assert node is not None
            _assert_ready_and_no_error(node, g2.NODE_READY)
            artifact_source = root / "node" / "node" / "enrollment-v2.pxea"
            assert artifact_source.is_file() and artifact_source.stat().st_size > 0
            artifact = root / "input" / "enrollment-v2.pxea"
            g2._write_owned(artifact, artifact_source.read_bytes(), 0o400, uid, gid)
            artifact_sha256 = hashlib.sha256(artifact.read_bytes()).digest()

            wrong_digest = bytes([artifact_sha256[0] ^ 1]) + artifact_sha256[1:]
            wrong_config = root / "cfg" / "deployment-v2-wrong-sha.toml"
            g2._write_owned(
                wrong_config,
                _deployment_v2_document(
                    state_root=root / "deployment-wrong-sha",
                    artifact=artifact,
                    artifact_sha256=wrong_digest,
                    controller_seed=controller_seed,
                    authority_seed=authority_seed,
                    authority_state=root / "authority-wrong-sha",
                    authority_socket=root / "authority-wrong-sha-socket" / "authority.sock",
                    credentials=deployment_credentials,
                    fabric_port=fabric_port,
                ).encode(),
                0o600,
                uid,
                gid,
            )
            wrong_pin = g2._spawn(
                [
                    *command_prefix,
                    str(binary),
                    "deployment",
                    "--config",
                    str(wrong_config),
                ],
                name="t1-deployment-wrong-sha",
                root=root,
                environment=environment,
            )
            _assert_failed_without_ready(wrong_pin, timeout=30)
            assert not any((root / "deployment-wrong-sha").iterdir())
            assert not any((root / "authority-wrong-sha").iterdir())
            assert not (root / "authority-wrong-sha-socket" / "authority.sock").exists()
            wrong_pin.close_logs()
            wrong_pin = None

            deployment_config = root / "cfg" / "deployment-v2.toml"
            deployment_text = _deployment_v2_document(
                state_root=root / "deployment",
                artifact=artifact,
                artifact_sha256=artifact_sha256,
                controller_seed=controller_seed,
                authority_seed=authority_seed,
                authority_state=root / "authority",
                authority_socket=root / "authority-socket" / "authority.sock",
                credentials=deployment_credentials,
                fabric_port=fabric_port,
            )
            g2._write_owned(deployment_config, deployment_text.encode(), 0o600, uid, gid)
            assert controller_seed_bytes not in deployment_text.encode()
            assert authority_seed_bytes not in deployment_text.encode()

            deployment = g2._spawn(
                [
                    *command_prefix,
                    str(binary),
                    "deployment",
                    "--config",
                    str(deployment_config),
                ],
                name="t1-deployment-fresh",
                root=root,
                environment=environment,
            )
            _assert_ready_and_no_error(deployment)
            _assert_joined_sigterm(deployment)
            deployment.close_logs()
            deployment = None

            assert node.process.poll() is None
            _assert_joined_sigterm(node, g2.NODE_READY)
            node.close_logs()
            node = None

            node_restart = g2._spawn(
                [*command_prefix, str(binary), "node", "--config", str(node_config)],
                name="t1-node-resume",
                root=root,
                environment=environment,
            )
            _assert_ready_and_no_error(node_restart, g2.NODE_READY)

            deployment_restart = g2._spawn(
                [
                    *command_prefix,
                    str(binary),
                    "deployment",
                    "--config",
                    str(deployment_config),
                ],
                name="t1-deployment-resume",
                root=root,
                environment=environment,
            )
            _assert_ready_and_no_error(deployment_restart)
            _assert_joined_sigterm(deployment_restart)
            deployment_restart.close_logs()
            deployment_restart = None

            assert node_restart.process.poll() is None
            _assert_joined_sigterm(node_restart, g2.NODE_READY)
            node_restart.close_logs()
            node_restart = None

            node_down_config = root / "cfg" / "deployment-v2-node-down.toml"
            node_down_socket = root / "authority-node-down-socket" / "authority.sock"
            g2._write_owned(
                node_down_config,
                _deployment_v2_document(
                    state_root=root / "deployment-node-down",
                    artifact=artifact,
                    artifact_sha256=artifact_sha256,
                    controller_seed=controller_seed,
                    authority_seed=authority_seed,
                    authority_state=root / "authority-node-down",
                    authority_socket=node_down_socket,
                    credentials=deployment_credentials,
                    fabric_port=fabric_port,
                ).encode(),
                0o600,
                uid,
                gid,
            )
            node_down = g2._spawn(
                [
                    *command_prefix,
                    str(binary),
                    "deployment",
                    "--config",
                    str(node_down_config),
                ],
                name="t1-deployment-node-down",
                root=root,
                environment=environment,
            )
            _assert_failed_without_ready(node_down, timeout=90)
            assert not node_down_socket.exists()
            node_down.close_logs()
            node_down = None

            _assert_logs_do_not_contain_secrets(
                root,
                (
                    controller_seed_bytes,
                    authority_seed_bytes,
                    runtime_key,
                    node_key,
                    runtime_client_key,
                    node_client_key,
                ),
            )
        finally:
            for process in (
                node_down,
                wrong_pin,
                deployment_restart,
                deployment,
                node_restart,
                node,
            ):
                if process is not None:
                    g2._stop_process(process)
