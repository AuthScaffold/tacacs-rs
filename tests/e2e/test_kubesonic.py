"""End-to-end KubeSONiC native profile tests over isolated Redis and mounted PKI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import threading

import pytest

from conftest import (
    CertificateBundle,
    ProcessManager,
    RedisInstance,
    find_yang_leaf,
    reserve_loopback_port,
    wait_until,
)


class KubeSonicHarness:
    """Orchestrates tacacsrs-agentd --kubesonic, Redis DB 4, and health probes."""

    def __init__(
        self,
        root: Path,
        socket_dir: Path,
        binaries: Path,
        manager: ProcessManager,
    ) -> None:
        self.root = root
        self.binaries = binaries
        self.manager = manager
        self.redis = RedisInstance(socket_dir, manager)
        self.pki = CertificateBundle(root)
        self.api_socket = socket_dir / "api.sock"
        self.statistics = root / "statistics.json"
        self.proxy_port: int | None = None
        self.agent: subprocess.Popen[bytes] | None = None
        self.base_env = {
            key: value for key, value in os.environ.items() if not key.startswith("TACACSD_")
        }
        self.base_env.update(
            {
                "TACACSD_CONFIGDB_SOCKET": str(self.redis.socket),
                "TACACSD_CONFIGDB_WATCH_RECONCILE_INTERVAL_SECONDS": "1",
                "TACACSD_TLS_CLIENT_CERTIFICATE": str(self.pki.client_pem),
                "TACACSD_TLS_CA_FILE": str(self.pki.ca_pem),
                "TACACSD_TLS_CA_DIRECTORY": str(self.pki.trust_dir),
                "TACACSD_SERVICES_CLIENT_API_ENDPOINT": str(self.api_socket),
                "TACACSD_SERVICES_TACACS_PROXY_ENDPOINT": "127.0.0.1:0",
                "TACACSD_PROCESS_STATISTICS_FILE": str(self.statistics),
                "TACACSD_POLICY_SHUTDOWN_TIMEOUT_SECONDS": "5",
                "TACACSD_LOOPBACK_RETRY_INTERVAL_SECONDS": "1",
                "TACACSD_LOG_STYLE": "never",
            }
        )

    def start_agent(self, name: str = "agent", **overrides: str) -> subprocess.Popen[bytes]:
        env = {**self.base_env, **overrides}
        if (
            env.get("TACACSD_LOOPBACK_REGISTRATION_ENABLED", "").lower()
            in ("1", "true", "yes", "on")
            and "TACACSD_SERVICES_TACACS_PROXY_ENDPOINT" not in overrides
        ):
            self.proxy_port = reserve_loopback_port()
            env["TACACSD_SERVICES_TACACS_PROXY_ENDPOINT"] = f"127.0.0.1:{self.proxy_port}"
        proc = self.manager.spawn(name, [str(self.binaries / "tacacsrs-agentd"), "--kubesonic"], env=env)
        self.agent = proc
        wait_until(
            lambda: self.api_socket.exists() or proc.poll() is not None,
            "KubeSONiC agent listener",
        )
        assert proc.poll() is None, "tacacsrs-agentd exited during startup"
        return proc

    def stop_agent(self) -> None:
        assert self.agent is not None
        assert self.manager.terminate(self.agent) == 0
        self.agent = None

    def check_health(self, kind: str) -> bool:
        assert self.agent is not None and self.agent.poll() is None, "Agent exited unexpectedly"
        return (
            subprocess.run(
                [
                    str(self.binaries / "tacacsrs-agent-health"),
                    "--endpoint",
                    str(self.api_socket),
                    "--check",
                    kind,
                    "--timeout-seconds",
                    "2",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0
        )

    def runtime_generation(self) -> int | None:
        if not self.statistics.is_file():
            return None
        gen = find_yang_leaf(json.loads(self.statistics.read_text(encoding="utf-8")), "runtime-generation")
        if gen is None:
            raise AssertionError("Statistics omitted runtime-generation")
        return int(str(gen))

    def published_servers(self) -> list[str] | None:
        if not self.statistics.is_file():
            return None
        entries = find_yang_leaf(json.loads(self.statistics.read_text(encoding="utf-8")), "server")
        if not isinstance(entries, list):
            return []
        return [entry["name"] for entry in entries]

    def server_diagnostic(self, server_name: str, leaf: str) -> object:
        if not self.statistics.is_file():
            return None
        entries = find_yang_leaf(json.loads(self.statistics.read_text(encoding="utf-8")), "server")
        if not isinstance(entries, list):
            return None
        for entry in entries:
            if entry.get("name") == server_name:
                diag = find_yang_leaf(entry, "diagnostics")
                if isinstance(diag, dict):
                    return diag.get(leaf)
        return None


def test_kubesonic_live_updates_certificate_rotation_and_retain_policy(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    harness = KubeSonicHarness(tmp_path, socket_dir, binaries, process_manager)
    harness.start_agent("agent-retain")

    wait_until(lambda: harness.check_health("liveness"), "liveness while Redis is unavailable")
    assert not harness.check_health("readiness")

    harness.redis.start()
    first_key = "TACPLUS_SERVER|192.0.2.10"
    second_key = "TACPLUS_SERVER|192.0.2.11"
    harness.redis.cli("HSET", first_key, "tcp_port", 449, "priority", 1)
    wait_until(lambda: harness.check_health("readiness"), "initial native publication")
    wait_until(lambda: harness.published_servers() == ["192.0.2.10"], "initial server statistics")

    socket_inode = harness.api_socket.stat().st_ino
    harness.redis.cli("HSET", second_key, "tcp_port", 449, "priority", 2)
    wait_until(
        lambda: harness.published_servers() == ["192.0.2.11", "192.0.2.10"],
        "live server addition in priority order",
    )
    assert harness.server_diagnostic("192.0.2.10", "port") == 449
    assert harness.server_diagnostic("192.0.2.10", "client-certificate-sha256") == harness.pki.fingerprint

    harness.redis.cli("HSET", first_key, "tcp_port", 450)
    wait_until(
        lambda: harness.server_diagnostic("192.0.2.10", "port") == 450,
        "live server port update",
    )
    assert harness.server_diagnostic("192.0.2.11", "port") == 449

    rotated_fp = harness.pki.issue_client_certificate(serial=3)
    assert rotated_fp != harness.pki.fingerprint
    wait_until(
        lambda: all(
            harness.server_diagnostic(name, "client-certificate-sha256") == rotated_fp
            for name in ("192.0.2.10", "192.0.2.11")
        ),
        "mounted client certificate rotation",
    )
    assert harness.api_socket.stat().st_ino == socket_inode

    before_del = harness.runtime_generation()
    harness.redis.cli("DEL", first_key, second_key)
    wait_until(
        lambda: harness.runtime_generation() not in (None, before_del),
        "retain-on-clear publication",
    )
    assert harness.published_servers() == ["192.0.2.11", "192.0.2.10"]
    assert harness.check_health("readiness")

    harness.redis.stop()
    harness.redis.start()
    before_reconnect = harness.runtime_generation()
    wait_until(
        lambda: harness.runtime_generation() not in (None, before_reconnect),
        "retention after Redis restart",
    )
    assert harness.check_health("readiness")

    harness.stop_agent()
    assert not harness.api_socket.exists()


def test_kubesonic_clear_policy_withdraws_and_restores_readiness(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    harness = KubeSonicHarness(tmp_path, socket_dir, binaries, process_manager)
    harness.redis.start()
    key = "TACPLUS_SERVER|192.0.2.10"
    harness.redis.cli("HSET", key, "tcp_port", 449)

    harness.start_agent("agent-clear", TACACSD_CONFIGDB_EMPTY_SERVER_POLICY="clear")
    wait_until(lambda: harness.check_health("readiness"), "clear-mode initial publication")

    harness.redis.cli("DEL", key)
    wait_until(lambda: not harness.check_health("readiness"), "clear-mode readiness withdrawal")
    assert harness.check_health("liveness")

    harness.redis.cli("HSET", key, "tcp_port", 449)
    wait_until(lambda: harness.check_health("readiness"), "clear-mode recovery")
    harness.stop_agent()


@pytest.mark.parametrize("server_name", [None, "wrong.example", "upstream.example"])
def test_kubesonic_tls_server_name_verifies_dns_identity_and_sends_sni(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
    server_name: str | None,
) -> None:
    harness = KubeSonicHarness(tmp_path, socket_dir, binaries, process_manager)
    server_key = tmp_path / "upstream.key"
    server_csr = tmp_path / "upstream.csr"
    server_cert = tmp_path / "upstream.pem"
    CertificateBundle._openssl(
        "req", "-new", "-newkey", "ec",
        "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
        "-subj", "/CN=upstream.example",
        "-addext", "subjectAltName=DNS:upstream.example",
        "-addext", "extendedKeyUsage=serverAuth",
        "-keyout", str(server_key), "-out", str(server_csr),
    )
    CertificateBundle._openssl(
        "x509", "-req", "-in", str(server_csr),
        "-CA", str(harness.pki.ca_pem), "-CAkey", str(harness.pki.ca_key),
        "-set_serial", "10", "-days", "1", "-copy_extensions", "copy",
        "-out", str(server_cert),
    )
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
    tls_context.load_cert_chain(str(server_cert), str(server_key))
    tls_context.load_verify_locations(cafile=str(harness.pki.ca_pem))
    tls_context.verify_mode = ssl.CERT_REQUIRED
    received_names: list[str | None] = []
    tls_context.set_servername_callback(
        lambda _socket, name, _context: received_names.append(name)
    )
    received_bodies: list[bytes] = []
    peer_errors: list[Exception] = []

    # Select a non-loopback local address without sending a packet.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(("192.0.2.1", 9))
        address = route.getsockname()[0]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as upstream:
        upstream.bind((address, 0))
        upstream.listen(4)
        upstream.settimeout(10.0)
        harness.redis.start()
        harness.redis.cli(
            "HSET", f"TACPLUS_SERVER|{address}", "tcp_port", upstream.getsockname()[1]
        )

        def serve_accounting() -> None:
            try:
                conn, _ = upstream.accept()
                with conn:
                    conn.settimeout(5.0)
                    with tls_context.wrap_socket(conn, server_side=True) as tls_conn:
                        with tls_conn.makefile("rb") as reader:
                            header = reader.read(12)
                            assert len(header) == 12
                            assert header[1:3] == bytes([3, 1])
                            assert header[3] & 0x01, "TLS request must be unobfuscated"
                            body_length = int.from_bytes(header[8:12], "big")
                            body = reader.read(body_length)
                            assert len(body) == body_length
                            received_bodies.append(body)
                            reply = b"\x00\x00\x00\x00\x01"
                            tls_conn.sendall(
                                bytes([header[0], 3, 2, header[3]])
                                + header[4:8]
                                + len(reply).to_bytes(4, "big")
                                + reply
                            )
            except Exception as error:
                peer_errors.append(error)

        peer = threading.Thread(target=serve_accounting, daemon=True)
        peer.start()
        try:
            overrides = {"TACACSD_POLICY_ACCOUNTING_REQUEST_TIMEOUT_SECONDS": "3"}
            if server_name is not None:
                overrides["TACACSD_TLS_SERVER_NAME"] = server_name
            harness.start_agent(**overrides)
            wait_until(lambda: harness.check_health("readiness"), "TLS upstream publication")
            result = subprocess.run(
                [
                    str(binaries / "tacon"), "--service-endpoint", str(harness.api_socket),
                    "accounting", "start", "--user", "alice", "--port", "tty0",
                    "--rem-addr", "192.0.2.10",
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=10.0,
            )
        finally:
            peer.join(timeout=10.0)
        assert not peer.is_alive(), "TLS peer did not finish"
        assert received_names == [server_name]
        if server_name == "upstream.example":
            assert result.returncode == 0, result.stderr
            assert not peer_errors, peer_errors
            assert len(received_bodies) == 1
            assert b"alice" in received_bodies[0]
        else:
            assert result.returncode != 0, result.stdout
            assert not received_bodies
            assert len(peer_errors) == 1, peer_errors
            assert isinstance(peer_errors[0], ssl.SSLError), peer_errors
        harness.stop_agent()


def test_kubesonic_loopback_registration_repairs_deletion_and_preserves_external_owner(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    harness = KubeSonicHarness(tmp_path, socket_dir, binaries, process_manager)
    harness.redis.start()
    harness.redis.cli("HSET", "TACPLUS_SERVER|192.0.2.10", "tcp_port", 449)
    loopback = "TACPLUS_SERVER|127.0.0.1"

    harness.start_agent("agent-loopback", TACACSD_LOOPBACK_REGISTRATION_ENABLED="true")
    assert harness.proxy_port is not None
    wait_until(
        lambda: harness.redis.cli("HGET", loopback, "tcp_port") == str(harness.proxy_port),
        "ready loopback registration at configured port",
    )

    harness.redis.cli("DEL", loopback)
    wait_until(
        lambda: harness.redis.cli("HGET", loopback, "tcp_port") == str(harness.proxy_port),
        "missing loopback row repair",
    )

    harness.redis.cli("HSET", loopback, "owner", "external")
    harness.stop_agent()
    assert harness.redis.cli("HGET", loopback, "owner") == "external"
