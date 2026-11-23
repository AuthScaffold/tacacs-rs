"""End-to-end KubeSONiC native profile tests over isolated Redis and mounted PKI."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

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

    def __init__(self, root: Path, binaries: Path, manager: ProcessManager) -> None:
        self.root = root
        self.binaries = binaries
        self.manager = manager
        self.redis = RedisInstance(root, manager)
        self.pki = CertificateBundle(root)
        self.api_socket = root / "api.sock"
        self.statistics = root / "statistics.json"
        self.proxy_port = reserve_loopback_port()
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
                "TACACSD_SERVICES_TACACS_PROXY_ENDPOINT": f"127.0.0.1:{self.proxy_port}",
                "TACACSD_PROCESS_STATISTICS_FILE": str(self.statistics),
                "TACACSD_POLICY_SHUTDOWN_TIMEOUT_SECONDS": "5",
                "TACACSD_LOOPBACK_RETRY_INTERVAL_SECONDS": "1",
                "TACACSD_LOG_STYLE": "never",
            }
        )

    def start_agent(self, name: str = "agent", **overrides: str) -> subprocess.Popen[bytes]:
        env = {**self.base_env, **overrides}
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
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    harness = KubeSonicHarness(tmp_path, binaries, process_manager)
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
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    harness = KubeSonicHarness(tmp_path, binaries, process_manager)
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


def test_kubesonic_loopback_registration_repairs_deletion_and_preserves_external_owner(
    tmp_path: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    harness = KubeSonicHarness(tmp_path, binaries, process_manager)
    harness.redis.start()
    harness.redis.cli("HSET", "TACPLUS_SERVER|192.0.2.10", "tcp_port", 449)
    loopback = "TACPLUS_SERVER|127.0.0.1"

    harness.start_agent("agent-loopback", TACACSD_LOOPBACK_REGISTRATION_ENABLED="true")
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
