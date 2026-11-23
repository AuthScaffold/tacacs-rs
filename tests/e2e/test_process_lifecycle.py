"""Black-box daemon signal, socket ownership, systemd helper, and statistics E2E tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess

import pytest

from conftest import ProcessManager, wait_for_signal_handlers, wait_until


def test_statistics_export_is_read_only_private_and_generation_bound(
    tmp_path: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    endpoint = tmp_path / "agent.sock"
    report = tmp_path / "statistics.json"
    agent = process_manager.spawn(
        "agent",
        [
            str(binaries / "tacacsrs-agentd"),
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "private-test-key",
            "--host-integration",
            "none",
            "--listen-endpoint",
            str(endpoint),
            "--statistics-file",
            str(report),
        ],
    )
    wait_for_signal_handlers(agent)
    wait_until(lambda: report.is_file() and report.stat().st_size > 0, "statistics file creation")

    raw = report.read_text(encoding="utf-8")
    payload = json.loads(raw)
    root = payload["ietf-system-tacacs-plus:tacacs-plus"]
    assert isinstance(root["tacacsrs:runtime-generation"], str)
    assert isinstance(root["server"][0]["tacacsrs:counter-epoch"], str)
    assert root["server"][0]["statistics"]["connection-opens"] == "0"
    assert isinstance(root["server"][0]["statistics"]["discontinuity-time"], str)
    assert "private-test-key" not in raw
    assert "shared-secret" not in raw
    assert stat.S_IMODE(report.stat().st_mode) == 0o600

    assert process_manager.terminate(agent, signal.SIGTERM) == 0
    assert not endpoint.exists()
    assert report.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_diagnostics_and_health_details_share_client_api_socket(
    tmp_path: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    endpoint = tmp_path / "agent.sock"
    agent = process_manager.spawn(
        "agent",
        [
            str(binaries / "tacacsrs-agentd"),
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "private-test-key",
            "--host-integration",
            "none",
            "--listen-endpoint",
            str(endpoint),
        ],
    )
    wait_until(lambda: endpoint.exists() and agent.poll() is None, "agent Unix listener")

    health_bin = str(binaries / "tacacsrs-agent-health")

    def _read_stats(*extra: str) -> str:
        res = subprocess.run(
            [health_bin, "statistics", "--endpoint", str(endpoint), "--format", "json", *extra],
            text=True,
            capture_output=True,
            check=True,
        )
        return res.stdout

    first_raw = wait_until(lambda: _read_stats(), "diagnostics statistics RPC")
    first = json.loads(first_raw)["ietf-system-tacacs-plus:tacacs-plus"]
    server_name = first["server"][0]["name"]

    for extra_args in ((), ("--server", server_name)):
        raw = _read_stats(*extra_args)
        assert "private-test-key" not in raw and "shared-secret" not in raw
        snapshot = json.loads(raw)["ietf-system-tacacs-plus:tacacs-plus"]
        assert len(snapshot["server"]) == 1
        assert snapshot["tacacsrs:runtime-generation"] == first["tacacsrs:runtime-generation"]
        assert (
            snapshot["server"][0]["tacacsrs:counter-epoch"]
            == first["server"][0]["tacacsrs:counter-epoch"]
        )
        assert snapshot["server"][0]["statistics"]["connection-opens"] == "0"
        assert snapshot["server"][0]["statistics"]["messages-sent"] == "0"

    details_res = subprocess.run(
        [health_bin, "details", "--endpoint", str(endpoint), "--format", "json"],
        text=True,
        capture_output=True,
        check=True,
    )
    details = json.loads(details_res.stdout)
    assert details["lifecycle"] == "serving"
    assert details["applied-configuration"] is True
    assert details["eligible-server-count"] == 1
    assert any(
        entry["service"] == "client-api" and entry["state"] == "bound"
        for entry in details["listeners"]
    )

    assert process_manager.terminate(agent, signal.SIGTERM) == 0
    assert not endpoint.exists()


def test_statistics_export_failure_stops_supervised_daemon(
    tmp_path: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    endpoint = tmp_path / "agent.sock"
    report = tmp_path / "statistics.json"
    agent = process_manager.spawn(
        "agent",
        [
            str(binaries / "tacacsrs-agentd"),
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "secret",
            "--host-integration",
            "none",
            "--listen-endpoint",
            str(endpoint),
            "--statistics-file",
            str(report),
        ],
    )
    wait_until(lambda: report.exists() and agent.poll() is None, "initial statistics export")

    report.unlink()
    report.mkdir()
    wait_until(lambda: agent.poll() is not None, "daemon exit on statistics export failure")
    assert agent.returncode != 0
    log_text = (tmp_path / "agent.log").read_text(encoding="utf-8", errors="replace")
    assert "operational statistics" in log_text
    assert not endpoint.exists()


def test_statistics_export_cannot_replace_inputs_or_listener(
    tmp_path: Path,
    binaries: Path,
) -> None:
    agent_bin = str(binaries / "tacacsrs-agentd")
    config = tmp_path / "config.json"
    original = b"operator configuration remains unchanged"
    config.write_bytes(original)

    overwrite = subprocess.run(
        [agent_bin, "--config", str(config), "--statistics-file", str(config)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert overwrite.returncode != 0
    assert "cannot overwrite" in overwrite.stderr
    assert config.read_bytes() == original

    sock = tmp_path / "agent.sock"
    replace_listener = subprocess.run(
        [
            agent_bin,
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "secret",
            "--host-integration",
            "none",
            "--listen-endpoint",
            str(sock),
            "--statistics-file",
            str(sock),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert replace_listener.returncode != 0
    assert "cannot replace a listener" in replace_listener.stderr
    assert not sock.exists()


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_host_signals_cancel_blocked_bootstrap_without_binding(
    tmp_path: Path,
    binaries: Path,
    process_manager: ProcessManager,
    sig: signal.Signals,
) -> None:
    endpoint = tmp_path / "agent.sock"
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fake_redis:
        fake_redis.bind(("127.0.0.1", 0))
        fake_redis.listen(4)
        fake_redis.settimeout(15.0)
        redis_port = fake_redis.getsockname()[1]

        agent = process_manager.spawn(
            f"agent-{sig.name}",
            [
                str(binaries / "tacacsrs-agentd"),
                "--sonic",
                "--sonic-redis-url",
                f"redis://127.0.0.1:{redis_port}",
                "--service-mode",
                "both",
                "--host-integration",
                "none",
                "--listen-endpoint",
                str(endpoint),
            ],
        )
        conn, _ = fake_redis.accept()
        with conn:
            conn.settimeout(15.0)
            assert len(conn.recv(1)) == 1
            assert process_manager.terminate(agent, sig) == 0
            assert not endpoint.exists()


def test_host_signal_drains_serving_agent_and_closes_idle_ipc_connection(
    tmp_path: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    endpoint = tmp_path / "agent.sock"
    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps(
            {
                "tacacsrs:runtime-policy": {
                    "authentication": {"request-timeout-seconds": 1},
                    "authorization": {"request-timeout-seconds": 1},
                    "accounting": {"request-timeout-seconds": 1},
                }
            }
        ),
        encoding="utf-8",
    )
    agent = process_manager.spawn(
        "agent",
        [
            str(binaries / "tacacsrs-agentd"),
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "test-secret",
            "--host-integration",
            "none",
            "--listen-endpoint",
            str(endpoint),
            "--runtime-policy",
            str(policy),
        ],
    )
    wait_for_signal_handlers(agent)
    wait_until(lambda: endpoint.exists() and agent.poll() is None, "agent IPC socket bound")

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10.0)
        client.connect(str(endpoint))
        assert process_manager.terminate(agent, signal.SIGTERM) == 0
        while True:
            try:
                chunk = client.recv(1024)
            except OSError:
                break
            if not chunk:
                break
    assert not endpoint.exists()


def test_shutdown_budget_terminates_stalled_systemd_helper(
    tmp_path: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    endpoint = tmp_path / "agent.sock"
    policy = tmp_path / "policy.json"
    helper = tmp_path / "systemd-notify"
    helper_pid_file = tmp_path / "helper.pid"
    policy.write_text(
        json.dumps({"tacacsrs:runtime-policy": {"shutdown-timeout-seconds": 1}}),
        encoding="utf-8",
    )
    helper.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$TACACSRS_HELPER_PID\"\nexec /bin/sleep 60\n",
        encoding="utf-8",
    )
    helper.chmod(0o700)

    env = {
        **os.environ,
        "PATH": f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}",
        "NOTIFY_SOCKET": str(tmp_path / "notify.sock"),
        "TACACSRS_HELPER_PID": str(helper_pid_file),
    }
    agent = process_manager.spawn(
        "agent",
        [
            str(binaries / "tacacsrs-agentd"),
            "--server-addr",
            "192.0.2.10:49",
            "--shared-secret",
            "test-secret",
            "--host-integration",
            "systemd",
            "--listen-endpoint",
            str(endpoint),
            "--runtime-policy",
            str(policy),
        ],
        env=env,
    )
    wait_for_signal_handlers(agent)
    helper_pid = int(
        wait_until(
            lambda: helper_pid_file.read_text(encoding="utf-8").strip()
            if helper_pid_file.is_file() and helper_pid_file.read_text(encoding="utf-8").strip().isdigit()
            else "",
            "stalled systemd-notify helper PID",
        )
    )

    rc = process_manager.terminate(agent, signal.SIGTERM)
    assert rc != 0
    log_text = (tmp_path / "agent.log").read_text(encoding="utf-8", errors="replace")
    assert "Shutdown deadline elapsed" in log_text

    def _helper_reaped() -> bool:
        proc_status = Path(f"/proc/{helper_pid}/status")
        if not proc_status.exists():
            return True
        for line in proc_status.read_text(encoding="utf-8").splitlines():
            if line.startswith("State:") and "Z" in line:
                return True
        return False

    wait_until(_helper_reaped, "stalled systemd helper termination", timeout=5.0, interval=0.02)
    assert not endpoint.exists()
