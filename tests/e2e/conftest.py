"""Shared black-box process, Redis, and PKI fixtures for Linux E2E tests."""

from __future__ import annotations

import contextlib
import hashlib
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from typing import Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
REQUIRED_BINARIES = ("tacacsrs-agentd", "tacacsrs-agent-health", "tacon")
DEFAULT_WAIT_TIMEOUT = 30.0


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--bin-dir",
        action="store",
        default=os.environ.get("TACACSRS_BIN_DIR"),
        help="Directory containing prebuilt tacacsrs-agentd, tacacsrs-agent-health, and tacon binaries.",
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        tmp_path: Path | None = item.funcargs.get("tmp_path")
        if tmp_path and tmp_path.is_dir():
            sections: list[str] = []
            for log_file in sorted(tmp_path.glob("*.log")):
                sections.append(f"--- {log_file.name} ---\n{log_file.read_text(errors='replace')}")
            stats_file = tmp_path / "statistics.json"
            if stats_file.is_file():
                sections.append(f"--- statistics.json ---\n{stats_file.read_text(errors='replace')}")
            if sections:
                report.sections.append(("E2E process artifacts", "\n".join(sections)))


def wait_until(
    predicate: Callable[[], object],
    label: str,
    *,
    timeout: float = DEFAULT_WAIT_TIMEOUT,
    interval: float = 0.05,
):
    """Polls ``predicate`` until truthy or raises AssertionError after ``timeout``."""
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
            last_error = None
        except Exception as exc:  # noqa: BLE001 - surface final predicate error on timeout
            last_error = exc
        time.sleep(interval)
    detail = f" (last error: {last_error})" if last_error is not None else ""
    raise AssertionError(f"Deadline expired waiting for {label}{detail}")


def find_yang_leaf(value: object, leaf_name: str) -> object:
    """Recursively locates ``leaf_name`` ignoring RFC 7951 module prefixes."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key.split(":")[-1] == leaf_name:
                return child
            nested = find_yang_leaf(child, leaf_name)
            if nested is not None:
                return nested
    elif isinstance(value, list):
        for item in value:
            nested = find_yang_leaf(item, leaf_name)
            if nested is not None:
                return nested
    return None


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_signal_handlers(process: subprocess.Popen[bytes]) -> None:
    """Waits until a Linux guest process installs SIGINT (2) and SIGTERM (15) handlers."""
    mask = (1 << 1) | (1 << 14)

    def _registered() -> bool:
        if process.poll() is not None:
            raise RuntimeError(f"Process {process.pid} exited early with {process.returncode}")
        status_text = Path(f"/proc/{process.pid}/status").read_text(encoding="utf-8")
        for line in status_text.splitlines():
            if line.startswith("SigCgt:"):
                caught = int(line.removeprefix("SigCgt:").strip(), 16)
                return (caught & mask) == mask
        return False

    wait_until(_registered, f"signal handlers on PID {process.pid}", interval=0.02)


@pytest.fixture(scope="session")
def binaries(request: pytest.FixtureRequest) -> Path:
    if sys.platform != "linux":
        pytest.skip("Linux daemon and Redis E2E tests run on Linux only")

    configured = request.config.getoption("--bin-dir")
    if configured:
        bin_dir = Path(configured).resolve()
        missing = [name for name in REQUIRED_BINARIES if not (bin_dir / name).is_file()]
        if missing:
            raise pytest.UsageError(f"--bin-dir {bin_dir} is missing binaries: {', '.join(missing)}")
        return bin_dir

    target_root = Path(os.environ.get("CARGO_TARGET_DIR", REPO_ROOT / "target")).resolve()
    debug_dir = target_root / "debug"
    if any(not (debug_dir / name).is_file() for name in REQUIRED_BINARIES):
        subprocess.run(
            [
                "cargo",
                "build",
                "--locked",
                "--bins",
                "-p",
                "tacacsrs-agentd",
                "-p",
                "tacacsrs-agent-health",
                "-p",
                "tacon",
            ],
            cwd=REPO_ROOT,
            check=True,
        )
    return debug_dir


class ProcessManager:
    """Spawns and cleans up child processes inside one test's ExitStack."""

    def __init__(self, root: Path, stack: contextlib.ExitStack) -> None:
        self.root = root
        self._stack = stack

    def spawn(
        self,
        name: str,
        args: list[str],
        *,
        env: dict[str, str] | None = None,
    ) -> subprocess.Popen[bytes]:
        log_handle = self._stack.enter_context((self.root / f"{name}.log").open("ab"))
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            env=env,
        )
        self._stack.callback(self.terminate, proc)
        return proc

    @staticmethod
    def terminate(
        proc: subprocess.Popen[bytes],
        sig: signal.Signals = signal.SIGTERM,
        timeout: float = 10.0,
    ) -> int:
        if proc.poll() is None:
            proc.send_signal(sig)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                proc.kill()
                proc.wait()
                raise AssertionError(f"Process {proc.pid} exceeded {timeout}s shutdown deadline") from exc
        assert proc.returncode is not None
        return proc.returncode


@pytest.fixture()
def process_manager(tmp_path: Path):
    with contextlib.ExitStack() as stack:
        yield ProcessManager(tmp_path, stack)


class RedisInstance:
    """Isolated Unix-socket Redis server with ConfigDB keyspace notifications enabled."""

    def __init__(self, root: Path, manager: ProcessManager) -> None:
        self.socket = root / "redis.sock"
        self._manager = manager
        self.process: subprocess.Popen[bytes] | None = None

    def start(self) -> None:
        self.process = self._manager.spawn(
            "redis",
            [
                "redis-server",
                "--port",
                "0",
                "--save",
                "",
                "--appendonly",
                "no",
                "--unixsocket",
                str(self.socket),
                "--notify-keyspace-events",
                "AKE",
            ],
        )
        wait_until(
            lambda: self.socket.exists() and self.process is not None and self.process.poll() is None,
            "Redis Unix socket creation",
        )
        wait_until(lambda: self.cli("PING") == "PONG", "Redis PING readiness")

    def stop(self) -> None:
        if self.process is not None:
            self._manager.terminate(self.process)
            self.process = None

    def cli(self, *arguments: object) -> str:
        result = subprocess.run(
            ["redis-cli", "--raw", "-s", str(self.socket), "-n", "4", *map(str, arguments)],
            text=True,
            capture_output=True,
            check=True,
        )
        return result.stdout.strip()


class CertificateBundle:
    """OpenSSL CA and rotatable client PEM bundle for mounted-credential tests."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.ca_pem = root / "ca.pem"
        self.ca_key = root / "ca.key"
        self.client_pem = root / "client.pem"
        self.trust_dir = root / "trust"
        self.trust_dir.mkdir(exist_ok=True)
        self._openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=e2e-ca",
            "-keyout",
            str(self.ca_key),
            "-out",
            str(self.ca_pem),
        )
        self.fingerprint = self.issue_client_certificate(serial=2)

    @staticmethod
    def _openssl(*arguments: str) -> bytes:
        return subprocess.run(
            ["openssl", *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout

    def issue_client_certificate(self, *, serial: int) -> str:
        key_path = self.root / "client.key"
        csr_path = self.root / "client.csr"
        crt_path = self.root / "client.crt"
        self._openssl(
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-subj",
            "/CN=e2e-client",
            "-keyout",
            str(key_path),
            "-out",
            str(csr_path),
        )
        self._openssl(
            "x509",
            "-req",
            "-in",
            str(csr_path),
            "-CA",
            str(self.ca_pem),
            "-CAkey",
            str(self.ca_key),
            "-set_serial",
            str(serial),
            "-days",
            "1",
            "-out",
            str(crt_path),
        )
        staged = self.root / "client.pem.tmp"
        staged.write_bytes(crt_path.read_bytes() + key_path.read_bytes())
        os.replace(staged, self.client_pem)
        der = self._openssl("x509", "-in", str(crt_path), "-outform", "DER")
        return hashlib.sha256(der).hexdigest()
