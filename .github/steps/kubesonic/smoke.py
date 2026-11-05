"""Exercise the native profile with isolated Redis, files, and subprocesses."""

import argparse
import contextlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time


def wait(predicate, label, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError(f"Deadline expired: {label}")


def generation(path):
    if not path.exists():
        return None
    def find(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key.split(":")[-1] == "runtime-generation":
                    return int(child)
                result = find(child)
                if result is not None:
                    return result
        if isinstance(value, list):
            for child in value:
                result = find(child)
                if result is not None:
                    return result
        return None
    result = find(json.loads(path.read_text()))
    if result is None:
        raise AssertionError("Statistics omitted runtime-generation")
    return result


class Fixture:
    def __init__(self, directory, binaries, stack):
        self.root = directory
        self.binaries = binaries
        self.stack = stack
        self.socket = directory / "redis.sock"
        self.api = directory / "api.sock"
        self.statistics = directory / "statistics.json"
        self.agent = None
        self.redis = None
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith("AAAAGENT_")
            and key not in {"SSL_CERT_FILE", "SSL_CERT_DIR", "RUST_LOG", "RUST_LOG_STYLE"}
        }
        self.environment.update({
            "AAAAGENT_CONFIGDB_SOCKET": str(self.socket),
            "AAAAGENT_CONFIGDB_WATCH_RECONCILE_INTERVAL_SECONDS": "1",
            "AAAAGENT_TLS_CLIENT_CERTIFICATE": str(directory / "client.pem"),
            "AAAAGENT_TLS_CA_FILE": str(directory / "ca.pem"),
            "AAAAGENT_TLS_CA_DIRECTORY": str(directory / "trust"),
            "AAAAGENT_SERVICES_CLIENT_API_ENDPOINT": str(self.api),
            "AAAAGENT_SERVICES_TACACS_PROXY_ENDPOINT": f"127.0.0.1:{self.port}",
            "AAAAGENT_PROCESS_STATISTICS_FILE": str(self.statistics),
            "AAAAGENT_POLICY_SHUTDOWN_TIMEOUT_SECONDS": "5",
            "AAAAGENT_LOOPBACK_RETRY_INTERVAL_SECONDS": "1",
            "AAAAGENT_LOG_STYLE": "never",
        })
        (directory / "trust").mkdir()
        def openssl(*arguments):
            subprocess.run(["openssl", *arguments], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=smoke-ca", "-keyout", str(directory / "ca.key"),
                "-out", str(directory / "ca.pem"))
        openssl("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=smoke-client",
                "-keyout", str(directory / "client.key"), "-out", str(directory / "client.csr"))
        openssl("x509", "-req", "-in", str(directory / "client.csr"), "-CA", str(directory / "ca.pem"),
                "-CAkey", str(directory / "ca.key"), "-set_serial", "2", "-days", "1",
                "-out", str(directory / "client.crt"))
        (directory / "client.pem").write_bytes(
            (directory / "client.crt").read_bytes() + (directory / "client.key").read_bytes())

    def spawn(self, name, arguments, **options):
        log = self.stack.enter_context((self.root / f"{name}.log").open("ab"))
        process = subprocess.Popen(arguments, stdout=log, stderr=log, **options)
        self.stack.callback(self.stop, process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("Owned process exceeded shutdown deadline")

    def redis_command(self, *arguments):
        result = subprocess.run(
            ["redis-cli", "--raw", "-s", str(self.socket), "-n", "4", *map(str, arguments)],
            text=True, capture_output=True, check=True,
        )
        return result.stdout.strip()

    def start_redis(self):
        self.redis = self.spawn("redis", [
            "redis-server", "--port", "0", "--save", "", "--appendonly", "no",
            "--unixsocket", str(self.socket), "--notify-keyspace-events", "AKE",
        ])
        wait(lambda: self.socket.exists() and self.redis.poll() is None, "Redis socket")
        wait(lambda: self.redis_command("PING") == "PONG", "Redis readiness")

    def start_agent(self, **overrides):
        environment = {**self.environment, **overrides}
        self.agent = self.spawn("agent", [str(self.binaries / "tacacsrs-agentd"), "--kubesonic"],
                                env=environment)
        wait(lambda: self.api.exists() or self.agent.poll() is not None, "Agent listener")
        assert self.agent.poll() is None, "Agent exited during startup"

    def health(self, check):
        assert self.agent.poll() is None, "Agent exited unexpectedly"
        return subprocess.run([
            str(self.binaries / "tacacsrs-agent-health"), "--endpoint", str(self.api),
            "--check", check, "--timeout-seconds", "1",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

    def changed(self, previous):
        return generation(self.statistics) not in (None, previous)

    def run(self):
        self.start_agent()
        wait(lambda: self.health("liveness"), "Liveness during unavailable Redis")
        assert not self.health("readiness")
        self.start_redis()
        key = "TACPLUS_SERVER|192.0.2.10"
        self.redis_command("HSET", key, "tcp_port", 449, "priority", 1)
        wait(lambda: self.health("readiness"), "Initial native publication")
        wait(lambda: generation(self.statistics) is not None, "Initial statistics")
        inode = self.api.stat().st_ino
        initial = generation(self.statistics)
        self.redis_command("HSET", key, "tcp_port", 450)
        wait(lambda: self.changed(initial), "Live server update")
        assert self.api.stat().st_ino == inode
        initial = generation(self.statistics)
        self.redis_command("DEL", key)
        wait(lambda: self.changed(initial), "Retain-on-clear publication")
        assert self.health("readiness")
        self.stop(self.redis)
        self.start_redis()
        initial = generation(self.statistics)
        wait(lambda: self.changed(initial), "Retention after Redis reconnect")
        assert self.health("readiness")
        self.stop(self.agent)
        assert self.agent.returncode == 0
        assert not self.api.exists()

        self.redis_command("HSET", key, "tcp_port", 449)
        self.start_agent(AAAAGENT_CONFIGDB_EMPTY_SERVER_POLICY="clear")
        wait(lambda: self.health("readiness"), "Clear-mode initial publication")
        self.redis_command("DEL", key)
        wait(lambda: not self.health("readiness"), "Clear-mode readiness withdrawal")
        assert self.health("liveness")
        self.redis_command("HSET", key, "tcp_port", 449)
        wait(lambda: self.health("readiness"), "Clear-mode recovery")
        self.stop(self.agent)
        assert self.agent.returncode == 0

        loopback = "TACPLUS_SERVER|127.0.0.1"
        self.start_agent(AAAAGENT_LOOPBACK_REGISTRATION_ENABLED="true")
        wait(lambda: self.redis_command("HGET", loopback, "tcp_port") == str(self.port),
             "Ready registration at configured port")
        self.redis_command("DEL", loopback)
        wait(lambda: self.redis_command("HGET", loopback, "tcp_port") == str(self.port),
             "Missing-row repair")
        self.redis_command("HSET", loopback, "owner", "external")
        self.stop(self.agent)
        assert self.agent.returncode == 0
        assert self.redis_command("HGET", loopback, "owner") == "external"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin-dir", type=Path, required=True)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="kubesonic-") as directory, contextlib.ExitStack() as stack:
        fixture = Fixture(Path(directory), arguments.bin_dir.resolve(), stack)
        try:
            fixture.run()
        except BaseException:
            for log in Path(directory).glob("*.log"):
                print(f"--- {log.name} ---\n{log.read_text()}")
            raise
    print("PASS: native KubeSONiC startup, live updates, both clear policies, reconnect, registration, and shutdown")


if __name__ == "__main__":
    main()
