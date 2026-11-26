"""Scenarios: Single-connect proxy session caps, packet rate pacing, body limits, and live reload.

Motivation
----------
Even when downstream clients legitimately negotiate ``TAC_PLUS_SINGLE_CONNECT_FLAG``,
a buggy or malicious single-connect peer can open hundreds of concurrent
sessions on one socket, transmit oversized packet bodies, or send sustained
high-rate packet bursts that would overload the upstream TACACS+ server once
in-flight request slots clear. Operators also need adjustments to
``tacacsrs:runtime-policy`` to take effect on open connections without
restarting ``tacacsrs-agentd``.

Topology
--------
Each test starts an isolated ``tacacsrs-agentd`` process in ``both`` mode
(Client API Unix socket plus loopback TCP proxy with MD5 shared-secret
obfuscation), watches a test-local ``--runtime-policy`` JSON file, and connects
to an isolated TLS 1.3 single-connect ``ScriptedTlsUpstream`` server.

Scenarios in this module
------------------------
1. ``test_single_connect_per_connection_session_cap``: With
   ``max-proxy-sessions-per-connection = 2``, a single-connect client holds two
   concurrent sessions open and sends a third on the same TCP connection. The
   proxy returns a local ``TAC_PLUS_ACCT_STATUS_ERROR`` reply for the third
   session with ``TAC_PLUS_SINGLE_CONNECT_FLAG`` preserved while keeping the
   stream and the first two sessions alive until upstream replies release.
2. ``test_token_bucket_packet_rate_pacing_and_operation_isolation``: With
   ``accounting.max-packets-per-second = 2``, four back-to-back accounting
   requests clear the two-packet burst and pace the third and fourth packets at
   500 ms intervals (elapsed time at least ``0.9 s``), while authorization
   traffic uses its own independent token bucket without delay.
3. ``test_packet_body_length_limit_isolates_offending_connection``: With
   ``max-packet-body-length = 4096``, sending an 8 KiB frame closes only that
   offending client socket while a separate open single-connect client continues
   serving requests normally.
4. ``test_live_runtime_policy_reload_updates_open_single_connect_stream``:
   Atomically updating the watched ``--runtime-policy`` file advances
   ``revisions.applied-policy`` in ``tacacsrs-agent-health details`` and raises
   ``max-proxy-sessions-per-connection`` and ``max-packet-body-length`` on an
   already-open single-connect proxy connection without reconnecting.
"""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

from conftest import ProcessManager, reserve_loopback_port, wait_until
from tacacs_wire import (
    ACCT_STATUS_ERROR,
    ACCT_STATUS_SUCCESS,
    AUTHOR_STATUS_PASS_ADD,
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_SINGLE_CONNECT_FLAG,
    RawPacket,
    ScriptedTlsUpstream,
    decode_acct_status,
    decode_author_status,
    encode_acct_reply,
    encode_author_reply,
    read_packet,
    send_packet,
)

PROXY_SECRET = b"single-connect-proxy-secret"
HOLD_MARKER = b"HOLD:"


class ProxyPolicyHarness:
    """Isolated tacacsrs-agentd + TLS 1.3 upstream fixture for one runtime-policy scenario."""

    def __init__(
        self,
        root: Path,
        socket_dir: Path,
        binaries: Path,
        process_manager: ProcessManager,
    ) -> None:
        self.root = root
        self.api_socket = socket_dir / "agent.sock"
        self.proxy_port = reserve_loopback_port()
        self.policy_path = root / "runtime-policy.json"
        self.health_bin = str(binaries / "tacacsrs-agent-health")
        self._binaries = binaries
        self._process_manager = process_manager
        self.release_held = threading.Event()
        self._held_lock = threading.Lock()
        self._held_arrived = 0
        self.upstream = ScriptedTlsUpstream(root, responder=self._responder)

    def _responder(self, request: RawPacket) -> bytes:
        if request.tacacs_type == TAC_PLUS_ACCT and request.body.startswith(HOLD_MARKER):
            with self._held_lock:
                self._held_arrived += 1
            assert self.release_held.wait(
                timeout=15.0
            ), "Timed out waiting to release held upstream reply"
            return encode_acct_reply(ACCT_STATUS_SUCCESS, b"released")
        if request.tacacs_type == TAC_PLUS_ACCT:
            return encode_acct_reply(ACCT_STATUS_SUCCESS, b"recorded")
        if request.tacacs_type == TAC_PLUS_AUTHOR:
            return encode_author_reply(AUTHOR_STATUS_PASS_ADD, b"authorized")
        raise AssertionError(f"Unexpected packet type: {request.tacacs_type}")

    def held_arrived(self) -> int:
        with self._held_lock:
            return self._held_arrived

    def write_policy(self, body: dict[str, object]) -> None:
        staged = self.policy_path.with_suffix(".json.tmp")
        staged.write_text(json.dumps({"tacacsrs:runtime-policy": body}), encoding="utf-8")
        os.replace(staged, self.policy_path)

    def applied_policy_revision(self) -> int:
        res = subprocess.run(
            [self.health_bin, "details", "--endpoint", str(self.api_socket), "--format", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
        payload = json.loads(res.stdout)
        revisions = payload.get("revisions") or {}
        return int(revisions.get("applied-policy") or 0)

    def open_single_connect_client(self, warmup_session_id: int = 0x4000) -> socket.socket:
        """Connects to the TCP proxy and settles single-connect negotiation on both legs."""
        sock = socket.create_connection(("127.0.0.1", self.proxy_port), timeout=15.0)
        send_packet(
            sock,
            tacacs_type=TAC_PLUS_AUTHOR,
            seq_no=1,
            session_id=warmup_session_id,
            body=b"negotiate-single-connect",
            secret=PROXY_SECRET,
            single_connect=True,
        )
        warmup_reply = read_packet(sock, secret=PROXY_SECRET)
        assert warmup_reply.session_id == warmup_session_id
        assert (warmup_reply.flags & TAC_PLUS_SINGLE_CONNECT_FLAG) != 0
        assert decode_author_status(warmup_reply)[0] == AUTHOR_STATUS_PASS_ADD
        return sock


@contextlib.contextmanager
def running_policy_scenario(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
    initial_policy: dict[str, object],
) -> Iterator[ProxyPolicyHarness]:
    harness = ProxyPolicyHarness(tmp_path, socket_dir, binaries, process_manager)
    harness.write_policy(initial_policy)
    harness.upstream.start()
    try:
        agent = process_manager.spawn(
            "agent",
            [
                str(binaries / "tacacsrs-agentd"),
                "--server-addr",
                f"127.0.0.1:{harness.upstream.port}",
                "--use-tls",
                "--insecure-disable-certificate-verification",
                "--service-mode",
                "both",
                "--listen-endpoint",
                str(harness.api_socket),
                "--proxy-endpoint",
                f"127.0.0.1:{harness.proxy_port}",
                "--proxy-shared-secret",
                PROXY_SECRET.decode("ascii"),
                "--runtime-policy",
                str(harness.policy_path),
                "--host-integration",
                "none",
            ],
        )
        wait_until(
            lambda: harness.api_socket.exists()
            and agent.poll() is None
            and subprocess.run(
                [harness.health_bin, "--endpoint", str(harness.api_socket), "--check", "readiness"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0,
            "agent readiness with initial runtime policy",
        )
        yield harness
    finally:
        harness.release_held.set()
        harness.upstream.stop()


def test_single_connect_per_connection_session_cap(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    """Rejects a 3rd concurrent session on one single-connect stream while preserving active sessions."""
    with running_policy_scenario(
        tmp_path,
        socket_dir,
        binaries,
        process_manager,
        {"max-proxy-sessions-per-connection": 2},
    ) as harness, harness.open_single_connect_client() as mux_sock:
        for sid in (0x4001, 0x4002):
            send_packet(
                mux_sock,
                tacacs_type=TAC_PLUS_ACCT,
                seq_no=1,
                session_id=sid,
                body=HOLD_MARKER + f"{sid:#x}".encode("ascii"),
                secret=PROXY_SECRET,
                single_connect=True,
            )
        wait_until(lambda: harness.held_arrived() == 2, "two held sessions reaching upstream")

        send_packet(
            mux_sock,
            tacacs_type=TAC_PLUS_ACCT,
            seq_no=1,
            session_id=0x4003,
            body=b"excess-third-session",
            secret=PROXY_SECRET,
            single_connect=True,
        )
        excess_reply = read_packet(mux_sock, secret=PROXY_SECRET)
        assert excess_reply.session_id == 0x4003
        assert (excess_reply.flags & TAC_PLUS_SINGLE_CONNECT_FLAG) != 0
        status, message = decode_acct_status(excess_reply)
        assert status == ACCT_STATUS_ERROR
        assert "concurrent session limit" in message

        harness.release_held.set()
        completed = {
            read_packet(mux_sock, secret=PROXY_SECRET).session_id,
            read_packet(mux_sock, secret=PROXY_SECRET).session_id,
        }
        assert completed == {0x4001, 0x4002}


def test_token_bucket_packet_rate_pacing_and_operation_isolation(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    """Paces sustained accounting packets after the 1s burst without throttling authorization."""
    with running_policy_scenario(
        tmp_path,
        socket_dir,
        binaries,
        process_manager,
        {
            "max-upstream-packets-per-second": 512,
            "authorization": {"max-packets-per-second": 256},
            "accounting": {"max-packets-per-second": 2},
        },
    ) as harness, harness.open_single_connect_client() as mux_sock:
        pace_start = time.monotonic()
        for offset in range(4):
            sid = 0x5000 + offset
            send_packet(
                mux_sock,
                tacacs_type=TAC_PLUS_ACCT,
                seq_no=1,
                session_id=sid,
                body=b"paced-accounting",
                secret=PROXY_SECRET,
                single_connect=True,
            )
            paced_reply = read_packet(mux_sock, secret=PROXY_SECRET)
            assert paced_reply.session_id == sid
            assert decode_acct_status(paced_reply)[0] == ACCT_STATUS_SUCCESS
        elapsed = time.monotonic() - pace_start
        assert (
            elapsed >= 0.9
        ), f"4 accounting packets at 2 pkt/s (burst 2) must take >= 0.9s, took {elapsed:.3f}s"

        send_packet(
            mux_sock,
            tacacs_type=TAC_PLUS_AUTHOR,
            seq_no=1,
            session_id=0x5100,
            body=b"author-request",
            secret=PROXY_SECRET,
            single_connect=True,
        )
        author_reply = read_packet(mux_sock, secret=PROXY_SECRET)
        assert author_reply.session_id == 0x5100
        assert decode_author_status(author_reply)[0] == AUTHOR_STATUS_PASS_ADD


def test_packet_body_length_limit_isolates_offending_connection(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    """Closes a client connection that exceeds max-packet-body-length without affecting other clients."""
    with running_policy_scenario(
        tmp_path,
        socket_dir,
        binaries,
        process_manager,
        {
            "max-packet-body-length": 4096,
            "authentication": {"max-body-length": 2048},
            "authorization": {"max-body-length": 4096},
            "accounting": {"max-body-length": 4096},
        },
    ) as harness, harness.open_single_connect_client() as healthy_sock:
        with socket.create_connection(("127.0.0.1", harness.proxy_port), timeout=10.0) as oversized:
            try:
                send_packet(
                    oversized,
                    tacacs_type=TAC_PLUS_ACCT,
                    seq_no=1,
                    session_id=0x6001,
                    body=b"x" * 8192,
                    secret=PROXY_SECRET,
                    single_connect=True,
                )
                oversized_eof = oversized.recv(16)
            except OSError:
                oversized_eof = b""
            assert oversized_eof == b"", "Oversized frame must close the offending client connection"

        send_packet(
            healthy_sock,
            tacacs_type=TAC_PLUS_ACCT,
            seq_no=1,
            session_id=0x6002,
            body=b"normal-body",
            secret=PROXY_SECRET,
            single_connect=True,
        )
        healthy_reply = read_packet(healthy_sock, secret=PROXY_SECRET)
        assert healthy_reply.session_id == 0x6002
        assert decode_acct_status(healthy_reply)[0] == ACCT_STATUS_SUCCESS


def test_live_runtime_policy_reload_updates_open_single_connect_stream(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    """Applies raised session and packet-body limits to an already-open single-connect proxy stream."""
    with running_policy_scenario(
        tmp_path,
        socket_dir,
        binaries,
        process_manager,
        {
            "max-proxy-sessions-per-connection": 2,
            "max-packet-body-length": 4096,
            "authentication": {"max-body-length": 2048},
            "authorization": {"max-body-length": 4096},
            "accounting": {"max-body-length": 4096},
        },
    ) as harness, harness.open_single_connect_client() as mux_sock:
        initial_revision = harness.applied_policy_revision()
        harness.write_policy(
            {
                "max-proxy-sessions-per-connection": 8,
                "max-packet-body-length": 32768,
                "authentication": {"max-body-length": 4096},
                "authorization": {"max-body-length": 16384},
                "accounting": {"max-body-length": 32768},
            }
        )
        wait_until(
            lambda: harness.applied_policy_revision() > initial_revision,
            "live runtime-policy revision advance",
        )

        for sid in (0x7001, 0x7002, 0x7003):
            send_packet(
                mux_sock,
                tacacs_type=TAC_PLUS_ACCT,
                seq_no=1,
                session_id=sid,
                body=HOLD_MARKER + (b"y" * 8192),
                secret=PROXY_SECRET,
                single_connect=True,
            )
        wait_until(
            lambda: harness.held_arrived() == 3,
            "three 8 KiB concurrent sessions reaching upstream on the existing connection",
        )
        harness.release_held.set()

        reloaded_completed = set()
        for _ in range(3):
            reply = read_packet(mux_sock, secret=PROXY_SECRET)
            assert decode_acct_status(reply)[0] == ACCT_STATUS_SUCCESS
            reloaded_completed.add(reply.session_id)
        assert reloaded_completed == {0x7001, 0x7002, 0x7003}

