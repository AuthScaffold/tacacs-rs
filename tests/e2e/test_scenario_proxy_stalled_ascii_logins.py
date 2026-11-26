"""Scenario: Stalled non-single-connect ASCII logins alongside auditd and IPC traffic.

Motivation
----------
On SONiC hosts, ``pam_tacplus`` (SSH interactive login) and ``audisp-tacplus``
(``auditd`` command accounting) speak classic MD5-obfuscated TACACS+ over
loopback TCP without negotiating ``TAC_PLUS_SINGLE_CONNECT_FLAG``. An operator
or attacker can open many SSH sessions that receive an ASCII ``GETPASS`` prompt
and never submit a password or close the TCP socket.

Topology
--------
- ``tacacsrs-agentd`` runs in ``both`` mode:
  - Client API Unix domain socket for ``tacon`` and ``tacacsrs-agent-health``.
  - Raw TACACS+ proxy TCP listener on loopback with MD5 shared-secret
    obfuscation (``--proxy-shared-secret``).
  - ``authentication.max-in-flight-requests = 4`` in ``--runtime-policy``.
- ``ScriptedTlsUpstream`` runs a single-connect TLS 1.3 TACACS+ server on
  loopback.

Expected sequence and outcomes
------------------------------
1. Eight non-single-connect login clients connect to the TCP proxy, send
   ``START`` (``seq_no = 1``), receive ``GETPASS`` (``seq_no = 2``), and hold
   their sockets open without sending ``CONTINUE``. Because ``max-in-flight-requests``
   bounds only active upstream round trips awaiting a server reply and releases
   its slot while waiting on downstream client input, all eight prompts succeed
   even though ``max-in-flight-requests`` is ``4``.
2. While all eight login sockets remain stalled at ``GETPASS``:
   - A ninth non-single-connect ASCII login completes ``START -> GETPASS ->
     CONTINUE -> PASS``, and ``tacacsrs-agentd`` closes that TCP socket
     immediately after delivering ``PASS`` without waiting for client EOF or the
     idle read timeout.
   - A non-single-connect ``audisp-tacplus`` accounting client completes its
     exchange and observes immediate TCP EOF from the proxy.
   - ``tacon`` executes an accounting record through the Unix Client API socket.
   - Sending a second ``session_id`` on one of the stalled non-single-connect
     sockets closes only that offending client connection; the daemon, the
     remaining seven stalled logins, and new clients continue normally.
3. The remaining seven stalled login clients send ``CONTINUE`` (``seq_no = 3``),
   receive ``PASS`` (``seq_no = 4``), and observe immediate TCP EOF.
4. Every upstream packet crosses one shared TLS 1.3 single-connect connection
   with RFC 9887 unobfuscated framing.
"""

from __future__ import annotations

import json
from pathlib import Path
import socket
import subprocess

from conftest import ProcessManager, reserve_loopback_port, wait_until
from tacacs_wire import (
    ACCT_STATUS_SUCCESS,
    AUTHEN_STATUS_GETPASS,
    AUTHEN_STATUS_PASS,
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_SINGLE_CONNECT_FLAG,
    ScriptedTlsUpstream,
    decode_acct_status,
    decode_authen_status,
    read_packet,
    send_packet,
)

PROXY_SECRET = b"sonic-loopback-proxy-secret"


def test_stalled_ascii_logins_do_not_starve_new_logins_auditd_or_ipc(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
) -> None:
    """Verifies non-single-connect ASCII prompt isolation, 1-session socket close, and fault containment."""
    upstream = ScriptedTlsUpstream(tmp_path)
    upstream.start()
    try:
        api_socket = socket_dir / "agent.sock"
        proxy_port = reserve_loopback_port()
        policy_path = tmp_path / "runtime-policy.json"
        policy_path.write_text(
            json.dumps(
                {
                    "tacacsrs:runtime-policy": {
                        "authentication": {
                            "max-in-flight-requests": 4,
                            "request-timeout-seconds": 30,
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

        agent = process_manager.spawn(
            "agent-stalled-ascii",
            [
                str(binaries / "tacacsrs-agentd"),
                "--server-addr",
                f"127.0.0.1:{upstream.port}",
                "--use-tls",
                "--insecure-disable-certificate-verification",
                "--service-mode",
                "both",
                "--listen-endpoint",
                str(api_socket),
                "--proxy-endpoint",
                f"127.0.0.1:{proxy_port}",
                "--proxy-shared-secret",
                PROXY_SECRET.decode("ascii"),
                "--runtime-policy",
                str(policy_path),
                "--host-integration",
                "none",
            ],
        )

        health_bin = str(binaries / "tacacsrs-agent-health")
        wait_until(
            lambda: api_socket.exists()
            and agent.poll() is None
            and subprocess.run(
                [health_bin, "--endpoint", str(api_socket), "--check", "readiness"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            ).returncode
            == 0,
            "agent IPC and proxy readiness",
        )

        stalled_sockets: list[tuple[int, socket.socket]] = []
        try:
            # Step 1: Open 8 non-single-connect ASCII logins (> max-in-flight-requests=4) and stall at GETPASS.
            for index in range(1, 9):
                session_id = 0x1000 + index
                sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0)
                stalled_sockets.append((session_id, sock))
                send_packet(
                    sock,
                    tacacs_type=TAC_PLUS_AUTHEN,
                    seq_no=1,
                    session_id=session_id,
                    body=f"ascii-start-{index}".encode("ascii"),
                    secret=PROXY_SECRET,
                    single_connect=False,
                )
                reply = read_packet(sock, secret=PROXY_SECRET)
                assert reply.session_id == session_id
                assert reply.seq_no == 2
                assert (reply.flags & TAC_PLUS_SINGLE_CONNECT_FLAG) == 0
                status, _ = decode_authen_status(reply)
                assert status == AUTHEN_STATUS_GETPASS

            # Step 2a: A 9th interactive login completes START -> GETPASS -> CONTINUE -> PASS and closes at once.
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as login9:
                sid9 = 0x2009
                send_packet(
                    login9,
                    tacacs_type=TAC_PLUS_AUTHEN,
                    seq_no=1,
                    session_id=sid9,
                    body=b"ascii-start-9",
                    secret=PROXY_SECRET,
                    single_connect=False,
                )
                prompt9 = read_packet(login9, secret=PROXY_SECRET)
                assert decode_authen_status(prompt9)[0] == AUTHEN_STATUS_GETPASS

                send_packet(
                    login9,
                    tacacs_type=TAC_PLUS_AUTHEN,
                    seq_no=3,
                    session_id=sid9,
                    body=b"ascii-password-9",
                    secret=PROXY_SECRET,
                    single_connect=False,
                )
                pass9 = read_packet(login9, secret=PROXY_SECRET)
                assert pass9.session_id == sid9
                assert pass9.seq_no == 4
                assert decode_authen_status(pass9)[0] == AUTHEN_STATUS_PASS
                assert login9.recv(16) == b"", "Non-single-connect proxy socket must close immediately after PASS"

            # Step 2b: A non-single-connect auditd accounting client completes and receives immediate EOF.
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as audit_sock:
                audit_sid = 0x3001
                send_packet(
                    audit_sock,
                    tacacs_type=TAC_PLUS_ACCT,
                    seq_no=1,
                    session_id=audit_sid,
                    body=b"auditd-execve-record",
                    secret=PROXY_SECRET,
                    single_connect=False,
                )
                acct_reply = read_packet(audit_sock, secret=PROXY_SECRET)
                assert acct_reply.session_id == audit_sid
                assert decode_acct_status(acct_reply)[0] == ACCT_STATUS_SUCCESS
                assert audit_sock.recv(16) == b"", "Non-single-connect accounting socket must close immediately"

            # Step 2c: tacon over the Client API Unix socket succeeds alongside the stalled proxy logins.
            tacon_result = subprocess.run(
                [
                    str(binaries / "tacon"),
                    "--service-endpoint",
                    str(api_socket),
                    "accounting",
                    "start",
                    "--user",
                    "sonic-admin",
                    "--port",
                    "pts/0",
                    "--rem-addr",
                    "192.0.2.50",
                    "--",
                    "show",
                    "version",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            assert tacon_result.returncode == 0, f"tacon failed: {tacon_result.stderr}"

            # Step 2d: Injecting a second session_id on a non-single-connect socket closes ONLY that socket.
            _bad_sid, bad_sock = stalled_sockets.pop(0)
            with bad_sock:
                send_packet(
                    bad_sock,
                    tacacs_type=TAC_PLUS_AUTHEN,
                    seq_no=1,
                    session_id=0x9999,
                    body=b"illegal-second-session",
                    secret=PROXY_SECRET,
                    single_connect=False,
                )
                assert bad_sock.recv(16) == b"", "Violating non-single-connect socket must close"

            # Step 3: All 7 remaining stalled ASCII logins resume with CONTINUE, receive PASS, and close cleanly.
            while stalled_sockets:
                session_id, sock = stalled_sockets.pop(0)
                with sock:
                    send_packet(
                        sock,
                        tacacs_type=TAC_PLUS_AUTHEN,
                        seq_no=3,
                        session_id=session_id,
                        body=b"delayed-password",
                        secret=PROXY_SECRET,
                        single_connect=False,
                    )
                    final_reply = read_packet(sock, secret=PROXY_SECRET)
                    assert final_reply.session_id == session_id
                    assert final_reply.seq_no == 4
                    assert decode_authen_status(final_reply)[0] == AUTHEN_STATUS_PASS
                    assert sock.recv(16) == b""

            # Step 4: Proxy and IPC operations multiplexed onto 1 upstream TLS 1.3 connection.
            assert upstream.connections_accepted == 1
        finally:
            for _sid, sock in stalled_sockets:
                sock.close()
    finally:
        upstream.stop()
