"""Scenario suite: Non-single-connection client-to-proxy termination across RFC 8907 request types.

Motivation
----------
Legacy TACACS+ clients such as ``pam_tacplus`` and ``audisp-tacplus`` omit
``TAC_PLUS_SINGLE_CONNECT_FLAG`` and open one TCP socket per TACACS+ session.
Per RFC 8907 Section 4.3, a non-single-connection TCP stream carries exactly
one TACACS+ session and closes as soon as that session terminates. If the proxy
keeps non-single-connection client sockets open after terminal replies or client
aborts, slow-closing clients hold listener connection slots unnecessarily.

Topology
--------
- ``tacacsrs-agentd`` runs its loopback TCP TACACS+ proxy with MD5 shared-secret
  obfuscation (``--proxy-shared-secret``).
- ``Rfc8907Server`` emulates a stateful RFC 8907 TACACS+ server that validates
  major/minor versions, odd/even sequence numbers, structured packet bodies,
  attribute-value separators, accounting flag rules, multi-turn authentication
  prompts, and silent session termination on ``TAC_PLUS_CONTINUE_FLAG_ABORT``.
- The suite validates both upstream deployment topologies:
  - TLS 1.3 single-connection upstream (downstream non-single-connect clients
    multiplexed over one persistent upstream TLS connection).
  - Classic TCP non-single-connection upstream (``--dedicated`` against an
    upstream server that closes after one session per RFC 8907 Section 4.3).

Expected outcomes
-----------------
For every non-single-connection request type and terminal outcome below, the
client leaves its TCP write half open while reading from the proxy, and the
proxy must:
1. Omit ``TAC_PLUS_SINGLE_CONNECT_FLAG`` on every downstream reply packet.
2. Keep the downstream TCP connection open across intermediate authentication
   prompts (``GETUSER``, ``GETPASS``, ``GETDATA``).
3. Close the downstream TCP connection immediately (``recv`` returns ``b""``
   EOF) as soon as the session reaches any terminal reply status — or as soon
   as the client sends ``CONTINUE`` with ``TAC_PLUS_CONTINUE_FLAG_ABORT``
   (without emitting a forbidden ``REPLY`` packet).
"""

from __future__ import annotations

from collections.abc import Iterator
import contextlib
from pathlib import Path
import socket
import subprocess

import pytest

from conftest import ProcessManager, reserve_loopback_port, wait_until
from rfc8907_server import (
    ACCT_FLAG_START,
    ACCT_FLAG_STOP,
    ACCT_FLAG_WATCHDOG,
    ACCT_STATUS_FOLLOW,
    AUTHEN_ACTION_CHPASS,
    AUTHEN_ACTION_LOGIN,
    AUTHEN_METH_NONE,
    AUTHEN_METH_TACACSPLUS,
    AUTHEN_STATUS_FAIL,
    AUTHEN_STATUS_FOLLOW,
    AUTHEN_STATUS_GETDATA,
    AUTHEN_STATUS_GETUSER,
    AUTHEN_STATUS_RESTART,
    AUTHEN_SVC_ENABLE,
    AUTHEN_SVC_LOGIN,
    AUTHEN_SVC_PPP,
    AUTHEN_TYPE_ASCII,
    AUTHEN_TYPE_CHAP,
    AUTHEN_TYPE_MSCHAP,
    AUTHEN_TYPE_MSCHAPV2,
    AUTHEN_TYPE_PAP,
    AUTHOR_STATUS_ERROR,
    AUTHOR_STATUS_FAIL,
    AUTHOR_STATUS_FOLLOW,
    AUTHOR_STATUS_PASS_REPL,
    CONTINUE_FLAG_ABORT,
    MINOR_VER_DEFAULT,
    MINOR_VER_ONE,
    REPLY_FLAG_NOECHO,
    AcctReplyBody,
    AcctRequestBody,
    AuthenContinueBody,
    AuthenReplyBody,
    AuthenStartBody,
    AuthorReplyBody,
    AuthorRequestBody,
    Rfc8907Server,
    build_chap_data,
    build_mschapv1_data,
    build_mschapv2_data,
)
from tacacs_wire import (
    ACCT_STATUS_ERROR,
    ACCT_STATUS_SUCCESS,
    AUTHEN_STATUS_ERROR,
    AUTHEN_STATUS_GETPASS,
    AUTHEN_STATUS_PASS,
    AUTHOR_STATUS_PASS_ADD,
    TAC_PLUS_ACCT,
    TAC_PLUS_AUTHEN,
    TAC_PLUS_AUTHOR,
    TAC_PLUS_SINGLE_CONNECT_FLAG,
    RawPacket,
    read_packet,
    send_packet,
)

DOWNSTREAM_SECRET = b"downstream-non-sc-secret"
UPSTREAM_TCP_SECRET = b"upstream-classic-tcp-secret"


def _assert_immediate_proxy_eof(sock: socket.socket) -> None:
    """Verifies the proxy closed its TCP write half without waiting on client close or idle timeout."""
    sock.settimeout(2.0)
    trailing = sock.recv(16)
    assert trailing == b"", f"Expected immediate TCP EOF from proxy, received {trailing!r}"


def _read_non_sc_reply(sock: socket.socket, expected_session_id: int, expected_seq: int) -> RawPacket:
    reply = read_packet(sock, secret=DOWNSTREAM_SECRET)
    assert reply.session_id == expected_session_id
    assert reply.seq_no == expected_seq
    assert (
        reply.flags & TAC_PLUS_SINGLE_CONNECT_FLAG
    ) == 0, "Proxy must not advertise single-connect to a non-single-connect client"
    return reply


@contextlib.contextmanager
def _running_proxy(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
    *,
    upstream_tls_single_connect: bool = True,
) -> Iterator[tuple[int, Rfc8907Server]]:
    upstream = Rfc8907Server(
        tmp_path,
        use_tls=upstream_tls_single_connect,
        single_connect=upstream_tls_single_connect,
        shared_secret=None if upstream_tls_single_connect else UPSTREAM_TCP_SECRET,
    )
    upstream.start()
    try:
        api_socket = socket_dir / "agent.sock"
        proxy_port = reserve_loopback_port()
        args = [
            str(binaries / "tacacsrs-agentd"),
            "--server-addr",
            f"127.0.0.1:{upstream.port}",
            "--service-mode",
            "both",
            "--listen-endpoint",
            str(api_socket),
            "--proxy-endpoint",
            f"127.0.0.1:{proxy_port}",
            "--proxy-shared-secret",
            DOWNSTREAM_SECRET.decode("ascii"),
            "--host-integration",
            "none",
        ]
        if upstream_tls_single_connect:
            args.extend(["--use-tls", "--insecure-disable-certificate-verification"])
        else:
            args.extend(["--shared-secret", UPSTREAM_TCP_SECRET.decode("ascii"), "--dedicated"])

        agent = process_manager.spawn("agent-non-sc", args)
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
            "agent readiness for non-single-connect suite",
        )
        yield proxy_port, upstream
    finally:
        upstream.stop()


@pytest.mark.parametrize(
    "upstream_tls_single_connect",
    [True, False],
    ids=["tls-single-connect-upstream", "tcp-dedicated-upstream"],
)
def test_non_single_connect_ascii_authentication_flows_and_abort(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
    upstream_tls_single_connect: bool,
) -> None:
    """Verifies multi-turn ASCII login, fail, enable, chpass, restart/follow/error, and CONTINUE abort."""
    with _running_proxy(
        tmp_path,
        socket_dir,
        binaries,
        process_manager,
        upstream_tls_single_connect=upstream_tls_single_connect,
    ) as (proxy_port, upstream):
        # 1. Full 3-round-trip ASCII login: START(empty user) -> GETUSER -> CONTINUE -> GETPASS -> CONTINUE -> PASS -> EOF
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
            sid = 0x1001
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=1,
                session_id=sid,
                body=AuthenStartBody(
                    AUTHEN_ACTION_LOGIN, 1, AUTHEN_TYPE_ASCII, AUTHEN_SVC_LOGIN, "", "pts/0", "192.0.2.10", b""
                ).to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
                minor_version=MINOR_VER_DEFAULT,
            )
            r1 = AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 2).body)
            assert r1.status == AUTHEN_STATUS_GETUSER

            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=3,
                session_id=sid,
                body=AuthenContinueBody(user_msg="alice", data=b"").to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            r2 = AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 4).body)
            assert r2.status == AUTHEN_STATUS_GETPASS
            assert (r2.flags & REPLY_FLAG_NOECHO) != 0

            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=5,
                session_id=sid,
                body=AuthenContinueBody(user_msg="alice-correct-pw", data=b"").to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            r3 = AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 6).body)
            assert r3.status == AUTHEN_STATUS_PASS
            _assert_immediate_proxy_eof(sock)

        # 2. ASCII wrong password -> FAIL -> immediate EOF
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
            sid = 0x1002
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=1,
                session_id=sid,
                body=AuthenStartBody(
                    AUTHEN_ACTION_LOGIN, 1, AUTHEN_TYPE_ASCII, AUTHEN_SVC_LOGIN, "alice", "pts/0", "192.0.2.10", b""
                ).to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            assert AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 2).body).status == AUTHEN_STATUS_GETPASS
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=3,
                session_id=sid,
                body=AuthenContinueBody(user_msg="wrong-password", data=b"").to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            assert AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 4).body).status == AUTHEN_STATUS_FAIL
            _assert_immediate_proxy_eof(sock)

        # 3. ASCII ENABLE service (priv_lvl=15) and CHPASS (GETDATA -> GETPASS -> PASS) -> immediate EOF
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
            sid = 0x1003
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=1,
                session_id=sid,
                body=AuthenStartBody(
                    AUTHEN_ACTION_LOGIN, 15, AUTHEN_TYPE_ASCII, AUTHEN_SVC_ENABLE, "alice", "pts/0", "192.0.2.10", b""
                ).to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            assert AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 2).body).status == AUTHEN_STATUS_GETPASS
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=3,
                session_id=sid,
                body=AuthenContinueBody(user_msg="sonic-enable-15", data=b"").to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            assert AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 4).body).status == AUTHEN_STATUS_PASS
            _assert_immediate_proxy_eof(sock)

        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
            sid = 0x1004
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=1,
                session_id=sid,
                body=AuthenStartBody(
                    AUTHEN_ACTION_CHPASS, 1, AUTHEN_TYPE_ASCII, AUTHEN_SVC_LOGIN, "alice", "pts/0", "192.0.2.10", b""
                ).to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            assert AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 2).body).status == AUTHEN_STATUS_GETDATA
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=3,
                session_id=sid,
                body=AuthenContinueBody(user_msg="alice-correct-pw", data=b"").to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            assert AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 4).body).status == AUTHEN_STATUS_GETPASS
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=5,
                session_id=sid,
                body=AuthenContinueBody(user_msg="alice-new-strong-pw", data=b"").to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            assert AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 6).body).status == AUTHEN_STATUS_PASS
            _assert_immediate_proxy_eof(sock)

        # 4. Terminal RESTART, FOLLOW, and ERROR replies each close the non-single-connect socket immediately.
        for offset, (user, expected_status) in enumerate(
            [
                ("trigger-restart", AUTHEN_STATUS_RESTART),
                ("trigger-follow", AUTHEN_STATUS_FOLLOW),
                ("trigger-error", AUTHEN_STATUS_ERROR),
            ]
        ):
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
                sid = 0x1010 + offset
                send_packet(
                    sock,
                    tacacs_type=TAC_PLUS_AUTHEN,
                    seq_no=1,
                    session_id=sid,
                    body=AuthenStartBody(
                        AUTHEN_ACTION_LOGIN, 1, AUTHEN_TYPE_ASCII, AUTHEN_SVC_LOGIN, user, "pts/0", "192.0.2.10", b""
                    ).to_bytes(),
                    secret=DOWNSTREAM_SECRET,
                    single_connect=False,
                )
                reply = AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 2).body)
                assert reply.status == expected_status
                _assert_immediate_proxy_eof(sock)

        # 5. RFC 8907 Section 5.3 CONTINUE with TAC_PLUS_CONTINUE_FLAG_ABORT: no REPLY, immediate EOF!
        with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
            sid = 0x1020
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=1,
                session_id=sid,
                body=AuthenStartBody(
                    AUTHEN_ACTION_LOGIN, 1, AUTHEN_TYPE_ASCII, AUTHEN_SVC_LOGIN, "alice", "pts/0", "192.0.2.10", b""
                ).to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            assert AuthenReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 2).body).status == AUTHEN_STATUS_GETPASS
            send_packet(
                sock,
                tacacs_type=TAC_PLUS_AUTHEN,
                seq_no=3,
                session_id=sid,
                body=AuthenContinueBody(
                    user_msg="",
                    data=b"user pressed Ctrl-C",
                    flags=CONTINUE_FLAG_ABORT,
                ).to_bytes(),
                secret=DOWNSTREAM_SECRET,
                single_connect=False,
            )
            _assert_immediate_proxy_eof(sock)
        wait_until(
            lambda: b"user pressed Ctrl-C" in upstream.aborted_reasons,
            "upstream receipt of CONTINUE abort reason",
        )


@pytest.mark.parametrize(
    "upstream_tls_single_connect",
    [True, False],
    ids=["tls-single-connect-upstream", "tcp-dedicated-upstream"],
)
def test_non_single_connect_minor_v1_authentication_types(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
    upstream_tls_single_connect: bool,
) -> None:
    """Verifies RFC 8907 Section 5.4.2 single-exchange PAP, CHAP, MS-CHAPv1, and MS-CHAPv2 termination."""
    with _running_proxy(
        tmp_path,
        socket_dir,
        binaries,
        process_manager,
        upstream_tls_single_connect=upstream_tls_single_connect,
    ) as (proxy_port, _upstream):
        cases = [
            (
                0x2001,
                AUTHEN_TYPE_PAP,
                AUTHEN_SVC_LOGIN,
                "alice",
                b"alice-correct-pw",
                AUTHEN_STATUS_PASS,
            ),
            (
                0x2002,
                AUTHEN_TYPE_PAP,
                AUTHEN_SVC_LOGIN,
                "alice",
                b"bad-pw",
                AUTHEN_STATUS_FAIL,
            ),
            (
                0x2003,
                AUTHEN_TYPE_CHAP,
                AUTHEN_SVC_PPP,
                "bob",
                build_chap_data(7, b"0123456789abcdef", b"bob-chap-secret"),
                AUTHEN_STATUS_PASS,
            ),
            (
                0x2004,
                AUTHEN_TYPE_CHAP,
                AUTHEN_SVC_PPP,
                "bob",
                build_chap_data(7, b"0123456789abcdef", b"wrong-chap-secret"),
                AUTHEN_STATUS_FAIL,
            ),
            (
                0x2005,
                AUTHEN_TYPE_MSCHAP,
                AUTHEN_SVC_PPP,
                "bob",
                build_mschapv1_data(3, b"87654321", b"bob-chap-secret"),
                AUTHEN_STATUS_PASS,
            ),
            (
                0x2006,
                AUTHEN_TYPE_MSCHAPV2,
                AUTHEN_SVC_PPP,
                "bob",
                build_mschapv2_data(
                    4,
                    b"auth-chall-16byt",
                    b"peer-chall-16byt",
                    "bob",
                    b"bob-chap-secret",
                ),
                AUTHEN_STATUS_PASS,
            ),
        ]
        for sid, authen_type, svc, user, data, expected_status in cases:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
                send_packet(
                    sock,
                    tacacs_type=TAC_PLUS_AUTHEN,
                    seq_no=1,
                    session_id=sid,
                    body=AuthenStartBody(
                        AUTHEN_ACTION_LOGIN, 1, authen_type, svc, user, "ttyS0", "198.51.100.7", data
                    ).to_bytes(),
                    secret=DOWNSTREAM_SECRET,
                    single_connect=False,
                    minor_version=MINOR_VER_ONE,
                )
                pkt = _read_non_sc_reply(sock, sid, 2)
                assert (pkt.version & 0x0F) == MINOR_VER_ONE
                reply = AuthenReplyBody.from_bytes(pkt.body)
                assert reply.status == expected_status
                _assert_immediate_proxy_eof(sock)


@pytest.mark.parametrize(
    "upstream_tls_single_connect",
    [True, False],
    ids=["tls-single-connect-upstream", "tcp-dedicated-upstream"],
)
def test_non_single_connect_authorization_request_types(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
    upstream_tls_single_connect: bool,
) -> None:
    """Verifies RFC 8907 Section 6 authorization PASS_ADD, PASS_REPL, FAIL, ERROR, and FOLLOW termination."""
    with _running_proxy(
        tmp_path,
        socket_dir,
        binaries,
        process_manager,
        upstream_tls_single_connect=upstream_tls_single_connect,
    ) as (proxy_port, _upstream):
        cases = [
            (0x3001, ["service=shell", "cmd="], AUTHOR_STATUS_PASS_ADD, ("priv-lvl=15",)),
            (
                0x3002,
                ["service=shell", "cmd=rewrite", "priv-lvl*1"],
                AUTHOR_STATUS_PASS_REPL,
                ("service=shell", "cmd=show", "cmd-arg=running-config"),
            ),
            (0x3003, ["service=shell", "cmd=reload"], AUTHOR_STATUS_FAIL, ()),
            (0x3004, ["service=shell", "cmd=trigger-error"], AUTHOR_STATUS_ERROR, ()),
            (0x3005, ["service=shell", "cmd=trigger-follow"], AUTHOR_STATUS_FOLLOW, ()),
        ]
        for sid, args, expected_status, expected_args in cases:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
                send_packet(
                    sock,
                    tacacs_type=TAC_PLUS_AUTHOR,
                    seq_no=1,
                    session_id=sid,
                    body=AuthorRequestBody(
                        AUTHEN_METH_TACACSPLUS,
                        15,
                        AUTHEN_TYPE_ASCII,
                        AUTHEN_SVC_LOGIN,
                        "alice",
                        "pts/1",
                        "192.0.2.25",
                        args,
                    ).to_bytes(),
                    secret=DOWNSTREAM_SECRET,
                    single_connect=False,
                    minor_version=MINOR_VER_DEFAULT,
                )
                reply = AuthorReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 2).body)
                assert reply.status == expected_status
                assert reply.args == expected_args
                _assert_immediate_proxy_eof(sock)


@pytest.mark.parametrize(
    "upstream_tls_single_connect",
    [True, False],
    ids=["tls-single-connect-upstream", "tcp-dedicated-upstream"],
)
def test_non_single_connect_accounting_record_types(
    tmp_path: Path,
    socket_dir: Path,
    binaries: Path,
    process_manager: ProcessManager,
    upstream_tls_single_connect: bool,
) -> None:
    """Verifies RFC 8907 Section 7 START, WATCHDOG, WATCHDOG|START, STOP, ERROR, and FOLLOW termination."""
    with _running_proxy(
        tmp_path,
        socket_dir,
        binaries,
        process_manager,
        upstream_tls_single_connect=upstream_tls_single_connect,
    ) as (proxy_port, upstream):
        cases = [
            (
                0x4001,
                ACCT_FLAG_START,
                ["task_id=42", "service=shell", "start_time=1700000000"],
                ACCT_STATUS_SUCCESS,
            ),
            (
                0x4002,
                ACCT_FLAG_WATCHDOG,
                ["task_id=42", "elapsed_time=30"],
                ACCT_STATUS_SUCCESS,
            ),
            (
                0x4003,
                ACCT_FLAG_WATCHDOG | ACCT_FLAG_START,
                ["task_id=42", "elapsed_time=60"],
                ACCT_STATUS_SUCCESS,
            ),
            (
                0x4004,
                ACCT_FLAG_STOP,
                ["task_id=42", "service=shell", "cmd=show version", "stop_time=1700000090"],
                ACCT_STATUS_SUCCESS,
            ),
            (
                0x4005,
                ACCT_FLAG_STOP,
                ["task_id=43", "event=trigger-error"],
                ACCT_STATUS_ERROR,
            ),
            (
                0x4006,
                ACCT_FLAG_STOP,
                ["task_id=44", "event=trigger-follow"],
                ACCT_STATUS_FOLLOW,
            ),
            # RFC 8907 Section 7.1 forbids setting START and STOP together; server returns ERROR.
            (
                0x4007,
                ACCT_FLAG_START | ACCT_FLAG_STOP,
                ["task_id=45"],
                ACCT_STATUS_ERROR,
            ),
        ]
        for sid, flags, args, expected_status in cases:
            with socket.create_connection(("127.0.0.1", proxy_port), timeout=10.0) as sock:
                send_packet(
                    sock,
                    tacacs_type=TAC_PLUS_ACCT,
                    seq_no=1,
                    session_id=sid,
                    body=AcctRequestBody(
                        flags,
                        AUTHEN_METH_NONE if flags == ACCT_FLAG_WATCHDOG else AUTHEN_METH_TACACSPLUS,
                        15,
                        AUTHEN_TYPE_PAP,
                        AUTHEN_SVC_LOGIN,
                        "alice",
                        "pts/2",
                        "192.0.2.30",
                        args,
                    ).to_bytes(),
                    secret=DOWNSTREAM_SECRET,
                    single_connect=False,
                    minor_version=MINOR_VER_DEFAULT,
                )
                reply = AcctReplyBody.from_bytes(_read_non_sc_reply(sock, sid, 2).body)
                assert reply.status == expected_status
                _assert_immediate_proxy_eof(sock)

        # Six valid records (excluding the rejected START|STOP flag combination) were recorded upstream.
        assert len(upstream.accounting_records) == 6
        if upstream_tls_single_connect:
            assert upstream.connections_accepted == 1
        else:
            assert upstream.connections_accepted == len(cases)
