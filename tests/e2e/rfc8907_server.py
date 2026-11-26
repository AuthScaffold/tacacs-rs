"""RFC 8907 wire codecs and stateful TACACS+ server emulator for E2E protocol tests.

This module implements structured RFC 8907 packet bodies and a stateful server
that enforces header versions, odd/even sequence numbers, single-connection vs.
non-single-connection socket closure (Section 4.3), multi-turn ASCII login,
enable, and password-change state machines (Section 5.4.1), client ``CONTINUE``
aborts without a server ``REPLY`` (Section 5.3), minor-version-1 single-exchange
PAP/CHAP/MS-CHAP authentication (Section 5.4.2), attribute-value authorization
(Section 6), and ``START``/``WATCHDOG``/``STOP`` accounting flag rules (Section 7).
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
import hmac
from pathlib import Path
import select
import socket
import ssl
import struct
import subprocess
import threading

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
    TAC_PLUS_UNENCRYPTED_FLAG,
    RawPacket,
    read_packet,
    send_packet,
)

# RFC 8907 Section 4.1 minor versions
MINOR_VER_DEFAULT = 0x0
MINOR_VER_ONE = 0x1

# RFC 8907 Section 5.1 authentication actions, types, and services
AUTHEN_ACTION_LOGIN = 0x01
AUTHEN_ACTION_CHPASS = 0x02

AUTHEN_TYPE_ASCII = 0x01
AUTHEN_TYPE_PAP = 0x02
AUTHEN_TYPE_CHAP = 0x03
AUTHEN_TYPE_MSCHAP = 0x05
AUTHEN_TYPE_MSCHAPV2 = 0x06

AUTHEN_SVC_NONE = 0x00
AUTHEN_SVC_LOGIN = 0x01
AUTHEN_SVC_ENABLE = 0x02
AUTHEN_SVC_PPP = 0x03

# RFC 8907 Section 5.2 authentication reply statuses and flags
AUTHEN_STATUS_FAIL = 0x02
AUTHEN_STATUS_GETDATA = 0x03
AUTHEN_STATUS_GETUSER = 0x04
AUTHEN_STATUS_RESTART = 0x06
AUTHEN_STATUS_FOLLOW = 0x21

REPLY_FLAG_NOECHO = 0x01

# RFC 8907 Section 5.3 authentication continue flags
CONTINUE_FLAG_ABORT = 0x01

# RFC 8907 Section 6.1 & 6.2 authorization methods and statuses
AUTHEN_METH_NONE = 0x01
AUTHEN_METH_TACACSPLUS = 0x06

AUTHOR_STATUS_PASS_REPL = 0x02
AUTHOR_STATUS_FAIL = 0x10
AUTHOR_STATUS_ERROR = 0x11
AUTHOR_STATUS_FOLLOW = 0x21

# RFC 8907 Section 7.1 & 7.2 accounting flags and statuses
ACCT_FLAG_START = 0x02
ACCT_FLAG_STOP = 0x04
ACCT_FLAG_WATCHDOG = 0x08

ACCT_STATUS_FOLLOW = 0x21


@dataclass(frozen=True)
class AuthenStartBody:
    action: int
    priv_lvl: int
    authen_type: int
    authen_service: int
    user: str
    port: str
    rem_addr: str
    data: bytes

    def to_bytes(self) -> bytes:
        user_b = self.user.encode("utf-8")
        port_b = self.port.encode("utf-8")
        rem_b = self.rem_addr.encode("utf-8")
        header = struct.pack(
            "!BBBBBBBB",
            self.action,
            self.priv_lvl,
            self.authen_type,
            self.authen_service,
            len(user_b),
            len(port_b),
            len(rem_b),
            len(self.data),
        )
        return header + user_b + port_b + rem_b + self.data

    @classmethod
    def from_bytes(cls, raw: bytes) -> AuthenStartBody:
        if len(raw) < 8:
            raise ValueError(f"Authentication START body too short: {len(raw)}")
        action, priv_lvl, authen_type, authen_service, u_len, p_len, r_len, d_len = struct.unpack(
            "!BBBBBBBB", raw[:8]
        )
        expected = 8 + u_len + p_len + r_len + d_len
        if len(raw) != expected:
            raise ValueError(f"Authentication START length mismatch: expected {expected}, got {len(raw)}")
        pos = 8
        user = raw[pos : pos + u_len].decode("utf-8")
        pos += u_len
        port = raw[pos : pos + p_len].decode("utf-8")
        pos += p_len
        rem_addr = raw[pos : pos + r_len].decode("utf-8")
        pos += r_len
        data = raw[pos : pos + d_len]
        return cls(action, priv_lvl, authen_type, authen_service, user, port, rem_addr, data)


@dataclass(frozen=True)
class AuthenContinueBody:
    user_msg: str
    data: bytes
    flags: int = 0

    def to_bytes(self) -> bytes:
        msg_b = self.user_msg.encode("utf-8")
        return struct.pack("!HHB", len(msg_b), len(self.data), self.flags) + msg_b + self.data

    @classmethod
    def from_bytes(cls, raw: bytes) -> AuthenContinueBody:
        if len(raw) < 5:
            raise ValueError(f"Authentication CONTINUE body too short: {len(raw)}")
        msg_len, data_len, flags = struct.unpack("!HHB", raw[:5])
        expected = 5 + msg_len + data_len
        if len(raw) != expected:
            raise ValueError(
                f"Authentication CONTINUE length mismatch: expected {expected}, got {len(raw)}"
            )
        user_msg = raw[5 : 5 + msg_len].decode("utf-8")
        data = raw[5 + msg_len : expected]
        return cls(user_msg=user_msg, data=data, flags=flags)


@dataclass(frozen=True)
class AuthenReplyBody:
    status: int
    flags: int = 0
    server_msg: str = ""
    data: bytes = b""

    def to_bytes(self) -> bytes:
        msg_b = self.server_msg.encode("utf-8")
        return (
            struct.pack("!BBHH", self.status, self.flags, len(msg_b), len(self.data))
            + msg_b
            + self.data
        )

    @classmethod
    def from_bytes(cls, raw: bytes) -> AuthenReplyBody:
        if len(raw) < 6:
            raise ValueError(f"Authentication REPLY body too short: {len(raw)}")
        status, flags, msg_len, data_len = struct.unpack("!BBHH", raw[:6])
        expected = 6 + msg_len + data_len
        if len(raw) != expected:
            raise ValueError(f"Authentication REPLY length mismatch: expected {expected}, got {len(raw)}")
        server_msg = raw[6 : 6 + msg_len].decode("utf-8")
        data = raw[6 + msg_len : expected]
        return cls(status=status, flags=flags, server_msg=server_msg, data=data)


@dataclass(frozen=True)
class AuthorRequestBody:
    authen_method: int
    priv_lvl: int
    authen_type: int
    authen_service: int
    user: str
    port: str
    rem_addr: str
    args: list[str]

    def to_bytes(self) -> bytes:
        user_b = self.user.encode("utf-8")
        port_b = self.port.encode("utf-8")
        rem_b = self.rem_addr.encode("utf-8")
        arg_bytes = [arg.encode("utf-8") for arg in self.args]
        header = struct.pack(
            "!BBBBBBBB",
            self.authen_method,
            self.priv_lvl,
            self.authen_type,
            self.authen_service,
            len(user_b),
            len(port_b),
            len(rem_b),
            len(arg_bytes),
        )
        lengths = bytes(len(item) for item in arg_bytes)
        return header + lengths + user_b + port_b + rem_b + b"".join(arg_bytes)

    @classmethod
    def from_bytes(cls, raw: bytes) -> AuthorRequestBody:
        if len(raw) < 8:
            raise ValueError(f"Authorization REQUEST body too short: {len(raw)}")
        method, priv_lvl, authen_type, authen_service, u_len, p_len, r_len, arg_cnt = struct.unpack(
            "!BBBBBBBB", raw[:8]
        )
        if len(raw) < 8 + arg_cnt:
            raise ValueError("Authorization REQUEST missing arg length bytes")
        arg_lens = list(raw[8 : 8 + arg_cnt])
        expected = 8 + arg_cnt + u_len + p_len + r_len + sum(arg_lens)
        if len(raw) != expected:
            raise ValueError(
                f"Authorization REQUEST length mismatch: expected {expected}, got {len(raw)}"
            )
        pos = 8 + arg_cnt
        user = raw[pos : pos + u_len].decode("utf-8")
        pos += u_len
        port = raw[pos : pos + p_len].decode("utf-8")
        pos += p_len
        rem_addr = raw[pos : pos + r_len].decode("utf-8")
        pos += r_len
        args: list[str] = []
        for length in arg_lens:
            args.append(raw[pos : pos + length].decode("utf-8"))
            pos += length
        return cls(method, priv_lvl, authen_type, authen_service, user, port, rem_addr, args)


@dataclass(frozen=True)
class AuthorReplyBody:
    status: int
    server_msg: str = ""
    data: str = ""
    args: tuple[str, ...] = ()

    def to_bytes(self) -> bytes:
        msg_b = self.server_msg.encode("utf-8")
        data_b = self.data.encode("utf-8")
        arg_bytes = [arg.encode("utf-8") for arg in self.args]
        header = struct.pack("!BBHH", self.status, len(arg_bytes), len(msg_b), len(data_b))
        lengths = bytes(len(item) for item in arg_bytes)
        return header + lengths + msg_b + data_b + b"".join(arg_bytes)

    @classmethod
    def from_bytes(cls, raw: bytes) -> AuthorReplyBody:
        if len(raw) < 6:
            raise ValueError(f"Authorization RESPONSE body too short: {len(raw)}")
        status, arg_cnt, msg_len, data_len = struct.unpack("!BBHH", raw[:6])
        if len(raw) < 6 + arg_cnt:
            raise ValueError("Authorization RESPONSE missing arg length bytes")
        arg_lens = list(raw[6 : 6 + arg_cnt])
        expected = 6 + arg_cnt + msg_len + data_len + sum(arg_lens)
        if len(raw) != expected:
            raise ValueError(
                f"Authorization RESPONSE length mismatch: expected {expected}, got {len(raw)}"
            )
        pos = 6 + arg_cnt
        server_msg = raw[pos : pos + msg_len].decode("utf-8")
        pos += msg_len
        data = raw[pos : pos + data_len].decode("utf-8")
        pos += data_len
        args: list[str] = []
        for length in arg_lens:
            args.append(raw[pos : pos + length].decode("utf-8"))
            pos += length
        return cls(status=status, server_msg=server_msg, data=data, args=tuple(args))


@dataclass(frozen=True)
class AcctRequestBody:
    flags: int
    authen_method: int
    priv_lvl: int
    authen_type: int
    authen_service: int
    user: str
    port: str
    rem_addr: str
    args: list[str]

    def to_bytes(self) -> bytes:
        user_b = self.user.encode("utf-8")
        port_b = self.port.encode("utf-8")
        rem_b = self.rem_addr.encode("utf-8")
        arg_bytes = [arg.encode("utf-8") for arg in self.args]
        header = struct.pack(
            "!BBBBBBBBB",
            self.flags,
            self.authen_method,
            self.priv_lvl,
            self.authen_type,
            self.authen_service,
            len(user_b),
            len(port_b),
            len(rem_addr := rem_b),
            len(arg_bytes),
        )
        lengths = bytes(len(item) for item in arg_bytes)
        return header + lengths + user_b + port_b + rem_addr + b"".join(arg_bytes)

    @classmethod
    def from_bytes(cls, raw: bytes) -> AcctRequestBody:
        if len(raw) < 9:
            raise ValueError(f"Accounting REQUEST body too short: {len(raw)}")
        flags, method, priv_lvl, authen_type, svc, u_len, p_len, r_len, arg_cnt = struct.unpack(
            "!BBBBBBBBB", raw[:9]
        )
        if len(raw) < 9 + arg_cnt:
            raise ValueError("Accounting REQUEST missing arg length bytes")
        arg_lens = list(raw[9 : 9 + arg_cnt])
        expected = 9 + arg_cnt + u_len + p_len + r_len + sum(arg_lens)
        if len(raw) != expected:
            raise ValueError(
                f"Accounting REQUEST length mismatch: expected {expected}, got {len(raw)}"
            )
        pos = 9 + arg_cnt
        user = raw[pos : pos + u_len].decode("utf-8")
        pos += u_len
        port = raw[pos : pos + p_len].decode("utf-8")
        pos += p_len
        rem_addr = raw[pos : pos + r_len].decode("utf-8")
        pos += r_len
        args: list[str] = []
        for length in arg_lens:
            args.append(raw[pos : pos + length].decode("utf-8"))
            pos += length
        return cls(flags, method, priv_lvl, authen_type, svc, user, port, rem_addr, args)


@dataclass(frozen=True)
class AcctReplyBody:
    status: int
    server_msg: str = ""
    data: str = ""

    def to_bytes(self) -> bytes:
        msg_b = self.server_msg.encode("utf-8")
        data_b = self.data.encode("utf-8")
        return struct.pack("!HHB", len(msg_b), len(data_b), self.status) + msg_b + data_b

    @classmethod
    def from_bytes(cls, raw: bytes) -> AcctReplyBody:
        if len(raw) < 5:
            raise ValueError(f"Accounting REPLY body too short: {len(raw)}")
        msg_len, data_len, status = struct.unpack("!HHB", raw[:5])
        expected = 5 + msg_len + data_len
        if len(raw) != expected:
            raise ValueError(f"Accounting REPLY length mismatch: expected {expected}, got {len(raw)}")
        server_msg = raw[5 : 5 + msg_len].decode("utf-8")
        data = raw[5 + msg_len : expected].decode("utf-8")
        return cls(status=status, server_msg=server_msg, data=data)


def build_chap_data(ppp_id: int, challenge: bytes, secret: bytes) -> bytes:
    """Builds RFC 8907 Section 5.4.2.2 CHAP ``START.data`` (PPP ID + challenge + MD5 digest)."""
    digest = hashlib.md5(bytes([ppp_id]) + secret + challenge).digest()
    return bytes([ppp_id]) + challenge + digest


def build_mschapv1_data(ppp_id: int, challenge: bytes, secret: bytes) -> bytes:
    """Builds RFC 8907 Section 5.4.2.3 49-byte MS-CHAPv1 response framing (24B LM + 24B NT + 1B flag)."""
    assert len(challenge) >= 8
    lm_resp = bytes(24)
    nt_resp = hashlib.sha256(b"mschapv1:" + bytes([ppp_id]) + challenge + secret).digest()[:24]
    return bytes([ppp_id]) + challenge + lm_resp + nt_resp + b"\x01"


def build_mschapv2_data(ppp_id: int, auth_challenge: bytes, peer_challenge: bytes, user: str, secret: bytes) -> bytes:
    """Builds RFC 8907 Section 5.4.2.4 49-byte MS-CHAPv2 response framing (16B peer + 8B zero + 24B NT + 1B flags)."""
    assert len(auth_challenge) >= 16
    assert len(peer_challenge) == 16
    nt_resp = hashlib.sha256(
        b"mschapv2:" + peer_challenge + auth_challenge + user.encode("utf-8") + secret
    ).digest()[:24]
    return bytes([ppp_id]) + auth_challenge + peer_challenge + bytes(8) + nt_resp + b"\x00"


@dataclass
class _AuthenSessionState:
    expected_seq: int
    minor_version: int
    action: int
    authen_service: int
    user: str
    stage: str
    old_password_ok: bool = False


class Rfc8907Server:
    """Stateful RFC 8907 TACACS+ server supporting TLS 1.3 single-connect or classic TCP dedicated mode."""

    USERS: dict[str, bytes] = {
        "alice": b"alice-correct-pw",
        "bob": b"bob-chap-secret",
    }
    ENABLE_SECRET = b"sonic-enable-15"

    def __init__(
        self,
        root: Path,
        *,
        use_tls: bool = True,
        single_connect: bool = True,
        shared_secret: bytes | None = None,
    ) -> None:
        self.use_tls = use_tls
        self.single_connect = single_connect
        self.shared_secret = None if use_tls else shared_secret
        self._tls_ctx: ssl.SSLContext | None = None
        if use_tls:
            cert_path = root / "rfc-upstream-cert.pem"
            key_path = root / "rfc-upstream-key.pem"
            subprocess.run(
                [
                    "openssl",
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
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                    "-keyout",
                    str(key_path),
                    "-out",
                    str(cert_path),
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
            self._tls_ctx = ctx

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(32)
        self._listener.settimeout(0.2)
        self.port = int(self._listener.getsockname()[1])

        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.connections_accepted = 0
        self.aborted_reasons: list[bytes] = []
        self.accounting_records: list[AcctRequestBody] = []
        self.errors: list[Exception] = []
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self) -> None:
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._accept_thread.join(timeout=5.0)
        for worker in self._threads:
            worker.join(timeout=5.0)
        self._listener.close()
        if self.errors:
            raise AssertionError(f"RFC 8907 server protocol/transport errors: {self.errors!r}")

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            with self._lock:
                self.connections_accepted += 1
            worker = threading.Thread(target=self._serve_connection, args=(conn,), daemon=True)
            self._threads.append(worker)
            worker.start()

    def _serve_connection(self, raw_conn: socket.socket) -> None:
        sessions: dict[int, _AuthenSessionState] = {}
        bound_session_id: int | None = None
        negotiated_single_connect = False
        first_packet = True
        try:
            with raw_conn:
                raw_conn.settimeout(15.0)
                if self._tls_ctx is not None:
                    stream_cm = self._tls_ctx.wrap_socket(
                        raw_conn,
                        server_side=True,
                        do_handshake_on_connect=False,
                    )
                else:
                    stream_cm = raw_conn  # type: ignore[assignment]
                with stream_cm as stream:
                    if isinstance(stream, ssl.SSLSocket):
                        stream.do_handshake()
                    while not self._stop.is_set():
                        has_buffered_tls = isinstance(stream, ssl.SSLSocket) and stream.pending() > 0
                        if not has_buffered_tls:
                            readable, _, _ = select.select([stream], [], [], 0.1)
                            if not readable:
                                continue
                        try:
                            pkt = read_packet(stream, secret=self.shared_secret)
                        except (EOFError, ssl.SSLError, OSError):
                            break

                        if (pkt.version >> 4) != 0xC:
                            raise ValueError(f"Invalid TACACS+ major version in {pkt.version:#x}")
                        if pkt.seq_no % 2 != 1:
                            raise ValueError(f"Client request seq_no must be odd, got {pkt.seq_no}")
                        if self.use_tls and (pkt.flags & TAC_PLUS_UNENCRYPTED_FLAG) == 0:
                            raise ValueError("RFC 9887 requires unobfuscated flag over TLS")

                        echo_sc = False
                        if first_packet:
                            first_packet = False
                            if self.single_connect and (pkt.flags & TAC_PLUS_SINGLE_CONNECT_FLAG) != 0:
                                negotiated_single_connect = True
                                echo_sc = True
                            else:
                                bound_session_id = pkt.session_id
                        elif not negotiated_single_connect and pkt.session_id != bound_session_id:
                            raise ValueError(
                                f"Non-single-connect upstream received second session {pkt.session_id:#x} "
                                f"after {bound_session_id:#x}"
                            )

                        reply_body, terminal = self._handle_packet(pkt, sessions)
                        if reply_body is not None:
                            send_packet(
                                stream,
                                tacacs_type=pkt.tacacs_type,
                                seq_no=pkt.seq_no + 1,
                                session_id=pkt.session_id,
                                body=reply_body,
                                secret=self.shared_secret,
                                single_connect=echo_sc,
                                minor_version=pkt.version & 0x0F,
                            )
                        if terminal and not negotiated_single_connect:
                            with contextlib.suppress(OSError):
                                stream.shutdown(socket.SHUT_WR)
                            break
        except Exception as exc:  # noqa: BLE001
            if not self._stop.is_set():
                with self._lock:
                    self.errors.append(exc)

    def _handle_packet(
        self,
        pkt: RawPacket,
        sessions: dict[int, _AuthenSessionState],
    ) -> tuple[bytes | None, bool]:
        minor = pkt.version & 0x0F
        if pkt.tacacs_type == TAC_PLUS_AUTHEN:
            return self._handle_authentication(pkt, minor, sessions)
        if pkt.tacacs_type == TAC_PLUS_AUTHOR:
            return self._handle_authorization(pkt, minor), True
        if pkt.tacacs_type == TAC_PLUS_ACCT:
            return self._handle_accounting(pkt, minor), True
        raise ValueError(f"Unknown TACACS+ type: {pkt.tacacs_type}")

    def _handle_authentication(
        self,
        pkt: RawPacket,
        minor: int,
        sessions: dict[int, _AuthenSessionState],
    ) -> tuple[bytes | None, bool]:
        if pkt.seq_no == 1:
            if pkt.session_id in sessions:
                raise ValueError(f"Duplicate START for active session {pkt.session_id:#x}")
            start = AuthenStartBody.from_bytes(pkt.body)

            if start.user == "trigger-error":
                return AuthenReplyBody(AUTHEN_STATUS_ERROR, server_msg="backend error").to_bytes(), True
            if start.user == "trigger-restart":
                return AuthenReplyBody(AUTHEN_STATUS_RESTART, server_msg="restart auth").to_bytes(), True
            if start.user == "trigger-follow":
                return AuthenReplyBody(AUTHEN_STATUS_FOLLOW, server_msg="follow").to_bytes(), True

            if start.authen_type == AUTHEN_TYPE_ASCII:
                if minor != MINOR_VER_DEFAULT:
                    return (
                        AuthenReplyBody(
                            AUTHEN_STATUS_ERROR, server_msg="ASCII requires minor_version 0"
                        ).to_bytes(),
                        True,
                    )
                if start.action == AUTHEN_ACTION_CHPASS:
                    sessions[pkt.session_id] = _AuthenSessionState(
                        expected_seq=3,
                        minor_version=minor,
                        action=start.action,
                        authen_service=start.authen_service,
                        user=start.user,
                        stage="get_old_pw",
                    )
                    return (
                        AuthenReplyBody(
                            AUTHEN_STATUS_GETDATA,
                            flags=REPLY_FLAG_NOECHO,
                            server_msg="Old Password: ",
                        ).to_bytes(),
                        False,
                    )
                if start.authen_service == AUTHEN_SVC_ENABLE:
                    sessions[pkt.session_id] = _AuthenSessionState(
                        expected_seq=3,
                        minor_version=minor,
                        action=start.action,
                        authen_service=start.authen_service,
                        user=start.user,
                        stage="get_enable_pw",
                    )
                    return (
                        AuthenReplyBody(
                            AUTHEN_STATUS_GETPASS,
                            flags=REPLY_FLAG_NOECHO,
                            server_msg="Enable Password: ",
                        ).to_bytes(),
                        False,
                    )
                if not start.user:
                    sessions[pkt.session_id] = _AuthenSessionState(
                        expected_seq=3,
                        minor_version=minor,
                        action=start.action,
                        authen_service=start.authen_service,
                        user="",
                        stage="get_user",
                    )
                    return (
                        AuthenReplyBody(AUTHEN_STATUS_GETUSER, server_msg="Username: ").to_bytes(),
                        False,
                    )
                sessions[pkt.session_id] = _AuthenSessionState(
                    expected_seq=3,
                    minor_version=minor,
                    action=start.action,
                    authen_service=start.authen_service,
                    user=start.user,
                    stage="get_pass",
                )
                return (
                    AuthenReplyBody(
                        AUTHEN_STATUS_GETPASS,
                        flags=REPLY_FLAG_NOECHO,
                        server_msg="Password: ",
                    ).to_bytes(),
                    False,
                )

            # RFC 8907 Section 5.4.2 single-exchange authentication types require minor_version 1.
            if minor != MINOR_VER_ONE:
                return (
                    AuthenReplyBody(
                        AUTHEN_STATUS_ERROR, server_msg="Expected minor_version 1"
                    ).to_bytes(),
                    True,
                )
            secret = self.USERS.get(start.user)
            if start.authen_type == AUTHEN_TYPE_PAP:
                ok = secret is not None and hmac.compare_digest(start.data, secret)
                return (
                    AuthenReplyBody(
                        AUTHEN_STATUS_PASS if ok else AUTHEN_STATUS_FAIL,
                        server_msg="pap-ok" if ok else "pap-denied",
                    ).to_bytes(),
                    True,
                )
            if start.authen_type == AUTHEN_TYPE_CHAP:
                if len(start.data) < 18 or secret is None:
                    return AuthenReplyBody(AUTHEN_STATUS_FAIL, server_msg="chap-denied").to_bytes(), True
                ppp_id = start.data[0]
                challenge = start.data[1:-16]
                received_digest = start.data[-16:]
                expected_digest = hashlib.md5(bytes([ppp_id]) + secret + challenge).digest()
                ok = hmac.compare_digest(received_digest, expected_digest)
                return (
                    AuthenReplyBody(
                        AUTHEN_STATUS_PASS if ok else AUTHEN_STATUS_FAIL,
                        server_msg="chap-ok" if ok else "chap-denied",
                    ).to_bytes(),
                    True,
                )
            if start.authen_type == AUTHEN_TYPE_MSCHAP:
                if len(start.data) < 1 + 8 + 49 or secret is None:
                    return AuthenReplyBody(AUTHEN_STATUS_FAIL, server_msg="mschap-denied").to_bytes(), True
                ppp_id = start.data[0]
                challenge = start.data[1:-49]
                expected = build_mschapv1_data(ppp_id, challenge, secret)
                ok = hmac.compare_digest(start.data, expected)
                return (
                    AuthenReplyBody(
                        AUTHEN_STATUS_PASS if ok else AUTHEN_STATUS_FAIL,
                        server_msg="mschapv1-ok" if ok else "mschap-denied",
                    ).to_bytes(),
                    True,
                )
            if start.authen_type == AUTHEN_TYPE_MSCHAPV2:
                if len(start.data) < 1 + 16 + 49 or secret is None:
                    return AuthenReplyBody(AUTHEN_STATUS_FAIL, server_msg="mschapv2-denied").to_bytes(), True
                ppp_id = start.data[0]
                auth_challenge = start.data[1:-49]
                peer_challenge = start.data[-49:-33]
                expected = build_mschapv2_data(
                    ppp_id, auth_challenge, peer_challenge, start.user, secret
                )
                ok = hmac.compare_digest(start.data, expected)
                return (
                    AuthenReplyBody(
                        AUTHEN_STATUS_PASS if ok else AUTHEN_STATUS_FAIL,
                        server_msg="mschapv2-ok" if ok else "mschapv2-denied",
                    ).to_bytes(),
                    True,
                )

            return AuthenReplyBody(AUTHEN_STATUS_ERROR, server_msg="unsupported authen_type").to_bytes(), True

        # Continuing packet (seq_no >= 3, odd)
        state = sessions.get(pkt.session_id)
        if state is None or pkt.seq_no != state.expected_seq or minor != state.minor_version:
            sessions.pop(pkt.session_id, None)
            return AuthenReplyBody(AUTHEN_STATUS_ERROR, server_msg="invalid session state").to_bytes(), True

        cont = AuthenContinueBody.from_bytes(pkt.body)
        if (cont.flags & CONTINUE_FLAG_ABORT) != 0:
            sessions.pop(pkt.session_id, None)
            with self._lock:
                self.aborted_reasons.append(cont.data)
            # RFC 8907 Section 5.3: terminate the session and send NO REPLY message.
            return None, True

        answer = cont.user_msg.encode("utf-8") if cont.user_msg else cont.data
        if state.stage == "get_user":
            state.user = cont.user_msg
            state.stage = "get_pass"
            state.expected_seq += 2
            return (
                AuthenReplyBody(
                    AUTHEN_STATUS_GETPASS,
                    flags=REPLY_FLAG_NOECHO,
                    server_msg="Password: ",
                ).to_bytes(),
                False,
            )
        if state.stage == "get_pass":
            sessions.pop(pkt.session_id, None)
            secret = self.USERS.get(state.user)
            ok = secret is not None and hmac.compare_digest(answer, secret)
            return (
                AuthenReplyBody(
                    AUTHEN_STATUS_PASS if ok else AUTHEN_STATUS_FAIL,
                    server_msg="ascii-ok" if ok else "ascii-denied",
                ).to_bytes(),
                True,
            )
        if state.stage == "get_enable_pw":
            sessions.pop(pkt.session_id, None)
            ok = hmac.compare_digest(answer, self.ENABLE_SECRET)
            return (
                AuthenReplyBody(
                    AUTHEN_STATUS_PASS if ok else AUTHEN_STATUS_FAIL,
                    server_msg="enable-ok" if ok else "enable-denied",
                ).to_bytes(),
                True,
            )
        if state.stage == "get_old_pw":
            secret = self.USERS.get(state.user)
            state.old_password_ok = secret is not None and hmac.compare_digest(answer, secret)
            state.stage = "get_new_pw"
            state.expected_seq += 2
            return (
                AuthenReplyBody(
                    AUTHEN_STATUS_GETPASS,
                    flags=REPLY_FLAG_NOECHO,
                    server_msg="New Password: ",
                ).to_bytes(),
                False,
            )
        if state.stage == "get_new_pw":
            sessions.pop(pkt.session_id, None)
            ok = state.old_password_ok and len(answer) >= 8
            return (
                AuthenReplyBody(
                    AUTHEN_STATUS_PASS if ok else AUTHEN_STATUS_FAIL,
                    server_msg="chpass-ok" if ok else "chpass-denied",
                ).to_bytes(),
                True,
            )
        sessions.pop(pkt.session_id, None)
        return AuthenReplyBody(AUTHEN_STATUS_ERROR, server_msg="unknown stage").to_bytes(), True

    def _handle_authorization(self, pkt: RawPacket, minor: int) -> bytes:
        if pkt.seq_no != 1 or minor != MINOR_VER_DEFAULT:
            return AuthorReplyBody(
                AUTHOR_STATUS_ERROR, server_msg="invalid authorization header"
            ).to_bytes()
        req = AuthorRequestBody.from_bytes(pkt.body)
        if not req.args or any(("=" not in arg and "*" not in arg) for arg in req.args):
            return AuthorReplyBody(
                AUTHOR_STATUS_ERROR, server_msg="invalid authorization AV-pairs"
            ).to_bytes()

        if "cmd=reload" in req.args:
            return AuthorReplyBody(
                AUTHOR_STATUS_FAIL, server_msg="command denied"
            ).to_bytes()
        if "cmd=rewrite" in req.args:
            return AuthorReplyBody(
                AUTHOR_STATUS_PASS_REPL,
                server_msg="replaced",
                args=("service=shell", "cmd=show", "cmd-arg=running-config"),
            ).to_bytes()
        if "cmd=trigger-error" in req.args:
            return AuthorReplyBody(
                AUTHOR_STATUS_ERROR, server_msg="authorization backend error"
            ).to_bytes()
        if "cmd=trigger-follow" in req.args:
            return AuthorReplyBody(
                AUTHOR_STATUS_FOLLOW, server_msg="follow"
            ).to_bytes()
        return AuthorReplyBody(
            AUTHOR_STATUS_PASS_ADD,
            server_msg="authorized",
            args=("priv-lvl=15",),
        ).to_bytes()

    def _handle_accounting(self, pkt: RawPacket, minor: int) -> bytes:
        if pkt.seq_no != 1 or minor != MINOR_VER_DEFAULT:
            return AcctReplyBody(
                ACCT_STATUS_ERROR, server_msg="invalid accounting header"
            ).to_bytes()
        req = AcctRequestBody.from_bytes(pkt.body)
        valid_mask = ACCT_FLAG_START | ACCT_FLAG_STOP | ACCT_FLAG_WATCHDOG
        # RFC 8907 Section 7.1: START and STOP are mutually exclusive, and at least one flag must be set.
        if (
            req.flags == 0
            or (req.flags & ~valid_mask) != 0
            or ((req.flags & ACCT_FLAG_START) != 0 and (req.flags & ACCT_FLAG_STOP) != 0)
        ):
            return AcctReplyBody(
                ACCT_STATUS_ERROR, server_msg="invalid accounting flags"
            ).to_bytes()
        if any(("=" not in arg and "*" not in arg) for arg in req.args):
            return AcctReplyBody(
                ACCT_STATUS_ERROR, server_msg="invalid accounting AV-pairs"
            ).to_bytes()

        with self._lock:
            self.accounting_records.append(req)

        if "event=trigger-error" in req.args:
            return AcctReplyBody(ACCT_STATUS_ERROR, server_msg="accounting backend error").to_bytes()
        if "event=trigger-follow" in req.args:
            return AcctReplyBody(ACCT_STATUS_FOLLOW, server_msg="follow").to_bytes()
        return AcctReplyBody(ACCT_STATUS_SUCCESS, server_msg="recorded").to_bytes()
