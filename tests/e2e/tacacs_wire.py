"""Minimal RFC 8907 wire framing, MD5 obfuscation, and TLS 1.3 upstream peer helpers for E2E scenarios."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import hashlib
from pathlib import Path
import queue
import select
import socket
import ssl
import struct
import subprocess
import threading
from typing import Callable

HEADER_STRUCT = struct.Struct("!BBBBII")
TAC_PLUS_VERSION_1_0 = 0xC0

TAC_PLUS_AUTHEN = 1
TAC_PLUS_AUTHOR = 2
TAC_PLUS_ACCT = 3

TAC_PLUS_UNENCRYPTED_FLAG = 0x01
TAC_PLUS_SINGLE_CONNECT_FLAG = 0x04

AUTHEN_STATUS_PASS = 0x01
AUTHEN_STATUS_GETPASS = 0x05
AUTHEN_STATUS_ERROR = 0x07

AUTHOR_STATUS_PASS_ADD = 0x01

ACCT_STATUS_SUCCESS = 0x01
ACCT_STATUS_ERROR = 0x02


@dataclass(frozen=True)
class RawPacket:
    """Decoded TACACS+ frame with unobfuscated body bytes."""

    version: int
    tacacs_type: int
    seq_no: int
    flags: int
    session_id: int
    body: bytes


def recv_exact(stream: socket.socket, length: int) -> bytes:
    """Reads ``length`` bytes from ``stream`` or raises ``EOFError``."""
    buf = bytearray()
    while len(buf) < length:
        chunk = stream.recv(length - len(buf))
        if not chunk:
            raise EOFError(f"Expected {length} bytes, received {len(buf)} before EOF")
        buf.extend(chunk)
    return bytes(buf)


def xor_md5_body(
    session_id: int,
    version: int,
    seq_no: int,
    secret: bytes,
    body: bytes,
) -> bytes:
    """Applies RFC 8907 Section 4.5 MD5 pseudo-pad XOR obfuscation."""
    if not body:
        return b""
    prefix = session_id.to_bytes(4, "big") + secret + bytes([version, seq_no])
    out = bytearray(body)
    prev_digest = b""
    for offset in range(0, len(out), 16):
        digest = hashlib.md5(prefix + prev_digest).digest()
        block_end = min(offset + 16, len(out))
        for idx in range(offset, block_end):
            out[idx] ^= digest[idx - offset]
        prev_digest = digest
    return bytes(out)


def send_packet(
    stream: socket.socket,
    *,
    tacacs_type: int,
    seq_no: int,
    session_id: int,
    body: bytes,
    secret: bytes | None = None,
    single_connect: bool = False,
    minor_version: int = 0,
) -> None:
    """Writes one framed TACACS+ packet to ``stream``."""
    version = TAC_PLUS_VERSION_1_0 | (minor_version & 0x0F)
    flags = TAC_PLUS_SINGLE_CONNECT_FLAG if single_connect else 0
    if secret is None:
        flags |= TAC_PLUS_UNENCRYPTED_FLAG
        wire_body = body
    else:
        wire_body = xor_md5_body(session_id, version, seq_no, secret, body)
    header = HEADER_STRUCT.pack(
        version,
        tacacs_type,
        seq_no,
        flags,
        session_id,
        len(wire_body),
    )
    stream.sendall(header + wire_body)


def read_packet(stream: socket.socket, *, secret: bytes | None = None) -> RawPacket:
    """Reads one framed TACACS+ packet from ``stream`` and deobfuscates its body when needed."""
    raw_header = recv_exact(stream, HEADER_STRUCT.size)
    version, tacacs_type, seq_no, flags, session_id, length = HEADER_STRUCT.unpack(raw_header)
    wire_body = recv_exact(stream, length)
    if (flags & TAC_PLUS_UNENCRYPTED_FLAG) != 0:
        body = wire_body
    else:
        if secret is None:
            raise ValueError("Received obfuscated TACACS+ packet without a configured secret")
        body = xor_md5_body(session_id, version, seq_no, secret, wire_body)
    return RawPacket(
        version=version,
        tacacs_type=tacacs_type,
        seq_no=seq_no,
        flags=flags,
        session_id=session_id,
        body=body,
    )


def encode_authen_reply(status: int, server_msg: bytes = b"") -> bytes:
    """Encodes a TACACS+ Authentication REPLY body."""
    return struct.pack("!BBHH", status, 0, len(server_msg), 0) + server_msg


def decode_authen_status(packet: RawPacket) -> tuple[int, str]:
    """Extracts ``(status, server_msg)`` from an Authentication REPLY packet."""
    assert packet.tacacs_type == TAC_PLUS_AUTHEN
    status, _flags, msg_len, _data_len = struct.unpack("!BBHH", packet.body[:6])
    msg = packet.body[6 : 6 + msg_len].decode("utf-8", errors="replace")
    return status, msg


def encode_author_reply(status: int = AUTHOR_STATUS_PASS_ADD, server_msg: bytes = b"ok") -> bytes:
    """Encodes a TACACS+ Authorization RESPONSE body with zero arguments."""
    return struct.pack("!BBHH", status, 0, len(server_msg), 0) + server_msg


def decode_author_status(packet: RawPacket) -> tuple[int, str]:
    """Extracts ``(status, server_msg)`` from an Authorization RESPONSE packet."""
    assert packet.tacacs_type == TAC_PLUS_AUTHOR
    status, _arg_cnt, msg_len, _data_len = struct.unpack("!BBHH", packet.body[:6])
    msg = packet.body[6 : 6 + msg_len].decode("utf-8", errors="replace")
    return status, msg


def encode_acct_reply(status: int, server_msg: bytes = b"ok") -> bytes:
    """Encodes a TACACS+ Accounting REPLY body."""
    return struct.pack("!HHB", len(server_msg), 0, status) + server_msg


def decode_acct_status(packet: RawPacket) -> tuple[int, str]:
    """Extracts ``(status, server_msg)`` from an Accounting REPLY packet."""
    assert packet.tacacs_type == TAC_PLUS_ACCT
    msg_len, _data_len, status = struct.unpack("!HHB", packet.body[:5])
    msg = packet.body[5 : 5 + msg_len].decode("utf-8", errors="replace")
    return status, msg


UpstreamResponder = Callable[[RawPacket], bytes]


class ScriptedTlsUpstream:
    """Single-connect TLS 1.3 TACACS+ upstream server for black-box daemon tests."""

    def __init__(self, root: Path, responder: UpstreamResponder | None = None) -> None:
        self._responder = responder or self._default_responder
        cert_path = root / "upstream-cert.pem"
        key_path = root / "upstream-key.pem"
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
        self._tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self._tls_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self._listener.settimeout(0.2)
        self.port: int = int(self._listener.getsockname()[1])

        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.connections_accepted = 0
        self.received_packets: list[RawPacket] = []
        self.errors: list[Exception] = []
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)

    @staticmethod
    def _default_responder(request: RawPacket) -> bytes:
        if request.tacacs_type == TAC_PLUS_AUTHEN:
            if request.seq_no == 1:
                return encode_authen_reply(AUTHEN_STATUS_GETPASS, b"Password: ")
            return encode_authen_reply(AUTHEN_STATUS_PASS, b"authenticated")
        if request.tacacs_type == TAC_PLUS_AUTHOR:
            return encode_author_reply(AUTHOR_STATUS_PASS_ADD, b"authorized")
        if request.tacacs_type == TAC_PLUS_ACCT:
            return encode_acct_reply(ACCT_STATUS_SUCCESS, b"recorded")
        raise AssertionError(f"Unsupported TACACS+ packet type: {request.tacacs_type}")

    def start(self) -> None:
        self._accept_thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._accept_thread.join(timeout=5.0)
        for worker in self._threads:
            worker.join(timeout=5.0)
        self._listener.close()
        if self.errors:
            raise AssertionError(f"Upstream TLS server encountered errors: {self.errors!r}")

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
        reply_workers: list[threading.Thread] = []
        outbound: queue.Queue[tuple[RawPacket, bool, bytes]] = queue.Queue()
        wake_r, wake_w = socket.socketpair()
        try:
            with raw_conn, wake_r, wake_w:
                raw_conn.settimeout(15.0)
                with self._tls_ctx.wrap_socket(
                    raw_conn,
                    server_side=True,
                    do_handshake_on_connect=False,
                ) as tls_conn:
                    # Complete the TLS 1.3 handshake before entering the select loop.
                    tls_conn.do_handshake()
                    first_packet = True
                    while not self._stop.is_set():
                        while True:
                            try:
                                req, echo_sc, reply_body = outbound.get_nowait()
                            except queue.Empty:
                                break
                            send_packet(
                                tls_conn,
                                tacacs_type=req.tacacs_type,
                                seq_no=req.seq_no + 1,
                                session_id=req.session_id,
                                body=reply_body,
                                single_connect=echo_sc,
                                minor_version=req.version & 0x0F,
                            )

                        if tls_conn.pending() == 0:
                            readable, _, _ = select.select([tls_conn, wake_r], [], [], 0.1)
                            if wake_r in readable:
                                with contextlib.suppress(OSError):
                                    wake_r.recv(256)
                            if tls_conn not in readable and tls_conn.pending() == 0:
                                continue

                        try:
                            request = read_packet(tls_conn)
                        except (EOFError, ssl.SSLError, OSError):
                            break
                        assert (
                            request.flags & TAC_PLUS_UNENCRYPTED_FLAG
                        ) != 0, "RFC 9887 requires unobfuscated TACACS+ frames inside TLS"
                        advertise_sc = first_packet and (
                            (request.flags & TAC_PLUS_SINGLE_CONNECT_FLAG) != 0
                        )
                        first_packet = False
                        with self._lock:
                            self.received_packets.append(request)

                        def _reply_for(req: RawPacket, echo_sc: bool) -> None:
                            try:
                                body = self._responder(req)
                                outbound.put((req, echo_sc, body))
                                with contextlib.suppress(OSError):
                                    wake_w.send(b"\x01")
                            except Exception as exc:  # noqa: BLE001
                                if not self._stop.is_set():
                                    with self._lock:
                                        self.errors.append(exc)

                        worker = threading.Thread(
                            target=_reply_for,
                            args=(request, advertise_sc),
                            daemon=True,
                        )
                        reply_workers.append(worker)
                        worker.start()
                    for worker in reply_workers:
                        worker.join(timeout=5.0)
        except Exception as exc:  # noqa: BLE001
            if not self._stop.is_set():
                with self._lock:
                    self.errors.append(exc)
