"""Compare notification APIs on private Linux datagram sockets."""

import argparse
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time


def child(binary, candidate, address):
    environment = dict(os.environ)
    environment["NOTIFY_SOCKET"] = address
    environment["TACACSRS_NOTIFICATION_PROBE"] = "private-socket-only"
    return subprocess.Popen(
        [str(binary), candidate],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def finish(process, seconds):
    started = time.monotonic()
    timed_out = False
    wait_channel = None
    try:
        stdout, stderr = process.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        wait_channel = Path(f"/proc/{process.pid}/wchan").read_text().strip()
        process.kill()
        stdout, stderr = process.communicate(timeout=2)
    assert process.poll() is not None, "owned child must be reaped"
    return {
        "pid": process.pid,
        "exit": process.returncode,
        "timed_out": timed_out,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "stdout": stdout.decode().strip(),
        "stderr": stderr.decode().strip(),
        "reaped": True,
        "wait_channel_before_kill": wait_channel,
    }


def normal(binary, candidate, receiver, environment_address):
    process = child(binary, candidate, environment_address)
    result = finish(process, 1)
    if result["exit"] == 0:
        data, ancillary, flags, _ = receiver.recvmsg(4096, socket.CMSG_SPACE(12))
        assert flags == 0
        credentials = [
            struct.unpack("3i", value)
            for level, kind, value in ancillary
            if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS
        ]
        assert credentials == [(process.pid, os.getuid(), os.getgid())]
        assert data == b"READY=1\n"
        result["attributed_to_sender"] = True
        result["payload"] = data.decode().strip()
    return result


def pressure(binary, candidate, receiver, kernel_address, environment_address):
    with ExitStack() as sockets:
        queued = 0
        fillers = 0
        for _ in range(64):
            filler = sockets.enter_context(socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM))
            filler.setblocking(False)
            fillers += 1
            sent = 0
            for _ in range(65536):
                try:
                    filler.sendto(b"private-queue-filler", kernel_address)
                    queued += 1
                    sent += 1
                except BlockingIOError as error:
                    assert error.errno in (errno.EAGAIN, errno.EWOULDBLOCK)
                    break
            else:
                raise AssertionError("receiver queue did not reach pressure")
            # A fresh sender has an empty send buffer. Its EAGAIN proves that
            # the receiver queue is full, not merely a prior sender's buffer.
            if sent == 0:
                break
        else:
            raise AssertionError("fresh sender did not confirm receiver pressure")
        # Keep every filler alive. No receive call occurs before termination.
        process = child(binary, candidate, environment_address)
        result = finish(process, 0.75)
    result["queued_datagrams"] = queued
    result["filler_sockets"] = fillers
    result["fresh_sender_eagain"] = True
    result["receiver_did_not_drain"] = True
    assert queued > 0
    assert "notification started" in result["stderr"]
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    arguments = parser.parse_args()
    binary = arguments.binary.resolve(strict=True)
    directory = Path(f".notify-probe-{os.getpid()}").resolve()
    directory.mkdir(mode=0o700)
    results = []
    try:
        for candidate in ("sd-notify", "libsystemd"):
            for address_kind in ("pathname", "abstract"):
                name = f"tacacsrs-iteration16-{os.getpid()}-{candidate}-{address_kind}"
                path = directory / f"{candidate}.sock"
                kernel_address = str(path) if address_kind == "pathname" else "\0" + name
                environment_address = str(path) if address_kind == "pathname" else "@" + name
                with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
                    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                    receiver.settimeout(1)
                    receiver.bind(kernel_address)
                    result = normal(binary, candidate, receiver, environment_address)
                    results.append(
                        dict(candidate=candidate, address=address_kind, case="normal", **result)
                    )
                    if result["exit"] == 0:
                        result = pressure(
                            binary, candidate, receiver, kernel_address, environment_address
                        )
                        results.append(
                            dict(candidate=candidate, address=address_kind, case="pressure", **result)
                        )
                if path.exists():
                    path.unlink()
    finally:
        for path in directory.iterdir():
            path.unlink()
        directory.rmdir()
    print(json.dumps(results, indent=2))
    cases = {(r["candidate"], r["address"], r["case"]): r for r in results}
    assert cases["sd-notify", "pathname", "normal"]["exit"] == 0
    assert cases["sd-notify", "abstract", "normal"]["exit"] == 1
    assert cases["libsystemd", "pathname", "normal"]["exit"] == 0
    assert cases["libsystemd", "abstract", "normal"]["exit"] == 0
    for candidate, address in (
        ("sd-notify", "pathname"),
        ("libsystemd", "pathname"),
        ("libsystemd", "abstract"),
    ):
        assert cases[candidate, address, "pressure"]["timed_out"]
        assert cases[candidate, address, "pressure"]["exit"] == -9
    print("characterization passed: 7 cases, 0 skips; both candidates fail acceptance")


if __name__ == "__main__":
    main()
