#!/usr/bin/env python3
"""Exercise product TCP binding in disposable Linux user and network namespaces.

The host network, routes, and interfaces remain unchanged. Python 3, iproute2,
unshare, nftables, and permission to create user namespaces are required.
"""

import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import threading
import time


def ip(*args):
    subprocess.run(["ip", *args], check=True)


def require_disposable_namespaces():
    for kind, key in [
        ("net", "TACACSRS_BINDING_ORIGINAL_NETNS"),
        ("user", "TACACSRS_BINDING_ORIGINAL_USERNS"),
    ]:
        original = os.environ.get(key)
        current = str(os.stat(f"/proc/self/ns/{kind}").st_ino)
        if not original or original == current:
            raise RuntimeError("The binding lab requires its own disposable user and network namespaces")


def peer():
    require_disposable_namespaces()
    print("ready", flush=True)
    assert sys.stdin.readline().strip() == "configure"
    ip("link", "set", "lo", "up")
    for device, v4, v6 in [
        ("mgmt-peer", "192.0.2.2/24", "2001:db8:1::2/64"),
        ("data-peer", "203.0.113.2/24", "2001:db8:2::2/64"),
        ("stand-peer", "198.18.1.2/24", "2001:db8:4::2/64"),
        ("vrf-peer", "192.0.5.2/24", "2001:db8:6::2/64"),
    ]:
        ip("link", "set", device, "up")
        ip("address", "add", v4, "dev", device)
        ip("-6", "address", "add", v6, "dev", device, "nodad")
    ip("address", "add", "198.51.100.49/32", "dev", "lo")
    ip("-6", "address", "add", "2001:db8:ffff::49/128", "dev", "lo", "nodad")
    ip("route", "add", "198.18.0.1/32", "via", "203.0.113.1")
    ip("-6", "route", "add", "2001:db8:3::1/128", "via", "2001:db8:2::1")
    # Accept asymmetric source/egress tests without changing host sysctls.
    for name in ["all", "default", "mgmt-peer", "data-peer", "stand-peer", "vrf-peer"]:
        Path(f"/proc/sys/net/ipv4/conf/{name}/rp_filter").write_text("0")
    # These rejects come from the remote peer. The client's FIB remains valid.
    subprocess.run(["nft", "-f", "-"], input="""
table inet tacacs_binding_lab {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "stand-peer" meta nfproto ipv4 tcp dport 49492 reject with icmp type host-unreachable
        iifname "stand-peer" meta nfproto ipv6 tcp dport 49492 reject with icmpv6 type no-route
        iifname "stand-peer" tcp dport 49493 drop
    }
}
""", text=True, check=True)

    observed = {}
    lock = threading.Lock()
    captures = []
    for device in ["mgmt-peer", "data-peer", "stand-peer", "vrf-peer"]:
        capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        capture.bind((device, 0))
        captures.append(capture)

    def capture_syn():
        while True:
            readable, _, _ = select.select(captures, [], [])
            for capture in readable:
                packet = capture.recv(65535)
                protocol = struct.unpack("!H", packet[12:14])[0]
                if protocol == 0x0800 and len(packet) >= 54 and packet[23] == 6:
                    offset = 14 + (packet[14] & 15) * 4
                    source = socket.inet_ntop(socket.AF_INET, packet[26:30])
                elif protocol == 0x86DD and len(packet) >= 74 and packet[20] == 6:
                    offset = 54
                    source = socket.inet_ntop(socket.AF_INET6, packet[22:38])
                else:
                    continue
                if packet[offset + 13] & 0x12 == 0x02:
                    source_port, destination_port = struct.unpack("!HH", packet[offset:offset + 4])
                    if destination_port in (49490, 49491, 49492, 49493):
                        with lock:
                            observed[(source, source_port)] = capture.getsockname()[0]

    threading.Thread(target=capture_syn, daemon=True).start()
    listeners = []
    for family, host in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
        for port in (49490, 49491, 49492, 49493):
            listener = socket.socket(family, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            if port in (49491, 49492, 49493):
                # The management path refuses this port. Incorrect fallback
                # would reach this data-only listener and fail the Rust test.
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"data-peer\0")
            listener.bind((host, port))
            listener.listen()
            listeners.append(listener)
    print("listening", flush=True)
    while True:
        readable, _, _ = select.select(listeners, [], [])
        for listener in readable:
            stream, remote = listener.accept()
            with stream:
                key = remote[:2]
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    with lock:
                        device = observed.pop(key, None)
                    if device:
                        break
                    time.sleep(0.001)
                assert device, f"No ingress SYN capture for {key}"
                stream.sendall(f"{remote[0]} {device}\n".encode())


def lab(executable):
    require_disposable_namespaces()
    child = subprocess.Popen(
        ["unshare", "--net", sys.executable, __file__, "--peer"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    try:
        assert child.stdout.readline().strip() == "ready"
        ip("link", "set", "lo", "up")
        ip("link", "add", "mgmt-vrf", "type", "vrf", "table", "100")
        ip("link", "set", "mgmt-vrf", "up")
        ip("link", "add", "down0", "type", "dummy")
        ip("link", "set", "down0", "master", "mgmt-vrf")
        ip("link", "add", "unused0", "type", "dummy")
        ip("link", "set", "unused0", "master", "mgmt-vrf")
        ip("link", "set", "unused0", "up")
        ip("-6", "address", "add", "2001:db8:7::1/64", "dev", "unused0", "nodad")
        for device, other, v4, v6 in [
            ("mgmt0", "mgmt-peer", "192.0.2.1/24", "2001:db8:1::1/64"),
            ("data0", "data-peer", "203.0.113.1/24", "2001:db8:2::1/64"),
            ("standalone0", "stand-peer", "198.18.1.1/24", "2001:db8:4::1/64"),
            ("vrf-alt0", "vrf-peer", "192.0.5.1/24", "2001:db8:6::1/64"),
        ]:
            ip("link", "add", device, "type", "veth", "peer", "name", other)
            ip("link", "set", other, "netns", str(child.pid))
            if device in ("mgmt0", "vrf-alt0"):
                ip("link", "set", device, "master", "mgmt-vrf")
            ip("link", "set", device, "up")
            ip("address", "add", v4, "dev", device)
            ip("-6", "address", "add", v6, "dev", device, "nodad")
        ip("link", "add", "source0", "type", "dummy")
        ip("link", "set", "source0", "up")
        ip("address", "add", "198.18.0.1/32", "dev", "source0")
        ip("-6", "address", "add", "2001:db8:3::1/128", "dev", "source0", "nodad")
        for family, server, mgmt, data in [
            ("-4", "198.51.100.49/32", "192.0.2.2", "203.0.113.2"),
            ("-6", "2001:db8:ffff::49/128", "2001:db8:1::2", "2001:db8:2::2"),
        ]:
            ip(family, "route", "add", server, "via", mgmt, "dev", "mgmt0", "table", "100")
            ip(family, "route", "add", server, "via", data, "dev", "data0", "metric", "10")
            standalone = "198.18.1.2" if family == "-4" else "2001:db8:4::2"
            ip(family, "route", "add", server, "via", standalone, "dev", "standalone0", "metric", "100")
        for name in ["all", "default", "mgmt0", "data0", "standalone0", "vrf-alt0", "unused0"]:
            Path(f"/proc/sys/net/ipv4/conf/{name}/rp_filter").write_text("0")
        layout = os.environ.get("TACACSRS_NONPREFERRED_LAYOUT")
        if layout:
            assert layout in ("metric", "prefix")
            ip("-6", "route", "del", "2001:db8:ffff::49/128", "dev", "data0", "metric", "10")
            ip("-6", "route", "del", "2001:db8:ffff::49/128", "dev", "standalone0", "metric", "100")
            ip("-6", "route", "del", "table", "100", "2001:db8:ffff::49/128")
            preferred = "default" if layout == "metric" else "2001:db8:ffff::49/128"
            ip("-6", "route", "add", preferred, "via", "2001:db8:2::2", "dev", "data0", "metric", "100")
            ip("-6", "route", "add", "default", "via", "2001:db8:4::2", "dev", "standalone0", "metric", "1024")
            ip("-6", "route", "add", preferred, "via", "2001:db8:6::2", "dev", "vrf-alt0", "table", "100", "metric", "100")
            ip("-6", "route", "add", "default", "via", "2001:db8:1::2", "dev", "mgmt0", "table", "100", "metric", "1024")
        child.stdin.write("configure\n")
        child.stdin.flush()
        assert child.stdout.readline().strip() == "listening"
        command = [
            executable, "binding::tests_linux::namespace_client", "--exact", "--ignored", "--nocapture"
        ]
        subprocess.run(
            ["setpriv", "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", *command],
            env={**os.environ, "TACACSRS_BINDING_LAB": "1", "TACACSRS_BINDING_LAB_READONLY": "1"},
            check=True, timeout=60,
        )
        subprocess.run(
            command,
            env={**os.environ, "TACACSRS_BINDING_LAB": "1"}, check=True, timeout=60,
        )
    finally:
        child.terminate()
        child.wait(timeout=5)


def main():
    if sys.argv[1:] == ["--peer"]:
        peer()
    elif sys.argv[1:2] == ["--lab"]:
        lab(sys.argv[2])
    else:
        build = subprocess.run(
            ["cargo", "test", "-p", "tacacsrs-networking", "--lib", "--no-run", "--message-format=json"],
            text=True, stdout=subprocess.PIPE,
        )
        messages = [json.loads(line) for line in build.stdout.splitlines()]
        if build.returncode:
            for message in messages:
                if message.get("reason") == "compiler-message":
                    print(message["message"].get("rendered", ""), file=sys.stderr, end="")
            raise subprocess.CalledProcessError(build.returncode, build.args)
        executable = next(
            message["executable"] for message in messages if message.get("executable")
        )
        cases = [{}] if (
            os.environ.get("TACACSRS_NONPREFERRED_LAYOUT")
            or os.environ.get("TACACSRS_TCP_POLICY_LAB")
        ) else [
            {},
            {"TACACSRS_NONPREFERRED_LAYOUT": "metric"},
            {"TACACSRS_NONPREFERRED_LAYOUT": "prefix"},
            {"TACACSRS_TCP_POLICY_LAB": "1"},
        ]
        for case in cases:
            print(f"Linux binding lab case: {case or 'baseline'}", flush=True)
            subprocess.run(
                ["unshare", "--user", "--map-root-user", "--net",
                 sys.executable, __file__, "--lab", executable], check=True, timeout=90,
                env={
                    **os.environ,
                    **case,
                    "TACACSRS_BINDING_ORIGINAL_NETNS": str(os.stat("/proc/self/ns/net").st_ino),
                    "TACACSRS_BINDING_ORIGINAL_USERNS": str(os.stat("/proc/self/ns/user").st_ino),
                },
            )


if __name__ == "__main__":
    main()
