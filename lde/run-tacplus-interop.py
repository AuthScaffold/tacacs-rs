#!/usr/bin/env python3
"""Run opt-in client tests against a native tac_plus-ng process."""

import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "lde/containers/config/tac_plus.cfg"
CASES = {
    "baseline": ["tcp_operations", "certificate_tls_operations", "client_certificate_tls_operations", "psk_dhe_operations"],
    "mutual-tls": ["client_certificate_tls_operations", "missing_client_certificate_is_rejected"],
    "psk-only": ["psk_only_operations"],
    "sha384": ["psk_sha384_operations"],
    "plain-tcp": ["plain_tcp_operations"],
}


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"Fixture anchor must occur exactly once: {old}")
    return text.replace(old, new, 1)


def configuration(mode):
    text = FIXTURE.read_text(encoding="utf-8")
    addresses = {}
    reservations = []
    try:
        for name, port in [("TCP", 4949), ("TLS", 4449), ("PSK", 4450)]:
            reservation = socket.socket()
            reservation.bind(("127.0.0.1", 0))
            reservations.append(reservation)
            selected = reservation.getsockname()[1]
            addresses[f"TACPLUS_{name}_ADDR"] = f"127.0.0.1:{selected}"
            text = replace_once(text, f"listen {{ port = {port}",
                                f"listen {{ address = 127.0.0.1 port = {selected}")
    finally:
        for reservation in reservations:
            reservation.close()
    text = text.replace("/usr/local/etc/certificates/", f"{FIXTURE.parent}/certificates/")
    if mode == "mutual-tls":
        text = replace_once(text, "tls.peer.cert.validation = none", "tls.peer.cert.validation = cert")
    if mode == "psk-only":
        text = replace_once(text, "tls psk dhe-supported-groups = X25519:P-256",
                            "tls psk dhe-supported-groups = P-224")
    if mode == "sha384":
        text = replace_once(text, "tls cipher-suites = TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
                            "tls cipher-suites = TLS_AES_256_GCM_SHA384")
    if mode == "plain-tcp":
        text = replace_once(text, "device world {", "device world {\n    bug compatibility = 64")
    return text, addresses


def wait_ready(process, address):
    host, port = address.rsplit(":", 1)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"tac_plus-ng exited during startup ({process.returncode})")
        try:
            with socket.create_connection((host, int(port)), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"tac_plus-ng did not bind {address}")


def run_mode(binary, mode, work, environment):
    text, addresses = configuration(mode)
    config = work / f"{mode}.cfg"
    config.write_text(text, encoding="utf-8")
    subprocess.run([str(binary), "-P", str(config)], env=environment, check=True, timeout=10)
    with (work / f"{mode}.log").open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            [str(binary), "-f", "-1", "-p", str(work / f"{mode}.pid"), str(config)],
            env=environment, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            for address in addresses.values():
                wait_ready(process, address)
            for case in CASES[mode]:
                print(f"Checking {mode}: {case}", flush=True)
                subprocess.run(
                    ["cargo", "test", "-p", "tacacsrs-agentd", "--test", "tacplus_interop", "--locked",
                     "--", "--ignored", "--exact", case, "--test-threads=1"],
                    cwd=ROOT, env={**environment, **addresses}, check=True, timeout=180,
                )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def parse_args(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    default_binary = os.environ.get("TACPLUS_SERVER_BINARY")
    parser.add_argument(
        "--server-binary", required=not default_binary, default=default_binary, type=Path,
        help="Server executable (default: TACPLUS_SERVER_BINARY)",
    )
    parser.add_argument(
        "--library-dir", default=os.environ.get("TACPLUS_LIBRARY_DIR"), type=Path,
        help="Native libmavis directory (default: TACPLUS_LIBRARY_DIR)",
    )
    parser.add_argument("--mode", choices=["all", *CASES], default="all")
    return parser.parse_args(arguments)


def main():
    args = parse_args()
    environment = os.environ.copy()
    if args.library_dir:
        environment["LD_LIBRARY_PATH"] = os.pathsep.join(filter(None, [
            str(args.library_dir.resolve()), environment.get("LD_LIBRARY_PATH"),
        ]))
    work = Path(tempfile.mkdtemp(prefix="tacacs-rs-peer-run-"))
    print(f"Server logs and generated configurations: {work}", flush=True)
    subprocess.run([str(args.server_binary.resolve()), "-v"], env=environment, check=True, timeout=10)
    subprocess.run(
        ["cargo", "test", "-p", "tacacsrs-agentd", "--test", "tacplus_interop", "--locked", "--no-run"],
        cwd=ROOT, env=environment, check=True, timeout=600,
    )
    modes = CASES if args.mode == "all" else [args.mode]
    for mode in modes:
        run_mode(args.server_binary.resolve(), mode, work, environment)


if __name__ == "__main__":
    main()