#!/usr/bin/env python3
"""Expand the ietf-system-tacacs-plus YANG module into a fully resolved tree.

This script clones the required YANG module repositories (if not already
cached), then runs pyang to produce the expanded tree with all grouping
references from ietf-keystore, ietf-truststore, ietf-tls-client,
ietf-crypto-types, etc. fully inlined.

Prerequisites:
    pip install pyang

Usage:
    python expand_yang_tree.py                  # prints to stdout
    python expand_yang_tree.py -o tree.txt      # writes to file
    python expand_yang_tree.py --format jstree  # alternate pyang format
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TACACS_YANG_REPO = "https://github.com/IETF-OPSAWG-WG/secure-tacacs-yang.git"
YANG_MODELS_REPO = "https://github.com/YangModels/yang.git"

TACACS_MODULE = "ietf-system-tacacs-plus.yang"

SCRIPT_DIR = Path(__file__).resolve().parent
CACHE_DIR = SCRIPT_DIR / ".yang-cache"


def _run(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs)


def ensure_repo(url: str, name: str, sparse_paths: list[str] | None = None) -> Path:
    """Clone a repo into the cache directory (shallow, optionally sparse)."""
    dest = CACHE_DIR / name
    if dest.exists():
        return dest

    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if sparse_paths:
        _run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse", url, str(dest)])
        _run(["git", "sparse-checkout", "set"] + sparse_paths, cwd=str(dest))
    else:
        _run(["git", "clone", "--depth", "1", url, str(dest)])

    return dest


def find_pyang() -> str:
    """Return the pyang executable path, or exit with an error."""
    pyang = shutil.which("pyang")
    if pyang is None:
        print("error: pyang is not installed. Run: pip install pyang", file=sys.stderr)
        sys.exit(1)
    return pyang


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", type=Path, default=None, help="Write output to file instead of stdout")
    parser.add_argument("-f", "--format", default="tree", help="pyang output format (default: tree)")
    parser.add_argument("--depth", type=int, default=20, help="Tree depth limit (default: 20)")
    parser.add_argument("--clean", action="store_true", help="Remove cached repos and re-clone")
    args = parser.parse_args()

    if args.clean and CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
        print(f"Removed cache directory: {CACHE_DIR}", file=sys.stderr)

    pyang = find_pyang()

    # Clone required repos
    print("Fetching YANG modules (cached after first run)...", file=sys.stderr)
    tacacs_repo = ensure_repo(TACACS_YANG_REPO, "secure-tacacs-yang")
    yang_models = ensure_repo(YANG_MODELS_REPO, "yang-models", sparse_paths=["standard/ietf/RFC"])

    # Build search paths
    tacacs_yang_dir = tacacs_repo / "yang"
    rfc_yang_dir = yang_models / "standard" / "ietf" / "RFC"

    tacacs_module = tacacs_yang_dir / TACACS_MODULE
    if not tacacs_module.exists():
        print(f"error: {tacacs_module} not found", file=sys.stderr)
        sys.exit(1)

    # Run pyang
    cmd = [
        pyang,
        "-f", args.format,
        "--tree-depth", str(args.depth),
        "-p", str(rfc_yang_dir),
        "-p", str(tacacs_yang_dir),
        str(tacacs_module),
    ]

    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.stderr:
        print(result.stderr, file=sys.stderr)

    if result.returncode != 0:
        print(f"pyang exited with code {result.returncode}", file=sys.stderr)
        sys.exit(result.returncode)

    if args.output:
        args.output.write_text(result.stdout, encoding="utf-8")
        print(f"Wrote expanded tree to {args.output}", file=sys.stderr)
    else:
        print(result.stdout)


if __name__ == "__main__":
    main()
