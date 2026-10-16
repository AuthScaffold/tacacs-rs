#!/usr/bin/env bash
# Create a gzip-compressed tar archive from the staged package directory.
#
# Every input arrives through the environment so no caller data reaches the
# shell as code:
#   ASSET_NAME   Platform-specific release asset name (the archive base name).
#   PACKAGE_DIR  Directory whose contents the archive captures.
set -euo pipefail

: "${ASSET_NAME:?ASSET_NAME must be set}"
: "${PACKAGE_DIR:?PACKAGE_DIR must be set}"

mkdir -p packaged
tar \
  -C "$(dirname "$PACKAGE_DIR")" \
  -czf "packaged/${ASSET_NAME}.tar.gz" \
  "$(basename "$PACKAGE_DIR")"
