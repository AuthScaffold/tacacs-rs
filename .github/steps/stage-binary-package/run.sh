#!/usr/bin/env bash
# Stage the built artifact into the package directory WITHOUT stripping it.
#
# Stripping and debug-symbol extraction belong to package-debug-symbols, which
# must read the full unstripped binary to keep the embedded DWARF. This script
# only copies the artifact, so the later symbols step still sees the debug info.
#
# Every input arrives through the environment so no caller data reaches the
# shell as code:
#   TARGET             Rust target triple that was built.
#   PROFILE            Cargo profile directory name (release or debug).
#   ARTIFACT_FILENAME  File name of the built artifact.
#   PACKAGE_DIR        Directory that receives the staged package contents.
#   CARGO_TARGET_DIR   Optional build output root. It defaults to "target" so
#                      the in-tree CI build and an out-of-tree rehearsal build
#                      share one script.
#   RUNNER_OS          Optional GitHub runner OS. An unset value means a
#                      non-Windows host, which is also the rehearsal default.
set -euo pipefail

: "${TARGET:?TARGET must be set}"
: "${PROFILE:?PROFILE must be set}"
: "${ARTIFACT_FILENAME:?ARTIFACT_FILENAME must be set}"
: "${PACKAGE_DIR:?PACKAGE_DIR must be set}"

target_root="${CARGO_TARGET_DIR:-target}"
artifact_path="${target_root}/${TARGET}/${PROFILE}/${ARTIFACT_FILENAME}"

mkdir -p "$PACKAGE_DIR" packaged

if [ ! -f "$artifact_path" ]; then
  echo "Error: the expected artifact does not exist at $artifact_path." >&2
  exit 1
fi

cp "$artifact_path" "$PACKAGE_DIR/${ARTIFACT_FILENAME}"

if [ "${RUNNER_OS:-}" != "Windows" ]; then
  chmod +x "$PACKAGE_DIR/${ARTIFACT_FILENAME}"
fi
