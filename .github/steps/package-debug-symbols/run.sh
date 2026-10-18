#!/usr/bin/env bash
# Package debug symbols for a native ELF artifact (executable or shared object).
#
# This runs AFTER stage-binary-package, which copies the artifact into
# PACKAGE_DIR WITHOUT stripping it. For a release build this script:
#   1. copies the DWARF debug info out of the original build artifact into
#      PACKAGE_DIR/<artifact>.debug,
#   2. strips the staged copy in PACKAGE_DIR (its dynamic symbol table, and so
#      the shared-library exports, survive a plain strip), and
#   3. adds a .gnu_debuglink section so a debugger pairs the stripped binary
#      with its separate .debug file in the same directory.
# A debug build keeps the unstripped staged copy and gets no separate file.
# A split-DWARF .dwp package next to the build output is copied as-is for both
# profiles.
#
# Every input arrives through the environment so no caller data reaches the
# shell as code:
#   TARGET             Rust target triple that was built.
#   PROFILE            Cargo profile directory name (release or debug).
#   ARTIFACT_FILENAME  File name of the built artifact.
#   PACKAGE_DIR        Directory that holds the staged package contents.
#   CARGO_TARGET_DIR   Optional build output root. It defaults to "target" so
#                      the in-tree CI build and an out-of-tree rehearsal build
#                      share one script.
set -euo pipefail

: "${TARGET:?TARGET must be set}"
: "${PROFILE:?PROFILE must be set}"
: "${ARTIFACT_FILENAME:?ARTIFACT_FILENAME must be set}"
: "${PACKAGE_DIR:?PACKAGE_DIR must be set}"

target_root="${CARGO_TARGET_DIR:-target}"
build_dir="${target_root}/${TARGET}/${PROFILE}"
original="${build_dir}/${ARTIFACT_FILENAME}"
staged="${PACKAGE_DIR}/${ARTIFACT_FILENAME}"

if [ "$PROFILE" = "release" ]; then
  if [ ! -f "$original" ]; then
    echo "Error: the original build artifact does not exist at $original." >&2
    exit 1
  fi
  if [ ! -f "$staged" ]; then
    echo "Error: the staged artifact does not exist at $staged." >&2
    exit 1
  fi

  debug_file="${staged}.debug"
  # Keep the embedded DWARF in a separate file before the staged copy is
  # stripped. objcopy stores only the base name in the .gnu_debuglink section,
  # so the binary and its .debug file travel together inside PACKAGE_DIR.
  objcopy --only-keep-debug "$original" "$debug_file"
  strip "$staged"
  objcopy --add-gnu-debuglink="$debug_file" "$staged"
fi

# Keep a split-DWARF package when the build produced one next to the output.
for dwp in "${build_dir}/"*.dwp; do
  if [ -f "$dwp" ]; then
    cp "$dwp" "$PACKAGE_DIR/"
  fi
done
