#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The session-wrapper demos require Linux x86_64." >&2
  exit 1
fi

shell_path="${SESSION_WRAPPER_DEMO_SHELL:-/bin/bash}"
if [[ "$shell_path" != /* ]]; then
  shell_path="$(command -v "$shell_path")"
fi

if [[ ! -x "$shell_path" ]]; then
  echo "The shell is not executable: $shell_path" >&2
  exit 1
fi

echo "[demo] Run the build for session-wrapper."
cargo build -p session-wrapper

cat <<EOF
[demo] Start an interactive shell under session-wrapper.
[demo] The current authorization mode is allow-all. Run one of these commands:
[demo]   id
[demo]   bash -lc 'echo nested shell works'
[demo]   exit
EOF

exec target/debug/session-wrapper \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  --fail-policy open \
  -- "$shell_path"
