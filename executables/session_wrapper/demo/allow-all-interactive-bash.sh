#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "session-wrapper demos require Linux x86_64" >&2
  exit 1
fi

shell_path="${SESSION_WRAPPER_DEMO_SHELL:-/bin/bash}"
if [[ "$shell_path" != /* ]]; then
  shell_path="$(command -v "$shell_path")"
fi

if [[ ! -x "$shell_path" ]]; then
  echo "shell is not executable: $shell_path" >&2
  exit 1
fi

echo "[demo] building session-wrapper"
cargo build -p session-wrapper

cat <<EOF
[demo] starting an interactive shell under session-wrapper
[demo] current authorization mode is allow-all; try commands such as:
[demo]   id
[demo]   bash -lc 'echo nested shell works'
[demo]   exit
EOF

exec target/debug/session-wrapper \
  --intercept-fork \
  --shell "$shell_path" \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  -- "$shell_path"
