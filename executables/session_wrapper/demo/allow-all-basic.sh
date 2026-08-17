#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "The session-wrapper demos require Linux x86_64." >&2
  exit 1
fi

echo "[demo] Run the build for session-wrapper."
cargo build -p session-wrapper

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/allow-all-basic-command" <<'EOF'
#!/bin/sh
set -eu

echo "[wrapped] user=$(id -un) uid=$(id -u) gid=$(id -g)"
echo "[wrapped] The current allow-all supervisor continues each execve call."
printf 'allow-all-basic-ok\n' > "$SESSION_WRAPPER_DEMO_MARKER"
EOF
chmod +x "$tmp/allow-all-basic-command"

echo "[demo] Start the wrapped non-interactive command."
SESSION_WRAPPER_DEMO_MARKER="$tmp/marker" \
timeout 10s target/debug/session-wrapper \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  --fail-policy open \
  -- "$tmp/allow-all-basic-command" "demo-command-context"

if [[ "$(cat "$tmp/marker")" != "allow-all-basic-ok" ]]; then
  echo "[demo] The wrapped process did not write the marker." >&2
  exit 1
fi

echo "[demo] The basic allow-all demo succeeded."
