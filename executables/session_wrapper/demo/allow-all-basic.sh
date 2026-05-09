#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root"

if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  echo "session-wrapper demos require Linux x86_64" >&2
  exit 1
fi

echo "[demo] building session-wrapper"
cargo build -p session-wrapper

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/allow-all-basic-shell" <<'EOF'
#!/bin/sh
set -eu

echo "[wrapped] running as user=$(id -un) uid=$(id -u) gid=$(id -g)"
echo "[wrapped] every execve is being continued by the current allow-all supervisor"
printf 'allow-all-basic-ok\n' > "$SESSION_WRAPPER_DEMO_MARKER"
EOF
chmod +x "$tmp/allow-all-basic-shell"

echo "[demo] starting wrapped non-interactive shell"
SESSION_WRAPPER_DEMO_MARKER="$tmp/marker" \
timeout 10s target/debug/session-wrapper \
  --shell "$tmp/allow-all-basic-shell" \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  -- "$tmp/allow-all-basic-shell" "demo-command-context"

if [[ "$(cat "$tmp/marker")" != "allow-all-basic-ok" ]]; then
  echo "[demo] marker was not written by the wrapped process" >&2
  exit 1
fi

echo "[demo] allow-all basic demo succeeded"
