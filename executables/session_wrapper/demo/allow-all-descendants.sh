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

cat >"$tmp/allow-all-descendant-command" <<'EOF'
#!/bin/sh
set -eu

echo "[wrapped] initial shell pid=$$"
(
  sleep 1
  /bin/sh -c 'echo "[descendant] The supervisor continued the exec call after the initial shell exited."; printf "allow-all-descendant-ok\n" > "$SESSION_WRAPPER_DESCENDANT_MARKER"'
) &

echo "[wrapped] The initial shell exits. The descendant continues."
exit 0
EOF
chmod +x "$tmp/allow-all-descendant-command"

echo "[demo] Start the wrapped command with descendant supervision."
SESSION_WRAPPER_DESCENDANT_MARKER="$tmp/descendant-marker" \
timeout 10s target/debug/session-wrapper \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  --fail-policy open \
  -- "$tmp/allow-all-descendant-command" "demo-command-context"

if [[ "$(cat "$tmp/descendant-marker")" != "allow-all-descendant-ok" ]]; then
  echo "[demo] The descendant did not write the marker." >&2
  exit 1
fi

echo "[demo] The descendant allow-all demo succeeded."
