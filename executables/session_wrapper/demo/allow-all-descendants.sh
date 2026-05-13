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

cat >"$tmp/allow-all-descendant-command" <<'EOF'
#!/bin/sh
set -eu

echo "[wrapped] initial shell pid=$$"
(
  sleep 1
  /bin/sh -c 'echo "[descendant] exec continued after initial shell exited"; printf "allow-all-descendant-ok\n" > "$SESSION_WRAPPER_DESCENDANT_MARKER"'
) &

echo "[wrapped] exiting initial shell while descendant continues"
exit 0
EOF
chmod +x "$tmp/allow-all-descendant-command"

echo "[demo] starting wrapped command with descendant supervision"
SESSION_WRAPPER_DESCENDANT_MARKER="$tmp/descendant-marker" \
timeout 10s target/debug/session-wrapper \
  --user "$(id -un)" \
  --user-uid "$(id -u)" \
  --user-gid "$(id -g)" \
  --fail-policy open \
  -- "$tmp/allow-all-descendant-command" "demo-command-context"

if [[ "$(cat "$tmp/descendant-marker")" != "allow-all-descendant-ok" ]]; then
  echo "[demo] descendant marker was not written" >&2
  exit 1
fi

echo "[demo] descendant allow-all demo succeeded"
