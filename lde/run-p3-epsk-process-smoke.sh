#!/usr/bin/env bash
set -euo pipefail

# P3 EPSK process smoke.
#
# Drives a REAL TLS 1.3 EPSK TACACS+ exchange through tacacsrs-agentd against a
# tac_plus-ng upstream started on loopback from lde/containers/compose.yml,
# exercising EPSK bootstrap, immutable-ID and same-ID rotation, rejected-
# candidate fallback, readiness, redaction, and bounded shutdown.
#
# Must run as root in a disposable Linux environment with redis-server,
# redis-cli, podman (with the compose plugin), and xxd available.
#
# Assumptions to confirm when first run in a new environment:
#   * tac_plus-ng interprets `tls psk key` as HEX, so the EPSK object holds the
#     16 raw bytes decoded from the container key. If it uses the key as literal
#     ASCII, run with PSK_RAW=1 to store the key string verbatim instead.
#   * The proxy downstream defaults to unobfuscated, so tacon connects without a
#     shared secret using the plain-tcp validation relaxation.

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

redis_port="${REDIS_PORT:-6388}"
proxy_port="${PROXY_PORT:-10492}"
redis_db="${REDIS_DB:-4}"
upstream_host="127.0.0.1"
upstream_port="${UPSTREAM_PORT:-4450}"
psk_identity="${PSK_IDENTITY:-psk-demo}"
psk_hex="${PSK_HEX:-1ba799729c830152c91d4fbca5149972}"
compose_file="$repo_root/lde/containers/compose.yml"
socket_path="/tmp/tacacsrs-p3-process.sock"
redis_pidfile="/tmp/tacacsrs-p3-redis.pid"
redis_log="/tmp/tacacsrs-p3-redis.log"
agent_log="/tmp/tacacsrs-p3-agent.log"
tacon_log="/tmp/tacacsrs-p3-tacon.log"
epsk_root="/etc/sonic/tacacs/credentials/epsk"
agent_pid=""
container_started=0

if [[ "$(id -u)" -ne 0 ]]; then
    echo "P3 EPSK process smoke must run as root in a disposable Linux environment" >&2
    exit 40
fi
if [[ -e "$epsk_root" ]]; then
    echo "refusing to replace existing EPSK root: $epsk_root" >&2
    exit 41
fi
command -v redis-server >/dev/null
command -v redis-cli >/dev/null
command -v podman >/dev/null
command -v xxd >/dev/null

cleanup() {
    local status="$?"
    if [[ "$status" -ne 0 ]]; then
        echo "--- tacacsrs-agentd log ---" >&2
        cat "$agent_log" >&2 2>/dev/null || true
        echo "--- tacon log ---" >&2
        cat "$tacon_log" >&2 2>/dev/null || true
        echo "--- Redis log ---" >&2
        cat "$redis_log" >&2 2>/dev/null || true
    fi
    if [[ -n "$agent_pid" ]]; then
        kill -TERM "$agent_pid" >/dev/null 2>&1 || true
        wait "$agent_pid" >/dev/null 2>&1 || true
    fi
    redis-cli -p "$redis_port" shutdown nosave >/dev/null 2>&1 || true
    rm -f "$socket_path" "$redis_pidfile" "$redis_log" "$agent_log" "$tacon_log"
    # Remove only what this test created. rmdir refuses to delete a non-empty
    # directory, so a populated shared parent is never destroyed.
    rm -f "$epsk_root"/object-* "$epsk_root"/.object-* 2>/dev/null || true
    rmdir "$epsk_root" 2>/dev/null || true
    rmdir "/etc/sonic/tacacs/credentials" 2>/dev/null || true
    rmdir "/etc/sonic/tacacs" 2>/dev/null || true
    if [[ "$container_started" -eq 1 ]]; then
        timeout 60 podman compose -f "$compose_file" down >/dev/null 2>&1 || true
    fi
    return "$status"
}
trap cleanup EXIT

upstream_reachable() {
    timeout 3 bash -c "exec 3<>/dev/tcp/${upstream_host}/${upstream_port}" 2>/dev/null
}

ensure_upstream() {
    if upstream_reachable; then
        return 0
    fi
    echo "starting tac_plus-ng upstream via podman compose"
    timeout 300 podman compose -f "$compose_file" up -d
    container_started=1
    for _ in $(seq 1 100); do
        if upstream_reachable; then
            return 0
        fi
        sleep 0.3
    done
    echo "tac_plus-ng did not become reachable on ${upstream_host}:${upstream_port}" >&2
    exit 47
}

wait_for_log_count() {
    local expected="$1"
    local pattern="$2"
    for _ in $(seq 1 100); do
        if [[ "$(grep -c "$pattern" "$agent_log" 2>/dev/null || true)" -ge "$expected" ]]; then
            return 0
        fi
        sleep 0.1
    done
    echo "timed out waiting for log count $expected: $pattern" >&2
    return 1
}

wait_for_readiness() {
    for _ in $(seq 1 100); do
        kill -0 "$agent_pid"
        if timeout 5 "$probe" --endpoint "$socket_path" --check readiness --timeout-seconds 1 \
            >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "timed out waiting for agent readiness" >&2
    return 1
}

# Store an EPSK object as the raw key bytes the upstream expects.
write_object() {
    local name="$1"
    if [[ "${PSK_RAW:-0}" -eq 1 ]]; then
        printf '%s' "$psk_hex" >"$epsk_root/$name"
    else
        printf '%s' "$psk_hex" | xxd -r -p >"$epsk_root/$name"
    fi
    chmod 0640 "$epsk_root/$name"
}

# Drive a real accounting exchange through the agent proxy to the EPSK upstream.
tacacs_exchange() {
    local label="$1"
    if ! timeout 20 "$tacon" \
        --server-addr "127.0.0.1:${proxy_port}" \
        --validation-relaxation allow-plain-tcp-without-shared-secret \
        accounting --user testuser --port tty0 --rem-addr 127.0.0.1 "show version" \
        >>"$tacon_log" 2>&1; then
        echo "TACACS+ accounting exchange failed at: $label" >&2
        exit 45
    fi
}

export CARGO_INCREMENTAL=0
cargo build -p tacacsrs-agentd -p tacon --bins >/dev/null
target_dir="${CARGO_TARGET_DIR:-target}"
agent="$target_dir/debug/tacacsrs-agentd"
probe="$target_dir/debug/tacacsrs-agent-health"
tacon="$target_dir/debug/tacon"

ensure_upstream

mkdir -p "$epsk_root"
chmod 0750 "$epsk_root"
write_object object-a

redis-server \
    --bind 127.0.0.1 \
    --port "$redis_port" \
    --save '' \
    --appendonly no \
    --daemonize yes \
    --pidfile "$redis_pidfile" \
    --logfile "$redis_log"
redis-cli -p "$redis_port" PING | grep -q PONG
redis-cli -p "$redis_port" -n "$redis_db" CONFIG SET notify-keyspace-events KEA >/dev/null
redis-cli -p "$redis_port" -n "$redis_db" HSET \
    'TACPLUS_FORWARDER|global' \
    local_listen_address 127.0.0.1 \
    local_listen_port "$proxy_port" >/dev/null
redis-cli -p "$redis_port" -n "$redis_db" HSET \
    "TACPLUS_SERVER_TLS|${upstream_host}" \
    priority 64 \
    tcp_port "$upstream_port" \
    psk_identity "$psk_identity" \
    psk_secret_ref object-a >/dev/null

"$agent" \
    --sonic \
    --sonic-redis-url "redis://127.0.0.1:${redis_port}" \
    --sonic-redis-db "$redis_db" \
    --listen-endpoint "$socket_path" \
    --host-integration none \
    -vv >"$agent_log" 2>&1 &
agent_pid=$!

wait_for_readiness
wait_for_log_count 1 'Reloaded TACACS+ upstream server set: 1 server'
tacacs_exchange "initial EPSK generation"

# Immutable-ID rotation: point at a new reference object holding the same key
# material so the EPSK handshake continues to succeed.
write_object object-b
redis-cli -p "$redis_port" -n "$redis_db" HSET \
    "TACPLUS_SERVER_TLS|${upstream_host}" psk_secret_ref object-b >/dev/null
wait_for_log_count 2 'Reloaded TACACS+ upstream server set: 1 server'
wait_for_readiness
tacacs_exchange "immutable-ID rotation"

# Same-ID atomic replacement of the object contents.
temporary="$epsk_root/.object-b.tmp"
if [[ "${PSK_RAW:-0}" -eq 1 ]]; then
    printf '%s' "$psk_hex" >"$temporary"
else
    printf '%s' "$psk_hex" | xxd -r -p >"$temporary"
fi
chmod 0640 "$temporary"
mv -f "$temporary" "$epsk_root/object-b"
wait_for_log_count 3 'Reloaded TACACS+ upstream server set: 1 server'
wait_for_readiness
tacacs_exchange "same-ID atomic replacement"

# ConfigDB references the object, never the raw key material.
redis_cli_snapshot="$(redis-cli -p "$redis_port" -n "$redis_db" HGETALL \
    "TACPLUS_SERVER_TLS|${upstream_host}")"
grep -q 'object-b' <<<"$redis_cli_snapshot"
if grep -Fq "$psk_hex" <<<"$redis_cli_snapshot"; then
    echo "ConfigDB exposed raw EPSK material" >&2
    exit 42
fi

# Invalid replacement: the candidate is rejected and the prior known-good
# material still completes a new exchange.
redis-cli -p "$redis_port" -n "$redis_db" HSET \
    "TACPLUS_SERVER_TLS|${upstream_host}" psk_secret_ref missing-object >/dev/null
wait_for_log_count 1 'configuration candidate was rejected by runtime validation'
wait_for_readiness
tacacs_exchange "rejected-candidate fallback"
[[ "$(grep -c 'Reloaded TACACS+ upstream server set: 1 server' "$agent_log")" -eq 3 ]]

for forbidden in \
    "$psk_hex" \
    'object-a' 'object-b' 'missing-object' "$epsk_root"; do
    if grep -Fq "$forbidden" "$agent_log"; then
        echo "agent log exposed protected credential data" >&2
        exit 43
    fi
done

kill -TERM "$agent_pid"
for _ in $(seq 1 300); do
    if ! kill -0 "$agent_pid" 2>/dev/null; then
        break
    fi
    sleep 0.1
done
if kill -0 "$agent_pid" 2>/dev/null; then
    echo "agent did not exit within the shutdown bound" >&2
    kill -KILL "$agent_pid" 2>/dev/null || true
    exit 48
fi
wait "$agent_pid" 2>/dev/null || true
agent_pid=""
[[ ! -e "$socket_path" ]]
if timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/${proxy_port}" 2>/dev/null; then
    echo "proxy port remained bound after SIGTERM" >&2
    exit 44
fi

echo "PASS: real EPSK TACACS+ exchange across bootstrap, immutable and same-ID rotation, rejected fallback, readiness, redaction, and bounded shutdown."
