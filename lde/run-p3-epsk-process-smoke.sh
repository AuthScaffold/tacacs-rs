#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

redis_port="${REDIS_PORT:-6388}"
proxy_port="${PROXY_PORT:-10492}"
redis_db="${REDIS_DB:-4}"
socket_path="/tmp/tacacsrs-p3-process.sock"
redis_pidfile="/tmp/tacacsrs-p3-redis.pid"
redis_log="/tmp/tacacsrs-p3-redis.log"
agent_log="/tmp/tacacsrs-p3-agent.log"
epsk_root="/etc/sonic/tacacs/credentials/epsk"
agent_pid=""
secret_a="P3_SECRET_A_0123456789_ABCDEF"
secret_b="P3_SECRET_B_0123456789_ABCDEF"
secret_b_replacement="P3_SECRET_B_REPLACED_0123456789"

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

cleanup() {
    local status="$?"
    if [[ "$status" -ne 0 ]]; then
        echo "--- tacacsrs-agentd log ---" >&2
        cat "$agent_log" >&2 2>/dev/null || true
        echo "--- Redis log ---" >&2
        cat "$redis_log" >&2 2>/dev/null || true
    fi
    if [[ -n "$agent_pid" ]]; then
        kill -TERM "$agent_pid" >/dev/null 2>&1 || true
        wait "$agent_pid" >/dev/null 2>&1 || true
    fi
    redis-cli -p "$redis_port" shutdown nosave >/dev/null 2>&1 || true
    rm -f "$socket_path" "$redis_pidfile" "$redis_log" "$agent_log"
    rm -rf "/etc/sonic/tacacs/credentials"
    return "$status"
}
trap cleanup EXIT

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
        if "$probe" --endpoint "$socket_path" --check readiness --timeout-seconds 1 \
            >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    echo "timed out waiting for agent readiness" >&2
    return 1
}

write_object() {
    local name="$1"
    local value="$2"
    printf '%s' "$value" >"$epsk_root/$name"
    chmod 0640 "$epsk_root/$name"
}

export CARGO_INCREMENTAL=0
cargo build -p tacacsrs-agentd --bins >/dev/null
target_dir="${CARGO_TARGET_DIR:-target}"
agent="$target_dir/debug/tacacsrs-agentd"
probe="$target_dir/debug/tacacsrs-agent-health"

mkdir -p "$epsk_root"
chmod 0750 "$epsk_root"
write_object object-a "$secret_a"

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
    'TACPLUS_SERVER_TLS|192.0.2.70' \
    priority 64 \
    tcp_port 449 \
    psk_identity p3-client \
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
bash -c "exec 9<>/dev/tcp/127.0.0.1/${proxy_port}; exec 9>&-"

write_object object-b "$secret_b"
redis-cli -p "$redis_port" -n "$redis_db" HSET \
    'TACPLUS_SERVER_TLS|192.0.2.70' psk_secret_ref object-b >/dev/null
wait_for_log_count 2 'Reloaded TACACS+ upstream server set: 1 server'
wait_for_readiness

temporary="$epsk_root/.object-b.tmp"
printf '%s' "$secret_b_replacement" >"$temporary"
chmod 0640 "$temporary"
mv -f "$temporary" "$epsk_root/object-b"
wait_for_log_count 3 'Reloaded TACACS+ upstream server set: 1 server'
wait_for_readiness

redis_cli_snapshot="$(redis-cli -p "$redis_port" -n "$redis_db" HGETALL \
    'TACPLUS_SERVER_TLS|192.0.2.70')"
grep -q 'object-b' <<<"$redis_cli_snapshot"
for secret in "$secret_a" "$secret_b" "$secret_b_replacement"; do
    if grep -Fq "$secret" <<<"$redis_cli_snapshot"; then
        echo "ConfigDB exposed raw EPSK material" >&2
        exit 42
    fi
done

redis-cli -p "$redis_port" -n "$redis_db" HSET \
    'TACPLUS_SERVER_TLS|192.0.2.70' psk_secret_ref missing-object >/dev/null
wait_for_log_count 1 'configuration candidate was rejected by runtime validation'
wait_for_readiness
bash -c "exec 9<>/dev/tcp/127.0.0.1/${proxy_port}; exec 9>&-"
[[ "$(grep -c 'Reloaded TACACS+ upstream server set: 1 server' "$agent_log")" -eq 3 ]]

for forbidden in \
    "$secret_a" "$secret_b" "$secret_b_replacement" \
    'object-a' 'object-b' 'missing-object' "$epsk_root"; do
    if grep -Fq "$forbidden" "$agent_log"; then
        echo "agent log exposed protected credential data" >&2
        exit 43
    fi
done

kill -TERM "$agent_pid"
wait "$agent_pid"
agent_pid=""
[[ ! -e "$socket_path" ]]
if bash -c "exec 9<>/dev/tcp/127.0.0.1/${proxy_port}" 2>/dev/null; then
    echo "proxy port remained bound after SIGTERM" >&2
    exit 44
fi

echo "PASS: HLD tables, protected EPSK bootstrap, immutable and same-ID rotation, rejected fallback, readiness, redaction, and shutdown."
