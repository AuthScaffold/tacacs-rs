#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

container_runtime="${CONTAINER_RUNTIME:-podman.exe}"
redis_image="${REDIS_IMAGE:-docker.io/library/redis:7-alpine}"
redis_name="tacacsrs-p1-process-redis"
redis_port="${REDIS_PORT:-6387}"
proxy_port="${PROXY_PORT:-10491}"
socket_path="/tmp/tacacsrs-p1-process.sock"
strict_socket_path="/tmp/tacacsrs-p1-strict.sock"
auto_socket_path="/tmp/tacacsrs-p1-auto.sock"
agent_pid=""

cleanup() {
    if [[ -n "$agent_pid" ]]; then
        kill -TERM "$agent_pid" >/dev/null 2>&1 || true
    fi
    "$container_runtime" rm -f "$redis_name" >/dev/null 2>&1 || true
    rm -f "$socket_path" "$strict_socket_path" "$auto_socket_path"
}
trap cleanup EXIT

export CARGO_INCREMENTAL=0
cargo build -p tacacsrs-agentd --bins >/dev/null
agent="target/debug/tacacsrs-agentd"
probe="target/debug/tacacsrs-agent-health"

rm -f "$socket_path" "$strict_socket_path" "$auto_socket_path"
"$container_runtime" rm -f "$redis_name" >/dev/null 2>&1 || true
python3 -c 'import socket; s = socket.socket(socket.AF_UNIX); s.bind("/tmp/tacacsrs-p1-process.sock"); s.close()'

NOTIFY_SOCKET=/tmp/nonexistent-notify "$agent" \
    --sonic \
    --sonic-redis-url "redis://127.0.0.1:${redis_port}" \
    --sonic-redis-db 4 \
    --service-mode both \
    --listen-endpoint "$socket_path" \
    --proxy-endpoint "127.0.0.1:${proxy_port}" \
    --host-integration none \
    -vv >/dev/null 2>&1 &
agent_pid=$!

live=0
for _ in $(seq 1 80); do
    kill -0 "$agent_pid"
    if "$probe" --endpoint "$socket_path" --check liveness --timeout-seconds 2 >/dev/null 2>&1; then
        live=1
        break
    fi
done
[[ "$live" -eq 1 ]]

if "$probe" --endpoint "$socket_path" --check startup --timeout-seconds 2 >/dev/null 2>&1; then
    echo "startup unexpectedly serving before Redis" >&2
    exit 31
else
    exit_code=$?
    [[ "$exit_code" -eq 1 ]]
fi
"$probe" --endpoint "$socket_path" --check liveness --timeout-seconds 2 >/dev/null
if "$probe" --endpoint "$socket_path" --check readiness --timeout-seconds 2 >/dev/null 2>&1; then
    echo "readiness unexpectedly serving before Redis" >&2
    exit 32
else
    exit_code=$?
    [[ "$exit_code" -eq 1 ]]
fi

"$container_runtime" run -d \
    --name "$redis_name" \
    -p "${redis_port}:6379" \
    "$redis_image" >/dev/null

for _ in $(seq 1 30); do
    if "$container_runtime" exec "$redis_name" redis-cli PING 2>/dev/null | grep -q PONG; then
        break
    fi
done
"$container_runtime" exec "$redis_name" redis-cli PING | grep -q PONG
"$container_runtime" exec "$redis_name" redis-cli -n 4 \
    CONFIG SET notify-keyspace-events KEA >/dev/null
"$container_runtime" exec "$redis_name" redis-cli -n 4 \
    HSET 'TACPLUS|global' timeout 5 auth_type pap >/dev/null
"$container_runtime" exec "$redis_name" redis-cli -n 4 \
    HSET 'TACPLUS_SERVER|192.0.2.10' priority 64 tcp_port 49 timeout 5 >/dev/null

ready=0
for _ in $(seq 1 80); do
    if "$probe" --endpoint "$socket_path" --check readiness --timeout-seconds 2 >/dev/null 2>&1; then
        ready=1
        break
    fi
done
[[ "$ready" -eq 1 ]]

exec 9<>"/dev/tcp/127.0.0.1/${proxy_port}"
printf '\300' >&9

kill -TERM "$agent_pid"
kill -0 "$agent_pid"
exec 9>&-
wait "$agent_pid"
agent_pid=""
[[ ! -e "$socket_path" ]]
if bash -c "exec 9<>/dev/tcp/127.0.0.1/${proxy_port}" 2>/dev/null; then
    echo "proxy port remained bound after SIGTERM" >&2
    exit 33
fi

if env -u NOTIFY_SOCKET "$agent" \
    --server-addr 192.0.2.10:49 \
    --shared-secret placeholder \
    --host-integration systemd \
    --listen-endpoint "$strict_socket_path" >/dev/null 2>&1; then
    echo "strict systemd mode started without NOTIFY_SOCKET" >&2
    exit 34
fi

NOTIFY_SOCKET=/tmp/nonexistent-notify "$agent" \
    --server-addr 192.0.2.10:49 \
    --shared-secret placeholder \
    --host-integration auto \
    --listen-endpoint "$auto_socket_path" >/dev/null 2>&1 &
agent_pid=$!
auto_live=0
for _ in $(seq 1 80); do
    kill -0 "$agent_pid"
    if "$probe" --endpoint "$auto_socket_path" --check liveness --timeout-seconds 2 >/dev/null 2>&1; then
        auto_live=1
        break
    fi
done
[[ "$auto_live" -eq 1 ]]
kill -TERM "$agent_pid"
wait "$agent_pid"
agent_pid=""
[[ ! -e "$auto_socket_path" ]]

echo "PASS: stale UDS replacement, pre-Redis startup, health recovery, both listeners, active drain, none/auto modes, SIGTERM cleanup, port release, and strict systemd prerequisite failure."