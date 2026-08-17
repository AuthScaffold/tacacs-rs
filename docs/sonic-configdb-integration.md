# SONiC ConfigDB integration

`tacacsrs-agentd` can run as a native SONiC service. It sources its TACACS+
configuration from SONiC's Redis-backed Configuration Database (CONFIG_DB,
database index `4`) and reacts to ConfigDB changes through Redis keyspace
notifications.

This document covers the runtime side (how the daemon talks to ConfigDB).
Building static binaries and container images for SONiC is covered separately in
[Building for SONiC](sonic-build-guide.md). Running the agent image on a SONiC
host is covered in [Running tacacsrs-agentd as a SONiC Docker container](sonic-agentd-container.md).

## Architecture

The agent does not depend directly on Redis. The `tacacsrs-datastore::ConfigDatastore`
trait abstracts configuration sources, and the SONiC bridge
(`tacacsrs-sonic::SonicConfigDb`) is one concrete backend.
Any future vendor datastore (for example a different NOS, a YAML configuration
service, or a remote management plane) can be plugged in by implementing the
same trait.

```text
+-----------------------+        +----------------------------+
|  tacacsrs-agentd      | -----> |  ConfigDatastore (trait)   |
+-----------------------+        +----------------------------+
                                            |
                       +--------------------+----------------------+
                       |                                           |
              +----------------+                     +-----------------------+
              | StaticDatastore|                     | SonicConfigDb         |
              |  (file / CLI)  |                     |  (Redis CONFIG_DB)    |
              +----------------+                     +-----------------------+
```

`StaticDatastore` is used for file-based and CLI-based configuration. It
returns a single snapshot and never emits change events. `SonicConfigDb`
reads `TACPLUS|global` and `TACPLUS_SERVER|*` rows from Redis and emits
change events whenever a TACPLUS-prefixed key changes (subject to the
configured debounce window).

## ConfigDB schema mapping

The bridge maps SONiC's existing TACACS+ tables onto the
`ietf-system-tacacs-plus` YANG model used by the rest of the workspace.

```text
TACPLUS|global
    auth_type   "pap"             # logged only; no PAM-style selector yet
    timeout     "5"               # default per-server timeout
    passkey     "shared-secret"   # default shared secret
    src_intf    "Management0"     # default source interface

TACPLUS_SERVER|192.0.2.10
    priority           "64"       # higher = preferred; range is 1..64
    tcp_port           "49"
    timeout            "10"       # overrides TACPLUS|global.timeout
    passkey            "..."      # overrides TACPLUS|global.passkey
```

Each `TACPLUS_SERVER` row becomes one `TacacsPlusServer` in the YANG
configuration. Per-server fields fall back to the matching `TACPLUS|global`
field when absent. SONiC `priority` values are in the range `1..64`. Higher
numbers are preferred and therefore appear earlier in the daemon's failover
order. The synthesized YANG `name` for each server is
`sonic-server-<address>`.

### Compatibility extension keys

Compatibility rows accept these project extension keys:

| Key                 | YANG field         | Notes |
|---------------------|--------------------|-------|
| `single_connection` | `single-connection`| Boolean |
| `vrf_name`          | `vrf-instance`     | VRF name for outbound traffic |
| `src_ip`            | `source-ip`        | Mutually exclusive with `src_intf` |
| `src_intf`          | `source-interface` | Falls back to the global `TACPLUS` row |
| `server_type`       | `server-type`      | Defaults to `all` |

The bridge tolerates unknown compatibility fields and logs their names. It
does not log their values. Compatibility rows reject `use_tls`, `domain_name`,
and `sni_enabled`. Put TLS configuration in `TACPLUS_SERVER_TLS`.

### Version-1 TLS and forwarder tables

Each `TACPLUS_SERVER_TLS|<addr>` row defines one TLS 1.3 external PSK (EPSK)
server:

| Key | Requirement |
|-----|-------------|
| `psk_identity` | Required external identity |
| `psk_secret_ref` | Required opaque EPSK object ID |
| `priority` | Optional value from `1` through `64`; default `1` |
| `tcp_port` | Optional TLS port; default `449` |
| `timeout` | Optional timeout from `1` through `60` seconds; default `5` |
| `domain_name` | Optional SNI name |
| `sni_enabled` | Optional boolean; requires `domain_name` when true |
| `single_connection` | Optional boolean; default false |
| `psk_hash` | `sha-256` or `sha-384`; default `sha-256` |
| `psk_key_exchange` | `psk-dhe` or `psk-only`; default `psk-dhe` |
| `psk_key_exchange_groups` | Optional colon-separated groups for `psk-dhe` |

The production resolver reads `psk_secret_ref` from
`/etc/sonic/tacacs/credentials/epsk/<id>`. The credential file must satisfy
the ownership, permission, link-count, and size checks in
[`tacacsrs-sonic`](../libraries/tacacsrs_sonic/README.md).

`TACPLUS_FORWARDER|global` controls the local raw TACACS+ proxy listener. Its
`local_listen_address` field is required and must be loopback.
`local_listen_port` is optional and defaults to `49`. The TLS and forwarder
tables reject unknown fields.

## Running on SONiC

### 1. Enable Redis keyspace notifications

Hot reload requires Redis keyspace notifications to be turned on for the
ConfigDB instance. On SONiC, run once (and persist via `/etc/redis/redis.conf`
in your image build):

```bash
redis-cli -n 4 CONFIG SET notify-keyspace-events KEA
```

`KEA` enables `K`eyspace events, `E`vent expiration, and `A`ll command
classes. The bridge subscribes to `__keyspace@4__:TACPLUS*`.

### 2. Configure the local forwarder

The daemon reads its proxy listener from `TACPLUS_FORWARDER|global` before it
binds any service listener:

```bash
redis-cli -n 4 HSET 'TACPLUS_FORWARDER|global' \
    local_listen_address 127.0.0.1 local_listen_port 49
```

### 3. Install the systemd unit

The repository ships an example unit file at
[`executables/tacacsrs_agentd/sonic/tacacsrs-agentd.service`](../executables/tacacsrs_agentd/sonic/tacacsrs-agentd.service).

```bash
sudo install -m 0644 \
    executables/tacacsrs_agentd/sonic/tacacsrs-agentd.service \
    /etc/systemd/system/tacacsrs-agentd.service
sudo systemctl daemon-reload
sudo systemctl enable --now tacacsrs-agentd.service
```

The unit ordering pulls in `database.service` so the daemon starts only
after CONFIG_DB is available.

### 4. Register in the SONiC `FEATURE` table

`executables/tacacsrs_agentd/sonic/feature_table.json` is a sample row that
exposes the agent through SONiC's standard `config feature` CLI:

```bash
sonic-cfggen -j executables/tacacsrs_agentd/sonic/feature_table.json --write-to-db
config save -y
config feature state tacacsrs-agentd enabled
```

### 5. Start the daemon manually (for development)

```bash
sudo /usr/local/bin/tacacsrs-agentd \
    --sonic \
    --listen-endpoint /run/tacacs/tacacs.sock \
    -vv
```

You can override the Redis URL or database index for staging/testing
environments:

```bash
tacacsrs-agentd --sonic \
    --sonic-redis-url redis://127.0.0.1:6379 \
    --sonic-redis-db 4
```

## Local Redis smoke test

For branch validation on a development machine, run Redis locally over TCP and
seed database `4` with SONiC-style TACACS+ rows. On Windows, Docker Desktop or
WSL Redis is usually the simplest path.

The repository includes a PowerShell helper that runs the whole proof with
Podman, including Redis startup, seed data, example execution, ConfigDB
mutations, and output assertions:

```powershell
.\lde\run-sonic-configdb-smoke.ps1
```

From WSL, make sure that Cargo is on the PowerShell process path:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
pwsh -NoLogo -NoProfile -File ./lde/run-sonic-configdb-smoke.ps1
```

To validate the SONiC-style Unix domain socket path instead of TCP, run the
same helper from WSL with `-RedisTransport UnixSocket`:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
pwsh -NoLogo -NoProfile -File ./lde/run-sonic-configdb-smoke.ps1 -RedisTransport UnixSocket
```

To run the same flow manually, start Redis first:

```bash
docker run --rm -p 6379:6379 redis
```

In a second terminal, prepare the CONFIG_DB-like database:

```bash
redis-cli -n 4 CONFIG SET notify-keyspace-events KEA

redis-cli -n 4 DEL 'TACPLUS|global'
for key in $(redis-cli -n 4 --raw KEYS 'TACPLUS_SERVER|*'); do
    redis-cli -n 4 DEL "$key"
done

redis-cli -n 4 HSET 'TACPLUS_FORWARDER|global' \
    local_listen_address 127.0.0.1 local_listen_port 49
redis-cli -n 4 HSET 'TACPLUS|global' \
    timeout 5 passkey shared-secret auth_type pap src_intf Management0
redis-cli -n 4 HSET 'TACPLUS_SERVER|192.0.2.10' \
    priority 64 tcp_port 49 timeout 10 passkey server-secret \
    single_connection true
```

Run the `tacacsrs-sonic` watcher example to validate the datastore contract
directly:

```bash
cargo run -p tacacsrs-sonic --example configdb_watch -- \
    --redis-url redis://127.0.0.1:6379 \
    --redis-db 4
```

Then mutate ConfigDB rows. Make sure that the example emits a `ConfigChange`
with the expected delta:

```bash
redis-cli -n 4 HSET 'TACPLUS_SERVER|192.0.2.20' \
    priority 32 tcp_port 49 passkey backup-secret
redis-cli -n 4 HSET 'TACPLUS_SERVER|192.0.2.10' timeout 20
redis-cli -n 4 DEL 'TACPLUS_SERVER|192.0.2.20'
redis-cli -n 4 HSET 'TACPLUS|global' timeout 7
```

Expected results:

1. The initial load prints one server synthesized from
   `TACPLUS_SERVER|192.0.2.10`.
2. Adding `TACPLUS_SERVER|192.0.2.20` reports an added server.
3. Changing `TACPLUS_SERVER|192.0.2.10.timeout` reports a modified server.
4. Deleting `TACPLUS_SERVER|192.0.2.20` reports a removed server.
5. Updating `TACPLUS|global` emits a change event after the debounce window.
   The exact delta depends on whether the global value changes the effective
   validated YANG snapshot.

To validate the daemon path, start `tacacsrs-agentd` against the same Redis
instance:

```bash
cargo run -p tacacsrs-agentd -- \
    --sonic \
    --sonic-redis-url redis://127.0.0.1:6379 \
    --sonic-redis-db 4 \
    --listen-endpoint /tmp/tacacs.sock \
    -vv
```

Mutating the Redis rows produces the documented configuration-change log
message. The daemon atomically applies each valid filtered snapshot to new
sessions without restarting. In-flight sessions keep their existing server-set
snapshot and connection handles.

## Hot reload behavior

When a TACPLUS-prefixed key changes in CONFIG_DB, the runtime:

1. Coalesces additional changes that arrive within a short debounce window.
2. Re-reads the full TACPLUS / TACPLUS_SERVER tables.
3. Validates the new snapshot against the YANG schema.
4. Emits a typed changed or rejected event.
5. Filters proxy self-loops and validates the complete candidate.
6. Atomically replaces the server set for new sessions while preserving unchanged cached connections.

Invalid candidates leave the previous known-good configuration active and mark runtime health stale/degraded. If Redis is unavailable at process startup, enabled listeners still bind and liveness serves while startup/readiness remain not serving. The daemon retries with capped jittered backoff. Subscription setup failures and ended streams mark the snapshot stale, trigger a fresh load to cover missed changes, and resubscribe without exiting.

## Operational commands

```bash
# Inspect what the bridge will see.
redis-cli -n 4 HGETALL TACPLUS\|global
redis-cli -n 4 KEYS 'TACPLUS_SERVER|*'

# Tail change notifications the bridge subscribes to.
redis-cli -n 4 PSUBSCRIBE '__keyspace@4__:TACPLUS*'

# Drive the daemon's logs.
journalctl -u tacacsrs-agentd.service -f
```

## Secret handling

The bridge currently reads `passkey` directly from CONFIG_DB. The
`ConfigDatastore` trait does not constrain how secrets are fetched. A future
implementation can compose a secret-resolution backend, for example HashiCorp
Vault, Azure Key Vault, or encrypted ConfigDB fields. It can wrap
`SonicConfigDb` and rewrite the per-server `shared-secret` before
returning the snapshot from `load`.
