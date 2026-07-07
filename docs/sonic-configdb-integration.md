# SONiC ConfigDB integration

`tacacsrs-agentd` can run as a native SONiC service, sourcing its TACACS+
configuration from SONiC's Redis-backed Configuration Database (CONFIG_DB,
database index `4`) and reacting to ConfigDB changes via Redis keyspace
notifications.

This document covers the runtime side (how the daemon talks to ConfigDB).
Building static binaries and container images for SONiC is covered separately in
[Building for SONiC](sonic-build-guide.md). Running the agent image on a SONiC
host is covered in [Running tacacsrs-agentd as a SONiC Docker container](sonic-agentd-container.md).

## Architecture

The agent does not depend directly on Redis. Instead, configuration sources
are abstracted behind the `tacacsrs-datastore::ConfigDatastore` trait, and
the SONiC bridge (`tacacsrs-sonic::SonicConfigDb`) is one concrete backend.
Any future vendor datastore (for example a different NOS, a YAML config
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

`StaticDatastore` is used for file-based and CLI-based configuration; it
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
    priority           "1"        # lower = preferred (failover order)
    tcp_port           "49"
    timeout            "10"       # overrides TACPLUS|global.timeout
    passkey            "..."      # overrides TACPLUS|global.passkey
```

Each `TACPLUS_SERVER` row becomes one `TacacsPlusServer` in the YANG
configuration. Per-server fields fall back to the matching `TACPLUS|global`
field when absent. The synthesized YANG `name` for each server is
`sonic-server-<index>-<address>`.

### Forward-compatible extension keys

Operators and SONiC schema maintainers can experiment with TLS-aware fields
ahead of upstream ConfigDB schema work by adding the following keys to
`TACPLUS_SERVER|<addr>`:

| Key                 | YANG field          | Notes                                                                                          |
|---------------------|---------------------|------------------------------------------------------------------------------------------------|
| `use_tls`           | `server-authentication: {}` | Accepts the same boolean forms as `sni_enabled`; also supported on `TACPLUS|global` as a default |
| `domain_name`       | `domain-name`       | Used as SNI hostname                                                                           |
| `sni_enabled`       | `sni-enabled`       | `true`/`false`/`yes`/`no`/`1`/`0`                                                              |
| `single_connection` | `single-connection` | Boolean                                                                                        |
| `vrf_name`          | `vrf-instance`      | VRF name for outbound traffic                                                                  |
| `src_ip`            | `source-ip`         | Mutually exclusive with `src_intf`                                                             |
| `src_intf`          | `source-interface`  | Falls back to the global TACPLUS row                                                           |
| `server_type`       | `server-type`       | Defaults to `all`; tokens accept `authentication`, `authorization`, `accounting`, or `all`     |

Unknown fields are logged at `warn` level and ignored, so legacy operator
annotations on TACPLUS rows do not break the agent.

### Capability gap (TLS)

SONiC's upstream TACACS+ ConfigDB schema does not yet expose certificate
material, trust anchors, TLS 1.3 ePSKs, or other TLS-only fields from the
YANG model. Until SONiC adopts a richer schema, the bridge supports the
shared-secret / obfuscation path (`passkey`) plus a forward-compatible
`use_tls` extension that selects the empty `server-authentication` container
used by `tacon --use-tls` when no explicit certificate material is configured.
The mapping is structured so that promoting richer TLS support upstream will
only require new ConfigDB fields and a corresponding update to
`tacacsrs_sonic::mapping`; no daemon-level plumbing changes will be required.

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

### 2. Install the systemd unit

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

### 3. Register in the SONiC `FEATURE` table

`executables/tacacsrs_agentd/sonic/feature_table.json` is a sample row that
exposes the agent through SONiC's standard `config feature` CLI:

```bash
sonic-cfggen -j executables/tacacsrs_agentd/sonic/feature_table.json --write-to-db
config save -y
config feature state tacacsrs-agentd enabled
```

### 4. Start the daemon manually (for development)

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

From WSL, make sure Cargo is on the PowerShell process path:

```bash
export PATH="$HOME/.cargo/bin:$PATH"
pwsh -NoLogo -NoProfile -File ./lde/run-sonic-configdb-smoke.ps1
```

To validate the SONiC-style Unix-domain socket path instead of TCP, run the
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

redis-cli -n 4 HSET 'TACPLUS|global' \
    timeout 5 passkey shared-secret auth_type pap src_intf Management0
redis-cli -n 4 HSET 'TACPLUS_SERVER|192.0.2.10' \
    priority 1 tcp_port 49 timeout 10 passkey server-secret \
    domain_name tacacs-a.example.test sni_enabled true single_connection true
```

Run the `tacacsrs-sonic` watcher example to validate the datastore contract
directly:

```bash
cargo run -p tacacsrs-sonic --example configdb_watch -- \
    --redis-url redis://127.0.0.1:6379 \
    --redis-db 4
```

Then mutate ConfigDB rows and confirm the example emits a `ConfigChange` with
the expected delta:

```bash
redis-cli -n 4 HSET 'TACPLUS_SERVER|192.0.2.20' \
    priority 2 tcp_port 49 passkey backup-secret
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
5. Updating `TACPLUS|global` emits a change event after the debounce window;
   the exact delta depends on whether the global value changes the effective
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

Mutating the Redis rows should produce the documented configuration-change log
message. The current daemon observes changes but does not hot-swap upstream
connections in place; restart `tacacsrs-agentd` to apply a changed server set.

## Hot reload behaviour

When a TACPLUS-prefixed key changes in CONFIG_DB, the bridge:

1. Coalesces additional changes that arrive within a short debounce window.
2. Re-reads the full TACPLUS / TACPLUS_SERVER tables.
3. Validates the new snapshot against the YANG schema.
4. Emits a `ConfigChange` event carrying the new snapshot and a delta
   describing which servers were added, removed, or modified.

The current daemon does not yet hot-swap upstream connections in place: it
records the change and asks the operator to restart the service to apply
the new configuration. This is the smallest safe step that keeps in-flight
TACACS+ sessions intact, and the plumbing is shaped so that a future
implementation can replace the listener body with an atomic state-rebuild
without changing the surrounding lifecycle or the datastore contract.

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
`ConfigDatastore` trait does not constrain how secrets are fetched, so a
future implementation can compose a secret-resolution backend (HashiCorp
Vault, Azure Key Vault, encrypted ConfigDB fields, etc.) by wrapping
`SonicConfigDb` and rewriting the per-server `shared-secret` before
returning the snapshot from `load`.
