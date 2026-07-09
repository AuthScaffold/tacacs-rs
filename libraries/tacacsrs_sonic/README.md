# tacacsrs-sonic

SONiC ConfigDB datastore backend for the central TACACS+ client service
(`tacacsrs-agentd`).

This crate is one concrete implementation of the
[`tacacsrs_datastore::ConfigDatastore`] trait. It bridges between SONiC's
Redis-backed Configuration Database (`CONFIG_DB`, database index `4`) and the
shared `ietf-system-tacacs-plus` YANG configuration consumed by the agent.

## What the bridge does

1. Reads the legacy SONiC `TACPLUS|global` and `TACPLUS_SERVER|<addr>` tables.
2. Maps each row into a [`tacacsrs_config::TacacsPlusServer`].
3. Subscribes to Redis keyspace notifications (`__keyspace@4__:TACPLUS*`) and
   re-emits a [`tacacsrs_datastore::ConfigChange`] when relevant keys change.

All of the parsing and field-mapping logic is exposed as pure functions in the
[`mapping`] module and is fully unit-tested without a live Redis. The Redis
client only handles I/O.

## SONiC capability gap

SONiC's existing TACACS+ ConfigDB schema does not yet expose the full
TLS-related fields that the YANG `ietf-system-tacacs-plus` model supports
(client identity certificates, server authentication trust anchors, TLS 1.3
ePSKs, SNI, etc.). The mapping documents what would have to be added to
ConfigDB to enable the richer YANG features; today the bridge supports plain
TCP with an optional shared-secret / obfuscation key plus a forward-compatible
`use_tls` extension that selects the same empty `server-authentication`
container as `tacon --use-tls` when no explicit certificate material is
configured.

## Schema extensions

The mapping recognizes a small forward-compatible extension on top of the
upstream SONiC schema so that operators can experiment with the TLS-capable
YANG model without waiting for SONiC ConfigDB updates:

| Extension key on `TACPLUS_SERVER|<addr>` | YANG field                             |
|------------------------------------------|----------------------------------------|
| `use_tls`                                | `server-authentication: {}`            |
| `domain_name`                            | `domain-name` (used for SNI)           |
| `sni_enabled`                            | `sni-enabled`                          |
| `single_connection`                      | `single-connection`                    |
| `vrf_name`                               | `vrf-instance`                         |
| `src_intf` (also on `global`)            | `source-interface`                     |
| `src_ip`                                 | `source-ip`                            |
| `server_type`                            | `server-type` bitset, defaults to `all`|

The `use_tls` key is also accepted on `TACPLUS|global` and falls back to each
server row when the row does not override it. Unknown keys are ignored with a
`warn!` log so legacy SONiC builds with extra operator-specific keys do not
cause the bridge to fail at startup.

## Example watcher

The `configdb_watch` example demonstrates the crate's runtime contract: it
loads the current TACACS+ snapshot from Redis and then prints every
`ConfigChange` emitted by the keyspace-notification subscription. Each change
event carries the complete latest TACACS+ snapshot plus a delta that consumers
can use to decide whether an incremental update is enough. The example defaults
to a local TCP Redis instance so it works with Docker or WSL; production SONiC
deployments normally use the Unix socket default from `SonicConnection`.

From the repository root, the full local smoke test can be run with Podman:

```powershell
.\lde\run-sonic-configdb-smoke.ps1
```

The manual equivalent is:

SONiC TACACS+ server priorities are in the range `1..64`; higher values are
preferred and are placed earlier in the daemon failover order.

```bash
docker run --rm -p 6379:6379 redis
redis-cli -n 4 CONFIG SET notify-keyspace-events KEA

redis-cli -n 4 HSET 'TACPLUS|global' \
   timeout 5 auth_type pap src_intf Management0
redis-cli -n 4 HSET 'TACPLUS_SERVER|192.0.2.10' \
   priority 64 tcp_port 49 timeout 10 \
   use_tls true domain_name tacacs-a.example.test \
   sni_enabled true single_connection true

cargo run -p tacacsrs-sonic --example configdb_watch -- \
   --redis-url redis://127.0.0.1:6379 \
   --redis-db 4
```

In another terminal, mutate the Redis rows and watch the example print the
computed delta:

```bash
redis-cli -n 4 HSET 'TACPLUS_SERVER|192.0.2.20' \
   priority 32 tcp_port 49
redis-cli -n 4 HSET 'TACPLUS_SERVER|192.0.2.10' timeout 20
redis-cli -n 4 DEL 'TACPLUS_SERVER|192.0.2.20'
```

The example intentionally reports only whether a shared secret is configured;
it never prints secret values. Rows without a per-server or global `passkey`
are treated as plain TCP unless `use_tls` is enabled, in which case the bridge
emits the empty YANG `server-authentication` container used for TLS without
explicit certificate material.
