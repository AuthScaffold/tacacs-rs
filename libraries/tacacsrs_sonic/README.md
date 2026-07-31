# tacacsrs-sonic

SONiC ConfigDB datastore backend for the central TACACS+ client service
(`tacacsrs-agentd`).

This crate is one concrete implementation of the
[`tacacsrs_datastore::ConfigDatastore`] trait. It bridges between SONiC's
Redis-backed Configuration Database (`CONFIG_DB`, database index `4`) and the
shared `ietf-system-tacacs-plus` YANG configuration consumed by the agent.

## What the bridge does

1. Reads `TACPLUS|global`, compatibility `TACPLUS_SERVER|<addr>`, version-1
   `TACPLUS_SERVER_TLS|<addr>`, and `TACPLUS_FORWARDER|global` as one snapshot.
2. Parses raw Redis hashes into private typed rows before producing any RFC
   configuration.
3. Filters normalized loopback self-targets, rejects cross-table ambiguity,
   and orders mixed candidates by descending priority plus a stable normalized
   name/endpoint tie-breaker.
4. Maps compatibility rows into [`tacacsrs_config::TacacsPlusServer`] values.
5. Subscribes to Redis keyspace notifications (`__keyspace@4__:TACPLUS*`) and
   re-emits a [`tacacsrs_datastore::ConfigChange`] when relevant keys change.

Parsing and field mapping are implemented as pure functions in the [`mapping`]
module and are fully unit-tested without a live Redis. The Redis client only
handles I/O.

## Version-1 TLS boundary

The new TLS table is isolated from legacy compatibility rows. Version 1 accepts
only TLS 1.3 EPSK fields reviewed by the central-agent HLD. Certificate and
mTLS references, cipher-suite overrides, certificate-verification overrides,
TLS-row `passkey`, and unknown fields are rejected instead of ignored.

Validated TLS rows map to RFC 9950 central-keystore EPSK references. The
generated model retains the opaque object ID, external identity, hash, SNI,
connection policy, and exchange groups. It contains no inline or resolved key
bytes. Credential files are not read by this mapper.

## Compatibility isolation

Existing `TACPLUS` and `TACPLUS_SERVER` rows retain plain TCP/shared-secret
behavior. The mapper rejects the former provisional `use_tls`, `domain_name`,
and `sni_enabled` fields in those tables. TLS configuration belongs only in
`TACPLUS_SERVER_TLS`.

| Extension key on `TACPLUS_SERVER|<addr>` | YANG field                             |
|------------------------------------------|----------------------------------------|
| `single_connection`                      | `single-connection`                    |
| `vrf_name`                               | `vrf-instance`                         |
| `src_intf` (also on `global`)            | `source-interface`                     |
| `src_ip`                                 | `source-ip`                            |
| `server_type`                            | `server-type` bitset, defaults to `all`|

Unknown compatibility keys remain tolerated for existing SONiC deployments,
but their values are never logged. TLS and forwarder tables are strict because
unknown fields there can change security behavior.

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
podman run --rm -p 6379:6379 redis
redis-cli -n 4 CONFIG SET notify-keyspace-events KEA

redis-cli -n 4 HSET 'TACPLUS|global' \
   timeout 5 auth_type pap src_intf Management0
redis-cli -n 4 HSET 'TACPLUS_SERVER|192.0.2.10' \
   priority 64 tcp_port 49 timeout 10 single_connection true

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
it never prints secret values. Compatibility rows without a per-server or
global `passkey` are treated as unobfuscated plain TCP.
