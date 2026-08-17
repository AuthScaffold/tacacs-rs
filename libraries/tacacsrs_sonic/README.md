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

The [`mapping`] module implements parsing and field mapping as pure functions
and fully unit-tests them without a live Redis. The Redis client only handles
I/O.

## Version-1 TLS boundary

The mapper isolates the new TLS table from legacy compatibility rows. Version 1
accepts only TLS 1.3 EPSK fields reviewed by the central-agent HLD. The mapper
rejects certificate and mTLS references, cipher-suite overrides,
certificate-verification overrides, TLS-row `passkey`, and unknown fields
instead of ignoring them.

Validated TLS rows map to RFC 9950 central-keystore EPSK references. The
generated model retains the opaque object ID, external identity, hash, SNI,
connection policy, and exchange groups. It contains no inline or resolved key
bytes. This mapper does not read credential files.

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
but the mapper never logs their values. TLS and forwarder tables are strict
because unknown fields there can change security behavior.

## Credential provider

`SonicCredentialResolver` implements the provider-neutral
`CredentialResolver` contract for version-1 EPSKs. Production resolves opaque
IDs beneath `/etc/sonic/tacacs/credentials/epsk`. Callers inject the target
`aaaagent` group ID through `SonicCredentialPolicy::production`.

The Linux provider pre-opens a root-owned `0750` directory without following a
symlink. It opens each grammar-validated one-segment ID relative to that
descriptor with `O_NOFOLLOW`, `O_NONBLOCK`, and `O_CLOEXEC`. Before returning a
zeroizing `SecretBytes`, it requires a regular file with one link, exact
`root:<aaaagent-gid>` ownership, mode `0640`, and a bounded length from 16
through 4096 bytes. Metadata identity, size, and timestamps must remain stable
across the read. Errors expose only typed request context.

Version 1 rejects certificate-with-key and trust-bag requests as unsupported.
The reserved ACMS root defaults to `/etc/sonic/credentials`, but no ACMS path,
symlink, or certificate parsing behavior is implemented until the deferred
schema and stable-link contract is reviewed.

The datastore watches the EPSK root and its parent alongside Redis keyspace
notifications. Only reviewed opaque object names and root events trigger the
watcher. It ignores materializer temporary names and access-only events. The
watcher debounces filesystem and ConfigDB bursts and always causes a complete
snapshot reload, credential re-resolution, and atomic runtime candidate apply.
The watcher never patches bytes into an active runtime. This supports
immutable-ID ConfigDB switches and explicit same-ID atomic replacement while
preserving the prior runtime on missing or rejected material.

## Example watcher

The `configdb_watch` example demonstrates the crate's runtime contract: it
loads the current TACACS+ snapshot from Redis and then prints every
`ConfigChange` emitted by the keyspace-notification subscription. Each change
event carries the complete latest TACACS+ snapshot plus a delta that consumers
can use to decide whether an incremental update is enough. The example defaults
to a local TCP Redis instance so it works with Docker or WSL. Production SONiC
deployments normally use the Unix domain socket default from `SonicConnection`.

Run the full local smoke test with Podman from the repository root:

```powershell
.\lde\run-sonic-configdb-smoke.ps1
```

The manual equivalent is:

SONiC TACACS+ server priorities are in the range `1..64`. The daemon prefers
higher values and places them earlier in its failover order.

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

The example intentionally reports only whether a shared secret is configured.
It never prints secret values. The mapper treats compatibility rows without a
per-server or global `passkey` as unobfuscated plain TCP.
