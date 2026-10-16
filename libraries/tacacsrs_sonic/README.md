# tacacsrs-sonic

SONiC ConfigDB datastore backend for the central TACACS+ client service
(`tacacsrs-agentd`).

This crate is one concrete implementation of the
[`tacacsrs_config::source::ConfigDatastore`] trait. It bridges between SONiC's
Redis-backed Configuration Database (`CONFIG_DB`, database index `4`) and the
shared `ietf-system-tacacs-plus` YANG configuration consumed by the agent.

## What the bridge does

1. Reads `TACPLUS|global`, compatibility `TACPLUS_SERVER|<addr>`, version-1
   `TACPLUS_SERVER_TLS|<addr>`, and `TACPLUS_FORWARDER|global` as one snapshot.
2. Parses raw Redis hashes into private typed rows before producing any RFC
   configuration.
3. Preserves all source rows, rejects cross-table ambiguity, and orders mixed
   candidates by descending priority plus a stable normalized name/endpoint tie-breaker.
4. Maps compatibility rows into [`tacacsrs_config::TacacsPlusServer`] values.
5. Subscribes to Redis keyspace notifications (`__keyspace@4__:TACPLUS*`) and
   re-emits a [`tacacsrs_config::source::ConfigChange`] when relevant keys change.

The [`mapping`] module implements parsing and field mapping as pure functions
and fully unit-tests them without a live Redis. The Redis client only handles
I/O.

## Observation Ownership

`SonicConfigDb::observe()` establishes Redis notification delivery before the baseline read.
The returned session owns a notification pump and its pending snapshot future.
The pump coalesces invalidations through a bounded watch channel and never waits for a slow snapshot consumer.
There is no separate reload worker. Cancelling `next()` retains the pending read and concurrent invalidations.

Dropping the observation cancels the pump and drops the pending Redis operation.
Loss of the Pub/Sub connection returns an observation error. The agent opens a new session before it reads a recovery baseline.
Rejected mappings retain the previous accepted snapshot and its delta history.
The first valid snapshot after a rejection emits a recovery change, even when its TACACS+ delta is empty.
The matching restart-required event follows that recovery change.
The native tests verify idle cleanup, pending-read cleanup, cancellation, disconnect recovery, and removal of the final server.

`ConfigDatastore` requires an explicit observation implementation. Its former `subscribe()` method and default observation adapter are removed.
One-shot `load()` remains available for non-observing callers.

## Forwarder Ownership

`SonicForwarderSettings::local_services` normalizes the validated forwarder row into generated `LocalServices`.
The SONiC profile enables both services and selects `local-proxy-row` credentials.
Generated YANG defaults supply the client API path and socket permissions.
The optional ConfigDB listener port still defaults to 49 as a SONiC input rule. The canonical resource contains the explicit endpoint.

Mapping no longer deletes local compatibility rows or rejects TLS self-targets.
Canonical snapshots retain those rows and their credentials. The daemon's shared runtime filter performs both decisions before publication.
This preserves the local row needed for downstream credential preparation without adding it to the applied upstream set.
Distinct loopback addresses remain distinct hosts. IPv4-mapped addresses normalize to their IPv4 equivalents, but hostnames do not imply a particular IP address.

The daemon checks resolved destinations against the bound listener configuration and current local interfaces.
Uncertain DNS results reject the candidate instead of bypassing loop validation.
The agent also applies a connection-time guard using the actual bound proxy address, refreshed interfaces, and connected socket addresses.
Every resolved destination is checked before TCP connect. The connected socket is checked again before TLS or TACACS+ I/O.
These runtime checks supplement publication-time validation without changing the canonical SONiC snapshot.

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

`SonicCredentialChangeSource` watches the EPSK root and its parent independently of Redis configuration observation.
Its returned stream owns the watcher worker. Dropping the stream cancels that worker, even while it waits without an event.
Only reviewed opaque object names and root events trigger the watcher. It ignores temporary names and access-only events.
Rescan events require complete reconciliation. Failed root-watch re-registration reports `Unavailable` and ends the stream so the agent can reconnect.
`watch_credential_changes` exposes the owned debounced stream directly and requires an active Tokio runtime.
The agent re-resolves affected credentials and prepares an atomic runtime candidate from its retained canonical source.
The watcher never patches bytes into an active runtime. This supports
immutable-ID ConfigDB switches and explicit same-ID atomic replacement while
preserving the prior runtime on missing or rejected material.

## Example watcher

The `configdb_watch` example demonstrates the crate's runtime contract: it
opens one observation, prints its baseline, and then prints each
`ConfigChange` from that same session. Each change
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
It never prints secret values or the credential-bearing Redis URL. The mapper treats compatibility rows without a
per-server or global `passkey` as unobfuscated plain TCP.
