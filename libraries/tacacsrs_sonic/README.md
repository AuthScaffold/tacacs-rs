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
ConfigDB to enable the richer YANG features; today the bridge supports the
shared-secret / obfuscation-key path only and leaves the TLS-related YANG
fields unset on the resulting [`tacacsrs_config::TacacsPlusServer`].

## Schema extensions

The mapping recognizes a small forward-compatible extension on top of the
upstream SONiC schema so that operators can experiment with the TLS-capable
YANG model without waiting for SONiC ConfigDB updates:

| Extension key on `TACPLUS_SERVER|<addr>` | YANG field                             |
|------------------------------------------|----------------------------------------|
| `domain_name`                            | `domain-name` (used for SNI)           |
| `sni_enabled`                            | `sni-enabled`                          |
| `single_connection`                      | `single-connection`                    |
| `vrf_name`                               | `vrf-instance`                         |
| `src_intf` (also on `global`)            | `source-interface`                     |
| `src_ip`                                 | `source-ip`                            |
| `server_type`                            | `server-type` bitset, defaults to `all`|

Unknown keys are ignored with a `warn!` log so legacy SONiC builds with extra
operator-specific keys do not cause the bridge to fail at startup.
