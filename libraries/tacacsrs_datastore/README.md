# tacacsrs-datastore

Datastore abstraction layer for `tacacsrs-agentd` and other consumers that need
to receive a [`tacacsrs_config::TacacsPlus`] root configuration from a runtime
source.

The crate intentionally has no opinion on _where_ the configuration comes from.
It defines:

- [`ConfigDatastore`] — an `async` trait with `load` and `subscribe` methods.
- [`ConfigChange`] — the event emitted when the datastore reloads the upstream
  configuration. It carries the new complete `TacacsPlus` snapshot plus a delta
  computed against the previous snapshot. Consumers must treat the snapshot
  as authoritative and use the delta to decide whether incremental handling is
  sufficient or a full rebuild is clearer.
- [`StaticDatastore`] — an in-memory backend used for CLI / file / test
  workflows. `subscribe` returns a stream that never emits, since the
  configuration cannot change after construction.

Concrete backends (for example a `SONiC` `ConfigDB` adapter) live in their own
crates and only depend on this crate's small surface so the daemon and the
TACACS+ service stay decoupled from any specific datastore.
