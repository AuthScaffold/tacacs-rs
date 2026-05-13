# tacacsrs-datastore

Datastore abstraction layer for `tacacsrs-agentd` and other consumers that need
to receive a [`tacacsrs_config::TacacsPlus`] root configuration from a runtime
source.

The crate intentionally has no opinion on _where_ the configuration comes from.
It defines:

- [`ConfigDatastore`] — an `async` trait with `load` and `subscribe` methods.
- [`ConfigChange`] — the event emitted when the upstream configuration is
  reloaded; it carries the new `TacacsPlus` snapshot and a list of deltas
  computed against the previous snapshot.
- [`StaticDatastore`] — an in-memory backend used for CLI / file / test
  workflows. `subscribe` returns a stream that never emits, since the
  configuration cannot change after construction.

Concrete backends (for example a `SONiC` `ConfigDB` adapter) live in their own
crates and only depend on this crate's small surface so the daemon and the
TACACS+ service stay decoupled from any specific datastore.
