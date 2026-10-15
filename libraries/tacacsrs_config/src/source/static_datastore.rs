//! In-memory configuration backend for CLI, file, and test workflows.
//!
//! [`StaticDatastore`] serves one validated [`TacacsPlus`](crate::TacacsPlus)
//! snapshot for the process lifetime. It implements the
//! [`ConfigDatastore`](super::ConfigDatastore) contract defined in the parent
//! module. Observation yields the snapshot once as a baseline, then ends
//! without a worker task.

use std::sync::Arc;

use async_trait::async_trait;

use crate::TacacsPlus;
use super::{
    ChangeNotificationMode, ConfigChange, ConfigChangeEvent, ConfigDatastore, ConfigDelta,
    ConfigObservation, DatastoreRuntimePolicy, InitialLoadPolicy,
};

struct StaticObservation(Option<Arc<TacacsPlus>>);

#[async_trait]
impl ConfigObservation for StaticObservation {
    async fn next(&mut self) -> anyhow::Result<Option<ConfigChangeEvent>> {
        Ok(self.0.take().map(|config| {
            ConfigChangeEvent::Changed(ConfigChange {
                delta: ConfigDelta::diff(None, &config),
                config,
            })
        }))
    }
}

/// In-memory [`ConfigDatastore`] for CLI/file/test workflows.
///
/// `StaticDatastore` holds one `TacacsPlus` snapshot for the process lifetime.
/// Observation yields that snapshot once, then ends without a worker task.
#[derive(Debug, Clone)]
pub struct StaticDatastore {
    config: Arc<TacacsPlus>,
    label: &'static str,
}

impl StaticDatastore {
    /// Creates a static datastore with validated configuration.
    #[must_use]
    pub fn new(config: TacacsPlus) -> Self {
        Self::with_label(config, "static")
    }

    /// Creates a static datastore with a caller-supplied label.
    ///
    /// [`ConfigDatastore::label`] returns this label for operator logs.
    #[must_use]
    pub fn with_label(config: TacacsPlus, label: &'static str) -> Self {
        Self {
            config: Arc::new(config),
            label,
        }
    }
}

#[async_trait]
impl ConfigDatastore for StaticDatastore {
    async fn observe(&self) -> anyhow::Result<Box<dyn ConfigObservation>> {
        Ok(Box::new(StaticObservation(Some(self.config.clone()))))
    }

    fn runtime_policy(&self) -> DatastoreRuntimePolicy {
        DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None)
    }

    async fn load(&self) -> anyhow::Result<TacacsPlus> {
        Ok((*self.config).clone())
    }

    fn label(&self) -> &'static str {
        self.label
    }
}

#[cfg(test)]
mod tests {
    use crate::{TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};
    use super::*;

    fn sample_config(addr: &str) -> TacacsPlus {
        TacacsPlusBuilder::new()
            .with_server_builder(
                TacacsPlusServerBuilder::new("primary", TacacsPlusServerType::all(), addr, 49)
                    .with_shared_secret("topsecret"),
            )
            .build()
            .expect("sample configuration must be valid")
    }

    #[tokio::test]
    async fn static_datastore_returns_config_and_empty_stream() {
        let config = sample_config("192.0.2.1");
        let store = StaticDatastore::new(config.clone());
        let loaded = store.load().await.expect("load must succeed");
        assert_eq!(loaded.server.len(), 1);
        assert_eq!(store.label(), "static");
        assert_eq!(
            store.runtime_policy(),
            DatastoreRuntimePolicy::new(InitialLoadPolicy::FailFast, ChangeNotificationMode::None,)
        );

        let mut observation = store.observe().await.unwrap();
        let Some(ConfigChangeEvent::Changed(baseline)) = observation.next().await.unwrap() else {
            panic!("static observation must yield its canonical baseline");
        };
        assert_eq!(*baseline.config, config);
        assert_eq!(baseline.delta.added_servers, ["primary"]);
        assert!(observation.next().await.unwrap().is_none());
    }
}
