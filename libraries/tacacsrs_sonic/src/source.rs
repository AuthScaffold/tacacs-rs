//! Source-specific forwarder discovery and credential assembly.

use std::sync::Arc;
use std::time::Duration;

use tacacsrs_provider::CredentialProvider;

use crate::{
    SonicConnection, SonicCredentialChangeSource, SonicCredentialPolicy, SonicCredentialResolver,
    SonicCredentialRoots, SonicForwarderSettings,
};

/// Creates the SONiC credential provider for this connection.
#[must_use]
pub fn credentials(settings: &SonicConnection) -> CredentialProvider {
    let resolver = Arc::new(SonicCredentialResolver::reloadable(
        SonicCredentialRoots::default(),
        SonicCredentialPolicy::production_from_root_group(),
    ));
    match &settings.credential_watch_root {
        Some(root) => CredentialProvider::observed(
            resolver,
            Arc::new(SonicCredentialChangeSource::new(root.clone(), settings.debounce)),
        ),
        None => CredentialProvider::resolver(resolver),
    }
}

/// Retries forwarder discovery until ConfigDB returns a valid row.
///
/// Dropping the future stops discovery.
pub async fn wait_for_forwarder(settings: &SonicConnection) -> SonicForwarderSettings {
    let mut delay = Duration::from_millis(250);
    loop {
        match settings.load_forwarder_settings().await {
            Ok(forwarder) => return forwarder,
            Err(_) => {
                log::warn!("SONiC forwarder configuration is unavailable. The daemon retries before it binds.");
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(Duration::from_secs(30));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_notifications_follow_connection_settings() {
        let mut settings = SonicConnection::default();
        let (resolver, changes) = credentials(&settings).into_parts();
        assert!(resolver.is_some() && changes.is_some());
        settings.credential_watch_root = None;
        let (resolver, changes) = credentials(&settings).into_parts();
        assert!(resolver.is_some() && changes.is_none());
    }

    #[tokio::test]
    async fn forwarder_discovery_can_be_cancelled() {
        let settings = SonicConnection {
            url: "invalid".to_owned(),
            ..SonicConnection::default()
        };
        assert!(tokio::time::timeout(Duration::from_millis(20), wait_for_forwarder(&settings),)
            .await
            .is_err());
    }
}
