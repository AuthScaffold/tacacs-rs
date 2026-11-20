//! Host-supplied certificate revocation checks for new upstream connections.

use std::sync::Arc;

use tokio::sync::watch;

use tacacsrs_networking::{PreparedEndpoint, RevocationSettings, RevocationVerifier};

/// Certificate revocation input for the upstream connector.
///
/// The host creates the settings channel, gives the receiver to its verifier,
/// and supplies this value to the agent. The agent sends the settings of each
/// accepted configuration change through the channel. A settings change
/// affects only new connections. The agent never closes an established
/// connection because of revocation settings or evidence.
///
/// Without a verifier, the agent rejects new certificate TLS connections while
/// the active enforcement is not `disabled`.
#[derive(Clone)]
pub struct UpstreamRevocation {
    verifier: Option<Arc<dyn RevocationVerifier>>,
    settings: Arc<watch::Sender<RevocationSettings>>,
}

impl UpstreamRevocation {
    /// Creates an input with a verifier and the sender of its settings channel.
    #[must_use]
    pub fn new(
        verifier: Arc<dyn RevocationVerifier>,
        settings: watch::Sender<RevocationSettings>,
    ) -> Self {
        Self {
            verifier: Some(verifier),
            settings: Arc::new(settings),
        }
    }

    /// Creates an input without a verifier.
    ///
    /// Certificate TLS connections succeed only while enforcement is `disabled`.
    #[must_use]
    pub fn without_verifier() -> Self {
        Self {
            verifier: None,
            settings: Arc::new(watch::channel(RevocationSettings::default()).0),
        }
    }

    /// Returns the active settings.
    #[must_use]
    pub fn settings(&self) -> RevocationSettings {
        self.settings.borrow().clone()
    }

    /// Publishes new settings. Returns `true` when the settings changed.
    pub(crate) fn publish(&self, settings: &RevocationSettings) -> bool {
        self.settings.send_if_modified(|current| {
            if current == settings {
                return false;
            }
            log::info!("Certificate revocation enforcement is now {}", settings.enforcement);
            current.clone_from(settings);
            true
        })
    }

    /// Attaches the verifier to `endpoint`.
    ///
    /// # Errors
    /// Returns an error for a certificate TLS endpoint when enforcement is
    /// enabled and no verifier exists.
    pub(crate) fn attach(&self, endpoint: PreparedEndpoint) -> anyhow::Result<PreparedEndpoint> {
        if let Some(verifier) = &self.verifier {
            return Ok(endpoint.with_revocation_verifier(Arc::clone(verifier)));
        }
        let enforcement = self.settings.borrow().enforcement;
        anyhow::ensure!(
            !enforcement.requires_verifier() || !endpoint.verifies_server_certificate(),
            "Certificate revocation enforcement is {enforcement}, but this agent has no revocation verifier"
        );
        Ok(endpoint)
    }
}

impl Default for UpstreamRevocation {
    fn default() -> Self {
        Self::without_verifier()
    }
}

impl std::fmt::Debug for UpstreamRevocation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UpstreamRevocation")
            .field("verifier", &self.verifier.is_some())
            .field("enforcement", &self.settings.borrow().enforcement)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::sync::watch;

    use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerType};
    use tacacsrs_config::prepare::{prepare_endpoint, PrepareOptions};
    use tacacsrs_networking::{
        RevocationDecision, RevocationEnforcement, RevocationNetwork, RevocationSettings,
        RevocationVerifier, VerifiedPath,
    };

    use super::UpstreamRevocation;

    struct AcceptAll;

    #[async_trait]
    impl RevocationVerifier for AcceptAll {
        fn decide(&self, _: &VerifiedPath) -> RevocationDecision {
            RevocationDecision::Verified
        }

        async fn obtain(
            &self,
            _: &VerifiedPath,
            _: &RevocationNetwork,
            _: Option<tokio::time::Instant>,
        ) {
        }
    }

    fn enforced(enforcement: RevocationEnforcement) -> RevocationSettings {
        let mut settings = RevocationSettings::default();
        settings.enforcement = enforcement;
        settings
    }

    fn endpoint(tls: bool) -> tacacsrs_networking::PreparedEndpoint {
        let builder =
            TacacsPlusServerBuilder::new("server", TacacsPlusServerType::all(), "192.0.2.1", 300);
        let server = if tls {
            builder.with_tls_server_authentication().build()
        } else {
            builder.with_shared_secret("secret").build()
        };
        prepare_endpoint(&server, PrepareOptions::default()).unwrap()
    }

    #[test]
    fn enabled_enforcement_without_a_verifier_rejects_only_certificate_tls() {
        let revocation = UpstreamRevocation::without_verifier();
        assert!(revocation.attach(endpoint(true)).is_ok());
        for enforcement in [
            RevocationEnforcement::HardFail,
            RevocationEnforcement::SoftFail,
            RevocationEnforcement::WarnOnly,
        ] {
            assert!(revocation.publish(&enforced(enforcement)));
            let error = revocation.attach(endpoint(true)).unwrap_err();
            assert!(error.to_string().contains("no revocation verifier"), "{error:#}");
            assert!(revocation.attach(endpoint(false)).is_ok());
        }
    }

    #[test]
    fn a_verifier_attaches_under_every_enforcement() {
        let (sender, receiver) = watch::channel(RevocationSettings::default());
        let revocation = UpstreamRevocation::new(Arc::new(AcceptAll), sender);
        assert!(revocation
            .attach(endpoint(true))
            .unwrap()
            .has_revocation_verifier());
        assert!(revocation.publish(&enforced(RevocationEnforcement::HardFail)));
        assert!(!revocation.publish(&enforced(RevocationEnforcement::HardFail)));
        assert_eq!(receiver.borrow().enforcement, RevocationEnforcement::HardFail);
        assert!(revocation
            .attach(endpoint(true))
            .unwrap()
            .has_revocation_verifier());
    }
}
