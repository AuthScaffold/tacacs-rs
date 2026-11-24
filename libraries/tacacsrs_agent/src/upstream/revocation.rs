//! Host-supplied certificate revocation checks for new upstream connections.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::watch;

use tacacsrs_networking::{
    PreparedEndpoint, RevocationDecision, RevocationNetwork, RevocationRejection,
    RevocationSettings, RevocationVerifier, VerifiedPath,
};

struct MissingRevocationVerifier {
    settings: watch::Receiver<RevocationSettings>,
}

impl MissingRevocationVerifier {
    fn decide_current(&self) -> RevocationDecision {
        let enforcement = self.settings.borrow().enforcement;
        if enforcement.requires_verifier() {
            RevocationDecision::Reject(RevocationRejection::unverified(format!(
                "Certificate revocation enforcement is {enforcement}, but this agent has no revocation verifier"
            )))
        } else {
            RevocationDecision::Verified
        }
    }
}

#[async_trait]
impl RevocationVerifier for MissingRevocationVerifier {
    fn decide(&self, _: &VerifiedPath) -> RevocationDecision {
        self.decide_current()
    }

    async fn obtain(
        &self,
        _: &VerifiedPath,
        _: &RevocationNetwork,
        _: Option<tokio::time::Instant>,
    ) {
    }
}

#[derive(Clone)]
enum ConfiguredVerifier {
    Host(Arc<dyn RevocationVerifier>),
    Missing(Arc<MissingRevocationVerifier>),
}

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
    verifier: ConfiguredVerifier,
    settings: Arc<watch::Sender<RevocationSettings>>,
    network: Arc<watch::Sender<RevocationNetwork>>,
}

impl UpstreamRevocation {
    /// Creates an input with a verifier and the sender of its settings channel.
    #[must_use]
    pub fn new(
        verifier: Arc<dyn RevocationVerifier>,
        settings: watch::Sender<RevocationSettings>,
    ) -> Self {
        Self::with_network(verifier, settings, watch::channel(RevocationNetwork::default()).0)
    }

    /// Creates an input with a verifier, settings channel, and default prefetch network channel.
    #[must_use]
    pub fn with_network(
        verifier: Arc<dyn RevocationVerifier>,
        settings: watch::Sender<RevocationSettings>,
        network: watch::Sender<RevocationNetwork>,
    ) -> Self {
        Self {
            verifier: ConfiguredVerifier::Host(verifier),
            settings: Arc::new(settings),
            network: Arc::new(network),
        }
    }

    /// Creates an input without a verifier.
    ///
    /// Certificate TLS connections succeed only while enforcement is `disabled`.
    #[must_use]
    pub fn without_verifier() -> Self {
        let (settings, receiver) = watch::channel(RevocationSettings::default());
        Self {
            verifier: ConfiguredVerifier::Missing(Arc::new(MissingRevocationVerifier {
                settings: receiver,
            })),
            settings: Arc::new(settings),
            network: Arc::new(watch::channel(RevocationNetwork::default()).0),
        }
    }

    /// Publishes the default network context used for CRL prefetching.
    pub(crate) fn set_default_network(&self, network: RevocationNetwork) {
        self.network.send_if_modified(|current| {
            let changed = current.binding() != network.binding()
                || format!("{current:?}") != format!("{network:?}");
            if changed {
                *current = network;
            }
            changed
        });
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
        match &self.verifier {
            ConfiguredVerifier::Host(verifier) => {
                Ok(endpoint.with_revocation_verifier(Arc::clone(verifier)))
            }
            ConfiguredVerifier::Missing(fallback) => {
                let enforcement = self.settings.borrow().enforcement;
                anyhow::ensure!(
                    !enforcement.requires_verifier() || !endpoint.verifies_server_certificate(),
                    "Certificate revocation enforcement is {enforcement}, but this agent has no revocation verifier"
                );
                if endpoint.verifies_server_certificate() {
                    let verifier: Arc<dyn RevocationVerifier> = fallback.clone();
                    Ok(endpoint.with_revocation_verifier(verifier))
                } else {
                    Ok(endpoint)
                }
            }
        }
    }

    #[cfg(test)]
    fn missing_verifier(&self) -> Option<&Arc<MissingRevocationVerifier>> {
        match &self.verifier {
            ConfiguredVerifier::Host(_) => None,
            ConfiguredVerifier::Missing(verifier) => Some(verifier),
        }
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
            .field("verifier", &matches!(self.verifier, ConfiguredVerifier::Host(_)))
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
        assert_eq!(
            format!("{revocation:?}"),
            "UpstreamRevocation { verifier: false, enforcement: Disabled }"
        );
        let cached_tls = revocation.attach(endpoint(true)).unwrap();
        assert!(cached_tls.has_revocation_verifier());
        assert!(!revocation
            .attach(endpoint(false))
            .unwrap()
            .has_revocation_verifier());
        let attached_fallback = Arc::clone(revocation.missing_verifier().unwrap());
        assert_eq!(attached_fallback.decide_current(), RevocationDecision::Verified);

        for enforcement in [
            RevocationEnforcement::HardFail,
            RevocationEnforcement::SoftFail,
            RevocationEnforcement::WarnOnly,
        ] {
            assert!(revocation.publish(&enforced(enforcement)));
            let RevocationDecision::Reject(rejection) = attached_fallback.decide_current() else {
                panic!("expected cached fallback verifier to reject under {enforcement}");
            };
            assert!(!rejection.is_revoked());
            assert!(rejection.reason().contains("no revocation verifier"));
            let error = revocation.attach(endpoint(true)).unwrap_err();
            assert!(error.to_string().contains("no revocation verifier"), "{error:#}");
            assert!(revocation.attach(endpoint(false)).is_ok());
        }

        assert!(revocation.publish(&RevocationSettings::default()));
        assert_eq!(attached_fallback.decide_current(), RevocationDecision::Verified);
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
