//! Local client API bridge to managed upstream TACACS+ connections.
//!
//! Accounting and authorization use the same routing and failover mechanisms.
//! Each operation has separate request and reply types. This module keeps the
//! local request model in the client API service. Only TACACS+ messages cross
//! the server boundary.

use std::sync::Arc;

use crate::config::PolicyService;
use crate::upstream::OperationRouter;
use crate::upstream::manager::UpstreamManager;
use tacacsrs_networking::routed::EndpointConnector;

mod accounting;
mod authentication;
mod authorization;
mod routed;
mod watchdog;

#[cfg(test)]
mod routing_tests;

/// Sends local client API operations through selected server connections.
///
/// The bridge holds an [`OperationRouter`], not the whole upstream manager. It
/// can select servers and record outcomes. It cannot read proxy settings or
/// change the runtime configuration.
pub(crate) struct UpstreamBridge<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    router: OperationRouter<Connector>,
}

impl<Connector: EndpointConnector> Clone for UpstreamBridge<Connector> {
    fn clone(&self) -> Self {
        Self {
            router: self.router.clone(),
        }
    }
}

impl<Connector: EndpointConnector> UpstreamBridge<Connector> {
    /// Creates a client API bridge for the shared upstream manager.
    pub(crate) fn new(upstream_manager: Arc<UpstreamManager<Connector>>) -> Self {
        Self {
            router: OperationRouter::new(upstream_manager, PolicyService::ClientApi),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use tacacsrs_config::TacacsPlusServer;
    use tacacsrs_protocol::operations::{AuthenticationResponseStatus, PapAuthenticationOperation};
    use tacacsrs_secrets::SecretBytes;

    use super::UpstreamBridge;
    use crate::runtime::{REQUIRED_SERVER_TYPES, RuntimeHealthPublisher};
    use crate::test_support::{FakeConnection, FakeConnector, build_authorization_request};
    use crate::upstream::UpstreamConnector;
    use crate::upstream::manager::UpstreamManager;
    use crate::EnabledServices;

    fn test_server(address: &str) -> TacacsPlusServer {
        let (host, port) = match address.rsplit_once(':') {
            Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(49)),
            None => (address.to_owned(), 49),
        };

        tacacsrs_config::TacacsPlusServer {
            name: address.to_owned(),
            server_type: REQUIRED_SERVER_TYPES,
            address: host,
            port,
            shared_secret: None,
            timeout: 5,
            single_connection: false,
            domain_name: None,
            sni_enabled: None,
            client_identity: None,
            server_authentication: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
            egress_interface: None,
            binding_policy: tacacsrs_config::tacacsrs::BindingPolicy::BestEffort,
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn test_authorization_request_uses_configured_upstream_server() {
        let connection = Arc::new(FakeConnection {
            address: "server:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            "server:49".to_owned(),
            Arc::clone(&connection),
        )])));

        let state = Arc::new(UpstreamManager::new(
            vec![test_server("server:49")],
            Arc::clone(&connector) as Arc<UpstreamConnector>,
            Duration::from_millis(200),
            RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
        ));
        let bridge = UpstreamBridge::new(Arc::clone(&state));

        let response = bridge
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap();

        assert_eq!(response.server, "server:49");
        assert_eq!(connector.connect_attempts_for("server:49").await, 1);
    }

    #[tokio::test]
    async fn test_pap_authentication_uses_configured_upstream_server() {
        let connection = Arc::new(FakeConnection {
            address: "server:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            "server:49".to_owned(),
            Arc::clone(&connection),
        )])));
        let state = Arc::new(UpstreamManager::new(
            vec![test_server("server:49")],
            Arc::clone(&connector) as Arc<UpstreamConnector>,
            Duration::from_millis(200),
            RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
        ));
        let bridge = UpstreamBridge::new(state);

        let response = bridge
            .execute_pap_authentication_request(PapAuthenticationOperation {
                user: "admin".to_owned(),
                password: SecretBytes::new(b"secret".to_vec()),
                port: "tty0".to_owned(),
                remote_address: "192.0.2.1".to_owned(),
                privilege_level: tacacsrs_protocol::privilege::PrivilegeLevel::MAX,
            })
            .await
            .unwrap();

        assert_eq!(response.server, "server:49");
        assert_eq!(response.status, AuthenticationResponseStatus::Pass);
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn test_authorization_failure_returns_service_error_and_fails_over() {
        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(true),
        });
        let secondary = Arc::new(FakeConnection {
            address: "secondary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([
            ("primary:49".to_owned(), Arc::clone(&primary)),
            ("secondary:49".to_owned(), Arc::clone(&secondary)),
        ])));

        let state = Arc::new(UpstreamManager::new(
            vec![test_server("primary:49"), test_server("secondary:49")],
            Arc::clone(&connector) as Arc<UpstreamConnector>,
            Duration::from_millis(200),
            RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
        ));
        let bridge = UpstreamBridge::new(Arc::clone(&state));

        let error = bridge
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap_err();
        assert_eq!(error.server.as_deref(), Some("primary:49"));
        assert_eq!(error.facts.retry_advice(), tacacsrs_protocol::failure::RetryAdvice::Never);

        let response = bridge
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap();
        assert_eq!(response.server, "secondary:49");
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn watchdog_probe_failure_withdraws_readiness_and_success_restores_it() {
        use crate::services::client_api::{UpstreamProbeOutcome, probe::run_probe};
        use crate::{DegradationReason, ListenerState, RuntimeService};

        let connection = Arc::new(FakeConnection {
            address: "server:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            "server:49".to_owned(),
            Arc::clone(&connection),
        )])));
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let state = Arc::new(UpstreamManager::new(
            vec![test_server("server:49")],
            Arc::clone(&connector) as Arc<UpstreamConnector>,
            Duration::from_millis(200),
            health.clone(),
        ));
        health.set_applied_configuration(true);
        health.set_eligible_server_count(1);
        health.set_listener(RuntimeService::ClientApi, ListenerState::Bound);
        assert!(health.snapshot().is_readiness_serving());
        let bridge = UpstreamBridge::new(state);

        health.set_upstream_watchdog_failed(health.snapshot().upstream_watchdog_epoch(), true);
        assert!(!health.snapshot().is_readiness_serving());
        assert!(health.snapshot().is_listening());
        assert_eq!(run_probe(&bridge, &health).await, UpstreamProbeOutcome::Succeeded);
        assert!(health.snapshot().is_readiness_serving());

        connection
            .fail_next_request
            .store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(run_probe(&bridge, &health).await, UpstreamProbeOutcome::Failed);
        let snapshot = health.snapshot();
        assert!(!snapshot.is_readiness_serving());
        assert!(snapshot.is_listening());
        assert!(snapshot
            .degradation_reasons()
            .contains(&DegradationReason::UpstreamWatchdogFailed));
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn armed_watchdog_probe_tries_the_next_server_after_an_unknown_outcome() {
        use crate::services::client_api::{UpstreamProbeOutcome, probe::run_probe};
        use crate::{DegradationReason, ListenerState, RuntimeService};

        let primary = Arc::new(FakeConnection {
            address: "primary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(true),
        });
        let secondary = Arc::new(FakeConnection {
            address: "secondary:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([
            ("primary:49".to_owned(), Arc::clone(&primary)),
            ("secondary:49".to_owned(), Arc::clone(&secondary)),
        ])));
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        health.arm_upstream_watchdog();
        let state = Arc::new(UpstreamManager::new(
            vec![test_server("primary:49"), test_server("secondary:49")],
            Arc::clone(&connector) as Arc<UpstreamConnector>,
            Duration::from_millis(200),
            health.clone(),
        ));
        health.set_applied_configuration(true);
        health.set_eligible_server_count(2);
        health.set_listener(RuntimeService::ClientApi, ListenerState::Bound);
        let snapshot = health.snapshot();
        assert!(!snapshot.is_readiness_serving());
        assert!(snapshot
            .degradation_reasons()
            .contains(&DegradationReason::UpstreamWatchdogPending));

        let bridge = UpstreamBridge::new(state);
        assert_eq!(run_probe(&bridge, &health).await, UpstreamProbeOutcome::Succeeded);
        assert_eq!(connector.connect_attempts_for("secondary:49").await, 1);
        assert!(health.snapshot().is_readiness_serving());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // Miri does not support Tokio tasks or time.
    async fn watchdog_probe_counts_an_accounting_error_reply_as_success() {
        use crate::services::client_api::{UpstreamProbeOutcome, probe::run_probe};

        let connection = Arc::new(FakeConnection {
            address: "accounting-error:49".to_owned(),
            usable: AtomicBool::new(true),
            fail_next_request: AtomicBool::new(false),
        });
        let connector = Arc::new(FakeConnector::new(HashMap::from([(
            "accounting-error:49".to_owned(),
            Arc::clone(&connection),
        )])));
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let state = Arc::new(UpstreamManager::new(
            vec![test_server("accounting-error:49")],
            Arc::clone(&connector) as Arc<UpstreamConnector>,
            Duration::from_millis(200),
            health.clone(),
        ));
        health.set_upstream_watchdog_failed(health.snapshot().upstream_watchdog_epoch(), true);
        let bridge = UpstreamBridge::new(state);

        assert_eq!(run_probe(&bridge, &health).await, UpstreamProbeOutcome::Succeeded);
        assert!(!health
            .snapshot()
            .degradation_reasons()
            .contains(&crate::DegradationReason::UpstreamWatchdogFailed));
    }

    #[tokio::test]
    async fn watchdog_probe_without_accounting_servers_sends_nothing() {
        use crate::services::client_api::{UpstreamProbeOutcome, probe::run_probe};

        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let connector = Arc::new(FakeConnector::new(HashMap::new()));
        let state = Arc::new(UpstreamManager::new(
            Vec::new(),
            Arc::clone(&connector) as Arc<UpstreamConnector>,
            Duration::from_millis(200),
            health.clone(),
        ));
        health.set_upstream_watchdog_failed(health.snapshot().upstream_watchdog_epoch(), true);
        let bridge = UpstreamBridge::new(state);

        assert_eq!(run_probe(&bridge, &health).await, UpstreamProbeOutcome::Skipped);
        assert!(!health
            .snapshot()
            .degradation_reasons()
            .contains(&crate::DegradationReason::UpstreamWatchdogFailed));
    }

    #[tokio::test]
    async fn test_request_without_configured_servers_returns_waiting_error() {
        let state = Arc::new(UpstreamManager::new(
            Vec::new(),
            Arc::new(FakeConnector::new(HashMap::new())) as Arc<UpstreamConnector>,
            Duration::from_millis(200),
            RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
        ));
        let bridge = UpstreamBridge::new(Arc::clone(&state));

        let error = bridge
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap_err();

        assert_eq!(
            error.facts.retry_advice(),
            tacacsrs_protocol::failure::RetryAdvice::AfterRecovery
        );
        assert!(error.message.contains("waiting for initial configuration"));
    }
}
