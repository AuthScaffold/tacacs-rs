//! Local client API bridge to managed upstream TACACS+ connections.
//!
//! Accounting and authorization share the same routing and failover machinery,
//! but each operation has its own request/response types and upstream send
//! method. This module keeps the local client API request model contained in
//! the client API service while sending only TACACS+ protocol messages through
//! the upstream boundary.

use std::sync::Arc;

use crate::upstream::manager::UpstreamManager;

mod accounting;
mod authorization;
mod mapping;
mod routed;

/// Bridges local client API operations onto selected upstream connections.
#[derive(Clone)]
pub(super) struct UpstreamBridge {
    upstream_manager: Arc<UpstreamManager>,
}

impl UpstreamBridge {
    /// Creates a client API upstream bridge over the shared upstream manager.
    pub(super) fn new(upstream_manager: Arc<UpstreamManager>) -> Self {
        Self { upstream_manager }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use tacacsrs_config::TacacsPlusServer;

    use super::UpstreamBridge;
    use crate::runtime::REQUIRED_SERVER_TYPES;
    use crate::test_support::{FakeConnection, FakeConnector, build_authorization_request};
    use crate::upstream::UpstreamConnector;
    use crate::upstream::manager::UpstreamManager;

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
        }
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
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
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
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
    #[cfg_attr(miri, ignore)] // tokio spawn/time not supported
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
            Arc::clone(&connector) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
        ));
        let bridge = UpstreamBridge::new(Arc::clone(&state));

        let error = bridge
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap_err();
        assert_eq!(error.server.as_deref(), Some("primary:49"));
        assert!(error.retriable);

        let response = bridge
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap();
        assert_eq!(response.server, "secondary:49");
    }

    #[tokio::test]
    async fn test_request_without_configured_servers_returns_waiting_error() {
        let state = Arc::new(UpstreamManager::new(
            Vec::new(),
            Arc::new(FakeConnector::new(HashMap::new())) as Arc<dyn UpstreamConnector>,
            Duration::from_millis(200),
        ));
        let bridge = UpstreamBridge::new(Arc::clone(&state));

        let error = bridge
            .execute_authorization_request(build_authorization_request())
            .await
            .unwrap_err();

        assert!(error.retriable);
        assert!(error.message.contains("waiting for initial configuration"));
    }
}
