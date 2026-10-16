use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingResponseStatus, AuthenticationResponseStatus,
    PapAuthenticationOperation,
};
use tacacsrs_config::TacacsPlusServer;
use tacacsrs_protocol::exchange::authentication::PapAuthenticationExchange;
use tacacsrs_protocol::accounting::reply::AccountingReply;
use tacacsrs_protocol::accounting::request::AccountingRequest;
use tacacsrs_protocol::authentication::reply::AuthenticationReply;
use tacacsrs_protocol::authorization::reply::AuthorizationReply;
use tacacsrs_protocol::authorization::request::AuthorizationRequest;
use tacacsrs_protocol::enumerations::{
    TacacsAccountingStatus, TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus,
    TacacsAuthorizationStatus,
};
use tacacsrs_secrets::SecretBytes;
use tokio::sync::{Mutex, Notify};

use super::UpstreamBridge;
use crate::config::{FailoverStrategy, OperationPolicies, PreparedProxyPolicy, RuntimePolicy};
use crate::runtime::{REQUIRED_SERVER_TYPES, RuntimeHealthPublisher};
use crate::upstream::manager::UpstreamManager;
use crate::upstream::{OperationKind, UpstreamConnection, UpstreamRequestError};
use crate::EnabledServices;

struct ScriptedConnection {
    address: String,
    fail_authentication: AtomicBool,
    fail_accounting: AtomicBool,
    fail_authorization: AtomicBool,
    authentication_status: TacacsAuthenticationStatus,
    accounting_status: TacacsAccountingStatus,
    accounting_barrier: Option<(Arc<Notify>, Arc<Notify>)>,
    accounting_delay: Duration,
    accounting_started: Notify,
}

impl ScriptedConnection {
    fn successful(address: &str) -> Self {
        Self {
            address: address.to_owned(),
            fail_authentication: AtomicBool::new(false),
            fail_accounting: AtomicBool::new(false),
            fail_authorization: AtomicBool::new(false),
            authentication_status: TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            accounting_status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            accounting_barrier: None,
            accounting_delay: Duration::ZERO,
            accounting_started: Notify::new(),
        }
    }
}

#[async_trait]
impl UpstreamConnection for ScriptedConnection {
    fn server_address(&self) -> &str {
        &self.address
    }

    async fn stop_accepting_new_sessions(&self) {}

    fn close(&self) {}

    async fn close_and_join(
        &self,
        _deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn open_conversation(&self) -> anyhow::Result<tacacsrs_networking::ClientConversation> {
        anyhow::bail!("raw conversations are not used in client API routing tests")
    }

    async fn send_accounting(
        &self,
        _request: AccountingRequest,
        _deadline: tacacsrs_networking::RequestDeadline,
    ) -> Result<AccountingReply, UpstreamRequestError> {
        self.accounting_started.notify_one();
        if !self.accounting_delay.is_zero() {
            tokio::time::sleep(self.accounting_delay).await;
        }
        if let Some((entered, release)) = &self.accounting_barrier {
            entered.notify_one();
            release.notified().await;
        }
        if self.fail_accounting.swap(false, Ordering::AcqRel) {
            return Err(UpstreamRequestError::outcome_unknown(anyhow::anyhow!(
                "injected accounting transport failure"
            )));
        }
        Ok(AccountingReply {
            status: self.accounting_status,
            server_msg: String::new(),
            data: String::new(),
        })
    }

    async fn authenticate_pap(
        &self,
        _exchange: PapAuthenticationExchange,
        _deadline: tacacsrs_networking::RequestDeadline,
    ) -> Result<AuthenticationReply, UpstreamRequestError> {
        if self.fail_authentication.swap(false, Ordering::AcqRel) {
            return Err(UpstreamRequestError::outcome_unknown(anyhow::anyhow!(
                "injected authentication transport failure"
            )));
        }
        Ok(AuthenticationReply {
            status: self.authentication_status,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: String::new(),
            data: Vec::new(),
        })
    }

    async fn send_authorization(
        &self,
        _request: AuthorizationRequest,
        _deadline: tacacsrs_networking::RequestDeadline,
    ) -> Result<AuthorizationReply, UpstreamRequestError> {
        if self.fail_authorization.swap(false, Ordering::AcqRel) {
            return Err(UpstreamRequestError::outcome_unknown(anyhow::anyhow!(
                "injected authorization transport failure"
            )));
        }
        Ok(AuthorizationReply {
            status: TacacsAuthorizationStatus::TacPlusPassAdd,
            server_msg: String::new(),
            args: Vec::new(),
            data: String::new(),
        })
    }
}

struct OperationConnector {
    connections: HashMap<(String, OperationKind), Arc<ScriptedConnection>>,
    attempts: Mutex<HashMap<(String, OperationKind), usize>>,
}

impl OperationConnector {
    fn new(connections: HashMap<(String, OperationKind), Arc<ScriptedConnection>>) -> Self {
        Self {
            connections,
            attempts: Mutex::new(HashMap::new()),
        }
    }

    async fn attempts(&self, address: &str, operation: OperationKind) -> usize {
        *self
            .attempts
            .lock()
            .await
            .get(&(address.to_owned(), operation))
            .unwrap_or(&0)
    }
}

#[async_trait]
impl tacacsrs_networking::routed::EndpointConnector for OperationConnector {
    type Connection = dyn UpstreamConnection;

    async fn retire(&self, connection: &Self::Connection) {
        connection.stop_accepting_new_sessions().await;
    }
    fn close(&self, connection: &Self::Connection) {
        connection.close();
    }
    async fn close_and_join(
        &self,
        connection: &Self::Connection,
        deadline: tacacsrs_networking::RequestDeadline,
    ) -> anyhow::Result<()> {
        connection.close_and_join(deadline).await
    }

    async fn connect(
        &self,
        endpoint: tacacsrs_networking::PreparedEndpoint,
        operation: OperationKind,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let address = endpoint.address().to_owned();
        *self
            .attempts
            .lock()
            .await
            .entry((address.clone(), operation))
            .or_default() += 1;
        self.connections
            .get(&(address.clone(), operation))
            .cloned()
            .map(|connection| connection as Arc<dyn UpstreamConnection>)
            .ok_or_else(|| anyhow::anyhow!("no {operation:?} connection for {address}"))
    }
}

fn server(address: &str) -> Arc<TacacsPlusServer> {
    Arc::new(TacacsPlusServer {
        name: address.to_owned(),
        server_type: REQUIRED_SERVER_TYPES,
        address: address.to_owned(),
        port: 49,
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
    })
}

fn policy(strategy: FailoverStrategy) -> RuntimePolicy {
    RuntimePolicy::new(
        strategy,
        FailoverStrategy::default(),
        OperationPolicies::default(),
        Duration::from_secs(30),
    )
    .expect("test policy")
}

fn bridge(
    connector: Arc<OperationConnector>,
    strategy: FailoverStrategy,
) -> UpstreamBridge<crate::upstream::manager::ServiceConnector> {
    let manager = Arc::new(
        UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
            vec![server("primary"), server("backup")],
            PreparedProxyPolicy::unobfuscated(),
            policy(strategy),
            connector,
            RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
            tacacsrs_config::prepare::PrepareOptions::default(),
        )
        .expect("test endpoints must prepare"),
    );
    UpstreamBridge::new(manager)
}

fn authentication() -> PapAuthenticationOperation {
    PapAuthenticationOperation {
        user: "admin".to_owned(),
        password: SecretBytes::new(b"secret".to_vec()),
        port: "tty0".to_owned(),
        remote_address: "192.0.2.1".to_owned(),
        privilege_level: tacacsrs_protocol::privilege::PrivilegeLevel::MAX,
    }
}

fn accounting() -> AccountingOperation {
    AccountingOperation {
        user: "admin".to_owned(),
        port: "tty0".to_owned(),
        remote_address: "192.0.2.1".to_owned(),
        command: "show".to_owned(),
        command_arguments: vec!["users".to_owned()],
    }
}

fn operation_map(
    primary: Arc<ScriptedConnection>,
    backup: Arc<ScriptedConnection>,
    operation: OperationKind,
) -> HashMap<(String, OperationKind), Arc<ScriptedConnection>> {
    HashMap::from([
        (("primary:49".to_owned(), operation), primary),
        (("backup:49".to_owned(), operation), backup),
    ])
}

#[tokio::test]
async fn overload_is_retriable_without_upstream_io_and_cancellation_releases_capacity() {
    use crate::config::{PolicyService, RequestLimits};
    use crate::upstream::OperationRouter;

    tokio::time::timeout(Duration::from_secs(3), async {
        let release = Arc::new(Notify::new());
        let primary = Arc::new(ScriptedConnection {
            accounting_barrier: Some((Arc::new(Notify::new()), Arc::clone(&release))),
            ..ScriptedConnection::successful("primary:49")
        });
        let connector = Arc::new(OperationConnector::new(HashMap::from([(
            ("primary:49".to_owned(), OperationKind::Accounting),
            primary.clone(),
        )])));
        let limits = RequestLimits::new(1024, 1).unwrap();
        let manager = Arc::new(
            UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
                vec![server("primary")],
                PreparedProxyPolicy::unobfuscated(),
                RuntimePolicy::new(
                    FailoverStrategy::default(),
                    FailoverStrategy::default(),
                    OperationPolicies::new(limits, limits, limits),
                    Duration::from_secs(30),
                )
                .unwrap(),
                connector.clone(),
                RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
                tacacsrs_config::prepare::PrepareOptions::default(),
            )
            .unwrap(),
        );
        let bridge = UpstreamBridge::new(Arc::clone(&manager));
        let proxy = OperationRouter::new(manager, PolicyService::TacacsProxy)
            .capture_request(OperationKind::Accounting);
        {
            let active = bridge.execute_accounting_request(accounting());
            tokio::pin!(active);
            tokio::select! {
                () = primary.accounting_started.notified() => {},
                result = &mut active => panic!("request completed before its barrier: {result:?}"),
            }
            let pending = proxy.admit(1);
            tokio::pin!(pending);
            std::future::poll_fn(|context| {
                assert!(std::future::Future::poll(pending.as_mut(), context).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
            let error = bridge
                .execute_accounting_request(accounting())
                .await
                .unwrap_err();
            assert_eq!(
                error.facts.retry_advice(),
                tacacsrs_protocol::failure::RetryAdvice::AfterRecovery
            );
            assert!(error.message.contains("admission queue is full"));
            assert_eq!(
                connector
                    .attempts("primary:49", OperationKind::Accounting)
                    .await,
                1
            );
        }
        release.notify_one();
        let _released_capacity = proxy.admit(1).await.unwrap();
        assert_eq!(
            connector
                .attempts("primary:49", OperationKind::Accounting)
                .await,
            1
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn request_retry_keeps_original_servers_and_policy_across_reload() {
    tokio::time::timeout(Duration::from_secs(3), async {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let primary = Arc::new(ScriptedConnection {
            accounting_status: TacacsAccountingStatus::TacPlusAcctStatusError,
            accounting_barrier: Some((Arc::clone(&entered), Arc::clone(&release))),
            ..ScriptedConnection::successful("primary:49")
        });
        let backup = Arc::new(ScriptedConnection::successful("backup:49"));
        let mut connections = operation_map(primary, backup, OperationKind::Accounting);
        connections.insert(
            ("replacement:49".to_owned(), OperationKind::Accounting),
            Arc::new(ScriptedConnection::successful("replacement:49")),
        );
        let connector = Arc::new(OperationConnector::new(connections));
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let manager = Arc::new(
            UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
                vec![server("primary"), server("backup")],
                PreparedProxyPolicy::unobfuscated(),
                policy(FailoverStrategy::OrderedSafeRetry),
                connector.clone(),
                health.clone(),
                tacacsrs_config::prepare::PrepareOptions::default(),
            )
            .unwrap(),
        );
        let request = {
            let bridge = UpstreamBridge::new(Arc::clone(&manager));
            tokio::spawn(async move { bridge.execute_accounting_request(accounting()).await })
        };
        entered.notified().await;
        manager
            .reload_shared_servers(vec![server("replacement")])
            .await
            .unwrap();
        manager.reload_runtime_policy(policy(FailoverStrategy::DeferredFailover));
        release.notify_one();
        let response = request.await.unwrap().unwrap();
        assert_eq!(response.server, "backup:49");
        assert_eq!(
            connector
                .attempts("replacement:49", OperationKind::Accounting)
                .await,
            0
        );
        assert_eq!(
            health.snapshot().upstream_availability(),
            crate::runtime::UpstreamAvailability::Unknown,
            "an old request must not report availability for the replacement generation"
        );
        let next = UpstreamBridge::new(manager)
            .execute_accounting_request(accounting())
            .await
            .unwrap();
        assert_eq!(next.server, "replacement:49");
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn deadline_includes_admission_and_retry_and_survives_policy_reload() {
    use crate::config::{PolicyService, RequestLimits};
    use crate::upstream::OperationRouter;

    let primary = Arc::new(ScriptedConnection {
        accounting_status: TacacsAccountingStatus::TacPlusAcctStatusError,
        accounting_delay: Duration::from_secs(2),
        ..ScriptedConnection::successful("primary:49")
    });
    let backup = Arc::new(ScriptedConnection {
        accounting_delay: Duration::from_secs(4),
        ..ScriptedConnection::successful("backup:49")
    });
    let connector = Arc::new(OperationConnector::new(operation_map(
        primary.clone(),
        backup.clone(),
        OperationKind::Accounting,
    )));
    let policy = |seconds| {
        let limits = RequestLimits::new(1024, 1)
            .unwrap()
            .with_request_timeout(Duration::from_secs(seconds))
            .unwrap();
        RuntimePolicy::new(
            FailoverStrategy::OrderedSafeRetry,
            FailoverStrategy::default(),
            OperationPolicies::new(limits, limits, limits),
            Duration::from_secs(30),
        )
        .unwrap()
    };
    let manager = Arc::new(
        UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
            vec![server("primary"), server("backup")],
            PreparedProxyPolicy::unobfuscated(),
            policy(5),
            connector.clone(),
            RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
            tacacsrs_config::prepare::PrepareOptions::default(),
        )
        .unwrap(),
    );
    let occupied = OperationRouter::new(manager.clone(), PolicyService::TacacsProxy)
        .capture_request(OperationKind::Accounting)
        .admit(1)
        .await
        .unwrap();
    let bridge = UpstreamBridge::new(manager.clone());
    let started = tokio::time::Instant::now();
    let request = bridge.execute_accounting_request(accounting());
    tokio::pin!(request);
    std::future::poll_fn(|context| {
        assert!(std::future::Future::poll(request.as_mut(), context).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    tokio::time::advance(Duration::from_secs(2)).await;
    manager.reload_runtime_policy(policy(30));
    drop(occupied);
    tokio::select! {
        () = primary.accounting_started.notified() => {},
        result = &mut request => panic!("primary request did not start: {result:?}"),
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::select! {
        () = backup.accounting_started.notified() => {},
        result = &mut request => panic!("backup request did not start: {result:?}"),
    }
    let error = request.await.unwrap_err();
    assert_eq!(error.facts.retry_advice(), tacacsrs_protocol::failure::RetryAdvice::Never);
    assert_eq!(error.facts.delivery(), tacacsrs_protocol::failure::DeliveryState::OutcomeUnknown);
    assert_eq!(started.elapsed(), Duration::from_secs(5));
    assert_eq!(
        connector
            .attempts("primary:49", OperationKind::Accounting)
            .await,
        1
    );
    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Accounting)
            .await,
        1
    );
    assert!(bridge
        .execute_accounting_request(accounting())
        .await
        .is_err());
    tokio::time::advance(Duration::from_secs(30)).await;
    assert_eq!(
        bridge
            .execute_accounting_request(accounting())
            .await
            .unwrap()
            .server,
        "backup:49"
    );
}

#[tokio::test(start_paused = true)]
async fn expired_upstream_attempt_routes_the_next_request_to_backup() {
    use crate::config::RequestLimits;

    let primary = Arc::new(ScriptedConnection {
        accounting_delay: Duration::from_secs(60),
        ..ScriptedConnection::successful("primary:49")
    });
    let backup = Arc::new(ScriptedConnection::successful("backup:49"));
    let connector = Arc::new(OperationConnector::new(operation_map(
        primary,
        backup,
        OperationKind::Accounting,
    )));
    let limits = RequestLimits::new(1024, 1)
        .unwrap()
        .with_request_timeout(Duration::from_secs(1))
        .unwrap();
    let policy = RuntimePolicy::new(
        FailoverStrategy::default(),
        FailoverStrategy::default(),
        OperationPolicies::new(limits, limits, limits),
        Duration::from_secs(30),
    )
    .unwrap();
    let manager = Arc::new(
        UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
            vec![server("primary"), server("backup")],
            PreparedProxyPolicy::unobfuscated(),
            policy,
            connector.clone(),
            RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
            tacacsrs_config::prepare::PrepareOptions::default(),
        )
        .unwrap(),
    );
    let bridge = UpstreamBridge::new(manager);
    let error = bridge
        .execute_accounting_request(accounting())
        .await
        .unwrap_err();
    assert_eq!(error.facts.retry_advice(), tacacsrs_protocol::failure::RetryAdvice::Never);
    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Accounting)
            .await,
        0
    );
    let response = bridge
        .execute_accounting_request(accounting())
        .await
        .unwrap();
    assert_eq!(response.server, "backup:49");
}

#[tokio::test]
async fn ordered_retry_stops_on_unknown_authentication_outcome() {
    let mut primary = ScriptedConnection::successful("primary:49");
    primary.fail_authentication = AtomicBool::new(true);
    let primary = Arc::new(primary);
    let backup = Arc::new(ScriptedConnection::successful("backup:49"));
    let connector = Arc::new(OperationConnector::new(operation_map(
        primary,
        backup,
        OperationKind::Authentication,
    )));
    let bridge = bridge(Arc::clone(&connector), FailoverStrategy::OrderedSafeRetry);

    let error = bridge
        .execute_pap_authentication_request(authentication())
        .await
        .expect_err("uncertain authentication must not be replayed");

    assert_eq!(error.server.as_deref(), Some("primary:49"));
    assert_eq!(error.facts.retry_advice(), tacacsrs_protocol::failure::RetryAdvice::Never);
    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Authentication)
            .await,
        0
    );
}

#[tokio::test]
async fn authentication_denial_does_not_retry() {
    let primary = Arc::new(ScriptedConnection {
        authentication_status: TacacsAuthenticationStatus::TacPlusAuthenStatusFail,
        ..ScriptedConnection::successful("primary:49")
    });
    let backup = Arc::new(ScriptedConnection::successful("backup:49"));
    let connector = Arc::new(OperationConnector::new(operation_map(
        primary,
        backup,
        OperationKind::Authentication,
    )));
    let bridge = bridge(Arc::clone(&connector), FailoverStrategy::OrderedSafeRetry);

    let response = bridge
        .execute_pap_authentication_request(authentication())
        .await
        .expect("a denial is a valid response");

    assert_eq!(response.status, AuthenticationResponseStatus::Fail);
    assert_eq!(response.server, "primary:49");
    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Authentication)
            .await,
        0
    );
}

#[tokio::test]
async fn uncertain_accounting_failure_does_not_retry() {
    let mut primary = ScriptedConnection::successful("primary:49");
    primary.fail_accounting = AtomicBool::new(true);
    let primary = Arc::new(primary);
    let backup = Arc::new(ScriptedConnection::successful("backup:49"));
    let connector = Arc::new(OperationConnector::new(operation_map(
        primary,
        backup,
        OperationKind::Accounting,
    )));
    let bridge = bridge(Arc::clone(&connector), FailoverStrategy::OrderedSafeRetry);

    let error = bridge
        .execute_accounting_request(accounting())
        .await
        .expect_err("an uncertain accounting result must not be replayed");
    assert_eq!(error.facts.retry_advice(), tacacsrs_protocol::failure::RetryAdvice::Never);
    assert_eq!(error.facts.delivery(), tacacsrs_protocol::failure::DeliveryState::OutcomeUnknown);
    assert_eq!(error.runtime_generation, Some(0));
    assert_eq!(error.attempt.map(std::num::NonZeroU32::get), Some(1));

    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Accounting)
            .await,
        0
    );
}

#[tokio::test]
async fn uncertain_failure_stops_before_binding_a_missing_backup() {
    let primary = Arc::new(ScriptedConnection {
        fail_authentication: AtomicBool::new(true),
        ..ScriptedConnection::successful("primary:49")
    });
    let connector = Arc::new(OperationConnector::new(HashMap::from([(
        ("primary:49".to_owned(), OperationKind::Authentication),
        primary,
    )])));
    let bridge = bridge(Arc::clone(&connector), FailoverStrategy::OrderedSafeRetry);
    let error = bridge
        .execute_pap_authentication_request(authentication())
        .await
        .unwrap_err();
    assert_eq!(error.facts.retry_advice(), tacacsrs_protocol::failure::RetryAdvice::Never);
    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Authentication)
            .await,
        0
    );
}

#[tokio::test]
async fn ordered_retry_stops_on_unknown_authorization_outcome() {
    let primary = Arc::new(ScriptedConnection {
        fail_authorization: AtomicBool::new(true),
        ..ScriptedConnection::successful("primary:49")
    });
    let backup = Arc::new(ScriptedConnection::successful("backup:49"));
    let connector = Arc::new(OperationConnector::new(operation_map(
        primary,
        backup,
        OperationKind::Authorization,
    )));
    let bridge = bridge(Arc::clone(&connector), FailoverStrategy::OrderedSafeRetry);
    let request = tacacsrs_protocol::operations::AuthorizationOperation::builder(
        "admin",
        15,
        tacacsrs_protocol::operations::AuthorizationAuthenticationContext::TacacsPap,
    )
    .service("shell")
    .command("show")
    .build()
    .unwrap();
    let error = bridge
        .execute_authorization_request(request)
        .await
        .unwrap_err();
    assert_eq!(error.facts.retry_advice(), tacacsrs_protocol::failure::RetryAdvice::Never);
    assert_eq!(error.server.as_deref(), Some("primary:49"));
    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Authorization)
            .await,
        0
    );
}

#[tokio::test]
async fn ordered_retry_preserves_explicit_authentication_error_failover() {
    let primary = Arc::new(ScriptedConnection {
        authentication_status: TacacsAuthenticationStatus::TacPlusAuthenStatusError,
        ..ScriptedConnection::successful("primary:49")
    });
    let backup = Arc::new(ScriptedConnection::successful("backup:49"));
    let connector = Arc::new(OperationConnector::new(operation_map(
        primary,
        backup,
        OperationKind::Authentication,
    )));
    let bridge = bridge(Arc::clone(&connector), FailoverStrategy::OrderedSafeRetry);
    let response = bridge
        .execute_pap_authentication_request(authentication())
        .await
        .unwrap();
    assert_eq!(response.server, "backup:49");
    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Authentication)
            .await,
        1
    );
}

#[tokio::test]
async fn unsent_accounting_bind_failure_remains_retriable() {
    let connector = Arc::new(OperationConnector::new(HashMap::new()));
    let bridge = bridge(connector, FailoverStrategy::OrderedSafeRetry);
    let error = bridge
        .execute_accounting_request(accounting())
        .await
        .unwrap_err();
    assert_eq!(error.facts.retry_advice(), tacacsrs_protocol::failure::RetryAdvice::AfterRecovery);
    assert_eq!(error.facts.delivery(), tacacsrs_protocol::failure::DeliveryState::NotSent);
}

#[tokio::test]
async fn explicit_accounting_error_retries_the_next_server() {
    let primary = Arc::new(ScriptedConnection {
        accounting_status: TacacsAccountingStatus::TacPlusAcctStatusError,
        ..ScriptedConnection::successful("primary:49")
    });
    let backup = Arc::new(ScriptedConnection::successful("backup:49"));
    let connector = Arc::new(OperationConnector::new(operation_map(
        primary,
        backup,
        OperationKind::Accounting,
    )));
    let bridge = bridge(connector, FailoverStrategy::OrderedSafeRetry);

    let response = bridge
        .execute_accounting_request(accounting())
        .await
        .expect("an explicit accounting error permits the configured retry");

    assert_eq!(response.status, AccountingResponseStatus::Success);
    assert_eq!(response.server, "backup:49");
}
