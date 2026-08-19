use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use tacacsrs_agent_client::{
    AccountingOperation, AccountingResponseStatus, AuthenticationResponseStatus,
    PapAuthenticationOperation,
};
use tacacsrs_config::TacacsPlusServer;
use tacacsrs_flows::authentication::PapAuthenticationExchange;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::accounting::request::AccountingRequest;
use tacacsrs_messages::authentication::reply::AuthenticationReply;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::authorization::request::AuthorizationRequest;
use tacacsrs_messages::enumerations::{
    TacacsAccountingStatus, TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus,
    TacacsAuthorizationStatus,
};
use tacacsrs_secrets::SecretBytes;
use tokio::sync::Mutex;

use super::UpstreamBridge;
use crate::config::{FailoverStrategy, OperationPolicies, ProxyDownstreamObfuscation, RuntimePolicy};
use crate::runtime::{REQUIRED_SERVER_TYPES, RuntimeHealthPublisher};
use crate::upstream::manager::UpstreamManager;
use crate::upstream::{OperationKind, UpstreamConnection, UpstreamConnector, UpstreamRequestError};
use crate::EnabledServices;

struct ScriptedConnection {
    address: String,
    fail_authentication: AtomicBool,
    fail_accounting: AtomicBool,
    authentication_status: TacacsAuthenticationStatus,
    accounting_status: TacacsAccountingStatus,
}

impl ScriptedConnection {
    fn successful(address: &str) -> Self {
        Self {
            address: address.to_owned(),
            fail_authentication: AtomicBool::new(false),
            fail_accounting: AtomicBool::new(false),
            authentication_status: TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            accounting_status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
        }
    }
}

#[async_trait]
impl UpstreamConnection for ScriptedConnection {
    fn server_address(&self) -> &str {
        &self.address
    }

    async fn stop_accepting_new_sessions(&self) {}

    async fn open_conversation(&self) -> anyhow::Result<tacacsrs_networking::ClientConversation> {
        anyhow::bail!("raw conversations are not used in client API routing tests")
    }

    async fn send_accounting(
        &self,
        _request: AccountingRequest,
    ) -> Result<AccountingReply, UpstreamRequestError> {
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
    ) -> Result<AuthorizationReply, UpstreamRequestError> {
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
impl UpstreamConnector for OperationConnector {
    async fn connect(
        &self,
        server: Arc<TacacsPlusServer>,
        operation: OperationKind,
    ) -> anyhow::Result<Arc<dyn UpstreamConnection>> {
        let address = tacacsrs_config::TacacsPlusServerExt::socket_address(server.as_ref());
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

fn bridge(connector: Arc<OperationConnector>, strategy: FailoverStrategy) -> UpstreamBridge {
    let manager = Arc::new(UpstreamManager::new_shared_with_proxy_downstream_obfuscation(
        vec![server("primary"), server("backup")],
        ProxyDownstreamObfuscation::default(),
        policy(strategy),
        connector,
        RuntimeHealthPublisher::new(EnabledServices::CLIENT_API),
    ));
    UpstreamBridge::new(manager)
}

fn authentication() -> PapAuthenticationOperation {
    PapAuthenticationOperation {
        user: "admin".to_owned(),
        password: SecretBytes::new(b"secret".to_vec()),
        port: "tty0".to_owned(),
        remote_address: "192.0.2.1".to_owned(),
        privilege_level: 15,
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
async fn ordered_retry_moves_authentication_to_the_next_server() {
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

    let response = bridge
        .execute_pap_authentication_request(authentication())
        .await
        .expect("the backup must authenticate");

    assert_eq!(response.server, "backup:49");
    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Authentication)
            .await,
        1
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

    bridge
        .execute_accounting_request(accounting())
        .await
        .expect_err("an uncertain accounting result must not be replayed");

    assert_eq!(
        connector
            .attempts("backup:49", OperationKind::Accounting)
            .await,
        0
    );
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
