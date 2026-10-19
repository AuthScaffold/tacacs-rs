#[tokio::test]
async fn diagnostics_handle_does_not_retain_the_agent_runtime() {
    let service = super::TacacsClientService::waiting_for_configuration(
        crate::ServiceConfig {
            local_services: tacacsrs_config::tacacsrs::LocalServices::default(),
            tacacs_plus: tacacsrs_config::TacacsPlus::empty(),
            validation_options: tacacsrs_config::ValidationOptions::default(),
            runtime_policy: crate::RuntimePolicy::default(),
            certificate_verification: tacacsrs_networking::CertificateVerification::Required,
        },
        crate::RuntimeHealthPublisher::new(crate::EnabledServices::CLIENT_API),
    )
    .unwrap();
    let diagnostics = service.diagnostics_handle();
    assert!(diagnostics.statistics_json(None, 4096).is_ok());
    drop(service);
    assert!(diagnostics.statistics_json(None, 4096).is_err());
}

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tacacsrs_ipc::{IpcEndpoint, ServiceClient};
use tacacsrs_protocol::operations::{AuthorizationOperation, AuthorizationResponseStatus};

use crate::config::{
    EnabledServices, FailoverStrategy, OperationPolicies, PreparedProxyPolicy, RuntimePolicy,
};
type TacacsClientService = super::ServiceRuntime<crate::upstream::manager::ServiceConnector>;
use crate::runtime::{
    ListenerState, REQUIRED_SERVER_TYPES, RuntimeHealthPublisher, RuntimeLifecycle, RuntimeService,
    ShutdownCoordinator,
};
use crate::config::ServiceConfig;
use crate::test_support::{BlockingClientApiListener, FakeConnection, FakeConnector, build_request};
use crate::upstream::manager::UpstreamManager;

fn test_server(address: &str) -> tacacsrs_config::TacacsPlusServer {
    let (host, port) = match address.rsplit_once(':') {
        Some((h, p)) => (h.to_owned(), p.parse().unwrap_or(49)),
        None => (address.to_owned(), 49),
    };
    tacacsrs_config::TacacsPlusServer {
        name: address.to_owned(),
        server_type: REQUIRED_SERVER_TYPES,
        address: host,
        port,
        shared_secret: Some(tacacsrs_secrets::SecretString::new("test-secret".to_owned())),
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

fn service_config(
    endpoint: IpcEndpoint,
    servers: Vec<tacacsrs_config::TacacsPlusServer>,
) -> ServiceConfig {
    let tacacs_plus = servers
        .into_iter()
        .fold(
            tacacsrs_config::TacacsPlusBuilder::new(),
            tacacsrs_config::TacacsPlusBuilder::with_server,
        )
        .build()
        .expect("the test configuration must be valid");
    ServiceConfig {
        local_services: tacacsrs_config::tacacsrs::LocalServices {
            client_api_endpoint: match endpoint {
                IpcEndpoint::Unix(path) => path.to_str().unwrap().to_owned(),
                IpcEndpoint::Tcp(address) => address.to_string(),
            },
            ..Default::default()
        },
        tacacs_plus,
        validation_options: tacacsrs_config::ValidationOptions::default(),
        runtime_policy: RuntimePolicy::new(
            FailoverStrategy::default(),
            FailoverStrategy::default(),
            OperationPolicies::default(),
            Duration::from_millis(50),
        )
        .expect("test runtime policy"),
        certificate_verification: tacacsrs_networking::CertificateVerification::Required,
    }
}

fn test_service(config: ServiceConfig) -> anyhow::Result<TacacsClientService> {
    let health = RuntimeHealthPublisher::new(config.enabled_services());
    TacacsClientService::new(config, health)
}

#[test]
fn conflicting_listener_endpoints_fail_before_binding() {
    let endpoint = test_endpoint("conflicting-listeners");
    let mut config = service_config(endpoint, vec![test_server("primary:49")]);
    config.local_services.client_api_enabled = true;
    config.local_services.tacacs_proxy_enabled = true;
    config.local_services.tacacs_proxy_endpoint =
        Some(config.local_services.client_api_endpoint.clone());
    assert!(test_service(config).is_err());
}

#[tokio::test]
async fn runtime_health_generation_tracks_catalog_and_policy_publication() {
    use crate::runtime::RuntimeGeneration;

    let config =
        service_config(test_endpoint("publication-health"), vec![test_server("primary:49")]);
    let mut source = config.tacacs_plus.clone();
    let service = test_service(config).unwrap();
    assert_eq!(service.health.snapshot().runtime_generation(), Some(RuntimeGeneration::new(0)));
    service
        .health
        .set_upstream_availability(crate::UpstreamAvailability::Available);
    service
        .reload_runtime_policy(RuntimePolicy::default())
        .await
        .unwrap();
    let policy = service.health.snapshot();
    assert_eq!(policy.runtime_generation(), Some(RuntimeGeneration::new(1)));
    assert_eq!(policy.upstream_availability(), crate::UpstreamAvailability::Available);
    assert!(policy.has_applied_configuration());
    source.server.push(test_server("secondary:49"));
    service.reload_tacacs_plus(source.clone()).await.unwrap();
    let replacement = service.health.snapshot();
    assert_eq!(replacement.runtime_generation(), Some(RuntimeGeneration::new(2)));
    assert_eq!(replacement.eligible_server_count(), 2);
    assert_eq!(replacement.upstream_availability(), crate::UpstreamAvailability::Unknown);
    source.server[0].shared_secret = None;
    assert!(service.reload_tacacs_plus(source).await.is_err());
    assert_eq!(service.health.snapshot(), replacement);
}

#[tokio::test]
async fn shutdown_budget_reloads_without_changing_request_retirement_budget() {
    let config = service_config(test_endpoint("shutdown-budget"), vec![test_server("primary:49")]);
    let service = test_service(config).unwrap();
    let source = tacacsrs_config::policy::parse_runtime_policy(
        br#"{"tacacsrs:runtime-policy":{
            "shutdown-timeout-seconds":2,"authentication":{"request-timeout-seconds":100}}}"#,
    )
    .unwrap();
    let original = source.clone();
    service
        .reload_runtime_policy(RuntimePolicy::try_from(&source).unwrap())
        .await
        .unwrap();
    assert_eq!(source, original);
    assert_eq!(service.manager.shutdown_timeout(), Duration::from_secs(2));
    let now = tokio::time::Instant::now();
    assert!(
        service.manager.shutdown_deadline().unwrap().expires_at() <= now + Duration::from_secs(3)
    );
    assert!(
        service.manager.retirement_deadline().unwrap().expires_at()
            >= now + Duration::from_secs(99)
    );
}

#[tokio::test]
async fn already_stopped_host_does_not_attempt_listener_binding() {
    let endpoint = test_endpoint("stop-before-bind");
    let IpcEndpoint::Unix(path) = &endpoint else {
        panic!("Unix test endpoint required");
    };
    tokio::fs::write(path, b"unrelated existing file")
        .await
        .unwrap();
    let config = service_config(endpoint.clone(), vec![test_server("primary:49")]);
    let service = test_service(config).unwrap();
    let result = service.serve_until_for_test(std::future::ready(())).await;
    assert_eq!(tokio::fs::read(path).await.unwrap(), b"unrelated existing file");
    tokio::fs::remove_file(path).await.unwrap();
    assert!(result.is_ok(), "a stopped host must not attempt to bind: {result:?}");
    assert_eq!(service.health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
}

#[tokio::test]
async fn waiting_policy_publication_does_not_claim_an_applied_configuration() {
    let mut config =
        service_config(test_endpoint("waiting-policy-generation"), vec![test_server("primary:49")]);
    config.tacacs_plus = tacacsrs_config::TacacsPlus::empty();
    let health = RuntimeHealthPublisher::new(config.enabled_services());
    let service = TacacsClientService::waiting_for_configuration(config, health.clone()).unwrap();
    service
        .reload_runtime_policy(RuntimePolicy::default())
        .await
        .unwrap();
    let snapshot = health.snapshot();
    assert_eq!(snapshot.runtime_generation().unwrap().value(), 1);
    assert!(!snapshot.has_applied_configuration());
    assert_eq!(snapshot.eligible_server_count(), 0);
}

#[tokio::test]
async fn unchanged_reload_preserves_observed_upstream_availability() {
    let config = service_config(test_endpoint("unchanged-health"), vec![test_server("primary:49")]);
    let source = config.tacacs_plus.clone();
    let service = test_service(config).unwrap();
    service
        .health
        .set_upstream_availability(crate::UpstreamAvailability::Available);
    service.reload_tacacs_plus(source).await.unwrap();
    assert_eq!(
        service.health.snapshot().upstream_availability(),
        crate::UpstreamAvailability::Available
    );
}

#[tokio::test]
async fn public_facade_uses_concrete_native_connector_through_ipc_and_shutdown() {
    use tacacsrs_networking::{PacketReader, PacketReadResult, PacketWriter, PacketWriteResult};
    use tacacsrs_protocol::accounting::reply::AccountingReply;
    use tacacsrs_protocol::enumerations::TacacsAccountingStatus;
    use tacacsrs_protocol::packet::{Packet, PacketTrait};
    use tacacsrs_protocol::body::TacacsBodyTrait;

    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = test_server(&address);
        let endpoint = test_endpoint("concrete-production");
        let config = service_config(endpoint.clone(), vec![server]);
        let health = RuntimeHealthPublisher::new(config.enabled_services());
        let service = Arc::new(super::TacacsClientService::new(config, health.clone()).unwrap());
        let _: &UpstreamManager<crate::upstream::NetworkUpstreamConnector> =
            &service.runtime.manager;
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let PacketReadResult::Success(request) = PacketReader::new(Some(
                tacacsrs_secrets::SecretBytes::new(b"test-secret".to_vec()),
            ))
            .read_packet(&mut stream)
            .await
            else {
                panic!("expected accounting packet");
            };
            let body = AccountingReply {
                status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
                server_msg: String::new(),
                data: String::new(),
            }
            .to_bytes()
            .unwrap();
            let mut header = request.header().clone();
            header.seq_no += 1;
            header.length = u32::try_from(body.len()).unwrap();
            assert!(matches!(
                PacketWriter::new(Some(tacacsrs_secrets::SecretBytes::new(
                    b"test-secret".to_vec()
                )))
                .write_packet(&mut stream, Packet::new(header, body).unwrap())
                .await,
                PacketWriteResult::Success
            ));
        });
        let (stop, stopping) = tokio::sync::oneshot::channel();
        let running = service.clone();
        let task = tokio::spawn(async move {
            running
                .serve_until_for_test(async {
                    let _signal = stopping.await;
                })
                .await
        });
        let mut updates = health.subscribe();
        updates
            .wait_for(|snapshot| snapshot.lifecycle() == RuntimeLifecycle::Serving)
            .await
            .unwrap();
        let client = ServiceClient::connect(endpoint).await.unwrap();
        assert_eq!(
            client
                .send_accounting(build_request())
                .await
                .unwrap()
                .server,
            address
        );
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        peer.await.unwrap();
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
    })
    .await
    .expect("concrete production path must complete");
}

#[tokio::test]
#[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or TCP listeners.
async fn native_protocol_failure_survives_routing_and_ipc_without_backup_replay() {
    use tokio::io::AsyncWriteExt;

    use tacacsrs_networking::{PacketReadResult, PacketReader};
    use tacacsrs_protocol::enumerations::TacacsFlags;
    use tacacsrs_protocol::failure::{DeliveryState, FailureCategory, FailurePhase, RetryAdvice};
    use tacacsrs_protocol::packet::{Packet, PacketTrait};

    tokio::time::timeout(Duration::from_secs(3), async {
        let primary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backup = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let primary_address = primary.local_addr().unwrap().to_string();
        let backup_address = backup.local_addr().unwrap().to_string();
        let primary_task = tokio::spawn(async move {
            let (mut stream, _) = primary.accept().await.unwrap();
            let PacketReadResult::Success(request) = PacketReader::new(Some(
                tacacsrs_secrets::SecretBytes::new(b"test-secret".to_vec()),
            ))
            .read_packet(&mut stream)
            .await
            else {
                panic!("the authorization request must decode");
            };
            let body = vec![0];
            let mut header = request.header().clone();
            header.seq_no = header.seq_no.wrapping_add(1);
            header.flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG;
            header.length = u32::try_from(body.len()).unwrap();
            stream
                .write_all(&Packet::new(header, body).unwrap().to_bytes())
                .await
                .unwrap();
        });
        let backup_task = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_millis(250), backup.accept())
                .await
                .is_ok()
        });

        let endpoint = test_endpoint("native-protocol-failure-ipc");
        let config = service_config(
            endpoint.clone(),
            vec![test_server(&primary_address), test_server(&backup_address)],
        );
        let service = test_service(config).unwrap();
        let service_task =
            tokio::spawn(async move { service.serve_until_for_test(std::future::pending()).await });
        let client = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Ok(client) = ServiceClient::connect(endpoint.clone()).await {
                    break client;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the IPC listener must become ready");
        let request = AuthorizationOperation::builder(
            "admin",
            0,
            tacacsrs_protocol::operations::AuthorizationAuthenticationContext::TacacsAscii,
        )
        .port("pts/1")
        .remote_address("127.0.0.1")
        .service("shell")
        .command("/bin/echo")
        .build()
        .unwrap();

        let error = client.send_authorization(request).await.unwrap_err();
        assert_eq!(error.server.as_deref(), Some(primary_address.as_str()));
        assert_eq!(error.attempt.map(std::num::NonZeroU32::get), Some(1));
        assert_eq!(error.facts.category(), FailureCategory::Protocol);
        assert_eq!(error.facts.phase(), FailurePhase::Upstream);
        assert_eq!(error.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_eq!(error.facts.retry_advice(), RetryAdvice::Never);
        primary_task.await.unwrap();
        assert!(!backup_task.await.unwrap(), "the request must not reach the backup");

        service_task.abort();
        let _ = service_task.await;
        if let IpcEndpoint::Unix(path) = endpoint {
            let _ = tokio::fs::remove_file(path).await;
        }
    })
    .await
    .expect("the native IPC regression must finish");
}

#[tokio::test]
async fn downstream_credential_preparation_and_publication_preserve_active_generation() {
    use tacacsrs_config::proxy_policy::prepare_proxy_policy;
    use tacacsrs_config::tacacsrs::ProxyCredentialSource;
    use tacacsrs_secrets::SecretString;

    let mut config = service_config(test_endpoint("proxy-policy"), vec![test_server("primary:49")]);
    config.local_services.tacacs_proxy_enabled = true;
    config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:9050".to_owned());
    config.local_services.proxy_credential_source = ProxyCredentialSource::Inline;
    config.local_services.proxy_shared_secret =
        Some(SecretString::new("old-downstream-key".to_owned()));
    let source = config.local_services.clone();
    let service = test_service(config).unwrap();
    let old = service
        .manager
        .proxy_transport_settings()
        .downstream_obfuscation()
        .clone();
    let health_before = format!("{:?}", service.health.snapshot());
    let mut invalid = source.clone();
    invalid.proxy_shared_secret = Some(SecretString::new(String::new()));
    assert!(prepare_proxy_policy(&invalid, None).is_err());
    assert!(service
        .reload_materialized_servers_with_proxy_downstream_obfuscation(
            Vec::new(),
            PreparedProxyPolicy::unavailable(),
        )
        .await
        .is_err());
    assert_eq!(service.server_count(), 1);
    assert_eq!(
        service
            .manager
            .proxy_transport_settings()
            .downstream_obfuscation(),
        &old
    );
    assert_eq!(format!("{:?}", service.health.snapshot()), health_before);

    let mut replacement = source.clone();
    replacement.proxy_shared_secret = Some(SecretString::new("new-downstream-key".to_owned()));
    let prepared = prepare_proxy_policy(&replacement, None).unwrap();
    service
        .reload_materialized_servers_with_proxy_downstream_obfuscation(
            vec![Arc::new(test_server("primary:49"))],
            prepared.clone(),
        )
        .await
        .unwrap();
    assert_eq!(
        service
            .manager
            .proxy_transport_settings()
            .downstream_obfuscation(),
        &prepared
    );
    assert_eq!(old.shared_secret().unwrap(), source.proxy_shared_secret.as_ref());
    assert_eq!(service.config.local_services, source);
}

#[test]
fn waiting_proxy_cannot_treat_unresolved_row_credentials_as_plaintext() {
    let mut config =
        service_config(test_endpoint("pending-proxy"), vec![test_server("primary:49")]);
    config.tacacs_plus = tacacsrs_config::TacacsPlus::empty();
    config.local_services.tacacs_proxy_enabled = true;
    config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:49".to_owned());
    config.local_services.proxy_credential_source =
        tacacsrs_config::tacacsrs::ProxyCredentialSource::LocalProxyRow;
    let health = RuntimeHealthPublisher::new(config.enabled_services());
    let service = TacacsClientService::waiting_for_configuration(config, health).unwrap();
    assert!(service
        .manager
        .proxy_transport_settings()
        .downstream_obfuscation()
        .shared_secret()
        .is_err());
}

#[tokio::test]
async fn service_publication_preserves_explicit_source_validation_policy() {
    let mut plain = test_server("primary:49");
    plain.shared_secret = None;
    for allow_plain in [false, true] {
        let mut config =
            service_config(test_endpoint("validation-policy"), vec![test_server("primary:49")]);
        if allow_plain {
            config.validation_options = tacacsrs_config::ValidationOptions::new().with_relaxation(
                tacacsrs_config::ValidationRelaxation::AllowPlainTcpWithoutSharedSecret,
            );
        }
        let service = test_service(config.clone()).unwrap();
        let result = service
            .reload_materialized_servers_with_proxy_downstream_obfuscation(
                vec![Arc::new(plain.clone())],
                PreparedProxyPolicy::unobfuscated(),
            )
            .await;
        assert_eq!(result.is_ok(), allow_plain);
        config.tacacs_plus.server = vec![plain.clone()];
        assert_eq!(
            service
                .reload_tacacs_plus(config.tacacs_plus.clone())
                .await
                .is_ok(),
            allow_plain
        );
        assert_eq!(test_service(config).is_ok(), allow_plain);
    }
}

fn test_service_with_connector(
    config: ServiceConfig,
    connector: Arc<crate::upstream::UpstreamConnector>,
) -> anyhow::Result<TacacsClientService> {
    let health = RuntimeHealthPublisher::new(config.enabled_services());
    TacacsClientService::new_with_connector(config, connector, health)
}

#[test]
fn service_builds_independent_operation_catalogs() {
    let endpoint = test_endpoint("tacacs-service-runtime-filter");
    let mut partial = test_server("partial:49");
    partial.server_type = tacacsrs_config::TacacsPlusServerType::AUTHORIZATION
        | tacacsrs_config::TacacsPlusServerType::ACCOUNTING;
    let full = test_server("full:49");
    let config = service_config(endpoint, vec![partial, full]);

    let connector = Arc::new(FakeConnector::new(HashMap::new()));
    let service = test_service_with_connector(config, connector).unwrap();

    assert_eq!(service.manager.server_count(), 2);
    assert_eq!(
        service
            .manager
            .eligible_server_count(crate::OperationKind::Authentication),
        1
    );
    assert_eq!(
        service
            .manager
            .eligible_server_count(crate::OperationKind::Authorization),
        2
    );
}

#[test]
fn service_accepts_config_without_fully_capable_server() {
    let endpoint = test_endpoint("tacacs-service-no-full-server");
    let mut partial = test_server("partial:49");
    partial.server_type = tacacsrs_config::TacacsPlusServerType::AUTHORIZATION
        | tacacsrs_config::TacacsPlusServerType::ACCOUNTING;
    let config = service_config(endpoint, vec![partial]);

    let connector = Arc::new(FakeConnector::new(HashMap::new()));
    let service = test_service_with_connector(config, connector)
        .expect("the service must accept a waiting state");

    assert_eq!(service.manager.server_count(), 1);
    assert_eq!(
        service
            .manager
            .eligible_server_count(crate::OperationKind::Authentication),
        0
    );
    assert_eq!(
        service
            .manager
            .eligible_server_count(crate::OperationKind::Accounting),
        1
    );
}

#[test]
fn service_rejects_tcp_client_api_endpoint_on_unix() {
    let endpoint = IpcEndpoint::Tcp(
        "127.0.0.1:0"
            .parse()
            .expect("the test IPC endpoint must be valid"),
    );
    let config = service_config(endpoint, vec![test_server("primary:49")]);

    let Err(error) = test_service(config) else {
        panic!("the service must reject TCP client API endpoints on Unix");
    };

    assert!(error
        .to_string()
        .contains("invalid local-services/client-api-endpoint"));
}

#[test]
fn service_accepts_tcp_proxy_endpoint_on_unix() {
    let endpoint = test_endpoint("tacacs-service-proxy-tcp-client-api");
    let mut config = service_config(endpoint, vec![test_server("primary:49")]);
    config.local_services.client_api_enabled = true;
    config.local_services.tacacs_proxy_enabled = true;
    config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:0".to_owned());

    let service =
        test_service(config).expect("the service must accept TCP proxy endpoints on Unix");

    assert_eq!(service.manager.server_count(), 1);
}

#[test]
fn service_rejects_invalid_disabled_client_api_endpoint() {
    let endpoint = IpcEndpoint::Tcp(
        "127.0.0.1:0"
            .parse()
            .expect("the test IPC endpoint must be valid"),
    );
    let mut config = service_config(endpoint, vec![test_server("primary:49")]);
    config.local_services.client_api_enabled = false;
    config.local_services.tacacs_proxy_enabled = true;
    config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:1".to_owned());

    assert!(test_service(config).is_err());
}

#[test]
fn service_rejects_no_enabled_runtime_services() {
    let endpoint = test_endpoint("tacacs-service-no-services");
    let mut config = service_config(endpoint, vec![test_server("primary:49")]);
    config.local_services.client_api_enabled = false;
    config.local_services.tacacs_proxy_enabled = false;

    let Err(error) = test_service(config) else {
        panic!("the service must reject configuration with no enabled services");
    };

    assert!(error
        .to_string()
        .contains("Enable at least one runtime service"));
}

#[test]
fn service_rejects_proxy_service_without_proxy_endpoint() {
    let endpoint = test_endpoint("tacacs-service-proxy-without-endpoint");
    let mut config = service_config(endpoint, vec![test_server("primary:49")]);
    config.local_services.client_api_enabled = false;
    config.local_services.tacacs_proxy_enabled = true;

    let Err(error) = test_service(config) else {
        panic!("the service must reject proxy mode without an IPC endpoint");
    };

    assert!(error
        .to_string()
        .contains("The proxy endpoint must be present exactly when"));
}

fn test_endpoint(socket_name: &str) -> IpcEndpoint {
    let unique = format!(
        "{}-{}-{}.sock",
        socket_name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    IpcEndpoint::Unix(std::path::PathBuf::from("/tmp").join(unique))
}

#[tokio::test]
#[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or gRPC I/O.
async fn test_unix_socket_failover_and_preferred_recovery() {
    let primary = Arc::new(FakeConnection {
        address: "primary:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });
    let secondary = Arc::new(FakeConnection {
        address: "secondary:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });

    let connector = Arc::new(FakeConnector::new(HashMap::from([
        (primary.address.clone(), Arc::clone(&primary)),
        (secondary.address.clone(), Arc::clone(&secondary)),
    ])));

    let endpoint = test_endpoint("tacacs-service-test");
    let config = service_config(
        endpoint.clone(),
        vec![test_server("primary:49"), test_server("secondary:49")],
    );

    let service = test_service_with_connector(config, connector).unwrap();
    let service_task =
        tokio::spawn(async move { service.serve_until_for_test(std::future::pending()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = ServiceClient::connect(endpoint.clone()).await.unwrap();
    let request = build_request();

    let first = client.send_accounting(request.clone()).await.unwrap();
    assert_eq!(first.server, "primary:49");

    primary.fail_next_request.store(true, Ordering::Relaxed);
    let failure = client.send_accounting(request.clone()).await.unwrap_err();
    let failure_msg = failure.to_string();
    assert!(failure_msg.contains("primary:49"), "the error must contain primary:49: {failure_msg}");

    let second = client.send_accounting(request.clone()).await.unwrap();
    assert_eq!(second.server, "secondary:49");

    primary.usable.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(120)).await;

    let third = client.send_accounting(request).await.unwrap();
    assert_eq!(third.server, "primary:49");

    service_task.abort();
    let _ = service_task.await;

    if let IpcEndpoint::Unix(path) = endpoint {
        let _ = tokio::fs::remove_file(path).await;
    }
}

#[tokio::test]
#[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or gRPC I/O.
async fn test_authorization_rpc_uses_upstream_server() {
    let primary = Arc::new(FakeConnection {
        address: "primary:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });

    let connector = Arc::new(FakeConnector::new(HashMap::from([(
        primary.address.clone(),
        Arc::clone(&primary),
    )])));

    let endpoint = test_endpoint("tacacs-service-authorization-upstream");
    let config = service_config(endpoint.clone(), vec![test_server("primary:49")]);

    let service = test_service_with_connector(config, connector).unwrap();
    let service_task =
        tokio::spawn(async move { service.serve_until_for_test(std::future::pending()).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client = ServiceClient::connect(endpoint.clone()).await.unwrap();
    let request = AuthorizationOperation::builder(
        "admin",
        0,
        tacacsrs_protocol::operations::AuthorizationAuthenticationContext::TacacsAscii,
    )
    .port("pts/1")
    .remote_address("127.0.0.1")
    .service("shell")
    .command("/bin/echo")
    .command_arg("hello")
    .build()
    .unwrap();
    let response = client.send_authorization(request).await.unwrap();

    assert_eq!(response.server, "primary:49");
    assert_eq!(response.status, AuthorizationResponseStatus::PassAdd);
    assert!(response.server_message.contains("authorized by primary:49"));
    assert!(response.args.is_empty());
    assert!(response.data.is_empty());

    service_task.abort();
    let _ = service_task.await;

    if let IpcEndpoint::Unix(path) = endpoint {
        let _ = tokio::fs::remove_file(path).await;
    }
}

#[tokio::test]
#[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or TCP listeners.
async fn both_listeners_bind_with_wildcard_proxy_before_startup_serves_and_cleanup_on_shutdown() {
    use std::os::unix::fs::PermissionsExt;

    let endpoint = test_endpoint("tacacs-service-both-listeners");
    let socket_path = match &endpoint {
        IpcEndpoint::Unix(path) => path.clone(),
        IpcEndpoint::Tcp(_) => {
            unreachable!("the test IPC endpoint must be a Unix domain socket")
        }
    };
    let mut config = service_config(endpoint, vec![test_server("primary:49")]);
    config.local_services.client_api_enabled = true;
    config.local_services.tacacs_proxy_enabled = true;
    config.local_services.tacacs_proxy_endpoint = Some("0.0.0.0:0".to_owned());
    config.local_services.unix_socket_mode = 0o600;
    let health = RuntimeHealthPublisher::new(EnabledServices::BOTH);
    let upstream = Arc::new(FakeConnection {
        address: "primary:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });
    let connector =
        Arc::new(FakeConnector::new(HashMap::from([(upstream.address.clone(), upstream)])));
    let service = Arc::new(
        TacacsClientService::new_with_connector(config, connector, health.clone())
            .expect("the service must build"),
    );
    let shutdown = ShutdownCoordinator::new(health.clone());
    let task = {
        let service = Arc::clone(&service);
        let shutdown = shutdown.clone();
        tokio::spawn(async move { service.serve_with_shutdown_for_test(&shutdown).await })
    };

    tokio::time::timeout(Duration::from_secs(2), async {
        while health.snapshot().lifecycle() != RuntimeLifecycle::Serving {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both listeners must bind");
    assert!(health.snapshot().is_startup_serving());
    assert_eq!(health.snapshot().listener(RuntimeService::ClientApi), ListenerState::Bound,);
    assert_eq!(health.snapshot().listener(RuntimeService::TacacsProxy), ListenerState::Bound,);
    assert_eq!(
        tokio::fs::metadata(&socket_path)
            .await
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    shutdown.initiate_shutdown();
    task.await
        .expect("the service task must stop")
        .expect("shutdown must succeed");

    assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
    assert_eq!(health.snapshot().listener(RuntimeService::ClientApi), ListenerState::Stopped,);
    assert_eq!(health.snapshot().listener(RuntimeService::TacacsProxy), ListenerState::Stopped,);
    assert!(!tokio::fs::try_exists(socket_path)
        .await
        .expect("the socket inspection must succeed"));
}

#[tokio::test]
async fn cancelled_serving_future_closes_retained_upstreams() {
    use tokio::io::AsyncReadExt;

    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = service_config(
            test_endpoint("cancelled-service"),
            vec![test_server(&listener.local_addr().unwrap().to_string())],
        );
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let service = Arc::new(TacacsClientService::new(config, health.clone()).unwrap());
        let bound = service.manager.bind_server_for_new_session().await.unwrap();
        let _conversation = bound.connection.open_conversation().await.unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let running = service.clone();
        let task =
            tokio::spawn(async move { running.serve_until_for_test(std::future::pending()).await });
        while health.snapshot().lifecycle() != RuntimeLifecycle::Serving {
            tokio::task::yield_now().await;
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        service
            .close_and_join(tacacsrs_networking::RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        assert!(service.manager.bind_server_for_new_session().await.is_err());
    })
    .await
    .expect("cancelled serving must not retain upstream sockets");
}

#[tokio::test]
async fn embedded_shutdown_joins_retained_upstreams_and_prevents_restart() {
    use tokio::io::AsyncReadExt;
    use crate::config::RequestLimits;

    tokio::time::timeout(Duration::from_secs(3), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = test_endpoint("embedded-close");
        let IpcEndpoint::Unix(path) = &endpoint else {
            unreachable!()
        };
        let path = path.clone();
        let mut config = service_config(
            endpoint,
            vec![test_server(&listener.local_addr().unwrap().to_string())],
        );
        let limits = RequestLimits::new(1024, 1)
            .unwrap()
            .with_request_timeout(Duration::from_millis(50))
            .unwrap();
        config.runtime_policy = RuntimePolicy::new(
            FailoverStrategy::default(),
            FailoverStrategy::default(),
            OperationPolicies::new(limits, limits, limits),
            Duration::from_secs(30),
        )
        .unwrap();
        let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
        let service = Arc::new(TacacsClientService::new(config, health.clone()).unwrap());
        let bound = service.manager.bind_server_for_new_session().await.unwrap();
        let _conversation = bound.connection.open_conversation().await.unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let running = service.clone();
        let task = tokio::spawn(async move {
            running
                .serve_until_for_test(async {
                    let _stop = stopped.await;
                })
                .await
        });
        while health.snapshot().lifecycle() != RuntimeLifecycle::Serving {
            tokio::task::yield_now().await;
        }
        let _ipc = ServiceClient::connect(IpcEndpoint::Unix(path.clone()))
            .await
            .unwrap();
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
        assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
        assert!(!tokio::fs::try_exists(&path).await.unwrap());
        assert!(bound.connection.open_conversation().await.is_err());
        assert!(service
            .reload_materialized_servers_with_proxy_downstream_obfuscation(
                Vec::new(),
                PreparedProxyPolicy::unobfuscated()
            )
            .await
            .is_err());
        service
            .close_and_join(tacacsrs_networking::RequestDeadline::after(Duration::ZERO).unwrap())
            .await
            .unwrap();
        assert!(service
            .serve_until_for_test(std::future::pending())
            .await
            .is_err());
    })
    .await
    .expect("embedded shutdown must finish without process exit");
}

#[tokio::test]
async fn ephemeral_proxy_binding_guards_production_clients_after_reload_and_shutdown() {
    use tacacsrs_networking::ConnectionGuard;

    let mut config =
        service_config(test_endpoint("ephemeral-guard"), vec![test_server("192.0.2.20:49")]);
    config.local_services.client_api_enabled = false;
    config.local_services.tacacs_proxy_enabled = true;
    config.local_services.tacacs_proxy_endpoint = Some("127.0.0.1:0".to_owned());
    let canonical = config.local_services.clone();
    let service = Arc::new(test_service(config).unwrap());
    let shutdown = ShutdownCoordinator::new(service.health.clone());
    let task = {
        let service = Arc::clone(&service);
        let shutdown = shutdown.clone();
        tokio::spawn(async move { service.serve_with_shutdown_for_test(&shutdown).await })
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        while service
            .health
            .snapshot()
            .listener(RuntimeService::TacacsProxy)
            != ListenerState::Bound
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let bound_address = service.proxy_loop_guard.bound_endpoint().unwrap().unwrap();
    assert_ne!(bound_address.port(), 0);
    service
        .reload_materialized_servers_with_proxy_downstream_obfuscation(
            vec![Arc::new(test_server(&bound_address.to_string()))],
            PreparedProxyPolicy::unobfuscated(),
        )
        .await
        .unwrap();
    let bound = service.manager.bind_server_for_new_session().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), bound.connection.open_conversation())
        .await
        .unwrap();
    let error = match result {
        Ok(_) => panic!("production client connected to its proxy"),
        Err(error) => error,
    };
    assert!(format!("{error:#}").contains("targets the local TACACS+ proxy"));
    assert_eq!(service.config.local_services, canonical);
    shutdown.initiate_shutdown();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(service
        .proxy_loop_guard
        .check_destination(bound_address)
        .is_err());
    assert!(bound.connection.open_conversation().await.is_err());
}

#[tokio::test]
#[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or TCP listeners.
async fn listener_bind_failure_aborts_sibling_without_publishing_readiness() {
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the test must occupy the proxy IPC endpoint");
    let occupied_address = occupied
        .local_addr()
        .expect("the occupied IPC endpoint must have an address");
    let endpoint = test_endpoint("tacacs-service-bind-failure");
    let socket_path = match &endpoint {
        IpcEndpoint::Unix(path) => path.clone(),
        IpcEndpoint::Tcp(_) => {
            unreachable!("the test IPC endpoint must be a Unix domain socket")
        }
    };
    let mut config = service_config(endpoint, vec![test_server("primary:49")]);
    config.local_services.client_api_enabled = true;
    config.local_services.tacacs_proxy_enabled = true;
    config.local_services.tacacs_proxy_endpoint = Some(occupied_address.to_string());
    let health = RuntimeHealthPublisher::new(EnabledServices::BOTH);
    let upstream = Arc::new(FakeConnection {
        address: "primary:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });
    let connector =
        Arc::new(FakeConnector::new(HashMap::from([(upstream.address.clone(), upstream)])));
    let service = TacacsClientService::new_with_connector(config, connector, health.clone())
        .expect("the service must build");
    let shutdown = ShutdownCoordinator::new(health.clone());

    let result = service.serve_with_shutdown_for_test(&shutdown).await;

    assert!(result.is_err());
    assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Failed);
    assert!(!health.snapshot().is_readiness_serving());
    assert_eq!(health.snapshot().listener(RuntimeService::ClientApi), ListenerState::Stopped,);
    assert_eq!(health.snapshot().listener(RuntimeService::TacacsProxy), ListenerState::Stopped,);
    assert!(!tokio::fs::try_exists(socket_path)
        .await
        .expect("the socket inspection must succeed"));
}

#[tokio::test]
#[cfg_attr(miri, ignore)] // Miri does not support Unix domain sockets or listener drain.
async fn shutdown_withdraws_health_before_active_requests_finish_draining() {
    let endpoint = test_endpoint("tacacs-service-active-drain");
    let config = service_config(endpoint, vec![test_server("primary:49")]);
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let upstream = Arc::new(FakeConnection {
        address: "primary:49".to_owned(),
        usable: AtomicBool::new(true),
        fail_next_request: AtomicBool::new(false),
    });
    let connector =
        Arc::new(FakeConnector::new(HashMap::from([(upstream.address.clone(), upstream)])));
    let service = Arc::new(
        TacacsClientService::new_with_connector(config, connector, health.clone())
            .expect("the service must build"),
    );
    let (listener, release) = BlockingClientApiListener::pair();
    let shutdown = ShutdownCoordinator::new(health.clone());
    let mut task = {
        let service = Arc::clone(&service);
        let shutdown = shutdown.clone();
        tokio::spawn(async move { service.serve_with_shutdown(&shutdown, vec![listener]).await })
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        while health.snapshot().lifecycle() != RuntimeLifecycle::Serving {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the listener must bind");

    shutdown.initiate_shutdown();
    tokio::task::yield_now().await;

    assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Draining);
    assert!(!health.snapshot().is_liveness_serving());
    assert!(tokio::time::timeout(Duration::from_millis(25), &mut task)
        .await
        .is_err());

    release.notify_one();
    task.await
        .expect("the service task must stop")
        .expect("the drain must finish");
    assert_eq!(health.snapshot().lifecycle(), RuntimeLifecycle::Stopped);
}
