//! Upstream transport, source binding, and IPC client API scenarios.
//!
//! The other proxy scenarios use plain TCP with an obfuscation key. These
//! tests run the same traffic over TLS 1.3 with client certificates and with
//! external pre-shared keys. They also check failed and stalled TLS
//! handshakes, the source-address, egress-interface, and VRF constraints of
//! each upstream connection, and the `TacacsAgent` IPC operations that share
//! the routed upstream client with the proxy.
//!
//! The daemon reads each server from a YANG JSON `--config` file, because the
//! command-line server options support plain TCP only.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use openssl::ssl::SslContext;
use tokio::task::JoinSet;

use tacacsrs_config::tacacsrs::BindingPolicy;
use tacacsrs_config::{
    TacacsPlusBuilder, TacacsPlusServer, TacacsPlusServerBuilder, TacacsPlusServerType,
    TlsClientServerAuthentication,
};
use tacacsrs_ipc::{IpcEndpoint, ServiceClient};
use tacacsrs_protocol::failure::FailureCategory;
use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingResponseStatus, AuthenticationResponseStatus,
    AuthorizationAuthenticationContext, AuthorizationOperation, AuthorizationResponseStatus,
    PapAuthenticationOperation,
};
use tacacsrs_protocol::privilege::PrivilegeLevel;
use tacacsrs_secrets::SecretBytes;
use tacacsrs_testkit::pki::{TestPki, untrusted_server_context};
use tacacsrs_testkit::psk_peer::psk_server_context;
use tacacsrs_testkit::upstream::{self, Fault, Kind, SingleConnect, StalledHandshake, Upstream};

use super::{
    Daemon, OPERATION_LIMIT, Options, Outcome, Status, Traffic, USER_PREFIX, assert_recovers,
    broken_upstream_run, fast_recovery, heavy, mixed, once, recovery, run_traffic, single_request,
    succeeded, unused_port, wait_until,
};

const PSK_IDENTITY: &str = "proxy-traffic-client";

/// Public test key for the fixture, not a deployment credential.
const PSK_KEY: &[u8] = b"proxy-traffic-psk-0123456789abcd";

// A local interface name that no test host has.
const MISSING_INTERFACE: &str = "tacrs-none0";

fn test_pki() -> &'static TestPki {
    static PKI: OnceLock<TestPki> = OnceLock::new();
    PKI.get_or_init(|| TestPki::new().expect("generate ECDSA P-256 test PKI"))
}

fn mtls_context() -> SslContext {
    test_pki().mtls_server_context().unwrap()
}

fn untrusted_context() -> SslContext {
    untrusted_server_context().unwrap()
}

fn psk_context(key: &'static [u8], dhe: bool) -> SslContext {
    psk_server_context(PSK_IDENTITY, key, dhe).unwrap()
}

fn trust_store() -> TlsClientServerAuthentication {
    test_pki().inline_ca_trust_store().unwrap()
}

fn server_builder(address: SocketAddr) -> TacacsPlusServerBuilder {
    TacacsPlusServerBuilder::new(
        format!("server-{}", address.port()),
        TacacsPlusServerType::all(),
        address.ip().to_string(),
        address.port(),
    )
    .with_single_connection(true)
    .with_timeout(5)
}

fn plain_server(address: SocketAddr) -> TacacsPlusServerBuilder {
    server_builder(address).with_shared_secret(upstream::upstream_key())
}

fn mtls_server_with_timeout(address: SocketAddr, timeout_seconds: u16) -> TacacsPlusServer {
    let pki = test_pki();
    let certificate = pki.client.certificate_der().unwrap();
    let key = pki.client.private_key_pkcs8_der().unwrap();
    let mut server = server_builder(address)
        .with_timeout(timeout_seconds)
        .with_tls_client_certificate(Some(certificate), Some(key))
        .build();
    server.server_authentication = Some(trust_store());
    server
}

fn mtls_server(address: SocketAddr) -> TacacsPlusServer {
    mtls_server_with_timeout(address, 5)
}

fn psk_server(address: SocketAddr, key: &[u8], dhe: bool) -> TacacsPlusServer {
    let builder = server_builder(address);
    if dhe {
        builder.with_tls13_epsk(PSK_IDENTITY, key.to_vec()).build()
    } else {
        builder
            .with_tls13_epsk_psk_only(PSK_IDENTITY, key.to_vec())
            .build()
    }
}

/// Replaces each redacted secret in `value` with its inline value.
fn restore_secrets(value: &mut serde_json::Value, secrets: &[(&str, &str)]) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, entry) in map.iter_mut() {
                match secrets.iter().find(|(name, _)| name == key) {
                    Some((_, secret)) if entry == "<redacted>" => {
                        *entry = serde_json::Value::String((*secret).to_owned());
                    }
                    _ => restore_secrets(entry, secrets),
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                restore_secrets(item, secrets);
            }
        }
        _ => {}
    }
}

/// Serializes one server with its inline secrets for a `--config` file.
fn server_json(server: &TacacsPlusServer) -> serde_json::Value {
    let mut value = serde_json::to_value(server).unwrap();
    let shared = server
        .shared_secret
        .as_ref()
        .map(|secret| secret.expose_secret().to_owned());
    let identity = server.client_identity.as_ref();
    let private_key = identity
        .and_then(|identity| identity.certificate.as_ref())
        .and_then(|certificate| certificate.inline_definition.as_ref())
        .and_then(|definition| definition.cleartext_private_key.as_ref())
        .map(|key| openssl::base64::encode_block(key.expose_secret()));
    let symmetric_key = identity
        .and_then(|identity| identity.tls13_epsk.as_ref())
        .and_then(|epsk| epsk.inline_definition.as_ref())
        .and_then(|definition| definition.cleartext_symmetric_key.as_ref())
        .map(|key| openssl::base64::encode_block(key.expose_secret()));
    let mut secrets = Vec::new();
    if let Some(shared) = &shared {
        secrets.push(("shared-secret", shared.as_str()));
    }
    if let Some(key) = &private_key {
        secrets.push(("cleartext-private-key", key.as_str()));
    }
    if let Some(key) = &symmetric_key {
        secrets.push(("cleartext-symmetric-key", key.as_str()));
    }
    restore_secrets(&mut value, &secrets);
    value
}

/// Returns a `--config` document for `servers`, in failover order.
///
/// The document must parse back into the same model, so a serialization
/// change cannot silently remove a secret or a transport setting.
fn config(servers: &[TacacsPlusServer]) -> serde_json::Value {
    let source = servers
        .iter()
        .fold(TacacsPlusBuilder::new(), |builder, server| builder.with_server(server.clone()))
        .build()
        .unwrap();
    let servers: Vec<_> = source.server.iter().map(server_json).collect();
    let document =
        serde_json::json!({ "ietf-system-tacacs-plus:tacacs-plus": { "server": servers } });
    let parsed = tacacsrs_config::parse_yang_json(&document.to_string()).unwrap();
    assert_eq!(
        serde_json::to_value(&parsed).unwrap(),
        serde_json::to_value(&source).unwrap(),
        "the test configuration does not round-trip"
    );
    document
}

fn config_options(servers: &[TacacsPlusServer]) -> Options {
    Options {
        config: Some(config(servers)),
        ..Options::default()
    }
}

/// Returns `Options` with a request deadline of `seconds` for every operation.
fn deadline_options(seconds: u64, strategy: &str, servers: &[TacacsPlusServer]) -> Options {
    Options {
        connect_timeout_seconds: 1,
        policy: fast_recovery(serde_json::json!({
            "authentication": { "request-timeout-seconds": seconds },
            "authorization": { "request-timeout-seconds": seconds },
            "accounting": { "request-timeout-seconds": seconds },
            "tacacs-proxy-failover-strategy": strategy,
            "client-api-failover-strategy": strategy,
        })),
        ..config_options(servers)
    }
}

fn is_local_error(outcome: &Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Reply { status: Status::Error, server_msg } if !server_msg.starts_with(USER_PREFIX)
    )
}

/// Runs heavy traffic over TLS and checks connection reuse and cleanup.
async fn tls_traffic_case(upstream: &Upstream, mut server: TacacsPlusServer, mode: SingleConnect) {
    // Sample mTLS fixtures use 4096-bit RSA keys; give healthy handshakes and
    // round trips headroom under unoptimized QEMU ARMhf emulation.
    server.timeout = 20;
    let daemon = Daemon::start(upstream.address(), config_options(&[server])).await;
    let traffic = match mode {
        SingleConnect::Accept => heavy(true),
        SingleConnect::Decline => Traffic {
            clients: 8,
            operations_per_client: 12,
            concurrency: 2,
            single_connect: true,
            kinds: mixed,
            ascii_authentication: false,
        },
    };
    let tally = run_traffic(daemon.port, traffic, "tls").await;
    tally.assert_all_succeeded(traffic.total());
    assert_eq!(upstream.received_total(), traffic.total());
    assert_eq!(upstream.handshake_failures(), 0);
    match mode {
        SingleConnect::Accept => assert!(
            upstream.connections_accepted() < traffic.total() / 4,
            "TLS single-connect was not reused: {} connections for {} requests",
            upstream.connections_accepted(),
            traffic.total()
        ),
        SingleConnect::Decline => {
            assert!(upstream.connections_accepted() >= traffic.total());
            wait_until("TLS connections to close", || upstream.open_connections() == 0).await;
        }
    }
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutual_tls_traffic_shares_one_connection_with_single_connect() {
    let upstream = Upstream::start_tls(SingleConnect::Accept, mtls_context()).await;
    let server = mtls_server(upstream.address());
    tls_traffic_case(&upstream, server, SingleConnect::Accept).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutual_tls_traffic_opens_one_connection_per_session_without_single_connect() {
    let upstream = Upstream::start_tls(SingleConnect::Decline, mtls_context()).await;
    let server = mtls_server(upstream.address());
    tls_traffic_case(&upstream, server, SingleConnect::Decline).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls13_psk_traffic_succeeds_with_and_without_dhe() {
    for dhe in [true, false] {
        let upstream = Upstream::start_tls(SingleConnect::Accept, psk_context(PSK_KEY, dhe)).await;
        let server = psk_server(upstream.address(), PSK_KEY, dhe);
        tls_traffic_case(&upstream, server, SingleConnect::Accept).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_connection_close_is_bounded_and_recovers() {
    let upstream = Upstream::start_tls(SingleConnect::Accept, mtls_context()).await;
    let server = mtls_server(upstream.address());
    broken_upstream_run(&upstream, Fault::Close, Some(config(&[server]))).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_tls_reply_is_bounded_and_recovers() {
    let upstream = Upstream::start_tls(SingleConnect::Decline, mtls_context()).await;
    let server = mtls_server(upstream.address());
    broken_upstream_run(&upstream, Fault::PartialHeader, Some(config(&[server]))).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hung_tls_reply_is_bounded_and_recovers() {
    let upstream = Upstream::start_tls(SingleConnect::Accept, mtls_context()).await;
    let server = mtls_server(upstream.address());
    broken_upstream_run(&upstream, Fault::Hang, Some(config(&[server]))).await;
}

/// Checks that a failed TLS handshake on the only server gives a bounded local
/// `ERROR` reply and never sends a request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_tls_handshake_on_the_only_server_gets_a_local_error() {
    let cases = [
        (Upstream::start_tls(SingleConnect::Accept, untrusted_context()).await, None),
        (
            Upstream::start_tls(SingleConnect::Accept, psk_context(PSK_KEY, true)).await,
            Some(b"a-different-proxy-traffic-psk-key".as_slice()),
        ),
    ];
    for (upstream, psk) in &cases {
        let server = match psk {
            Some(key) => psk_server(upstream.address(), key, true),
            None => mtls_server(upstream.address()),
        };
        let daemon =
            Daemon::start(upstream.address(), deadline_options(2, "deferred-failover", &[server]))
                .await;
        for kind in Kind::ALL {
            let started = Instant::now();
            let outcome = single_request(daemon.port, kind, &format!("{USER_PREFIX}tls")).await;
            assert!(is_local_error(&outcome), "{kind:?} did not get a local ERROR: {outcome:?}");
            assert!(started.elapsed() < Duration::from_secs(4), "{kind:?} was not bounded");
        }
        assert!(upstream.handshake_failures() > 0);
        assert_eq!(upstream.received_total(), 0);
        daemon.stop().await;
    }
}

/// Checks that a failed TLS handshake is safe to replay on the next server.
///
/// The preferred server presents a certificate that the client does not trust.
/// No request reaches it, so ordered safe retry replays every request on the
/// backup server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untrusted_tls_server_fails_over_without_losing_requests() {
    let untrusted = Upstream::start_tls(SingleConnect::Accept, untrusted_context()).await;
    let backup = Upstream::start_tls(SingleConnect::Accept, mtls_context()).await;
    let servers = [
        mtls_server_with_timeout(untrusted.address(), 10),
        mtls_server_with_timeout(backup.address(), 30),
    ];
    let daemon =
        Daemon::start(untrusted.address(), deadline_options(30, "ordered-safe-retry", &servers))
            .await;
    let traffic = heavy(true);
    let tally = run_traffic(daemon.port, traffic, "untrusted").await;
    tally.assert_all_succeeded(traffic.total());
    assert!(untrusted.handshake_failures() > 0);
    assert_eq!(untrusted.received_total(), 0);
    assert_eq!(backup.received_total(), traffic.total());
    daemon.stop().await;
}

/// Checks that a stalled TLS handshake is bounded by the server timeout.
///
/// The stalled server accepts TCP and never sends a TLS record. Each attempt
/// must end after the 1-second server timeout, and ordered safe retry must
/// deliver every request through the backup server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_tls_handshake_is_bounded_and_fails_over() {
    let stalled = StalledHandshake::start().await;
    let backup = Upstream::start_tls(SingleConnect::Accept, mtls_context()).await;
    let servers = [
        mtls_server_with_timeout(stalled.address(), 1),
        mtls_server_with_timeout(backup.address(), 20),
    ];
    let daemon =
        Daemon::start(stalled.address(), deadline_options(20, "ordered-safe-retry", &servers))
            .await;
    let traffic = Traffic {
        clients: 6,
        operations_per_client: 12,
        concurrency: 2,
        single_connect: true,
        kinds: mixed,
        ascii_authentication: false,
    };
    let tally = run_traffic(daemon.port, traffic, "stalled").await;
    tally.assert_all_succeeded(traffic.total());
    assert!(stalled.accepted() > 0, "the daemon did not try the stalled server");
    for kind in Kind::ALL {
        assert!(
            tally.max_latency[kind as usize] < Duration::from_secs(6),
            "a stalled handshake delayed {kind:?} beyond the 1s server timeout plus backup handshake: {tally:#?}"
        );
    }
    assert_eq!(backup.received_total(), traffic.total());
    daemon.stop().await;
}

/// Starts a daemon with one plain-TCP server and checks that traffic succeeds.
async fn bound_traffic(upstream: &Upstream, server: TacacsPlusServer) {
    let daemon = Daemon::start(upstream.address(), config_options(&[server])).await;
    let traffic = recovery(true);
    run_traffic(daemon.port, traffic, "bound")
        .await
        .assert_all_succeeded(traffic.total());
    daemon.stop().await;
}

/// Checks that each upstream connection uses the configured source address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn source_ip_binds_every_upstream_connection() {
    let upstream = Upstream::start(SingleConnect::Decline).await;
    let source = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    bound_traffic(
        &upstream,
        plain_server(upstream.address())
            .with_source_ip(source)
            .build(),
    )
    .await;
    let peers = upstream.peers();
    assert!(!peers.is_empty());
    assert!(
        peers.iter().all(|peer| peer.ip() == source),
        "a connection did not use source {source}: {peers:?}"
    );
}

/// Checks strict source-interface and egress-interface binding on loopback.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_interface_binding_on_loopback_carries_traffic() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let server = plain_server(upstream.address())
        .with_source_interface("lo")
        .with_egress_interface("lo")
        .with_binding_policy(BindingPolicy::Strict)
        .build();
    bound_traffic(&upstream, server).await;
    let peers = upstream.peers();
    assert!(peers.iter().all(|peer| peer.ip().is_loopback()), "{peers:?}");
}

fn unavailable_bindings(address: SocketAddr) -> [(&'static str, TacacsPlusServerBuilder); 3] {
    // 192.0.2.1 is TEST-NET-1, which no local interface owns.
    let foreign = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    [
        ("source-ip", plain_server(address).with_source_ip(foreign)),
        ("egress-interface", plain_server(address).with_egress_interface(MISSING_INTERFACE)),
        ("vrf-instance", plain_server(address).with_vrf_instance(MISSING_INTERFACE)),
    ]
}

/// Checks that a strict binding failure gives a local `ERROR` reply and sends
/// nothing upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_unavailable_binding_gets_a_local_error() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    for (constraint, builder) in unavailable_bindings(upstream.address()) {
        let server = builder.with_binding_policy(BindingPolicy::Strict).build();
        let daemon = Daemon::start(upstream.address(), config_options(&[server])).await;
        for kind in Kind::ALL {
            let outcome =
                single_request(daemon.port, kind, &format!("{USER_PREFIX}{constraint}")).await;
            assert!(
                is_local_error(&outcome),
                "strict {constraint} gave {kind:?} no local ERROR: {outcome:?}"
            );
        }
        daemon.stop().await;
    }
    assert_eq!(upstream.connections_accepted(), 0);
}

/// Checks that a best-effort binding drops an unavailable constraint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn best_effort_unavailable_binding_falls_back() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    for (constraint, builder) in unavailable_bindings(upstream.address()) {
        let server = builder
            .with_binding_policy(BindingPolicy::BestEffort)
            .build();
        let before = upstream.received_total();
        bound_traffic(&upstream, server).await;
        assert!(upstream.received_total() > before, "{constraint} sent nothing upstream");
    }
    let peers = upstream.peers();
    assert!(peers.iter().all(|peer| peer.ip().is_loopback()), "{peers:?}");
}

/// IPC operation results in the shape of the proxy `Outcome`.
fn ipc_outcome<T>(
    result: Result<T, tacacsrs_protocol::failure::ServiceError>,
    status: impl FnOnce(&T) -> Status,
    message: impl FnOnce(&T) -> String,
) -> Result<Outcome, tacacsrs_protocol::failure::ServiceError> {
    result.map(|response| Outcome::Reply {
        status: status(&response),
        server_msg: message(&response),
    })
}

/// IPC result with the upstream server that answered.
struct IpcReply {
    outcome: Result<Outcome, tacacsrs_protocol::failure::ServiceError>,
    server: Option<String>,
}

async fn ipc_operation(client: &ServiceClient, kind: Kind, user: &str) -> IpcReply {
    let port = "pts/2".to_owned();
    let remote_address = "192.0.2.2".to_owned();
    match kind {
        Kind::Authentication => {
            let result = client
                .authenticate_pap(PapAuthenticationOperation {
                    user: user.to_owned(),
                    password: SecretBytes::new(upstream::good_password().to_vec()),
                    port,
                    remote_address,
                    privilege_level: PrivilegeLevel::MAX,
                })
                .await;
            let server = result.as_ref().ok().map(|response| response.server.clone());
            IpcReply {
                outcome: ipc_outcome(
                    result,
                    |response| match response.status {
                        AuthenticationResponseStatus::Pass => Status::Success,
                        AuthenticationResponseStatus::Error => Status::Error,
                        AuthenticationResponseStatus::Fail => Status::Fail,
                    },
                    |response| response.server_message.clone(),
                ),
                server,
            }
        }
        Kind::Authorization => {
            let operation = AuthorizationOperation::builder(
                user,
                15,
                AuthorizationAuthenticationContext::TacacsPap,
            )
            .port(&port)
            .remote_address(&remote_address)
            .service("shell")
            .command("show")
            .build()
            .unwrap();
            let result = client.send_authorization(operation).await;
            let server = result.as_ref().ok().map(|response| response.server.clone());
            IpcReply {
                outcome: ipc_outcome(
                    result,
                    |response| match response.status {
                        AuthorizationResponseStatus::PassAdd
                        | AuthorizationResponseStatus::PassRepl => Status::Success,
                        AuthorizationResponseStatus::Error => Status::Error,
                        AuthorizationResponseStatus::Fail | AuthorizationResponseStatus::Follow => {
                            Status::Fail
                        }
                    },
                    |response| response.server_message.clone(),
                ),
                server,
            }
        }
        Kind::Accounting => {
            let result = client
                .send_accounting(AccountingOperation {
                    user: user.to_owned(),
                    port,
                    remote_address,
                    command: "show".to_owned(),
                    command_arguments: vec!["version".to_owned()],
                })
                .await;
            let server = result.as_ref().ok().map(|response| response.server.clone());
            IpcReply {
                outcome: ipc_outcome(
                    result,
                    |response| match response.status {
                        AccountingResponseStatus::Success => Status::Success,
                        AccountingResponseStatus::Error => Status::Error,
                        AccountingResponseStatus::Follow => Status::Fail,
                    },
                    |response| response.server_message.clone(),
                ),
                server,
            }
        }
    }
}

/// Connects to the IPC socket after the daemon creates it.
async fn ipc_client(socket: &Path) -> ServiceClient {
    let started = Instant::now();
    loop {
        if socket.exists() {
            if let Ok(client) = ServiceClient::connect(IpcEndpoint::Unix(socket.to_owned())).await {
                return client;
            }
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "the IPC socket {} did not accept connections",
            socket.display()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn timed_ipc(client: &ServiceClient, kind: Kind, user: &str) -> (IpcReply, Duration) {
    let started = Instant::now();
    let reply = tokio::time::timeout(OPERATION_LIMIT, ipc_operation(client, kind, user))
        .await
        .unwrap_or_else(|_| panic!("an IPC {kind:?} request exceeded {OPERATION_LIMIT:?}"));
    (reply, started.elapsed())
}

fn ipc_options(strategy: &str, deadline_seconds: u64, backup_servers: Vec<SocketAddr>) -> Options {
    Options {
        service_mode: "both",
        connect_timeout_seconds: 1,
        policy: fast_recovery(serde_json::json!({
            "authentication": { "request-timeout-seconds": deadline_seconds },
            "authorization": { "request-timeout-seconds": deadline_seconds },
            "accounting": { "request-timeout-seconds": deadline_seconds },
            "client-api-failover-strategy": strategy,
        })),
        backup_servers,
        ..Options::default()
    }
}

/// Checks that IPC clients and proxy clients share the routed upstream client.
///
/// IPC operations use `TacacsClient::execute_classified_until` and the proxy
/// relays raw packets. Both kinds of traffic run at the same time and must use
/// the same single-connect upstream connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_and_proxy_traffic_share_upstream_connections() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon =
        Daemon::start(upstream.address(), ipc_options("deferred-failover", 5, Vec::new())).await;
    let socket = daemon.socket();
    const IPC_CLIENTS: usize = 8;
    const IPC_OPERATIONS: usize = 30;
    let mut ipc = JoinSet::new();
    for client_index in 0..IPC_CLIENTS {
        let socket = socket.clone();
        ipc.spawn(async move {
            let client = ipc_client(&socket).await;
            let mut failures = Vec::new();
            for index in 0..IPC_OPERATIONS {
                let kind = mixed(index);
                let user = format!("{USER_PREFIX}ipc/c{client_index}/o{index}");
                let (reply, _) = timed_ipc(&client, kind, &user).await;
                match reply.outcome {
                    Ok(Outcome::Reply {
                        status: Status::Success,
                        server_msg,
                    }) if server_msg == user => {}
                    other => failures.push(format!("{kind:?} {user}: {other:?}")),
                }
            }
            failures
        });
    }
    let traffic = heavy(true);
    let tally = run_traffic(daemon.port, traffic, "proxy").await;
    let mut failures = Vec::new();
    while let Some(result) = ipc.join_next().await {
        failures.extend(result.unwrap());
    }
    tally.assert_all_succeeded(traffic.total());
    assert!(failures.is_empty(), "IPC requests failed: {failures:#?}");
    let total = traffic.total() + (IPC_CLIENTS * IPC_OPERATIONS) as u64;
    assert_eq!(upstream.received_total(), total);
    assert!(
        upstream.connections_accepted() < total / 4,
        "IPC and proxy traffic did not share connections: {} connections for {total} requests",
        upstream.connections_accepted()
    );
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn watchdog_shares_client_connections_and_recovers_on_a_later_tick() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let mut options = ipc_options("ordered-safe-retry", 3, Vec::new());
    options.upstream_watchdog_interval_seconds = Some(1);
    let daemon = Daemon::start(upstream.address(), options).await;
    let endpoint = IpcEndpoint::Unix(daemon.socket());
    let mut health = tacacsrs_ipc::HealthClient::connect(&endpoint)
        .await
        .unwrap();

    for (fault, ready) in [
        (Fault::None, true),
        (Fault::Close, false),
        (Fault::None, true),
    ] {
        upstream.set_plan(Arc::new(move |request| {
            if request.user == "tacacsrs-agent" {
                fault
            } else {
                Fault::None
            }
        }));
        tokio::time::timeout(OPERATION_LIMIT, async {
            loop {
                let details = health.details().await.unwrap();
                assert!(details.watchdog.as_ref().unwrap().armed);
                if details.readiness == ready {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("watchdog readiness did not become {ready}: {}", daemon.log()));

        if ready && upstream.injected(Fault::Close) == 0 {
            let ipc = ipc_client(&daemon.socket()).await;
            let reply = ipc_operation(&ipc, Kind::Authorization, "watchdog-ipc").await;
            assert!(matches!(
                reply.outcome,
                Ok(Outcome::Reply {
                    status: Status::Success,
                    ..
                })
            ));
            let proxy = super::proxy_client(daemon.port, true).await.unwrap();
            let reply = super::run_operation(&proxy, Kind::Accounting, "watchdog-proxy")
                .await
                .unwrap();
            assert!(matches!(
                reply,
                Outcome::Reply {
                    status: Status::Success,
                    ..
                }
            ));
            assert_eq!(upstream.connections_accepted(), 1);
        }
    }

    assert!(upstream.injected(Fault::Close) > 0);
    assert!(upstream.received(Kind::Accounting) >= 3);
    daemon.stop().await;
}

/// Checks that IPC requests are bounded when the upstream hangs or fails.
///
/// With one server, an upstream `ERROR` reaches the IPC caller as an `ERROR`
/// response. A hung authorization ends at its 1-second deadline with a
/// deadline failure. A closed connection ends with a failure. The other
/// operations keep working, and all operations recover afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_requests_are_bounded_under_upstream_faults() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let mut daemon =
        Daemon::start(upstream.address(), ipc_options("deferred-failover", 1, Vec::new())).await;
    let client = ipc_client(&daemon.socket()).await;

    upstream.set_plan(Arc::new(|request| match request.kind {
        Kind::Authentication => Fault::Error,
        Kind::Authorization => Fault::Hang,
        Kind::Accounting => Fault::None,
    }));
    let user = format!("{USER_PREFIX}ipc-fault");
    let (reply, _) = timed_ipc(&client, Kind::Authentication, &user).await;
    assert!(
        matches!(&reply.outcome, Ok(Outcome::Reply { status: Status::Error, server_msg }) if *server_msg == user),
        "the upstream ERROR did not reach the IPC caller: {:?}",
        reply.outcome
    );
    let (reply, elapsed) = timed_ipc(&client, Kind::Authorization, &user).await;
    match &reply.outcome {
        Err(error) => assert_eq!(error.facts.category(), FailureCategory::Deadline, "{error:?}"),
        other => panic!("a hung authorization did not fail at its deadline: {other:?}"),
    }
    assert!(elapsed < Duration::from_secs(3), "a hung authorization took {elapsed:?}");
    let (reply, _) = timed_ipc(&client, Kind::Accounting, &user).await;
    assert!(
        matches!(&reply.outcome, Ok(outcome) if succeeded(outcome)),
        "accounting failed while authorization hung: {:?}",
        reply.outcome
    );

    upstream.set_plan(once(Kind::Accounting, Fault::Close));
    let (reply, elapsed) = timed_ipc(&client, Kind::Accounting, &user).await;
    assert!(reply.outcome.is_err(), "a closed connection gave a reply: {:?}", reply.outcome);
    assert!(elapsed < Duration::from_secs(3), "a closed connection took {elapsed:?}");

    upstream.set_plan(upstream::healthy());
    let started = Instant::now();
    for kind in Kind::ALL {
        loop {
            let (reply, _) = timed_ipc(&client, kind, &user).await;
            if matches!(&reply.outcome, Ok(outcome) if succeeded(outcome)) {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "IPC {kind:?} did not recover: {:?}",
                reply.outcome
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    daemon.assert_running();
    assert_recovers(daemon.port, true).await;
    daemon.stop().await;
}

/// Checks IPC failover for both strategies.
///
/// With deferred failover, the caller receives the upstream `ERROR` and the
/// next request of that operation uses the backup server. With ordered safe
/// retry, the request that received the `ERROR` is replayed on the backup
/// server. In both cases the other operations keep the preferred server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_error_fails_over_only_that_operation() {
    for strategy in ["deferred-failover", "ordered-safe-retry"] {
        let primary = Upstream::start(SingleConnect::Accept).await;
        let backup = Upstream::start(SingleConnect::Accept).await;
        let daemon =
            Daemon::start(primary.address(), ipc_options(strategy, 5, vec![backup.address()]))
                .await;
        let client = ipc_client(&daemon.socket()).await;
        let user = format!("{USER_PREFIX}{strategy}");
        for kind in Kind::ALL {
            let (reply, _) = timed_ipc(&client, kind, &user).await;
            assert!(matches!(&reply.outcome, Ok(outcome) if succeeded(outcome)));
        }
        assert_eq!(primary.received_total(), 3);

        primary.set_plan(once(Kind::Authorization, Fault::Error));
        let (reply, _) = timed_ipc(&client, Kind::Authorization, &user).await;
        let expected = if strategy == "deferred-failover" {
            Status::Error
        } else {
            Status::Success
        };
        assert!(
            matches!(&reply.outcome, Ok(Outcome::Reply { status, server_msg }) if *status == expected && *server_msg == user),
            "{strategy}: unexpected reply to the failed authorization: {:?}",
            reply.outcome
        );
        let (reply, _) = timed_ipc(&client, Kind::Authorization, &user).await;
        assert!(matches!(&reply.outcome, Ok(outcome) if succeeded(outcome)));
        let backup_port = backup.address().port().to_string();
        assert!(
            reply
                .server
                .as_deref()
                .is_some_and(|server| server.contains(&backup_port)),
            "{strategy}: authorization did not move to the backup: {:?}",
            reply.server
        );
        let expected_backup = if strategy == "deferred-failover" {
            1
        } else {
            2
        };
        assert_eq!(backup.received(Kind::Authorization), expected_backup, "{strategy}");
        for kind in [Kind::Authentication, Kind::Accounting] {
            let (reply, _) = timed_ipc(&client, kind, &user).await;
            assert!(matches!(&reply.outcome, Ok(outcome) if succeeded(outcome)));
            assert_eq!(backup.received(kind), 0, "{strategy}: {kind:?} left the preferred server");
        }
        daemon.stop().await;
    }
}

/// Checks that IPC requests replay safely when the preferred server is down.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ipc_requests_fail_over_from_an_unreachable_server() {
    let unreachable = SocketAddr::from(([127, 0, 0, 1], unused_port()));
    let backup = Upstream::start(SingleConnect::Accept).await;
    let daemon =
        Daemon::start(unreachable, ipc_options("ordered-safe-retry", 5, vec![backup.address()]))
            .await;
    let client = ipc_client(&daemon.socket()).await;
    for index in 0..9 {
        let kind = mixed(index);
        let user = format!("{USER_PREFIX}unreachable/{index}");
        let (reply, elapsed) = timed_ipc(&client, kind, &user).await;
        assert!(
            matches!(&reply.outcome, Ok(Outcome::Reply { status: Status::Success, server_msg }) if *server_msg == user),
            "{kind:?} did not fail over: {:?}",
            reply.outcome
        );
        assert!(elapsed < Duration::from_secs(3), "{kind:?} failover took {elapsed:?}");
    }
    assert_eq!(backup.received_total(), 9);
    daemon.stop().await;
}
