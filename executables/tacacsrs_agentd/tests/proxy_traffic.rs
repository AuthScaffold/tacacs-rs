//! Load and fault-injection tests for the raw TACACS+ proxy of `tacacsrs-agentd`.
//!
//! Each test starts the real daemon binary in `tacacs-proxy` mode. The daemon
//! connects to a scripted plain-TCP upstream server. Many concurrent
//! `TacacsClient` instances then send mixed authentication, authorization, and
//! accounting traffic through the proxy. The upstream server can reply with
//! errors, delay replies, hang, close connections, or send truncated packets.
//!
//! The tests check that every reply arrives at the session that sent the
//! request, that no request waits longer than its configured deadline, that
//! admission limits hold, and that the daemon recovers and releases resources
//! after each fault.

#[path = "proxy_traffic/upstream.rs"]
mod upstream;

use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::task::JoinSet;

use tacacsrs_config::prepare::{PrepareOptions, prepare_endpoint, validate_materialized_servers};
use tacacsrs_config::{TacacsPlusServerBuilder, TacacsPlusServerType, ValidationOptions};
use tacacsrs_networking::TacacsClient;
use tacacsrs_protocol::enumerations::{
    TacacsAccountingStatus, TacacsAuthenticationStatus, TacacsAuthorizationStatus,
};
use tacacsrs_protocol::operations::{
    AccountingOperation, AuthorizationAuthenticationContext, AuthorizationOperation,
    PapAuthenticationOperation,
};
use tacacsrs_protocol::privilege::PrivilegeLevel;
use tacacsrs_secrets::SecretBytes;

use upstream::{Fault, GOOD_PASSWORD, Kind, Plan, SingleConnect, UPSTREAM_KEY, Upstream};

const DOWNSTREAM_KEY: &str = "downstream-proxy-key";

const USER_PREFIX: &str = "u/";

// Slow ARMhf QEMU runners share this budget for daemon startup.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

// No single request may take longer than this, under any fault.
const OPERATION_LIMIT: Duration = Duration::from_secs(15);

const SHUTDOWN_LIMIT: Duration = Duration::from_secs(10);

struct ProcessDirectory(PathBuf);

impl ProcessDirectory {
    fn new() -> Self {
        static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        loop {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "tacacsrs-proxy-traffic-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("could not create process test directory: {error}"),
            }
        }
    }
}

impl Drop for ProcessDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// Daemon options that the scenarios change.
struct Options {
    /// Disables upstream single-connect with `--dedicated`.
    dedicated_upstream: bool,
    /// Per-attempt upstream round-trip timeout, in seconds.
    connect_timeout_seconds: u64,
    /// Content of the `tacacsrs:runtime-policy` object.
    policy: serde_json::Value,
    /// Servers after the preferred server, in failover order.
    backup_servers: Vec<SocketAddr>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            dedicated_upstream: false,
            connect_timeout_seconds: 5,
            policy: serde_json::json!({}),
            backup_servers: Vec::new(),
        }
    }
}

const LISTENER_LOG_TARGET: &str = "tacacsrs_agent::services::tacacs_proxy::listener::tcp";
const LISTENER_MESSAGE: &str = "The TACACS+ proxy listener accepts clients on TCP ";

struct Daemon {
    child: Child,
    port: u16,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_reader: Option<tokio::task::JoinHandle<()>>,
    _directory: ProcessDirectory,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let log = self.log();
            let tail: Vec<&str> = log.lines().rev().take(60).collect();
            eprintln!("--- daemon stderr (last 60 lines) ---");
            for line in tail.iter().rev() {
                eprintln!("{line}");
            }
        }
    }
}

impl Daemon {
    async fn start(upstream: SocketAddr, options: Options) -> Self {
        let directory = ProcessDirectory::new();
        let policy = directory.0.join("policy.json");
        let document = serde_json::json!({ "tacacsrs:runtime-policy": options.policy });
        std::fs::write(&policy, document.to_string()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_tacacsrs-agentd"));
        command
            .kill_on_drop(true)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            // Set `PROXY_TRAFFIC_LOG=debug` to see more daemon output on failure.
            // The tests read the bound proxy port from this info message.
            .env(
                "RUST_LOG",
                format!(
                    "{},{LISTENER_LOG_TARGET}=info",
                    std::env::var("PROXY_TRAFFIC_LOG").unwrap_or_else(|_| "warn".to_owned())
                ),
            )
            .arg("-v")
            .args(["--server-addr", &upstream.to_string()])
            .args(["--shared-secret", UPSTREAM_KEY])
            .args(["--service-mode", "tacacs-proxy"])
            // Port 0 lets the kernel select a free port without a race.
            .args(["--proxy-endpoint", "127.0.0.1:0"])
            .args(["--proxy-shared-secret", DOWNSTREAM_KEY])
            .args(["--host-integration", "none"])
            .args([
                "--connect-timeout-seconds",
                &options.connect_timeout_seconds.to_string(),
            ])
            .arg("--listen-endpoint")
            .arg(directory.0.join("agent.sock"))
            .arg("--runtime-policy")
            .arg(&policy);
        for backup in &options.backup_servers {
            command.args(["--server-addr", &backup.to_string()]);
        }
        if options.dedicated_upstream {
            command.arg("--dedicated");
        }
        let mut child = command.spawn().unwrap();

        // A full stderr pipe would block the daemon while it logs faults.
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let mut pipe = child.stderr.take().unwrap();
        let sink = Arc::clone(&stderr);
        let stderr_reader = tokio::spawn(async move {
            let mut buffer = [0_u8; 8192];
            while let Ok(read) = pipe.read(&mut buffer).await {
                if read == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buffer[..read]);
            }
        });

        let mut daemon = Self {
            child,
            port: 0,
            stderr,
            stderr_reader: Some(stderr_reader),
            _directory: directory,
        };
        daemon.wait_ready().await;
        daemon
    }

    async fn wait_ready(&mut self) {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("daemon exited during startup ({status}): {}", self.log());
            }
            if let Some(address) = self.bound_address() {
                self.port = address.port();
                TcpStream::connect(address).await.unwrap();
                return;
            }
            assert!(
                started.elapsed() < STARTUP_TIMEOUT,
                "proxy listener did not start: {}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Returns the proxy address from the first listener message in the log.
    fn bound_address(&self) -> Option<SocketAddr> {
        self.log().lines().find_map(|line| {
            let (_, address) = line.split_once(LISTENER_MESSAGE)?;
            address.trim().parse().ok()
        })
    }

    fn log(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }

    fn fd_count(&self) -> usize {
        let process = self.child.id().unwrap();
        std::fs::read_dir(format!("/proc/{process}/fd"))
            .unwrap()
            .count()
    }

    fn assert_running(&mut self) {
        if let Some(status) = self.child.try_wait().unwrap() {
            panic!("daemon exited unexpectedly ({status}): {}", self.log());
        }
    }

    /// Sends `SIGTERM` and returns the time that the daemon took to exit.
    async fn stop(mut self) -> Duration {
        self.assert_running();
        let started = Instant::now();
        let status = Command::new("kill")
            .arg("-TERM")
            .arg(self.child.id().unwrap().to_string())
            .status()
            .await
            .unwrap();
        assert!(status.success());
        let exit = tokio::time::timeout(SHUTDOWN_LIMIT, self.child.wait())
            .await
            .unwrap_or_else(|_| panic!("daemon did not stop: {}", self.log()))
            .unwrap();
        // The daemon can print its final error after the last log line.
        if let Some(reader) = self.stderr_reader.take() {
            let _ = tokio::time::timeout(Duration::from_secs(1), reader).await;
        }
        assert!(exit.success(), "daemon exited with {exit}: {}", self.log());
        started.elapsed()
    }

    /// Waits until the file-descriptor count is at most `limit`.
    async fn wait_fds_at_most(&self, limit: usize) {
        let started = Instant::now();
        loop {
            let count = self.fd_count();
            if count <= limit {
                return;
            }
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "daemon keeps {count} file descriptors open, expected at most {limit}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Returns a port that no process listens on at the time of the call.
fn unused_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn proxy_client(port: u16, single_connect: bool) -> anyhow::Result<TacacsClient> {
    let server =
        TacacsPlusServerBuilder::new("proxy", TacacsPlusServerType::all(), "127.0.0.1", port)
            .with_shared_secret(DOWNSTREAM_KEY)
            .with_single_connection(single_connect)
            .with_timeout(10)
            .build();
    validate_materialized_servers([&server], &ValidationOptions::default())?;
    let endpoint = prepare_endpoint(&server, PrepareOptions::default())?;
    TacacsClient::connect_prepared(endpoint).await
}

/// Normalized status of one reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Status {
    Success,
    Error,
    Fail,
}

/// Result of one downstream request.
#[derive(Debug)]
enum Outcome {
    Reply { status: Status, server_msg: String },
    Transport(String),
}

async fn run_operation(client: &TacacsClient, kind: Kind, user: &str) -> anyhow::Result<Outcome> {
    let port = "pts/1".to_owned();
    let remote_address = "192.0.2.1".to_owned();
    let result = match kind {
        Kind::Authentication => {
            let operation = PapAuthenticationOperation {
                user: user.to_owned(),
                password: SecretBytes::new(GOOD_PASSWORD.to_vec()),
                port,
                remote_address,
                privilege_level: PrivilegeLevel::MAX,
            };
            client.execute(&operation.exchange()?).await.map(|reply| {
                let status = match reply.status {
                    TacacsAuthenticationStatus::TacPlusAuthenStatusPass => Status::Success,
                    TacacsAuthenticationStatus::TacPlusAuthenStatusError => Status::Error,
                    _ => Status::Fail,
                };
                (status, reply.server_msg)
            })
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
            .build()?;
            client.execute(&operation.exchange()?).await.map(|reply| {
                let status = match reply.status {
                    TacacsAuthorizationStatus::TacPlusPassAdd
                    | TacacsAuthorizationStatus::TacPlusPassRepl => Status::Success,
                    TacacsAuthorizationStatus::TacPlusError => Status::Error,
                    _ => Status::Fail,
                };
                (status, reply.server_msg)
            })
        }
        Kind::Accounting => {
            let operation = AccountingOperation {
                user: user.to_owned(),
                port,
                remote_address,
                command: "show".to_owned(),
                command_arguments: vec!["version".to_owned()],
            };
            client.execute(&operation.exchange()?).await.map(|reply| {
                let status = match reply.status {
                    TacacsAccountingStatus::TacPlusAcctStatusSuccess => Status::Success,
                    TacacsAccountingStatus::TacPlusAcctStatusError => Status::Error,
                    _ => Status::Fail,
                };
                (status, reply.server_msg)
            })
        }
    };
    Ok(match result {
        Ok((status, server_msg)) => Outcome::Reply { status, server_msg },
        Err(error) => Outcome::Transport(format!("{error:#}")),
    })
}

/// Aggregated results of a traffic run, kept per operation.
#[derive(Debug, Default)]
struct Tally {
    success: [u64; 3],
    /// Upstream `ERROR` replies, identified by the echoed request user.
    error: [u64; 3],
    /// `ERROR` replies that the daemon generated itself.
    local_error: [u64; 3],
    fail: [u64; 3],
    transport: [u64; 3],
    /// Replies whose echoed user differs from the request user.
    misrouted: u64,
    /// Requests that did not complete within `OPERATION_LIMIT`.
    hung: u64,
    /// Clients that could not connect to the proxy.
    connect_failures: u64,
    max_latency: [Duration; 3],
    sample_transport_error: Option<String>,
}

impl Tally {
    fn total(values: [u64; 3]) -> u64 {
        values.iter().sum()
    }

    fn successes(&self) -> u64 {
        Self::total(self.success)
    }

    fn errors(&self) -> u64 {
        Self::total(self.error)
    }

    fn local_errors(&self) -> u64 {
        Self::total(self.local_error)
    }

    fn transport_errors(&self) -> u64 {
        Self::total(self.transport)
    }

    fn completed(&self) -> u64 {
        self.successes()
            + self.errors()
            + self.local_errors()
            + Self::total(self.fail)
            + self.transport_errors()
    }

    fn merge(&mut self, other: Self) {
        for index in 0..3 {
            self.success[index] += other.success[index];
            self.error[index] += other.error[index];
            self.local_error[index] += other.local_error[index];
            self.fail[index] += other.fail[index];
            self.transport[index] += other.transport[index];
            self.max_latency[index] = self.max_latency[index].max(other.max_latency[index]);
        }
        self.misrouted += other.misrouted;
        self.hung += other.hung;
        self.connect_failures += other.connect_failures;
        if self.sample_transport_error.is_none() {
            self.sample_transport_error = other.sample_transport_error;
        }
    }

    fn record(&mut self, kind: Kind, user: &str, latency: Duration, outcome: Option<Outcome>) {
        let index = kind as usize;
        self.max_latency[index] = self.max_latency[index].max(latency);
        match outcome {
            None => self.hung += 1,
            Some(Outcome::Transport(error)) => {
                self.transport[index] += 1;
                self.sample_transport_error.get_or_insert(error);
            }
            Some(Outcome::Reply { status, server_msg }) => {
                if server_msg != user {
                    // The fixture echoes a user name with the `USER_PREFIX`.
                    // A daemon-generated ERROR carries a diagnostic instead.
                    if status == Status::Error && !server_msg.starts_with(USER_PREFIX) {
                        self.local_error[index] += 1;
                    } else {
                        self.misrouted += 1;
                    }
                    return;
                }
                match status {
                    Status::Success => self.success[index] += 1,
                    Status::Error => self.error[index] += 1,
                    Status::Fail => self.fail[index] += 1,
                }
            }
        }
    }

    /// Asserts the invariants that every scenario requires.
    fn assert_sound(&self, expected: u64) {
        assert_eq!(self.misrouted, 0, "replies reached the wrong session: {self:#?}");
        assert_eq!(self.hung, 0, "requests exceeded {OPERATION_LIMIT:?}: {self:#?}");
        assert_eq!(self.connect_failures, 0, "clients could not connect: {self:#?}");
        assert_eq!(self.completed(), expected, "requests are missing: {self:#?}");
        assert_eq!(Self::total(self.fail), 0, "unexpected FAIL replies: {self:#?}");
    }

    fn assert_all_succeeded(&self, expected: u64) {
        self.assert_sound(expected);
        assert_eq!(self.successes(), expected, "not every request succeeded: {self:#?}");
    }
}

/// Traffic shape of one run.
#[derive(Clone, Copy)]
struct Traffic {
    clients: usize,
    operations_per_client: usize,
    /// Concurrent requests per client. Values above one need single-connect
    /// downstream clients for multiplexing, but dedicated clients also accept them.
    concurrency: usize,
    single_connect: bool,
    /// Selects the operation of request `index`.
    kinds: fn(usize) -> Kind,
}

impl Traffic {
    const fn total(&self) -> u64 {
        (self.clients * self.operations_per_client) as u64
    }
}

fn mixed(index: usize) -> Kind {
    Kind::ALL[index % 3]
}

async fn run_traffic(port: u16, traffic: Traffic, label: &str) -> Tally {
    let mut clients = JoinSet::new();
    for client_index in 0..traffic.clients {
        let label = label.to_owned();
        clients.spawn(async move {
            let mut tally = Tally::default();
            let client = match proxy_client(port, traffic.single_connect).await {
                Ok(client) => Arc::new(client),
                Err(_) => {
                    tally.connect_failures += 1;
                    return tally;
                }
            };
            let next = Arc::new(AtomicUsize::new(0));
            let mut workers = JoinSet::new();
            for _ in 0..traffic.concurrency {
                let client = Arc::clone(&client);
                let next = Arc::clone(&next);
                let label = label.clone();
                workers.spawn(async move {
                    let mut tally = Tally::default();
                    loop {
                        let index = next.fetch_add(1, Ordering::SeqCst);
                        if index >= traffic.operations_per_client {
                            return tally;
                        }
                        let kind = (traffic.kinds)(index);
                        let user = format!("{USER_PREFIX}{label}/c{client_index}/o{index}");
                        let started = Instant::now();
                        let outcome = tokio::time::timeout(
                            OPERATION_LIMIT,
                            run_operation(&client, kind, &user),
                        )
                        .await
                        .ok()
                        .map(|result| result.unwrap());
                        tally.record(kind, &user, started.elapsed(), outcome);
                    }
                });
            }
            while let Some(result) = workers.join_next().await {
                tally.merge(result.unwrap());
            }
            client.stop_accepting_new_sessions().await;
            tally
        });
    }
    let mut tally = Tally::default();
    while let Some(result) = clients.join_next().await {
        tally.merge(result.unwrap());
    }
    tally
}

const fn heavy(single_connect: bool) -> Traffic {
    Traffic {
        clients: 16,
        operations_per_client: 30,
        concurrency: 4,
        single_connect,
        kinds: mixed,
    }
}

const fn recovery(single_connect: bool) -> Traffic {
    Traffic {
        clients: 4,
        operations_per_client: 6,
        concurrency: 2,
        single_connect,
        kinds: mixed,
    }
}

async fn wait_until(what: &str, condition: impl Fn() -> bool) {
    let started = Instant::now();
    while !condition() {
        assert!(started.elapsed() < Duration::from_secs(10), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn healthy_case(mode: SingleConnect, dedicated_upstream: bool, single_connect: bool) {
    let upstream = Upstream::start(mode).await;
    let daemon = Daemon::start(
        upstream.address(),
        Options {
            dedicated_upstream,
            ..Options::default()
        },
    )
    .await;
    let traffic = heavy(single_connect);
    let tally = run_traffic(daemon.port, traffic, "healthy").await;
    tally.assert_all_succeeded(traffic.total());
    assert_eq!(upstream.received_total(), traffic.total());
    if mode == SingleConnect::Accept && !dedicated_upstream {
        assert!(
            upstream.connections_accepted() < traffic.total() / 4,
            "upstream single-connect was not reused: {} connections for {} requests",
            upstream.connections_accepted(),
            traffic.total()
        );
    } else {
        assert!(
            upstream.connections_accepted() >= traffic.total(),
            "each upstream session needs its own connection without single-connect"
        );
    }
    wait_until("upstream connections to drain", || {
        mode == SingleConnect::Accept && !dedicated_upstream || upstream.open_connections() == 0
    })
    .await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthy_traffic_single_connect_upstream_and_multiplexed_clients() {
    healthy_case(SingleConnect::Accept, false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthy_traffic_single_connect_upstream_and_dedicated_clients() {
    healthy_case(SingleConnect::Accept, false, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthy_traffic_upstream_that_declines_single_connect() {
    healthy_case(SingleConnect::Decline, false, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn healthy_traffic_dedicated_upstream_connections() {
    healthy_case(SingleConnect::Accept, true, true).await;
}


// One upstream fault opens the circuit of its operation for
// `failover-recovery-interval-seconds` (30 seconds by default). The agent
// still uses a server with an open circuit when no other server is available.
// The fault scenarios use a short interval so that they also exercise the
// recovery trial. The regression tests at the end use the default interval.
const RECOVERY_INTERVAL_SECONDS: u64 = 1;

// Recovery must complete within this time after the upstream becomes healthy.
const RECOVERY_LIMIT: Duration = Duration::from_secs(10);

/// Adds the short recovery interval to a runtime policy.
fn fast_recovery(mut policy: serde_json::Value) -> serde_json::Value {
    policy["failover-recovery-interval-seconds"] = RECOVERY_INTERVAL_SECONDS.into();
    policy
}

/// Sends one request on a new dedicated downstream connection.
async fn single_request(port: u16, kind: Kind, user: &str) -> Outcome {
    let client = proxy_client(port, false).await.unwrap();
    let outcome = tokio::time::timeout(OPERATION_LIMIT, run_operation(&client, kind, user))
        .await
        .expect("a single request exceeded the operation limit")
        .unwrap();
    client.stop_accepting_new_sessions().await;
    outcome
}

const fn succeeded(outcome: &Outcome) -> bool {
    matches!(
        outcome,
        Outcome::Reply {
            status: Status::Success,
            ..
        }
    )
}

/// Waits until each operation succeeds again and returns the time it took.
async fn await_recovery(port: u16) -> Duration {
    let started = Instant::now();
    for kind in Kind::ALL {
        let mut attempt = 0;
        loop {
            let user = format!("{USER_PREFIX}probe/{kind:?}/{attempt}");
            let outcome = single_request(port, kind, &user).await;
            if succeeded(&outcome) {
                break;
            }
            assert!(
                started.elapsed() < RECOVERY_LIMIT,
                "{kind:?} did not recover within {RECOVERY_LIMIT:?}: {outcome:?}"
            );
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    started.elapsed()
}

/// Waits for recovery, then checks that normal traffic succeeds again.
async fn assert_recovers(port: u16, single_connect: bool) {
    await_recovery(port).await;
    let traffic = recovery(single_connect);
    run_traffic(port, traffic, "recovered")
        .await
        .assert_all_succeeded(traffic.total());
}

/// Injects `fault` into the first request of `kind` only.
fn once(kind: Kind, fault: Fault) -> Plan {
    let fired = Arc::new(AtomicBool::new(false));
    Arc::new(move |request| {
        if request.kind == kind && !fired.swap(true, Ordering::SeqCst) {
            fault
        } else {
            Fault::None
        }
    })
}

fn intermittent_errors() -> Plan {
    Arc::new(|request| {
        let failing = match request.kind {
            Kind::Authentication => request.index % 11 == 2,
            Kind::Authorization => request.index % 7 == 3,
            Kind::Accounting => request.index % 5 == 1,
        };
        if failing {
            Fault::Error
        } else {
            Fault::None
        }
    })
}

async fn intermittent_error_case(mode: SingleConnect, single_connect: bool) {
    let upstream = Upstream::start(mode).await;
    let mut daemon = Daemon::start(
        upstream.address(),
        Options {
            policy: fast_recovery(serde_json::json!({})),
            ..Options::default()
        },
    )
    .await;
    upstream.set_plan(intermittent_errors());
    let traffic = heavy(single_connect);
    let tally = run_traffic(daemon.port, traffic, "errors").await;
    tally.assert_sound(traffic.total());
    // With one server there is no failover, so each ERROR reaches its client.
    assert!(upstream.injected(Fault::Error) > 0);
    assert_eq!(tally.errors(), upstream.injected(Fault::Error), "{tally:#?}");
    for kind in Kind::ALL {
        assert!(
            tally.max_latency[kind as usize] < Duration::from_secs(2),
            "a {kind:?} request was slow although the upstream replied at once: {tally:#?}"
        );
    }
    daemon.assert_running();

    upstream.set_plan(upstream::healthy());
    assert_recovers(daemon.port, single_connect).await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intermittent_error_replies_reach_the_right_sessions_with_single_connect() {
    intermittent_error_case(SingleConnect::Accept, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intermittent_error_replies_reach_the_right_sessions_without_single_connect() {
    intermittent_error_case(SingleConnect::Decline, false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_upstream_below_the_deadline_is_concurrent_and_correct() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(upstream.address(), Options::default()).await;
    upstream.set_plan(Arc::new(|request| {
        let jitter = (request.index * 37) % 150;
        Fault::Delay(Duration::from_millis(100 + jitter))
    }));
    let traffic = heavy(true);
    let started = Instant::now();
    let tally = run_traffic(daemon.port, traffic, "slow").await;
    let elapsed = started.elapsed();
    tally.assert_all_succeeded(traffic.total());
    // The serial sum is at least 48 seconds. Concurrency must hide most of it.
    let serial = Duration::from_millis(100) * u32::try_from(traffic.total()).unwrap();
    assert!(
        elapsed < serial / 4,
        "slow upstream replies were serialized: {elapsed:?} for a serial floor of {serial:?}"
    );
    assert!(upstream.max_in_flight(Kind::Authorization) > 4);
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_authorization_does_not_delay_other_operations() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(upstream.address(), Options::default()).await;
    upstream.set_plan(Arc::new(|request| match request.kind {
        Kind::Authorization => Fault::Delay(Duration::from_millis(1500)),
        Kind::Authentication | Kind::Accounting => Fault::None,
    }));
    let traffic = Traffic {
        clients: 8,
        operations_per_client: 15,
        concurrency: 3,
        single_connect: true,
        kinds: mixed,
    };
    let tally = run_traffic(daemon.port, traffic, "slow-authz").await;
    tally.assert_all_succeeded(traffic.total());
    for kind in [Kind::Authentication, Kind::Accounting] {
        assert!(
            tally.max_latency[kind as usize] < Duration::from_millis(1000),
            "slow authorization delayed {kind:?} on shared connections: {tally:#?}"
        );
    }
    daemon.stop().await;
}

fn hang_authorization() -> Plan {
    Arc::new(|request| match request.kind {
        Kind::Authorization => Fault::Hang,
        Kind::Authentication | Kind::Accounting => Fault::Delay(Duration::from_millis(20)),
    })
}

fn deadline_policy(authorization_seconds: u64) -> serde_json::Value {
    fast_recovery(serde_json::json!({
        "authorization": { "request-timeout-seconds": authorization_seconds },
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hanging_authorization_is_bounded_and_isolated_on_dedicated_clients() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(
        upstream.address(),
        Options {
            policy: deadline_policy(1),
            ..Options::default()
        },
    )
    .await;
    upstream.set_plan(hang_authorization());
    let traffic = Traffic {
        clients: 12,
        operations_per_client: 9,
        concurrency: 1,
        single_connect: false,
        kinds: mixed,
    };
    let tally = run_traffic(daemon.port, traffic, "hang").await;
    tally.assert_sound(traffic.total());
    let authorization = Kind::Authorization as usize;
    let per_kind = traffic.total() / 3;
    assert_eq!(tally.success[Kind::Authentication as usize], per_kind, "{tally:#?}");
    assert_eq!(tally.success[Kind::Accounting as usize], per_kind, "{tally:#?}");
    assert_eq!(tally.success[authorization], 0, "{tally:#?}");
    // The 1-second deadline must end each hung request well before the
    // 5-second attempt timeout and the 10-second client timeout.
    assert!(
        tally.max_latency[authorization] < Duration::from_secs(4),
        "the authorization deadline did not bound hung requests: {tally:#?}"
    );

    upstream.set_plan(upstream::healthy());
    assert_recovers(daemon.port, false).await;
    daemon.stop().await;
}

async fn broken_upstream_case(fault: Fault, mode: SingleConnect) {
    let upstream = Upstream::start(mode).await;
    let mut daemon = Daemon::start(
        upstream.address(),
        Options {
            connect_timeout_seconds: 1,
            policy: fast_recovery(serde_json::json!({
                "authentication": { "request-timeout-seconds": 2 },
                "authorization": { "request-timeout-seconds": 2 },
                "accounting": { "request-timeout-seconds": 2 },
            })),
            ..Options::default()
        },
    )
    .await;
    let warm = recovery(false);
    run_traffic(daemon.port, warm, "warm")
        .await
        .assert_all_succeeded(warm.total());
    let baseline_fds = daemon.fd_count();

    upstream.set_plan(Arc::new(move |request| {
        if request.index % 4 == 1 {
            fault
        } else {
            Fault::None
        }
    }));
    let traffic = Traffic {
        clients: 12,
        operations_per_client: 12,
        concurrency: 1,
        single_connect: false,
        kinds: mixed,
    };
    let tally = run_traffic(daemon.port, traffic, "broken").await;
    tally.assert_sound(traffic.total());
    assert!(upstream.injected(fault) > 0);
    for kind in Kind::ALL {
        assert!(
            tally.max_latency[kind as usize] < Duration::from_secs(5),
            "a {kind:?} request was not bounded by its deadline: {tally:#?}"
        );
    }
    daemon.assert_running();

    upstream.set_plan(upstream::healthy());
    assert_recovers(daemon.port, false).await;
    // A single-connect upstream connection may stay open, so allow slack.
    daemon.wait_fds_at_most(baseline_fds + 2).await;
    wait_until("upstream fixture handlers to finish", || upstream.in_flight() == 0).await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_connection_close_is_bounded_and_recovers_with_single_connect() {
    broken_upstream_case(Fault::Close, SingleConnect::Accept).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_connection_close_is_bounded_and_recovers_without_single_connect() {
    broken_upstream_case(Fault::Close, SingleConnect::Decline).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_upstream_reply_is_bounded_and_recovers_with_single_connect() {
    broken_upstream_case(Fault::PartialHeader, SingleConnect::Accept).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_upstream_reply_is_bounded_and_recovers_without_single_connect() {
    broken_upstream_case(Fault::PartialHeader, SingleConnect::Decline).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admission_limit_bounds_upstream_concurrency_and_sheds_excess_load() {
    const LIMIT: usize = 4;
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let limits = serde_json::json!({ "max-concurrent-requests": LIMIT });
    let daemon = Daemon::start(
        upstream.address(),
        Options {
            policy: serde_json::json!({
                "authentication": limits,
                "authorization": limits,
                "accounting": limits,
            }),
            ..Options::default()
        },
    )
    .await;
    upstream.set_plan(Arc::new(|_| Fault::Delay(Duration::from_millis(50))));

    // The pending queue holds as many requests as the active limit. Up to
    // twice the limit of concurrent requests per operation must all succeed.
    let within = Traffic {
        clients: 2,
        operations_per_client: 30,
        concurrency: 3,
        single_connect: true,
        kinds: mixed,
    };
    run_traffic(daemon.port, within, "within")
        .await
        .assert_all_succeeded(within.total());

    // Above that load, the daemon sheds the excess with local ERROR replies.
    let over = Traffic {
        clients: 8,
        operations_per_client: 12,
        concurrency: 4,
        single_connect: true,
        kinds: mixed,
    };
    let tally = run_traffic(daemon.port, over, "over").await;
    tally.assert_sound(over.total());
    for kind in Kind::ALL {
        let peak = upstream.max_in_flight(kind);
        assert!(peak <= LIMIT, "{kind:?} reached {peak} concurrent upstream requests");
    }
    assert_eq!(tally.transport_errors(), 0, "overload must not break connections: {tally:#?}");
    assert!(tally.local_errors() > 0, "the overload did not reach the limit: {tally:#?}");
    assert_eq!(tally.successes() + tally.local_errors(), over.total(), "{tally:#?}");

    // Load shedding must not disable the server.
    run_traffic(daemon.port, within, "after")
        .await
        .assert_all_succeeded(within.total());
    daemon.stop().await;
}

/// Starts 48 slow requests on 16 clients, then drops every client.
async fn abandon_slow_requests(daemon: &Daemon, upstream: &Upstream) {
    upstream.set_plan(Arc::new(|_| Fault::Delay(Duration::from_secs(3))));
    let mut abandoned = JoinSet::new();
    for client_index in 0..16 {
        let port = daemon.port;
        abandoned.spawn(async move {
            let client = Arc::new(proxy_client(port, client_index % 2 == 0).await.unwrap());
            let mut requests = JoinSet::new();
            for index in 0..3 {
                let client = Arc::clone(&client);
                requests.spawn(async move {
                    let user = format!("{USER_PREFIX}abandoned/c{client_index}/o{index}");
                    run_operation(&client, mixed(index), &user).await
                });
            }
            // Aborting this task drops the client and every pending request.
            let _requests = requests;
            std::future::pending::<()>().await;
        });
    }
    wait_until("abandoned requests to reach the upstream", || upstream.in_flight() >= 48).await;
    abandoned.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_downstream_clients_release_daemon_resources() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(
        upstream.address(),
        Options {
            policy: fast_recovery(serde_json::json!({})),
            ..Options::default()
        },
    )
    .await;
    let warm = recovery(true);
    run_traffic(daemon.port, warm, "warm")
        .await
        .assert_all_succeeded(warm.total());
    let baseline_fds = daemon.fd_count();

    abandon_slow_requests(&daemon, &upstream).await;
    wait_until("upstream fixture handlers to finish", || upstream.in_flight() == 0).await;
    daemon.wait_fds_at_most(baseline_fds + 2).await;

    upstream.set_plan(upstream::healthy());
    assert_recovers(daemon.port, true).await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sigterm_during_slow_traffic_stops_promptly_without_hung_clients() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(upstream.address(), Options::default()).await;
    upstream.set_plan(Arc::new(|request| {
        Fault::Delay(Duration::from_millis(200 + (request.index % 5) * 100))
    }));
    let port = daemon.port;
    let traffic = tokio::spawn(run_traffic(
        port,
        Traffic {
            clients: 8,
            operations_per_client: 200,
            concurrency: 4,
            single_connect: true,
            kinds: mixed,
        },
        "shutdown",
    ));
    wait_until("traffic to reach the upstream", || upstream.received_total() > 50).await;
    let stopped_after = daemon.stop().await;
    let tally = tokio::time::timeout(Duration::from_secs(30), traffic)
        .await
        .expect("clients must finish after the daemon stops")
        .unwrap();
    assert_eq!(tally.misrouted, 0, "{tally:#?}");
    assert_eq!(tally.hung, 0, "clients hung after shutdown: {tally:#?}");
    assert!(tally.successes() > 0, "{tally:#?}");
    assert!(stopped_after < SHUTDOWN_LIMIT);
}

// The regression tests below cover problems that the scenarios above found.
// They use the default 30-second recovery interval, as production does.

/// Checks that a request immediately after one fault succeeds on one server.
async fn assert_single_fault_is_contained(fault: Fault, kind: Kind) {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(
        upstream.address(),
        Options {
            connect_timeout_seconds: 1,
            policy: serde_json::json!({
                "authentication": { "request-timeout-seconds": 2 },
                "authorization": { "request-timeout-seconds": 2 },
                "accounting": { "request-timeout-seconds": 2 },
            }),
            ..Options::default()
        },
    )
    .await;
    upstream.set_plan(once(kind, fault));
    let first = single_request(daemon.port, kind, &format!("{USER_PREFIX}first")).await;
    assert!(!succeeded(&first), "the fault was not injected: {first:?}");
    let user = format!("{USER_PREFIX}second");
    let second = single_request(daemon.port, kind, &user).await;
    assert!(
        succeeded(&second),
        "one {fault:?} on {kind:?} disabled the only server: the next request got {second:?}"
    );
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_error_reply_does_not_disable_the_only_server() {
    assert_single_fault_is_contained(Fault::Error, Kind::Authorization).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_connection_close_does_not_disable_the_only_server() {
    assert_single_fault_is_contained(Fault::Close, Kind::Authentication).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upstream_timeout_does_not_disable_the_only_server() {
    assert_single_fault_is_contained(Fault::Hang, Kind::Accounting).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn abandoned_downstream_request_does_not_disable_a_healthy_server() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(upstream.address(), Options::default()).await;
    abandon_slow_requests(&daemon, &upstream).await;
    upstream.set_plan(upstream::healthy());
    for kind in Kind::ALL {
        let outcome = single_request(daemon.port, kind, &format!("{USER_PREFIX}after")).await;
        assert!(
            succeeded(&outcome),
            "client disconnects disabled {kind:?} on a healthy upstream: {outcome:?}"
        );
    }
    daemon.stop().await;
}

/// Checks that the client gets an `ERROR` reply when no server can answer.
///
/// RFC 8907 section 4.4 tells the client to treat `ERROR` as an unreachable
/// server and to try its backup servers. A closed connection without a reply
/// gives the client less information.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unreachable_server_gets_a_local_error_reply() {
    let unreachable = SocketAddr::from(([127, 0, 0, 1], unused_port()));
    let daemon = Daemon::start(
        unreachable,
        Options {
            connect_timeout_seconds: 1,
            ..Options::default()
        },
    )
    .await;
    for kind in Kind::ALL {
        for attempt in 0..2 {
            let user = format!("{USER_PREFIX}unreachable/{kind:?}/{attempt}");
            let outcome = single_request(daemon.port, kind, &user).await;
            assert!(
                matches!(
                    outcome,
                    Outcome::Reply {
                        status: Status::Error,
                        ..
                    }
                ),
                "expected a local ERROR reply for {kind:?}, got {outcome:?}"
            );
        }
    }
    daemon.stop().await;
}

/// Measures collateral damage when one multiplexed session times out.
///
/// The downstream client multiplexes authentication, authorization, and
/// accounting on one connection. Only authorization hangs upstream.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hanging_authorization_does_not_break_other_multiplexed_sessions() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(
        upstream.address(),
        Options {
            policy: deadline_policy(1),
            ..Options::default()
        },
    )
    .await;
    upstream.set_plan(hang_authorization());
    let traffic = Traffic {
        clients: 4,
        operations_per_client: 30,
        concurrency: 6,
        single_connect: true,
        kinds: mixed,
    };
    let tally = run_traffic(daemon.port, traffic, "collateral").await;
    tally.assert_sound(traffic.total());
    let collateral =
        tally.transport[Kind::Authentication as usize] + tally.transport[Kind::Accounting as usize];
    assert_eq!(
        collateral, 0,
        "an authorization timeout failed unrelated sessions on the same downstream connection \
         (sample: {:?}): {tally:#?}",
        tally.sample_transport_error
    );
    daemon.stop().await;
}

/// Starts a preferred and a backup upstream behind one daemon.
async fn start_failover_pair(strategy: &str) -> (Upstream, Upstream, Daemon) {
    let primary = Upstream::start(SingleConnect::Accept).await;
    let backup = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(
        primary.address(),
        Options {
            policy: serde_json::json!({ "tacacs-proxy-failover-strategy": strategy }),
            backup_servers: vec![backup.address()],
            ..Options::default()
        },
    )
    .await;
    for kind in Kind::ALL {
        let outcome = single_request(daemon.port, kind, &format!("{USER_PREFIX}warm")).await;
        assert!(succeeded(&outcome), "{kind:?} warm-up failed: {outcome:?}");
        assert_eq!(primary.received(kind), 1, "{kind:?} did not use the preferred server");
    }
    assert_eq!(backup.received_total(), 0);
    (primary, backup, daemon)
}

/// Checks that an `ERROR` affects only the operation type that received it.
///
/// RFC 8907 section 4.4 tells the client to treat an `ERROR` reply as an
/// unreachable server. The proxy sends new requests of that operation to the
/// backup. The other operation types keep the preferred server and its shared
/// connection.
async fn assert_error_isolated_to_operation(primary: &Upstream, backup: &Upstream, port: u16) {
    for kind in [Kind::Authentication, Kind::Accounting] {
        let before = primary.received(kind);
        let outcome = single_request(port, kind, &format!("{USER_PREFIX}other")).await;
        assert!(succeeded(&outcome), "{kind:?} failed after an authorization ERROR: {outcome:?}");
        assert_eq!(primary.received(kind), before + 1, "{kind:?} left the preferred server");
        assert_eq!(backup.received(kind), 0, "{kind:?} moved to the backup server");
    }
    assert_eq!(primary.open_connections(), 1, "the shared preferred connection closed");
    assert_eq!(primary.connections_accepted(), 1);

    // A second operation that fails over joins the open backup connection.
    let before = primary.received(Kind::Accounting);
    primary.set_plan(once(Kind::Accounting, Fault::Error));
    let _ = single_request(port, Kind::Accounting, &format!("{USER_PREFIX}a")).await;
    let moved = single_request(port, Kind::Accounting, &format!("{USER_PREFIX}m")).await;
    assert!(succeeded(&moved), "accounting failed after its ERROR: {moved:?}");
    assert_eq!(primary.received(Kind::Accounting), before + 1);
    assert!(backup.received(Kind::Accounting) >= 1, "accounting did not fail over");
    assert_eq!(backup.connections_accepted(), 1, "the backup opened a second connection");

    let authentication =
        single_request(port, Kind::Authentication, &format!("{USER_PREFIX}s")).await;
    assert!(succeeded(&authentication), "authentication failed: {authentication:?}");
    assert_eq!(backup.received(Kind::Authentication), 0, "authentication left the primary");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deferred_failover_forwards_an_error_and_moves_only_that_operation() {
    let (primary, backup, daemon) = start_failover_pair("deferred-failover").await;
    assert_eq!(primary.open_connections(), 1, "operations did not share one connection");
    primary.set_plan(once(Kind::Authorization, Fault::Error));

    let failed = single_request(daemon.port, Kind::Authorization, &format!("{USER_PREFIX}e")).await;
    assert!(
        matches!(
            failed,
            Outcome::Reply {
                status: Status::Error,
                ..
            }
        ),
        "deferred-failover must forward the server ERROR to the client: {failed:?}"
    );
    assert_eq!(backup.received_total(), 0, "deferred-failover replayed the request");

    let next = single_request(daemon.port, Kind::Authorization, &format!("{USER_PREFIX}n")).await;
    assert!(succeeded(&next), "the next authorization failed: {next:?}");
    assert_eq!(backup.received(Kind::Authorization), 1, "authorization did not fail over");
    assert_eq!(primary.received(Kind::Authorization), 2);

    assert_error_isolated_to_operation(&primary, &backup, daemon.port).await;
    daemon.stop().await;
}

/// Checks that a dropped connection that served valid replies reconnects to the same server.
///
/// A lost connection is a transport fault. If the server accepts the next
/// connection, the operation stays on the preferred server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropped_proven_connection_reconnects_to_the_preferred_server() {
    let (primary, backup, daemon) = start_failover_pair("deferred-failover").await;
    let accepted = primary.connections_accepted();
    primary.set_plan(once(Kind::Authorization, Fault::Close));

    let dropped =
        single_request(daemon.port, Kind::Authorization, &format!("{USER_PREFIX}c")).await;
    assert!(!succeeded(&dropped), "the dropped request reported success: {dropped:?}");

    let next = single_request(daemon.port, Kind::Authorization, &format!("{USER_PREFIX}n")).await;
    assert!(succeeded(&next), "the next authorization failed: {next:?}");
    assert_eq!(primary.connections_accepted(), accepted + 1, "authorization did not reconnect");
    assert_eq!(backup.received_total(), 0, "a transport fault moved traffic to the backup");
    assert_eq!(backup.connections_accepted(), 0);
    daemon.stop().await;
}

/// Checks that a preferred-server outage moves every operation onto one backup connection.
///
/// Each operation type discovers the outage separately. They must still share
/// one backup connection, so the backup does not receive three connections for
/// each proxy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn preferred_server_outage_converges_on_one_backup_connection() {
    let (primary, backup, daemon) = start_failover_pair("ordered-safe-retry").await;
    drop(primary);

    for kind in Kind::ALL {
        let mut outcome = None;
        for attempt in 0..3 {
            let next = single_request(daemon.port, kind, &format!("{USER_PREFIX}o{attempt}")).await;
            if succeeded(&next) {
                outcome = None;
                break;
            }
            outcome = Some(next);
        }
        assert!(outcome.is_none(), "{kind:?} did not recover on the backup: {outcome:?}");
        assert!(backup.received(kind) >= 1, "{kind:?} did not use the backup");
    }
    assert_eq!(backup.connections_accepted(), 1, "operations opened separate backup connections");
    assert_eq!(backup.open_connections(), 1);
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ordered_safe_retry_replays_an_error_on_the_backup_server() {
    let (primary, backup, daemon) = start_failover_pair("ordered-safe-retry").await;
    assert_eq!(primary.open_connections(), 1, "operations did not share one connection");
    primary.set_plan(once(Kind::Authorization, Fault::Error));

    let retried =
        single_request(daemon.port, Kind::Authorization, &format!("{USER_PREFIX}r")).await;
    assert!(succeeded(&retried), "the backup server did not answer the retry: {retried:?}");
    assert_eq!(primary.injected(Fault::Error), 1);
    assert_eq!(backup.received(Kind::Authorization), 1, "the request was not replayed");

    assert_error_isolated_to_operation(&primary, &backup, daemon.port).await;
    daemon.stop().await;
}
