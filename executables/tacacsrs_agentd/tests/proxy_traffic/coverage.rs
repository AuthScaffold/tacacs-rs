//! Proxy scenarios for multi-step sessions, malformed replies, and server changes.
//!
//! These tests drive the parts of the upstream path that single-packet
//! traffic does not reach. ASCII logins keep one upstream session open across
//! a `GETPASS` reply and the following `CONTINUE` packet. Malformed replies
//! exercise the packet reader and the session checks in `tacacsrs-networking`.
//! Configuration reloads, server restarts, and full outages exercise
//! connection retirement and recovery.
//!
//! The tests use the plain-TCP fixture in `upstream.rs`. The mock transport of
//! `tacacsrs-networking` is private to that crate's unit tests, and these
//! tests run the daemon as a separate process.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::task::JoinSet;

use tacacsrs_networking::TacacsClient;
use tacacsrs_protocol::authentication::continue_packet::AuthenticationContinue;
use tacacsrs_protocol::authentication::reply::AuthenticationReply;
use tacacsrs_protocol::authentication::start::AuthenticationStart;
use tacacsrs_protocol::body::TacacsBodyTrait;
use tacacsrs_protocol::enumerations::{
    TacacsAuthenticationAction, TacacsAuthenticationContinueFlags, TacacsAuthenticationService,
    TacacsAuthenticationStatus, TacacsAuthenticationType, TacacsFlags, TacacsMajorVersion,
    TacacsMinorVersion, TacacsType,
};
use tacacsrs_protocol::header::Header;
use tacacsrs_protocol::packet::{Packet, PacketTrait};

use super::upstream::{self, Fault, Kind, Plan, SingleConnect, Upstream};
use super::{
    Daemon, OPERATION_LIMIT, Options, Outcome, Status, Traffic, USER_PREFIX, assert_recovers,
    await_recovery, broken_upstream_case, fast_recovery, mixed, once, proxy_client, run_traffic,
    single_request, succeeded, wait_until,
};

const AUTHENTICATION_FOLLOW: u8 = TacacsAuthenticationStatus::TacPlusAuthenStatusFollow as u8;
const AUTHENTICATION_RESTART: u8 = TacacsAuthenticationStatus::TacPlusAuthenStatusRestart as u8;

// No TACACS+ reply type defines this status value.
const UNKNOWN_STATUS: u8 = 0x7f;

fn request_packet(session_id: u32, seq_no: u8, body: Vec<u8>) -> anyhow::Result<Packet> {
    let header = Header {
        major_version: TacacsMajorVersion::TacacsPlusMajor1,
        minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
        tacacs_type: TacacsType::TacPlusAuthentication,
        seq_no,
        flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
        session_id,
        length: u32::try_from(body.len())?,
    };
    Packet::new(header, body)
}

fn start(user: &str, authen_type: TacacsAuthenticationType, data: &[u8]) -> AuthenticationStart {
    AuthenticationStart {
        action: TacacsAuthenticationAction::TacPlusAuthenLogin,
        priv_lvl: 1,
        authen_type,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcLogin,
        user: user.to_owned(),
        port: "pts/1".to_owned(),
        rem_address: "192.0.2.1".to_owned(),
        data: data.to_vec(),
    }
}

fn outcome(reply: &AuthenticationReply) -> Outcome {
    let status = match reply.status {
        TacacsAuthenticationStatus::TacPlusAuthenStatusPass => Status::Success,
        TacacsAuthenticationStatus::TacPlusAuthenStatusError => Status::Error,
        _ => Status::Fail,
    };
    Outcome::Reply {
        status,
        server_msg: reply.server_msg.clone(),
    }
}

/// Runs an ASCII login: `START`, `GETPASS`, `CONTINUE` with the password, and the result.
pub(super) async fn ascii_login(client: &TacacsClient, user: &str, password: &[u8]) -> Outcome {
    match ascii_steps(client, user, password).await {
        Ok(outcome) => outcome,
        Err(error) => Outcome::Transport(format!("{error:#}")),
    }
}

async fn ascii_steps(
    client: &TacacsClient,
    user: &str,
    password: &[u8],
) -> anyhow::Result<Outcome> {
    let mut conversation = client.open_conversation().await?;
    let session_id = conversation
        .session_id()
        .context("the conversation has no session")?;
    let body = start(user, TacacsAuthenticationType::TacPlusAuthenTypeAscii, &[]).to_bytes()?;
    let first = conversation
        .round_trip(request_packet(session_id, 1, body)?)
        .await?;
    let prompt = AuthenticationReply::from_packet(&first)?;
    if prompt.status != TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass {
        conversation.complete().await;
        return Ok(outcome(&prompt));
    }
    let body = AuthenticationContinue {
        user_msg: String::new(),
        data: password.to_vec(),
        flags: TacacsAuthenticationContinueFlags::empty(),
    }
    .to_bytes()?;
    let second = conversation
        .round_trip(request_packet(session_id, 3, body)?)
        .await?;
    conversation.complete().await;
    Ok(outcome(&AuthenticationReply::from_packet(&second)?))
}

/// Sends one PAP `START` and returns the reply packet without status checks.
async fn raw_authentication(port: u16, user: &str) -> anyhow::Result<Packet> {
    let client = proxy_client(port, false).await?;
    let mut conversation = client.open_conversation().await?;
    let session_id = conversation
        .session_id()
        .context("the conversation has no session")?;
    let body =
        start(user, TacacsAuthenticationType::TacPlusAuthenTypePap, upstream::good_password())
            .to_bytes()?;
    let reply = tokio::time::timeout(
        OPERATION_LIMIT,
        conversation.round_trip(request_packet(session_id, 1, body)?),
    )
    .await
    .context("the raw authentication exceeded the operation limit")??;
    conversation.complete().await;
    client.stop_accepting_new_sessions().await;
    Ok(reply)
}

fn server_msg(packet: &Packet) -> String {
    AuthenticationReply::from_packet(packet)
        .map(|reply| reply.server_msg)
        .unwrap_or_default()
}

const fn ascii(single_connect: bool) -> Traffic {
    Traffic {
        clients: 12,
        operations_per_client: 18,
        concurrency: 3,
        single_connect,
        kinds: mixed,
        ascii_authentication: true,
    }
}

/// Short deadlines so that each fault ends within a few seconds.
fn short_deadlines() -> serde_json::Value {
    fast_recovery(serde_json::json!({
        "authentication": { "request-timeout-seconds": 2 },
        "authorization": { "request-timeout-seconds": 2 },
        "accounting": { "request-timeout-seconds": 2 },
    }))
}

async fn ascii_case(mode: SingleConnect, single_connect: bool) {
    let upstream = Upstream::start(mode).await;
    let daemon = Daemon::start(upstream.address(), Options::default()).await;
    let traffic = ascii(single_connect);
    run_traffic(daemon.port, traffic, "ascii")
        .await
        .assert_all_succeeded(traffic.total());
    // Each ASCII login sends a START and a CONTINUE upstream.
    let logins = traffic.total() / 3;
    assert_eq!(upstream.received(Kind::Authentication), logins * 2);

    let client = proxy_client(daemon.port, single_connect).await.unwrap();
    let user = format!("{USER_PREFIX}wrong-password");
    let wrong_password = upstream::good_password()
        .iter()
        .map(|byte| !byte)
        .collect::<Vec<_>>();
    let rejected = ascii_login(&client, &user, &wrong_password).await;
    assert!(
        matches!(&rejected, Outcome::Reply { status: Status::Fail, server_msg } if *server_msg == user),
        "a wrong ASCII password must reach its own session as FAIL: {rejected:?}"
    );
    client.stop_accepting_new_sessions().await;
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ascii_logins_continue_on_a_shared_single_connect_upstream() {
    ascii_case(SingleConnect::Accept, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ascii_logins_continue_on_dedicated_upstream_connections() {
    ascii_case(SingleConnect::Decline, false).await;
}

/// Injects `fault` into every third `CONTINUE` packet of an ASCII login.
async fn continue_fault_case(fault: Fault) {
    for (mode, single_connect) in [
        (SingleConnect::Accept, true),
        (SingleConnect::Decline, false),
    ] {
        let upstream = Upstream::start(mode).await;
        let mut daemon = Daemon::start(
            upstream.address(),
            Options {
                connect_timeout_seconds: 1,
                policy: short_deadlines(),
                ..Options::default()
            },
        )
        .await;
        upstream.set_plan(Arc::new(move |request| {
            if request.continuation && request.index % 3 == 1 {
                fault
            } else {
                Fault::None
            }
        }));
        let traffic = ascii(single_connect);
        let tally = run_traffic(daemon.port, traffic, "continue").await;
        tally.assert_sound(traffic.total());
        assert!(upstream.injected(fault) > 0, "{fault:?} was not injected in {mode:?}");
        for kind in Kind::ALL {
            assert!(
                tally.max_latency[kind as usize] < Duration::from_secs(5),
                "a {kind:?} request was not bounded after a {fault:?} on CONTINUE: {tally:#?}"
            );
        }
        daemon.assert_running();
        upstream.set_plan(upstream::healthy());
        assert_recovers(daemon.port, single_connect).await;
        if fault == Fault::Hang && mode == SingleConnect::Accept {
            // The server still holds the hung sessions. The shared connection stays usable.
            assert_eq!(upstream.open_connections(), 1);
        } else {
            wait_until("upstream fixture handlers to finish", || upstream.in_flight() == 0).await;
        }
        daemon.stop().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn error_on_continue_reaches_its_session_and_recovers() {
    continue_fault_case(Fault::Error).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hang_on_continue_is_bounded_and_recovers() {
    continue_fault_case(Fault::Hang).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn close_on_continue_is_bounded_and_recovers() {
    continue_fault_case(Fault::Close).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn truncated_reply_on_continue_is_bounded_and_recovers() {
    continue_fault_case(Fault::PartialHeader).await;
}

/// Checks that a client that leaves after `GETPASS` releases the upstream session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_abandoned_after_getpass_releases_the_upstream_session() {
    for mode in [SingleConnect::Accept, SingleConnect::Decline] {
        let upstream = Upstream::start(mode).await;
        let daemon = Daemon::start(upstream.address(), Options::default()).await;
        let warm = ascii(mode == SingleConnect::Accept);
        run_traffic(daemon.port, warm, "warm")
            .await
            .assert_all_succeeded(warm.total());
        wait_until("warm-up upstream connections to drain", || {
            mode == SingleConnect::Accept || upstream.open_connections() == 0
        })
        .await;
        let baseline_fds = daemon.fd_count();
        let started = upstream.received(Kind::Authentication);

        for index in 0..8 {
            let client = proxy_client(daemon.port, index % 2 == 0).await.unwrap();
            let mut conversation = client.open_conversation().await.unwrap();
            let session_id = conversation.session_id().unwrap();
            let user = format!("{USER_PREFIX}abandon/{index}");
            let body = start(&user, TacacsAuthenticationType::TacPlusAuthenTypeAscii, &[])
                .to_bytes()
                .unwrap();
            let prompt = conversation
                .round_trip(request_packet(session_id, 1, body).unwrap())
                .await
                .unwrap();
            assert_eq!(
                AuthenticationReply::from_packet(&prompt).unwrap().status,
                TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass
            );
            // Dropping both ends the downstream connection without a CONTINUE.
            drop(conversation);
            client.close();
        }
        assert_eq!(upstream.received(Kind::Authentication), started + 8);
        if mode == SingleConnect::Decline {
            wait_until("abandoned upstream sessions to close", || upstream.open_connections() == 0)
                .await;
        } else {
            assert_eq!(upstream.open_connections(), 1, "the shared upstream connection closed");
        }
        daemon.wait_fds_at_most(baseline_fds + 2).await;

        let client = proxy_client(daemon.port, true).await.unwrap();
        let user = format!("{USER_PREFIX}after-abandon");
        let after = ascii_login(&client, &user, upstream::good_password()).await;
        assert!(succeeded(&after), "a login after abandoned logins failed in {mode:?}: {after:?}");
        client.stop_accepting_new_sessions().await;
        daemon.stop().await;
    }
}

/// Checks that FOLLOW and RESTART replies reach the client and end the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn follow_and_restart_replies_are_forwarded_unchanged() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(upstream.address(), Options::default()).await;
    for status in [AUTHENTICATION_FOLLOW, AUTHENTICATION_RESTART] {
        upstream.set_plan(once(Kind::Authentication, Fault::Status(status)));
        let user = format!("{USER_PREFIX}status/{status}");
        let reply = raw_authentication(daemon.port, &user).await.unwrap();
        assert_eq!(
            AuthenticationReply::status_from_packet(&reply),
            Some(status),
            "the proxy changed the reply status"
        );
        assert_eq!(server_msg(&reply), user, "the reply reached the wrong session");
        let next = single_request(daemon.port, Kind::Authentication, &format!("{user}/next")).await;
        assert!(succeeded(&next), "status {status:#x} broke the next request: {next:?}");
    }
    for kind in [Kind::Authorization, Kind::Accounting] {
        upstream.set_plan(once(kind, Fault::Status(0x21)));
        let followed = single_request(daemon.port, kind, &format!("{USER_PREFIX}follow")).await;
        assert!(
            matches!(
                followed,
                Outcome::Reply {
                    status: Status::Fail,
                    ..
                }
            ),
            "the {kind:?} FOLLOW reply did not reach the client: {followed:?}"
        );
        let next = single_request(daemon.port, kind, &format!("{USER_PREFIX}after-follow")).await;
        assert!(succeeded(&next), "a {kind:?} FOLLOW broke the next request: {next:?}");
    }
    assert_eq!(upstream.connections_accepted(), 1, "a valid status closed the shared connection");
    daemon.stop().await;
}

/// Checks that an unknown status reaches the client and does not disable the only server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_reply_status_is_forwarded_and_the_only_server_stays_usable() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(upstream.address(), Options::default()).await;
    upstream.set_plan(once(Kind::Authentication, Fault::Status(UNKNOWN_STATUS)));
    let user = format!("{USER_PREFIX}unknown");
    let reply = raw_authentication(daemon.port, &user).await.unwrap();
    assert_eq!(reply.body().first().copied(), Some(UNKNOWN_STATUS));
    for kind in [Kind::Authorization, Kind::Accounting] {
        upstream.set_plan(once(kind, Fault::Status(UNKNOWN_STATUS)));
        let failed = single_request(daemon.port, kind, &format!("{USER_PREFIX}unknown")).await;
        assert!(!succeeded(&failed), "an unknown {kind:?} status reported success: {failed:?}");
    }
    for kind in Kind::ALL {
        let next = single_request(daemon.port, kind, &format!("{USER_PREFIX}next")).await;
        assert!(succeeded(&next), "an unknown status disabled {kind:?}: {next:?}");
    }
    daemon.stop().await;
}

/// Checks that an unknown status moves only its operation to the backup server.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_reply_status_moves_only_its_operation_to_the_backup() {
    let primary = Upstream::start(SingleConnect::Accept).await;
    let backup = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(
        primary.address(),
        Options {
            policy: serde_json::json!({ "tacacs-proxy-failover-strategy": "deferred-failover" }),
            backup_servers: vec![backup.address()],
            ..Options::default()
        },
    )
    .await;
    primary.set_plan(once(Kind::Authorization, Fault::Status(UNKNOWN_STATUS)));
    let failed = single_request(daemon.port, Kind::Authorization, &format!("{USER_PREFIX}u")).await;
    assert!(!succeeded(&failed), "the unknown status reported success: {failed:?}");
    let next = single_request(daemon.port, Kind::Authorization, &format!("{USER_PREFIX}n")).await;
    assert!(succeeded(&next), "authorization did not recover on the backup: {next:?}");
    assert_eq!(backup.received(Kind::Authorization), 1, "authorization did not fail over");
    for kind in [Kind::Authentication, Kind::Accounting] {
        let other = single_request(daemon.port, kind, &format!("{USER_PREFIX}o")).await;
        assert!(succeeded(&other), "{kind:?} failed: {other:?}");
        assert_eq!(backup.received(kind), 0, "{kind:?} left the preferred server");
    }
    daemon.stop().await;
}

/// Runs `broken_upstream_case` with and without upstream single-connect.
async fn malformed_case(fault: Fault) {
    broken_upstream_case(fault, SingleConnect::Accept).await;
    broken_upstream_case(fault, SingleConnect::Decline).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_with_a_wrong_session_id_is_bounded_and_recovers() {
    malformed_case(Fault::WrongSession).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_with_a_wrong_sequence_number_is_bounded_and_recovers() {
    malformed_case(Fault::WrongSequence).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_with_an_oversized_length_is_bounded_and_recovers() {
    malformed_case(Fault::OversizedLength).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_with_an_invalid_header_is_bounded_and_recovers() {
    malformed_case(Fault::BadHeader).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_with_the_wrong_shared_secret_is_bounded_and_recovers() {
    malformed_case(Fault::BadKey).await;
}

/// Checks that a reply after its deadline does not reach another session.
///
/// The late reply arrives on the shared upstream connection after the proxy
/// abandoned its session. Other sessions on the same connection continue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn late_reply_on_a_shared_connection_is_discarded() {
    let upstream = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(
        upstream.address(),
        Options {
            policy: super::deadline_policy(1),
            ..Options::default()
        },
    )
    .await;
    let late = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let fired = Arc::clone(&late);
    let plan: Plan = Arc::new(move |request| {
        if request.user.ends_with("/late") {
            fired.store(true, std::sync::atomic::Ordering::SeqCst);
            Fault::Delay(Duration::from_millis(2500))
        } else {
            Fault::Delay(Duration::from_millis(20))
        }
    });
    upstream.set_plan(plan);
    let port = daemon.port;
    let abandoned = tokio::spawn(async move {
        single_request(port, Kind::Authorization, &format!("{USER_PREFIX}abandoned/late")).await
    });
    let traffic = Traffic {
        clients: 4,
        operations_per_client: 40,
        concurrency: 2,
        single_connect: true,
        kinds: mixed,
        ascii_authentication: true,
    };
    let tally = run_traffic(port, traffic, "late").await;
    tally.assert_all_succeeded(traffic.total());
    let abandoned = abandoned.await.unwrap();
    assert!(
        matches!(&abandoned, Outcome::Reply { status: Status::Error, server_msg } if !server_msg.starts_with(USER_PREFIX)),
        "the late request did not get a local ERROR at its deadline: {abandoned:?}"
    );
    assert!(late.load(std::sync::atomic::Ordering::SeqCst));
    daemon.stop().await;
}

fn server_config(servers: &[SocketAddr]) -> serde_json::Value {
    let servers: Vec<_> = servers
        .iter()
        .map(|address| {
            serde_json::json!({
                "name": format!("server-{}", address.port()),
                "server-type": "authentication authorization accounting",
                "address": address.ip().to_string(),
                "port": address.port(),
                "shared-secret": upstream::upstream_key(),
                "single-connection": true,
                "timeout": 5,
            })
        })
        .collect();
    serde_json::json!({ "ietf-system-tacacs-plus:tacacs-plus": { "server": servers } })
}

/// Waits until a request of every operation reaches `target`.
async fn wait_for_routing(port: u16, target: &Upstream, label: &str) {
    let started = Instant::now();
    for kind in Kind::ALL {
        let before = target.received(kind);
        let mut attempt = 0;
        loop {
            let user = format!("{USER_PREFIX}{label}/{kind:?}/{attempt}");
            let outcome = single_request(port, kind, &user).await;
            if succeeded(&outcome) && target.received(kind) > before {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "{kind:?} did not move to {label} within 15 seconds: {outcome:?}"
            );
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Checks that a configuration reload under traffic loses no request.
///
/// The reload replaces server A with server B, then restores A as the
/// preferred server. Each retired upstream connection must close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn configuration_reload_under_traffic_moves_servers_without_loss() {
    let first = Upstream::start(SingleConnect::Accept).await;
    let second = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(
        first.address(),
        Options {
            config: Some(server_config(&[first.address()])),
            ..Options::default()
        },
    )
    .await;
    let steady = Traffic {
        clients: 6,
        operations_per_client: 60,
        concurrency: 2,
        single_connect: true,
        kinds: mixed,
        ascii_authentication: true,
    };
    let port = daemon.port;
    let background = tokio::spawn(run_traffic(port, steady, "reload"));
    wait_until("traffic to reach the first server", || first.received_total() > 20).await;

    daemon.rewrite_config(&server_config(&[second.address()]));
    wait_for_routing(port, &second, "second").await;
    let first_count = first.received_total();
    wait_until("the retired first-server connection to close", || first.open_connections() == 0)
        .await;

    daemon.rewrite_config(&server_config(&[first.address(), second.address()]));
    wait_for_routing(port, &first, "first").await;
    wait_until("the backup connection to close after the reload", || {
        second.open_connections() == 0
    })
    .await;
    assert!(first.received_total() > first_count);

    let tally = background.await.unwrap();
    tally.assert_all_succeeded(steady.total());
    daemon.stop().await;
}

/// Checks that traffic returns to a restarted preferred server.
///
/// The backup carries the traffic while the preferred server is down. After
/// the preferred server returns on the same port, new requests use it again
/// and the proxy closes its backup connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restarted_preferred_server_takes_traffic_back_from_the_backup() {
    let primary = Upstream::start(SingleConnect::Accept).await;
    let primary_address = primary.address();
    let backup = Upstream::start(SingleConnect::Accept).await;
    let daemon = Daemon::start(
        primary_address,
        Options {
            connect_timeout_seconds: 1,
            policy: fast_recovery(serde_json::json!({
                "tacacs-proxy-failover-strategy": "ordered-safe-retry",
            })),
            backup_servers: vec![backup.address()],
            ..Options::default()
        },
    )
    .await;
    await_recovery(daemon.port).await;
    assert_eq!(backup.received_total(), 0);

    drop(primary);
    wait_for_routing(daemon.port, &backup, "backup").await;
    assert_eq!(backup.connections_accepted(), 1, "operations opened separate backup connections");

    let restarted = Upstream::start_on(SingleConnect::Accept, primary_address).await;
    wait_for_routing(daemon.port, &restarted, "restarted").await;
    wait_until("the backup connection to close", || backup.open_connections() == 0).await;
    let traffic = super::recovery(true);
    let before = backup.received_total();
    run_traffic(daemon.port, traffic, "returned")
        .await
        .assert_all_succeeded(traffic.total());
    assert_eq!(backup.received_total(), before, "traffic stayed on the backup");
    daemon.stop().await;
}

/// Checks bounded local errors during a full outage and recovery afterward.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_outage_gives_bounded_local_errors_and_recovers() {
    let primary = Upstream::start(SingleConnect::Accept).await;
    let backup = Upstream::start(SingleConnect::Accept).await;
    let (primary_address, backup_address) = (primary.address(), backup.address());
    let mut daemon = Daemon::start(
        primary_address,
        Options {
            connect_timeout_seconds: 1,
            policy: short_deadlines(),
            backup_servers: vec![backup_address],
            ..Options::default()
        },
    )
    .await;
    await_recovery(daemon.port).await;
    drop(primary);
    drop(backup);

    let mut outage = JoinSet::new();
    for index in 0..12 {
        let port = daemon.port;
        outage.spawn(async move {
            let kind = mixed(index);
            let started = Instant::now();
            let outcome = single_request(port, kind, &format!("{USER_PREFIX}down/{index}")).await;
            (kind, started.elapsed(), outcome)
        });
    }
    while let Some(result) = outage.join_next().await {
        let (kind, elapsed, outcome) = result.unwrap();
        assert!(
            matches!(&outcome, Outcome::Reply { status: Status::Error, server_msg } if !server_msg.starts_with(USER_PREFIX)),
            "{kind:?} during the outage did not get a local ERROR: {outcome:?}"
        );
        assert!(elapsed < Duration::from_secs(5), "{kind:?} waited {elapsed:?} during the outage");
    }
    daemon.assert_running();

    let backup = Upstream::start_on(SingleConnect::Accept, backup_address).await;
    wait_for_routing(daemon.port, &backup, "backup").await;
    let primary = Upstream::start_on(SingleConnect::Accept, primary_address).await;
    wait_for_routing(daemon.port, &primary, "primary").await;
    assert_recovers(daemon.port, true).await;
    daemon.stop().await;
}
