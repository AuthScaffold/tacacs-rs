//! Schema-free operational counters owned by one prepared endpoint identity.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

mod diagnostics;
pub use diagnostics::{
    ConnectionDetails, DiagnosticsSnapshot, DisconnectReason, OperationStatistics, TlsDetails,
};
pub(crate) use diagnostics::{CertificateVerificationCode, ReplyWait};
use diagnostics::authentication_outcome;

/// A coherent snapshot of counters for one prepared endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatisticsSnapshot {
    /// Process-local identity of this counter lifetime, independent of routing generations.
    pub epoch: u64,
    /// Time this counter lifetime began. Counters are never reset in place.
    pub discontinuity_time: SystemTime,
    pub connection_opens: u64,
    /// Completed transport establishments, including TLS validation when enabled.
    pub connection_successes: u64,
    pub connection_closes: u64,
    pub connection_aborts: u64,
    pub connection_failures: u64,
    pub connection_timeouts: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub errors_received: u64,
    pub sessions: u64,
    pub cert_errors: u64,
    /// Bounded operational details and explicitly measured gauges.
    pub diagnostics: DiagnosticsSnapshot,
}

/// Shared counters for one immutable prepared endpoint and its connections.
#[derive(Debug, Clone)]
pub struct ServerCounters(
    Arc<Mutex<StatisticsSnapshot>>,
    Option<Arc<diagnostics::ConnectionScope>>,
);

impl Default for ServerCounters {
    fn default() -> Self {
        static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
        Self(
            Arc::new(Mutex::new(StatisticsSnapshot {
                epoch: NEXT_EPOCH.fetch_add(1, Ordering::Relaxed),
                discontinuity_time: SystemTime::now(),
                connection_opens: 0,
                connection_successes: 0,
                connection_closes: 0,
                connection_aborts: 0,
                connection_failures: 0,
                connection_timeouts: 0,
                messages_sent: 0,
                messages_received: 0,
                errors_received: 0,
                sessions: 0,
                cert_errors: 0,
                diagnostics: DiagnosticsSnapshot::default(),
            })),
            None,
        )
    }
}

impl ServerCounters {
    /// Reads all counters and their discontinuity identity under one short lock.
    #[must_use]
    pub fn snapshot(&self) -> StatisticsSnapshot {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn record(&self, event: CounterEvent) {
        let mut counters = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let counter = match event {
            CounterEvent::ConnectionOpen => {
                counters.diagnostics.connecting += 1;
                counters.diagnostics.last_attempt = Some(SystemTime::now());
                &mut counters.connection_opens
            }
            CounterEvent::ConnectionClose => &mut counters.connection_closes,
            CounterEvent::ConnectionAbort => &mut counters.connection_aborts,
            CounterEvent::MessageSent => {
                counters.diagnostics.packets_since_reset_sent = counters
                    .diagnostics
                    .packets_since_reset_sent
                    .wrapping_add(1);
                &mut counters.messages_sent
            }
            CounterEvent::MessageReceived => {
                counters.diagnostics.packets_since_reset_received = counters
                    .diagnostics
                    .packets_since_reset_received
                    .wrapping_add(1);
                &mut counters.messages_received
            }
            CounterEvent::ErrorReceived => &mut counters.errors_received,
            CounterEvent::SessionCompleted => &mut counters.sessions,
        };
        *counter = counter.wrapping_add(1);
    }
}

#[derive(Clone, Copy)]
pub(crate) enum CounterEvent {
    ConnectionOpen,
    ConnectionClose,
    ConnectionAbort,
    MessageSent,
    MessageReceived,
    ErrorReceived,
    SessionCompleted,
}

pub(crate) fn reply_classification(
    packet: &tacacsrs_protocol::packet::Packet,
) -> Option<(bool, bool)> {
    use tacacsrs_protocol::enumerations::{
        TacacsType, TacacsAuthenticationStatus, TacacsAuthorizationStatus, TacacsAccountingStatus,
    };
    use tacacsrs_protocol::packet::PacketTrait;
    if !packet.header().seq_no.is_multiple_of(2) {
        return None;
    }
    match packet.header().tacacs_type {
        TacacsType::TacPlusAuthentication => {
            let reply = tacacsrs_protocol::authentication::reply::AuthenticationReply::from_bytes(
                packet.body(),
            )
            .ok()?;
            Some((
                reply.status == TacacsAuthenticationStatus::TacPlusAuthenStatusError,
                !matches!(
                    reply.status,
                    TacacsAuthenticationStatus::TacPlusAuthenStatusGetdata
                        | TacacsAuthenticationStatus::TacPlusAuthenStatusGetuser
                        | TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass
                ),
            ))
        }
        TacacsType::TacPlusAuthorisation => {
            let reply = tacacsrs_protocol::authorization::reply::AuthorizationReply::from_bytes(
                packet.body(),
            )
            .ok()?;
            Some((reply.status == TacacsAuthorizationStatus::TacPlusError, true))
        }
        TacacsType::TacPlusAccounting => {
            let reply =
                tacacsrs_protocol::accounting::reply::AccountingReply::from_bytes(packet.body())
                    .ok()?;
            Some((reply.status == TacacsAccountingStatus::TacPlusAcctStatusError, true))
        }
    }
}

pub(crate) struct ConnectionAttempt {
    counters: ServerCounters,
    finished: bool,
    connected: bool,
    tls: bool,
    peer: Option<std::net::SocketAddr>,
    deadline: Option<crate::RequestDeadline>,
}

impl ConnectionAttempt {
    pub(crate) fn new(counters: ServerCounters) -> Self {
        counters.record(CounterEvent::ConnectionOpen);
        Self {
            counters,
            finished: false,
            connected: false,
            tls: false,
            peer: None,
            deadline: None,
        }
    }
    pub(crate) fn connected(&mut self) {
        self.connected = true;
    }
    pub(crate) fn peer(&mut self, peer: Option<std::net::SocketAddr>) {
        self.peer = peer;
    }
    pub(crate) fn with_deadline(mut self, deadline: Option<crate::RequestDeadline>) -> Self {
        self.deadline = deadline;
        self
    }
    pub(crate) fn peer_address(&self) -> Option<std::net::SocketAddr> {
        self.peer
    }
    pub(crate) fn handshake(&mut self) {
        self.tls = true;
        let mut snapshot = self
            .counters
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        snapshot.diagnostics.handshake_attempts =
            snapshot.diagnostics.handshake_attempts.wrapping_add(1);
    }
    pub(crate) fn failed_error(&mut self, error: &anyhow::Error) {
        if self.tls && !self.finished {
            self.counters.tls_failure(error);
        }
        self.failed(error.is::<tokio::time::error::Elapsed>(), error.is::<CertificateFailure>());
    }
    pub(crate) fn succeeded(&mut self) {
        if !self.finished {
            let mut counters = self
                .counters
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            counters.connection_successes = counters.connection_successes.wrapping_add(1);
            counters.diagnostics.connecting = counters.diagnostics.connecting.saturating_sub(1);
            counters.diagnostics.last_success = Some(SystemTime::now());
            if self.tls {
                counters.diagnostics.handshake_successes =
                    counters.diagnostics.handshake_successes.wrapping_add(1);
            }
            self.finished = true;
        }
    }
    pub(crate) fn failed(&mut self, timeout: bool, certificate: bool) {
        if !self.finished {
            let mut counters = self
                .counters
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            counters.connection_failures = counters.connection_failures.wrapping_add(1);
            counters.diagnostics.connecting = counters.diagnostics.connecting.saturating_sub(1);
            if self.tls {
                counters.diagnostics.handshake_failures =
                    counters.diagnostics.handshake_failures.wrapping_add(1);
            }
            if self.connected {
                counters.connection_aborts = counters.connection_aborts.wrapping_add(1);
            }
            if timeout {
                counters.connection_timeouts = counters.connection_timeouts.wrapping_add(1);
            }
            if certificate {
                counters.cert_errors = counters.cert_errors.wrapping_add(1);
            }
            self.finished = true;
        }
    }
}

impl Drop for ConnectionAttempt {
    fn drop(&mut self) {
        self.failed(
            self.deadline
                .is_some_and(|deadline| deadline.check().is_err()),
            false,
        );
    }
}

#[derive(Debug)]
pub(crate) struct CertificateFailure;
impl std::fmt::Display for CertificateFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TLS certificate verification failed")
    }
}
impl std::error::Error for CertificateFailure {}

pub(crate) struct ConnectionRecord {
    counters: ServerCounters,
    closed: std::sync::atomic::AtomicBool,
}

impl ConnectionRecord {
    pub(crate) fn new(counters: ServerCounters) -> Self {
        Self {
            counters,
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub(crate) fn close(&self, graceful: bool) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.counters.disconnected(graceful);
            self.counters.record(if graceful {
                CounterEvent::ConnectionClose
            } else {
                CounterEvent::ConnectionAbort
            });
        }
    }
}

impl Drop for ConnectionRecord {
    fn drop(&mut self) {
        self.close(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_attempt_results_are_terminal() {
        let counters = ServerCounters::default();
        let mut successful = ConnectionAttempt::new(counters.clone());
        successful.succeeded();
        successful.succeeded();
        successful.failed(true, true);
        drop(successful);
        let mut failed = ConnectionAttempt::new(counters.clone());
        failed.failed(false, false);
        failed.succeeded();
        drop(failed);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.connection_opens, 2);
        assert_eq!(snapshot.connection_successes, 1);
        assert_eq!(snapshot.connection_failures, 1);
        assert_eq!(snapshot.connection_timeouts, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn setup_cancellation_distinguishes_deadline_expiry() {
        let counters = ServerCounters::default();
        let deadline = crate::RequestDeadline::after(std::time::Duration::from_secs(1)).unwrap();
        let mut expired = ConnectionAttempt::new(counters.clone()).with_deadline(Some(deadline));
        expired.connected();
        expired.handshake();
        let cancelled = ConnectionAttempt::new(counters.clone());
        drop(cancelled);
        tokio::time::advance(std::time::Duration::from_secs(1)).await;
        drop(expired);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.connection_failures, 2);
        assert_eq!(snapshot.connection_timeouts, 1);
        assert_eq!(snapshot.diagnostics.handshake_failures, 1);
        assert_eq!(snapshot.diagnostics.connecting, 0);
    }

    #[test]
    fn timeout_and_connection_records_are_exactly_once() {
        let counters = ServerCounters::default();
        let mut attempt = ConnectionAttempt::new(counters.clone());
        attempt.failed(true, false);
        attempt.failed(true, true);
        drop(attempt);
        let record = ConnectionRecord::new(counters.clone());
        record.close(true);
        record.close(false);
        drop(record);
        drop(ConnectionRecord::new(counters.clone()));
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.connection_failures, 1);
        assert_eq!(snapshot.connection_timeouts, 1);
        assert_eq!(snapshot.cert_errors, 0);
        assert_eq!(snapshot.connection_closes, 1);
        assert_eq!(snapshot.connection_aborts, 1);
    }

    #[test]
    fn denial_is_a_terminal_reply_not_a_protocol_error() {
        use tacacsrs_protocol::packet::Packet;
        use tacacsrs_protocol::body::TacacsBodyTrait;
        use tacacsrs_protocol::enumerations::{TacacsType, TacacsAuthenticationStatus};
        let reply = tacacsrs_protocol::authentication::reply::AuthenticationReply {
            status: TacacsAuthenticationStatus::TacPlusAuthenStatusFail,
            flags: tacacsrs_protocol::enumerations::TacacsAuthenticationReplyFlags::empty(),
            server_msg: String::new(),
            data: Vec::new(),
        };
        let body = reply.to_bytes().unwrap();
        let header = tacacsrs_protocol::header::Header {
            major_version: tacacsrs_protocol::enumerations::TacacsMajorVersion::TacacsPlusMajor1,
            minor_version:
                tacacsrs_protocol::enumerations::TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAuthentication,
            seq_no: 2,
            flags: tacacsrs_protocol::enumerations::TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id: 1,
            length: u32::try_from(body.len()).unwrap(),
        };
        assert_eq!(reply_classification(&Packet::new(header, body).unwrap()), Some((false, true)));
    }

    #[tokio::test]
    async fn cancelled_tls_setup_records_one_failure_and_abort() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = crate::PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            false,
            None,
            crate::ConnectOptions::default(),
        )
        .with_certificate_tls("localhost", None, crate::CertificateTrust::Platform, None)
        .unwrap();
        let counters = endpoint.counters();
        let mut connecting = Box::pin(crate::establish::establish_stream(&endpoint));
        let (mut peer, _) = tokio::select! {
            result = &mut connecting => panic!("setup ended before cancellation: {}", result.is_ok()),
            peer = listener.accept() => peer.unwrap(),
        };
        let mut hello = [0; 4096];
        tokio::select! {
            result = &mut connecting => panic!("setup ended before TLS response: {}", result.is_ok()),
            length = peer.read(&mut hello) => assert!(length.unwrap() > 0),
        }
        drop(connecting);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.connection_opens, 1);
        assert_eq!(snapshot.connection_failures, 1);
        assert_eq!(snapshot.connection_aborts, 1);
        assert_eq!(snapshot.connection_closes, 0);
        assert_eq!(snapshot.cert_errors, 0);
    }

    #[tokio::test]
    async fn certificate_identity_failure_is_counted_as_a_failure_subset() {
        use openssl::{
            ssl::{SslContext, SslMethod, Ssl},
            x509::X509,
            pkey::PKey,
        };
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../lde/containers/config/certificates");
        let mut context = SslContext::builder(SslMethod::tls_server()).unwrap();
        context
            .set_certificate(
                X509::from_pem(&std::fs::read(fixtures.join("server.crt")).unwrap())
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();
        context
            .set_private_key(
                PKey::private_key_from_pem(&std::fs::read(fixtures.join("server.key")).unwrap())
                    .unwrap()
                    .as_ref(),
            )
            .unwrap();
        let context = context.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = X509::from_pem(&std::fs::read(fixtures.join("ca.crt")).unwrap())
            .unwrap()
            .to_der()
            .unwrap();
        let endpoint = crate::PreparedEndpoint::tcp(
            listener.local_addr().unwrap().to_string(),
            false,
            None,
            crate::ConnectOptions::default(),
        )
        .with_certificate_tls(
            "wrong.example.test",
            None,
            crate::CertificateTrust::Certificates {
                authorities: &[&authority],
                end_entities: &[],
            },
            None,
        )
        .unwrap();
        let counters = endpoint.counters();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream =
                tokio_openssl::SslStream::new(Ssl::new(&context).unwrap(), stream).unwrap();
            assert!(std::pin::Pin::new(&mut stream).accept().await.is_err());
        });
        assert!(crate::establish::establish_stream(&endpoint).await.is_err());
        peer.await.unwrap();
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.connection_failures, 1);
        assert_eq!(snapshot.cert_errors, 1);
        assert_eq!(snapshot.connection_aborts, 1);
    }

    #[test]
    fn clones_share_counters_but_new_owners_have_a_new_discontinuity() {
        let counters = ServerCounters::default();
        let clone = counters.clone();
        for event in [
            CounterEvent::ConnectionOpen,
            CounterEvent::ConnectionClose,
            CounterEvent::ConnectionAbort,
            CounterEvent::MessageSent,
            CounterEvent::MessageReceived,
            CounterEvent::ErrorReceived,
            CounterEvent::SessionCompleted,
        ] {
            clone.record(event);
        }
        ConnectionAttempt::new(counters.clone()).failed(true, true);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot, clone.snapshot());
        assert_eq!(snapshot.sessions, 1);
        assert_eq!(snapshot.cert_errors, 1);
        assert_ne!(snapshot.epoch, ServerCounters::default().snapshot().epoch);
        counters.0.lock().unwrap().messages_sent = u64::MAX;
        counters.record(CounterEvent::MessageSent);
        assert_eq!(counters.snapshot().messages_sent, 0);
        assert_eq!(counters.snapshot().discontinuity_time, snapshot.discontinuity_time);
    }
}
