//! Read-only connection and operation telemetry. No packet contents are retained.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use tacacsrs_protocol::enumerations::{
    TacacsType, TacacsAuthenticationStatus, TacacsAuthorizationStatus, TacacsAccountingStatus,
};
use tacacsrs_protocol::packet::{Packet, PacketTrait};

use super::ServerCounters;

const MAX_CONNECTION_DETAILS: usize = 32;

/// Negotiated public TLS parameters. FIPS state is unknown unless the backend reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDetails {
    pub version: String,
    pub cipher: Option<String>,
    pub fips_enabled: Option<bool>,
}

impl TlsDetails {
    pub(crate) fn from_ssl(ssl: &openssl::ssl::SslRef) -> Self {
        Self {
            version: ssl.version_str().to_owned(),
            cipher: ssl.current_cipher().map(|cipher| cipher.name().to_owned()),
            fips_enabled: None,
        }
    }
}

/// A connection's public transport state, not its credentials or payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDetails {
    pub id: u64,
    pub peer: Option<SocketAddr>,
    pub established_at: SystemTime,
    pub single_connect: Option<bool>,
    pub tls: Option<TlsDetails>,
}

/// Why an established connection closed. Cleanup does not overwrite the first cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DisconnectReason {
    Graceful = 1,
    Peer = 2,
    MalformedPacket = 3,
    NoResponse = 4,
    WriteError = 5,
    ReadError = 6,
    CredentialExpired = 7,
    Other = 8,
}

impl DisconnectReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Graceful => "graceful",
            Self::Peer => "peer",
            Self::MalformedPacket => "malformed-packet",
            Self::NoResponse => "no-response",
            Self::WriteError => "write-error",
            Self::ReadError => "read-error",
            Self::CredentialExpired => "credential-expired",
            Self::Other => "other",
        }
    }

    fn from_code(value: u8) -> Self {
        match value {
            1 => Self::Graceful,
            2 => Self::Peer,
            3 => Self::MalformedPacket,
            4 => Self::NoResponse,
            5 => Self::WriteError,
            6 => Self::ReadError,
            7 => Self::CredentialExpired,
            _ => Self::Other,
        }
    }
}

/// Validated terminal server replies in completion order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperationStatistics {
    pub requests: u64,
    pub passed: u64,
    pub denied: u64,
    pub errors: u64,
    pub consecutive_failures: u64,
}

impl OperationStatistics {
    fn reply(&mut self, passed: bool, denied: bool) {
        if passed {
            self.passed = self.passed.wrapping_add(1);
            self.consecutive_failures = 0;
        } else {
            if denied {
                self.denied = self.denied.wrapping_add(1);
            } else {
                self.errors = self.errors.wrapping_add(1);
            }
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        }
    }
}

/// Additional measured statistics. Unsupported watchdog and idle policies are not fabricated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiagnosticsSnapshot {
    pub connecting: u64,
    pub connected: u64,
    pub expected_replies: u64,
    pub last_attempt: Option<SystemTime>,
    pub last_success: Option<SystemTime>,
    pub last_disconnect: Option<SystemTime>,
    pub last_disconnect_reason: Option<DisconnectReason>,
    pub connections: Vec<ConnectionDetails>,
    pub connections_omitted: u64,
    pub last_connection: Option<ConnectionDetails>,
    pub handshake_attempts: u64,
    pub handshake_successes: u64,
    pub handshake_failures: u64,
    pub tls_read_errors: u64,
    pub tls_write_errors: u64,
    pub tls_certificate_errors: u64,
    pub tls_revoked_certificates: u64,
    pub tls_untrusted_ca: u64,
    pub tls_expired_certificates: u64,
    pub tls_protocol_mismatches: u64,
    pub tls_cipher_mismatches: u64,
    pub tls_other_errors: u64,
    pub read_errors: u64,
    pub write_errors: u64,
    pub receive_timeouts: u64,
    pub send_timeouts: u64,
    pub resets: u64,
    pub peer_disconnects: u64,
    pub malformed_disconnects: u64,
    pub no_response_disconnects: u64,
    pub credential_expiry_disconnects: u64,
    pub other_disconnects: u64,
    pub packets_since_reset_sent: u64,
    pub packets_since_reset_received: u64,
    pub watchdog_preflights: u64,
    pub watchdog_successes: u64,
    pub watchdog_failures: u64,
    pub watchdog_preflights_since_reset: u64,
    pub authentication: OperationStatistics,
    pub authorization: OperationStatistics,
    pub accounting: OperationStatistics,
}

#[derive(Debug)]
pub(super) struct ConnectionScope {
    details: ConnectionDetails,
    reason: AtomicU8,
}

impl ServerCounters {
    pub(crate) fn watchdog_preflight(&self) -> WatchdogPreflight {
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        snapshot.diagnostics.watchdog_preflights =
            snapshot.diagnostics.watchdog_preflights.wrapping_add(1);
        snapshot.diagnostics.watchdog_preflights_since_reset = snapshot
            .diagnostics
            .watchdog_preflights_since_reset
            .wrapping_add(1);
        WatchdogPreflight {
            counters: self.clone(),
            succeeded: false,
        }
    }

    pub(crate) fn for_connection(&self, peer: Option<SocketAddr>, tls: Option<TlsDetails>) -> Self {
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let diagnostics = &mut snapshot.diagnostics;
        let details = ConnectionDetails {
            id: snapshot_id(),
            peer,
            tls,
            established_at: SystemTime::now(),
            single_connect: None,
        };
        diagnostics.connected += 1;
        diagnostics.last_connection = Some(details.clone());
        if diagnostics.connections.len() < MAX_CONNECTION_DETAILS {
            diagnostics.connections.push(details.clone());
        } else {
            diagnostics.connections_omitted += 1;
        }
        Self(
            Arc::clone(&self.0),
            Some(Arc::new(ConnectionScope {
                details,
                reason: AtomicU8::new(0),
            })),
        )
    }

    pub(crate) fn disconnect_reason(&self, reason: DisconnectReason) {
        if let Some(scope) = &self.1 {
            let _ =
                scope
                    .reason
                    .compare_exchange(0, reason as u8, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    pub(super) fn disconnected(&self, graceful: bool) {
        let Some(scope) = &self.1 else {
            return;
        };
        self.disconnect_reason(if graceful {
            DisconnectReason::Graceful
        } else {
            DisconnectReason::Other
        });
        let reason = DisconnectReason::from_code(scope.reason.load(Ordering::Acquire));
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let diagnostics = &mut snapshot.diagnostics;
        diagnostics.connected = diagnostics.connected.saturating_sub(1);
        let length = diagnostics.connections.len();
        diagnostics
            .connections
            .retain(|connection| connection.id != scope.details.id);
        if diagnostics.connections.len() == length {
            diagnostics.connections_omitted = diagnostics.connections_omitted.saturating_sub(1);
        }
        diagnostics.last_disconnect = Some(SystemTime::now());
        diagnostics.last_disconnect_reason = Some(reason);
        if reason != DisconnectReason::Graceful {
            diagnostics.resets = diagnostics.resets.wrapping_add(1);
            diagnostics.packets_since_reset_sent = 0;
            diagnostics.packets_since_reset_received = 0;
            diagnostics.watchdog_preflights_since_reset = 0;
            let counter = match reason {
                DisconnectReason::Peer => &mut diagnostics.peer_disconnects,
                DisconnectReason::MalformedPacket => &mut diagnostics.malformed_disconnects,
                DisconnectReason::NoResponse => &mut diagnostics.no_response_disconnects,
                DisconnectReason::CredentialExpired => {
                    &mut diagnostics.credential_expiry_disconnects
                }
                _ => &mut diagnostics.other_disconnects,
            };
            *counter = counter.wrapping_add(1);
        }
    }

    pub(crate) fn single_connect(&self, supported: bool) {
        let Some(scope) = &self.1 else {
            return;
        };
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let diagnostics = &mut snapshot.diagnostics;
        for connection in &mut diagnostics.connections {
            if connection.id == scope.details.id {
                connection.single_connect = Some(supported);
            }
        }
        if let Some(connection) = &mut diagnostics.last_connection {
            if connection.id == scope.details.id {
                connection.single_connect = Some(supported);
            }
        }
    }

    pub(crate) fn io_error(&self, error: &std::io::Error, writing: bool) {
        let reason = match error.kind() {
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::UnexpectedEof => {
                DisconnectReason::Peer
            }
            std::io::ErrorKind::TimedOut => DisconnectReason::NoResponse,
            _ if writing => DisconnectReason::WriteError,
            _ => DisconnectReason::ReadError,
        };
        if let Some(scope) = &self.1 {
            if scope
                .reason
                .compare_exchange(0, reason as u8, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return;
            }
        }
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let diagnostics = &mut snapshot.diagnostics;
        let count = if writing {
            &mut diagnostics.write_errors
        } else {
            &mut diagnostics.read_errors
        };
        *count = count.wrapping_add(1);
        if self
            .1
            .as_ref()
            .is_some_and(|scope| scope.details.tls.is_some())
        {
            let count = if writing {
                &mut diagnostics.tls_write_errors
            } else {
                &mut diagnostics.tls_read_errors
            };
            *count = count.wrapping_add(1);
        }
        if error.kind() == std::io::ErrorKind::TimedOut {
            let count = if writing {
                &mut diagnostics.send_timeouts
            } else {
                &mut diagnostics.receive_timeouts
            };
            *count = count.wrapping_add(1);
        }
    }

    pub(crate) fn awaiting_reply(&self, packet: &Packet) -> ReplyWait {
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let diagnostics = &mut snapshot.diagnostics;
        diagnostics.expected_replies += 1;
        if packet.header().seq_no == 1 {
            let operation = match packet.header().tacacs_type {
                TacacsType::TacPlusAuthentication => &mut diagnostics.authentication,
                TacacsType::TacPlusAuthorisation => &mut diagnostics.authorization,
                TacacsType::TacPlusAccounting => &mut diagnostics.accounting,
            };
            operation.requests = operation.requests.wrapping_add(1);
        }
        ReplyWait(self.clone())
    }

    pub(crate) fn terminal_reply(&self, packet: &Packet) {
        let result = match packet.header().tacacs_type {
            TacacsType::TacPlusAuthentication => crate::statistics::authentication_outcome(packet),
            TacacsType::TacPlusAuthorisation => {
                tacacsrs_protocol::authorization::reply::AuthorizationReply::from_bytes(
                    packet.body(),
                )
                .ok()
                .map(|reply| {
                    (
                        matches!(
                            reply.status,
                            TacacsAuthorizationStatus::TacPlusPassAdd
                                | TacacsAuthorizationStatus::TacPlusPassRepl
                        ),
                        reply.status == TacacsAuthorizationStatus::TacPlusFail,
                    )
                })
            }
            TacacsType::TacPlusAccounting => {
                tacacsrs_protocol::accounting::reply::AccountingReply::from_bytes(packet.body())
                    .ok()
                    .map(|reply| {
                        (reply.status == TacacsAccountingStatus::TacPlusAcctStatusSuccess, false)
                    })
            }
        };
        let Some((passed, denied)) = result else {
            return;
        };
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let diagnostics = &mut snapshot.diagnostics;
        let operation = match packet.header().tacacs_type {
            TacacsType::TacPlusAuthentication => &mut diagnostics.authentication,
            TacacsType::TacPlusAuthorisation => &mut diagnostics.authorization,
            TacacsType::TacPlusAccounting => &mut diagnostics.accounting,
        };
        operation.reply(passed, denied);
    }

    pub(crate) fn request_timeout(&self) {
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        snapshot.diagnostics.receive_timeouts =
            snapshot.diagnostics.receive_timeouts.wrapping_add(1);
    }

    pub(crate) fn tls_failure(&self, error: &anyhow::Error) {
        let category = error
            .downcast_ref::<CertificateVerificationCode>()
            .map(|code| match code.0 {
                openssl_sys::X509_V_ERR_CERT_REVOKED => TlsFailure::Revoked,
                openssl_sys::X509_V_ERR_CERT_HAS_EXPIRED
                | openssl_sys::X509_V_ERR_CERT_NOT_YET_VALID => TlsFailure::Expired,
                openssl_sys::X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
                | openssl_sys::X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
                | openssl_sys::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
                | openssl_sys::X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN => TlsFailure::Untrusted,
                _ => TlsFailure::Certificate,
            })
            .or_else(|| {
                error
                    .chain()
                    .find_map(|source| source.downcast_ref::<openssl::error::ErrorStack>())
                    .and_then(|stack| {
                        stack.errors().iter().find_map(|error| {
                            if error.library_code() != OPENSSL_SSL_LIBRARY {
                                return None;
                            }
                            match error.reason_code() {
                                SSL_UNSUPPORTED_PROTOCOL
                                | SSL_WRONG_VERSION
                                | SSL_VERSION_TOO_HIGH
                                | SSL_VERSION_TOO_LOW
                                | SSL_ALERT_PROTOCOL_VERSION => Some(TlsFailure::Protocol),
                                SSL_NO_CIPHERS | SSL_NO_SHARED_CIPHER => Some(TlsFailure::Cipher),
                                _ => None,
                            }
                        })
                    })
            })
            .unwrap_or(if error.is::<super::CertificateFailure>() {
                TlsFailure::Certificate
            } else {
                TlsFailure::Other
            });
        let mut snapshot = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let diagnostics = &mut snapshot.diagnostics;
        if matches!(
            category,
            TlsFailure::Certificate
                | TlsFailure::Revoked
                | TlsFailure::Expired
                | TlsFailure::Untrusted
        ) {
            diagnostics.tls_certificate_errors = diagnostics.tls_certificate_errors.wrapping_add(1);
        }
        let counter = match category {
            TlsFailure::Revoked => &mut diagnostics.tls_revoked_certificates,
            TlsFailure::Expired => &mut diagnostics.tls_expired_certificates,
            TlsFailure::Untrusted => &mut diagnostics.tls_untrusted_ca,
            TlsFailure::Protocol => &mut diagnostics.tls_protocol_mismatches,
            TlsFailure::Cipher => &mut diagnostics.tls_cipher_mismatches,
            TlsFailure::Other => &mut diagnostics.tls_other_errors,
            TlsFailure::Certificate => return,
        };
        *counter = counter.wrapping_add(1);
    }
}

/// OpenSSL's stable library and reason identifiers from err.h and sslerr.h.
const OPENSSL_SSL_LIBRARY: i32 = 20;
const SSL_NO_CIPHERS: i32 = 181;
const SSL_NO_SHARED_CIPHER: i32 = 193;
const SSL_UNSUPPORTED_PROTOCOL: i32 = 258;
const SSL_WRONG_VERSION: i32 = 267;
const SSL_VERSION_TOO_HIGH: i32 = 166;
const SSL_VERSION_TOO_LOW: i32 = 396;
const SSL_ALERT_PROTOCOL_VERSION: i32 = 1070;

enum TlsFailure {
    Certificate,
    Revoked,
    Expired,
    Untrusted,
    Protocol,
    Cipher,
    Other,
}

#[derive(Debug)]
pub(crate) struct CertificateVerificationCode(pub(crate) i32);
impl std::fmt::Display for CertificateVerificationCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Certificate verification code {}", self.0)
    }
}
impl std::error::Error for CertificateVerificationCode {}

fn snapshot_id() -> u64 {
    static NEXT_CONNECTION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed)
}

pub(crate) struct ReplyWait(ServerCounters);

pub(crate) struct WatchdogPreflight {
    counters: ServerCounters,
    pub(crate) succeeded: bool,
}

impl Drop for WatchdogPreflight {
    fn drop(&mut self) {
        let mut snapshot = self
            .counters
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let counter = if self.succeeded {
            &mut snapshot.diagnostics.watchdog_successes
        } else {
            &mut snapshot.diagnostics.watchdog_failures
        };
        *counter = counter.wrapping_add(1);
    }
}

impl Drop for ReplyWait {
    fn drop(&mut self) {
        let mut snapshot = self
            .0
             .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        snapshot.diagnostics.expected_replies =
            snapshot.diagnostics.expected_replies.saturating_sub(1);
    }
}

pub(super) fn authentication_outcome(packet: &Packet) -> Option<(bool, bool)> {
    tacacsrs_protocol::authentication::reply::AuthenticationReply::from_bytes(packet.body())
        .ok()
        .map(|reply| {
            (
                reply.status == TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
                reply.status == TacacsAuthenticationStatus::TacPlusAuthenStatusFail,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::statistics::ConnectionRecord;

    #[test]
    fn connection_details_are_bounded_and_close_once() {
        let counters = ServerCounters::default();
        let records = (0..40)
            .map(|_| {
                let connected = counters.for_connection(None, None);
                connected.disconnect_reason(DisconnectReason::MalformedPacket);
                connected.disconnect_reason(DisconnectReason::Other);
                ConnectionRecord::new(connected)
            })
            .collect::<Vec<_>>();
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.diagnostics.connected, 40);
        assert_eq!(snapshot.diagnostics.connections.len(), 32);
        assert_eq!(snapshot.diagnostics.connections_omitted, 8);
        for record in &records {
            record.close(false);
            record.close(false);
        }
        drop(records);
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.diagnostics.connected, 0);
        assert_eq!(snapshot.diagnostics.connections_omitted, 0);
        assert_eq!(snapshot.diagnostics.malformed_disconnects, 40);
        assert_eq!(snapshot.diagnostics.other_disconnects, 0);
    }

    #[test]
    fn reply_wait_drop_clears_gauge_without_a_reply() {
        let counters = ServerCounters::default();
        let packet = Packet::new(
            tacacsrs_protocol::header::Header {
                major_version:
                    tacacsrs_protocol::enumerations::TacacsMajorVersion::TacacsPlusMajor1,
                minor_version:
                    tacacsrs_protocol::enumerations::TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAuthentication,
                seq_no: 1,
                flags: tacacsrs_protocol::enumerations::TacacsFlags::empty(),
                session_id: 1,
                length: 0,
            },
            Vec::new(),
        )
        .unwrap();
        let waiting = counters.awaiting_reply(&packet);
        assert_eq!(counters.snapshot().diagnostics.expected_replies, 1);
        drop(waiting);
        assert_eq!(counters.snapshot().diagnostics.expected_replies, 0);
        assert_eq!(counters.snapshot().diagnostics.authentication.requests, 1);
    }

    #[test]
    fn denial_streaks_reset_on_pass_without_changing_transport_failures() {
        let mut outcomes = OperationStatistics::default();
        outcomes.reply(false, true);
        outcomes.reply(false, false);
        assert_eq!(outcomes.consecutive_failures, 2);
        outcomes.reply(true, false);
        assert_eq!(outcomes.consecutive_failures, 0);
        assert_eq!((outcomes.passed, outcomes.denied, outcomes.errors), (1, 1, 1));
    }

    #[test]
    fn typed_certificate_failures_have_specific_counters() {
        let counters = ServerCounters::default();
        for code in [
            openssl_sys::X509_V_ERR_CERT_REVOKED,
            openssl_sys::X509_V_ERR_CERT_HAS_EXPIRED,
            openssl_sys::X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
        ] {
            counters.tls_failure(&anyhow::Error::new(CertificateVerificationCode(code)));
        }
        let snapshot = counters.snapshot().diagnostics;
        assert_eq!(snapshot.tls_certificate_errors, 3);
        assert_eq!(snapshot.tls_revoked_certificates, 1);
        assert_eq!(snapshot.tls_expired_certificates, 1);
        assert_eq!(snapshot.tls_untrusted_ca, 1);
        assert_eq!(snapshot.tls_other_errors, 0);
    }

    #[test]
    fn cleanup_io_errors_do_not_replace_or_recount_the_first_failure() {
        let owner = ServerCounters::default();
        let connection = owner.for_connection(None, None);
        let record = ConnectionRecord::new(connection.clone());
        connection.io_error(&std::io::Error::from(std::io::ErrorKind::ConnectionReset), false);
        connection.io_error(&std::io::Error::from(std::io::ErrorKind::BrokenPipe), true);
        record.close(false);
        let snapshot = owner.snapshot().diagnostics;
        assert_eq!(snapshot.read_errors, 1);
        assert_eq!(snapshot.write_errors, 0);
        assert_eq!(snapshot.peer_disconnects, 1);
    }
}
