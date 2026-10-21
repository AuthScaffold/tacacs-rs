//! YANG-shaped operational diagnostics without desired configuration or credentials.

use serde::Serialize;
use tacacsrs_networking::{ConnectionDetails, DiagnosticsSnapshot, OperationStatistics};

use super::{counter64, timestamp};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConnectionStatistics {
    #[serde(serialize_with = "counter64")]
    pub connection_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_family: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "timestamp")]
    pub established_at: Option<std::time::SystemTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub single_connect: Option<bool>,
    pub tls_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_cipher: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fips_enabled: Option<bool>,
}

impl From<ConnectionDetails> for ConnectionStatistics {
    fn from(value: ConnectionDetails) -> Self {
        Self {
            connection_id: value.id,
            peer_address: value.peer.map(|address| address.to_string()),
            address_family: value.peer.map(|address| {
                if address.is_ipv4() {
                    "IPv4"
                } else {
                    "IPv6"
                }
            }),
            established_at: Some(value.established_at),
            single_connect: value.single_connect,
            tls_enabled: value.tls.is_some(),
            tls_version: value.tls.as_ref().map(|tls| tls.version.clone()),
            tls_cipher: value.tls.as_ref().and_then(|tls| tls.cipher.clone()),
            fips_enabled: value.tls.and_then(|tls| tls.fips_enabled),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct OperationCounters {
    #[serde(serialize_with = "counter64")]
    pub requests: u64,
    #[serde(serialize_with = "counter64")]
    pub passed: u64,
    #[serde(serialize_with = "counter64")]
    pub denied: u64,
    #[serde(serialize_with = "counter64")]
    pub errors: u64,
    #[serde(serialize_with = "counter64")]
    pub consecutive_failures: u64,
}

impl From<OperationStatistics> for OperationCounters {
    fn from(value: OperationStatistics) -> Self {
        Self {
            requests: value.requests,
            passed: value.passed,
            denied: value.denied,
            errors: value.errors,
            consecutive_failures: value.consecutive_failures,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RoutingStatus {
    pub operation: &'static str,
    pub eligible: bool,
    pub on_hold: bool,
}

/// Measured endpoint diagnostics. Missing native details are not synthesized as zeros.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerDiagnostics {
    pub address: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_instance: Option<String>,
    pub configured_single_connect: bool,
    pub connection_timeout_seconds: u16,
    pub state: &'static str,
    pub routing: Vec<RoutingStatus>,
    #[serde(serialize_with = "counter64")]
    pub connecting: u64,
    #[serde(serialize_with = "counter64")]
    pub connected: u64,
    #[serde(serialize_with = "counter64")]
    pub expected_replies: u64,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "timestamp")]
    pub last_attempt: Option<std::time::SystemTime>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "timestamp")]
    pub last_success: Option<std::time::SystemTime>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "timestamp")]
    pub last_disconnect: Option<std::time::SystemTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_disconnect_reason: Option<&'static str>,
    pub connection: Vec<ConnectionStatistics>,
    #[serde(serialize_with = "counter64")]
    pub connections_omitted: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_connection: Option<ConnectionStatistics>,
    #[serde(serialize_with = "counter64")]
    pub handshake_attempts: u64,
    #[serde(serialize_with = "counter64")]
    pub handshake_successes: u64,
    #[serde(serialize_with = "counter64")]
    pub handshake_failures: u64,
    #[serde(serialize_with = "counter64")]
    pub tls_read_errors: u64,
    #[serde(serialize_with = "counter64")]
    pub tls_write_errors: u64,
    #[serde(serialize_with = "counter64")]
    pub tls_certificate_errors: u64,
    #[serde(serialize_with = "counter64")]
    pub tls_revoked_certificates: u64,
    #[serde(serialize_with = "counter64")]
    pub tls_untrusted_ca: u64,
    #[serde(serialize_with = "counter64")]
    pub tls_expired_certificates: u64,
    #[serde(serialize_with = "counter64")]
    pub tls_protocol_mismatches: u64,
    #[serde(serialize_with = "counter64")]
    pub tls_cipher_mismatches: u64,
    #[serde(serialize_with = "counter64")]
    pub tls_other_errors: u64,
    #[serde(serialize_with = "counter64")]
    pub read_errors: u64,
    #[serde(serialize_with = "counter64")]
    pub write_errors: u64,
    #[serde(serialize_with = "counter64")]
    pub receive_timeouts: u64,
    #[serde(serialize_with = "counter64")]
    pub send_timeouts: u64,
    #[serde(serialize_with = "counter64")]
    pub resets: u64,
    #[serde(serialize_with = "counter64")]
    pub peer_disconnects: u64,
    #[serde(serialize_with = "counter64")]
    pub malformed_disconnects: u64,
    #[serde(serialize_with = "counter64")]
    pub no_response_disconnects: u64,
    #[serde(serialize_with = "counter64")]
    pub credential_expiry_disconnects: u64,
    #[serde(serialize_with = "counter64")]
    pub other_disconnects: u64,
    #[serde(serialize_with = "counter64")]
    pub packets_since_reset_sent: u64,
    #[serde(serialize_with = "counter64")]
    pub packets_since_reset_received: u64,
    #[serde(serialize_with = "counter64")]
    pub watchdog_preflights: u64,
    #[serde(serialize_with = "counter64")]
    pub watchdog_successes: u64,
    #[serde(serialize_with = "counter64")]
    pub watchdog_failures: u64,
    #[serde(serialize_with = "counter64")]
    pub watchdog_preflights_since_reset: u64,
    pub authentication: OperationCounters,
    pub authorization: OperationCounters,
    pub accounting: OperationCounters,
    pub unsupported: Vec<&'static str>,
}

impl ServerDiagnostics {
    #[must_use]
    pub fn new(
        server: &crate::TacacsPlusServer,
        value: DiagnosticsSnapshot,
        routing: Vec<RoutingStatus>,
    ) -> Self {
        Self {
            address: server.address.clone(),
            port: server.port,
            source_address: server.source_ip.clone(),
            routing_instance: server.vrf_instance.clone(),
            configured_single_connect: server.single_connection,
            connection_timeout_seconds: server.timeout,
            state: if value.connected > 0 {
                "connected"
            } else if value.connecting > 0 {
                "connecting"
            } else if value.last_attempt.is_none() {
                "not-attempted"
            } else {
                "disconnected"
            },
            routing,
            connecting: value.connecting,
            connected: value.connected,
            expected_replies: value.expected_replies,
            last_attempt: value.last_attempt,
            last_success: value.last_success,
            last_disconnect: value.last_disconnect,
            last_disconnect_reason: value
                .last_disconnect_reason
                .map(tacacsrs_networking::DisconnectReason::as_str),
            connection: value.connections.into_iter().map(Into::into).collect(),
            connections_omitted: value.connections_omitted,
            last_connection: value.last_connection.map(Into::into),
            handshake_attempts: value.handshake_attempts,
            handshake_successes: value.handshake_successes,
            handshake_failures: value.handshake_failures,
            read_errors: value.read_errors,
            tls_read_errors: value.tls_read_errors,
            tls_write_errors: value.tls_write_errors,
            tls_certificate_errors: value.tls_certificate_errors,
            tls_revoked_certificates: value.tls_revoked_certificates,
            tls_untrusted_ca: value.tls_untrusted_ca,
            tls_expired_certificates: value.tls_expired_certificates,
            tls_protocol_mismatches: value.tls_protocol_mismatches,
            tls_cipher_mismatches: value.tls_cipher_mismatches,
            tls_other_errors: value.tls_other_errors,
            write_errors: value.write_errors,
            receive_timeouts: value.receive_timeouts,
            send_timeouts: value.send_timeouts,
            resets: value.resets,
            peer_disconnects: value.peer_disconnects,
            malformed_disconnects: value.malformed_disconnects,
            no_response_disconnects: value.no_response_disconnects,
            credential_expiry_disconnects: value.credential_expiry_disconnects,
            other_disconnects: value.other_disconnects,
            packets_since_reset_sent: value.packets_since_reset_sent,
            packets_since_reset_received: value.packets_since_reset_received,
            watchdog_preflights: value.watchdog_preflights,
            watchdog_successes: value.watchdog_successes,
            watchdog_failures: value.watchdog_failures,
            watchdog_preflights_since_reset: value.watchdog_preflights_since_reset,
            authentication: value.authentication.into(),
            authorization: value.authorization.into(),
            accounting: value.accounting.into(),
            unsupported: vec![
                "idle-timeout",
                "packets-since-idle-timeout",
                "periodic-watchdog-timer",
                "fips-state",
            ],
        }
    }
}
