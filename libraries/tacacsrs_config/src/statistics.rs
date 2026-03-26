/// Runtime statistics counters for a TACACS+ server.
///
/// Maps to the YANG `grouping statistics` container.
/// All counters are `config false` (read-only) in the YANG model.
/// These are not deserialized from configuration — they are populated
/// at runtime as connections are established and packets are exchanged.
#[derive(Debug, Clone, Default)]
pub struct ServerStatistics {
    /// Number of new connection requests sent (socket opens).
    pub connection_opens: u64,
    /// Number of graceful connection closes.
    pub connection_closes: u64,
    /// Number of aborted connections (non-graceful).
    pub connection_aborts: u64,
    /// Number of connection failures.
    pub connection_failures: u64,
    /// Number of connection timeouts.
    pub connection_timeouts: u64,
    /// Number of messages sent to the server.
    pub messages_sent: u64,
    /// Number of messages received from the server.
    pub messages_received: u64,
    /// Number of error messages received.
    pub errors_received: u64,
    /// Number of TACACS+ sessions completed.
    pub sessions: u64,
    /// Number of connection failures due to certificate issues.
    pub cert_errors: u64,
    /// Number of RPK-related connection failures.
    pub rpk_errors: u64,
}
