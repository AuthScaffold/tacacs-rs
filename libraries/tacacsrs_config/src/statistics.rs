//! Operational YANG snapshots and their RFC 7951 serialization.

mod diagnostics;
pub use diagnostics::{ConnectionStatistics, OperationCounters, RoutingStatus, ServerDiagnostics};

/// Runtime statistics counters for a TACACS+ server.
///
/// This type maps to the YANG `grouping statistics` container. All counters are
/// `config false` (read-only) in the YANG model. This type is used for
/// operational-data publication and is never embedded in desired configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ServerStatistics {
    /// Start of the current counter lifetime.
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "timestamp")]
    pub discontinuity_time: Option<std::time::SystemTime>,
    /// Number of requests to open a connection.
    #[serde(serialize_with = "counter64")]
    pub connection_opens: u64,
    /// Successful transport establishments, not attempts still in progress.
    #[serde(rename = "tacacsrs:connection-successes", serialize_with = "counter64")]
    pub connection_successes: u64,
    /// Number of graceful connection closes.
    #[serde(serialize_with = "counter64")]
    pub connection_closes: u64,
    /// Number of connections that closed without a graceful shutdown.
    #[serde(serialize_with = "counter64")]
    pub connection_aborts: u64,
    /// Number of connection failures.
    #[serde(serialize_with = "counter64")]
    pub connection_failures: u64,
    /// Number of connection timeouts.
    #[serde(serialize_with = "counter64")]
    pub connection_timeouts: u64,
    /// Number of messages sent to the server.
    #[serde(serialize_with = "counter64")]
    pub messages_sent: u64,
    /// Number of messages received from the server.
    #[serde(serialize_with = "counter64")]
    pub messages_received: u64,
    /// Number of error messages received.
    #[serde(serialize_with = "counter64")]
    pub errors_received: u64,
    /// Number of TACACS+ sessions completed.
    #[serde(serialize_with = "counter64")]
    pub sessions: u64,
    /// Number of connection failures due to certificate issues.
    #[serde(serialize_with = "counter64")]
    pub cert_errors: u64,
    /// Reserved RPK counter. Omitted from export because the workspace disables that feature.
    #[serde(skip_serializing)]
    pub rpk_errors: u64,
}

impl From<tacacsrs_networking::StatisticsSnapshot> for ServerStatistics {
    fn from(value: tacacsrs_networking::StatisticsSnapshot) -> Self {
        Self {
            discontinuity_time: Some(value.discontinuity_time),
            connection_opens: value.connection_opens,
            connection_successes: value.connection_successes,
            connection_closes: value.connection_closes,
            connection_aborts: value.connection_aborts,
            connection_failures: value.connection_failures,
            connection_timeouts: value.connection_timeouts,
            messages_sent: value.messages_sent,
            messages_received: value.messages_received,
            errors_received: value.errors_received,
            sessions: value.sessions,
            cert_errors: value.cert_errors,
            rpk_errors: 0,
        }
    }
}

/// Read-only server entry from a captured runtime generation. No credentials are included.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ServerOperationalStatistics {
    /// Configured server identity, without endpoint or credential data.
    pub name: String,
    /// Process-local identity of the counter lifetime.
    #[serde(rename = "tacacsrs:counter-epoch", serialize_with = "counter64")]
    pub counter_epoch: u64,
    /// Read-only counters for this server and epoch.
    pub statistics: ServerStatistics,
    /// Read-only endpoint diagnostics from the same counter snapshot.
    #[serde(rename = "tacacsrs:diagnostics", skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<ServerDiagnostics>,
}

/// Operational server counters captured from one runtime generation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OperationalStatistics {
    /// Routing generation captured before reading its counter owners.
    #[serde(rename = "tacacsrs:runtime-generation", serialize_with = "counter64")]
    pub runtime_generation: u64,
    /// Servers present in that generation, in configured order.
    #[serde(rename = "server")]
    pub servers: Vec<ServerOperationalStatistics>,
}

impl OperationalStatistics {
    /// Serializes the operational subtree within a caller-supplied byte limit.
    /// # Errors
    /// Returns an error if the output exceeds the limit or contains an invalid timestamp.
    pub fn to_yang_json_bounded(&self, limit: usize) -> anyhow::Result<String> {
        #[derive(serde::Serialize)]
        struct Root<'a> {
            #[serde(rename = "ietf-system-tacacs-plus:tacacs-plus")]
            statistics: &'a OperationalStatistics,
        }
        struct Output {
            bytes: Vec<u8>,
            limit: usize,
        }
        impl std::io::Write for Output {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                if data.len() > self.limit.saturating_sub(self.bytes.len()) {
                    return Err(std::io::Error::other(
                        "Operational statistics exceed the response limit",
                    ));
                }
                self.bytes.extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut output = Output {
            bytes: Vec::new(),
            limit,
        };
        serde_json::to_writer_pretty(&mut output, &Root { statistics: self })?;
        Ok(String::from_utf8(output.bytes)?)
    }

    /// Serializes an RFC 7951 operational subtree, not a loadable configuration document.
    /// # Errors
    /// Returns an error for an unrepresentable timestamp or serialization failure.
    pub fn to_yang_json(&self) -> anyhow::Result<String> {
        #[derive(serde::Serialize)]
        struct Root<'a> {
            #[serde(rename = "ietf-system-tacacs-plus:tacacs-plus")]
            statistics: &'a OperationalStatistics,
        }
        Ok(serde_json::to_string_pretty(&Root { statistics: self })?)
    }
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    reason = "Serde serialize_with requires a borrowed field"
)]
fn counter64<S: serde::Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

#[allow(clippy::ref_option, reason = "Serde serialize_with requires a borrowed field")]
fn timestamp<S: serde::Serializer>(
    value: &Option<std::time::SystemTime>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_str(
            &jiff::Timestamp::try_from(*value)
                .map_err(serde::ser::Error::custom)?
                .to_string(),
        ),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operational_json_uses_counter64_strings_and_excludes_disabled_features() {
        let statistics = ServerStatistics {
            discontinuity_time: Some(std::time::SystemTime::UNIX_EPOCH),
            messages_sent: u64::MAX,
            ..ServerStatistics::default()
        };
        let snapshot = OperationalStatistics {
            runtime_generation: 4,
            servers: vec![ServerOperationalStatistics {
                name: "primary".to_owned(),
                counter_epoch: 9,
                statistics,
                diagnostics: None,
            }],
        };
        let json = snapshot.to_yang_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let server = &parsed["ietf-system-tacacs-plus:tacacs-plus"]["server"][0];
        assert_eq!(server["statistics"]["messages-sent"], u64::MAX.to_string());
        assert_eq!(server["statistics"]["discontinuity-time"], "1970-01-01T00:00:00Z");
        assert!(server["statistics"].get("rpk-errors").is_none());
        assert!(
            crate::parse_yang_json(&json).is_err(),
            "operational state must not be accepted as desired configuration"
        );
        let mut invalid = snapshot;
        invalid.servers[0].statistics.discontinuity_time = std::time::SystemTime::UNIX_EPOCH
            .checked_add(std::time::Duration::from_secs(1_000_000_000_000));
        if invalid.servers[0].statistics.discontinuity_time.is_some() {
            assert!(invalid.to_yang_json().is_err());
        }
    }
}
