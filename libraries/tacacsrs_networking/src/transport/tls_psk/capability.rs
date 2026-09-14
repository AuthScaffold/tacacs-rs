//! Process-local OpenSSL capabilities required by TLS 1.3 PSK.

use std::fmt;

use tacacsrs_config::TacacsPlusServer;

/// A process-local OpenSSL capability required by a configured transport.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LocalCapability {
    /// The OpenSSL `TLS13-KDF` implementation used by TLS 1.3 handshakes.
    Tls13Kdf,
}

impl fmt::Display for LocalCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls13Kdf => formatter.write_str("OpenSSL TLS13-KDF"),
        }
    }
}

/// A configured transport cannot run under the process OpenSSL provider policy.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LocalCapabilityError {
    capability: LocalCapability,
}

impl LocalCapabilityError {
    /// Creates the typed error for an unavailable OpenSSL `TLS13-KDF`.
    #[must_use]
    pub const fn tls13_kdf_unavailable() -> Self {
        Self {
            capability: LocalCapability::Tls13Kdf,
        }
    }

    /// Returns the unavailable process-local capability.
    #[must_use]
    pub const fn capability(self) -> LocalCapability {
        self.capability
    }
}

impl fmt::Display for LocalCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} is unavailable under the active OpenSSL provider policy; enable TLS13-KDF and restart the process",
            self.capability
        )
    }
}

impl std::error::Error for LocalCapabilityError {}

/// Checks the process-local capabilities required by one server.
///
/// The OpenSSL provider policy is process-level state. Callers must run this
/// check when they apply a configuration generation. A provider-policy change
/// requires a process restart.
///
/// # Errors
///
/// Returns a typed error when a PSK server requires an unavailable local
/// OpenSSL capability.
pub fn validate_server_local_capabilities(
    server: &TacacsPlusServer,
) -> Result<(), LocalCapabilityError> {
    let has_psk = server
        .client_identity
        .as_ref()
        .is_some_and(|identity| identity.tls13_epsk.is_some());
    if !has_psk {
        return Ok(());
    }

    validate_tls13_kdf(super::ffi::has_tls13_kdf)
}

fn validate_tls13_kdf(fetch: impl FnOnce() -> bool) -> Result<(), LocalCapabilityError> {
    if fetch() {
        Ok(())
    } else {
        Err(LocalCapabilityError::tls13_kdf_unavailable())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls13_kdf_failure_is_typed_and_actionable() {
        let error = validate_tls13_kdf(|| false).expect_err("the capability must be absent");

        assert_eq!(error.capability(), LocalCapability::Tls13Kdf);
        assert_eq!(
            error.to_string(),
            "OpenSSL TLS13-KDF is unavailable under the active OpenSSL provider policy; enable TLS13-KDF and restart the process"
        );
    }

    #[test]
    fn tls13_kdf_success_is_accepted() {
        validate_tls13_kdf(|| true).expect("the capability must be available");
    }
}
