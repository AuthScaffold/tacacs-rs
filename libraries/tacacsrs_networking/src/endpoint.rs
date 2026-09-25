//! Connection-ready values derived from authoritative configuration.
//!
//! Prepared endpoints own native TLS contexts and protected credential bytes.
//! They are not a configuration schema and do not retain the source snapshot.

use std::fmt;

use tacacsrs_secrets::SecretBytes;

use crate::establish::{ConnectOptions, PreparedTransport};

/// An immutable endpoint with validated native transport material.
///
/// Use [`crate::prepare_endpoint`] to derive this value from a materialized
/// YANG server. Clones share native contexts but not connection or session state.
#[derive(Clone)]
pub struct PreparedEndpoint {
    pub(crate) address: String,
    pub(crate) single_connection: bool,
    pub(crate) obfuscation_key: Option<SecretBytes>,
    pub(crate) transport: PreparedTransport,
    pub(crate) options: ConnectOptions,
}

impl PreparedEndpoint {
    /// Returns the prepared host and port without resolving DNS.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Returns whether this endpoint requests TACACS+ single-connection mode.
    #[must_use]
    pub const fn single_connection(&self) -> bool {
        self.single_connection
    }

    pub(crate) const fn security_label(&self) -> &'static str {
        match self.transport {
            PreparedTransport::Tls(_) | PreparedTransport::Psk(_, _) => "tls",
            PreparedTransport::Tcp if self.obfuscation_key.is_some() => "obfuscation",
            PreparedTransport::Tcp => "plain-tcp",
        }
    }
}

impl fmt::Debug for PreparedEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedEndpoint")
            .field("address", &self.address)
            .field("single_connection", &self.single_connection)
            .field("security", &self.security_label())
            .finish_non_exhaustive()
    }
}
