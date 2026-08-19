//! Downstream transport settings for the raw TACACS+ proxy listener.
//!
//! These settings describe how the proxy talks to its own clients, not how the
//! agent talks to upstream servers. They live beside the server set because a
//! configuration reload publishes both as one generation. The proxy service
//! reads them through one value object so it does not reach into upstream
//! routing state for unrelated settings.

use std::time::Duration;

use crate::config::ProxyDownstreamObfuscation;

/// Settings that the raw TACACS+ proxy applies to a downstream connection.
#[derive(Clone, Debug)]
pub(crate) struct ProxyTransportSettings {
    read_timeout: Duration,
    downstream_obfuscation: ProxyDownstreamObfuscation,
}

impl ProxyTransportSettings {
    pub(super) const fn new(
        read_timeout: Duration,
        downstream_obfuscation: ProxyDownstreamObfuscation,
    ) -> Self {
        Self {
            read_timeout,
            downstream_obfuscation,
        }
    }

    /// Returns the bounded wait for one downstream round trip.
    pub(crate) const fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Returns the obfuscation applied to downstream proxy packets.
    pub(crate) const fn downstream_obfuscation(&self) -> &ProxyDownstreamObfuscation {
        &self.downstream_obfuscation
    }
}
