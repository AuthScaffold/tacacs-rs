use std::time::Duration;

use crate::{TacacsPlusServer, TacacsPlusServerType};

/// Convenience helpers for runtime-oriented access to a TACACS+ server entry.
///
/// These helpers derive values from the generated YANG model without changing
/// its round-trip semantics.
pub trait TacacsPlusServerExt {
    /// Returns the server socket address in host:port form, using brackets for IPv6.
    fn socket_address(&self) -> String;

    /// Returns the configured timeout as a `Duration`.
    fn timeout_duration(&self) -> Duration;

    /// Returns the obfuscation key bytes when shared-secret mode is configured.
    fn obfuscation_key(&self) -> Option<Vec<u8>>;

    /// Returns true when the server uses any TLS-based configuration.
    fn is_tls(&self) -> bool;

    /// Returns true when the server uses TACACS+ obfuscation instead of TLS.
    fn is_obfuscation(&self) -> bool;

    /// Returns true when SNI is explicitly enabled.
    fn sni_enabled(&self) -> bool;

    /// Returns true when this server is configured for all requested service types.
    fn supports_server_type(&self, server_type: TacacsPlusServerType) -> bool;
}

impl TacacsPlusServerExt for TacacsPlusServer {
    fn socket_address(&self) -> String {
        if self.address.contains(':') {
            format!("[{}]:{}", self.address, self.port)
        } else {
            format!("{}:{}", self.address, self.port)
        }
    }

    fn timeout_duration(&self) -> Duration {
        Duration::from_secs(u64::from(self.timeout))
    }

    fn obfuscation_key(&self) -> Option<Vec<u8>> {
        self.shared_secret
            .as_ref()
            .map(|value| value.as_bytes().to_vec())
    }

    fn is_tls(&self) -> bool {
        self.client_identity.is_some() || self.server_authentication.is_some()
    }

    fn is_obfuscation(&self) -> bool {
        !self.is_tls()
    }

    fn sni_enabled(&self) -> bool {
        self.sni_enabled.unwrap_or(false)
    }

    fn supports_server_type(&self, server_type: TacacsPlusServerType) -> bool {
        self.server_type.contains(server_type)
    }
}

#[cfg(test)]
mod tests {
    use super::TacacsPlusServerExt;
    use crate::{TacacsPlusServer, TacacsPlusServerType, TlsClientServerAuthentication};

    fn base_server() -> TacacsPlusServer {
        TacacsPlusServer {
            name: "server-1".to_owned(),
            server_type: TacacsPlusServerType::ACCOUNTING,
            domain_name: None,
            sni_enabled: None,
            address: "192.0.2.10".to_owned(),
            port: 49,
            client_identity: None,
            server_authentication: None,
            shared_secret: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
            single_connection: false,
            timeout: 5,
        }
    }

    #[test]
    fn socket_address_formats_ipv4() {
        let server = base_server();
        assert_eq!(server.socket_address(), "192.0.2.10:49");
    }

    #[test]
    fn socket_address_formats_ipv6() {
        let mut server = base_server();
        server.address = "2001:db8::1".to_owned();
        assert_eq!(server.socket_address(), "[2001:db8::1]:49");
    }

    #[test]
    fn tls_and_obfuscation_helpers_reflect_security_shape() {
        let mut server = base_server();
        assert!(!server.is_tls());
        assert!(server.is_obfuscation());
        assert_eq!(server.obfuscation_key(), None);

        server.shared_secret = Some("secret".to_owned());
        assert!(!server.is_tls());
        assert!(server.is_obfuscation());
        assert_eq!(server.obfuscation_key(), Some(b"secret".to_vec()));

        server.shared_secret = None;
        server.server_authentication = Some(TlsClientServerAuthentication {
            credentials_reference: None,
            ca_certs: None,
            ee_certs: None,
            tls13_epsks: None,
        });
        assert!(server.is_tls());
        assert!(!server.is_obfuscation());
    }

    #[test]
    fn supports_server_type_requires_all_requested_services() {
        let mut server = base_server();
        server.server_type =
            TacacsPlusServerType::AUTHENTICATION | TacacsPlusServerType::ACCOUNTING;

        assert!(server.supports_server_type(TacacsPlusServerType::ACCOUNTING));
        assert!(server.supports_server_type(
            TacacsPlusServerType::AUTHENTICATION | TacacsPlusServerType::ACCOUNTING
        ));
        assert!(!server.supports_server_type(TacacsPlusServerType::AUTHORIZATION));
    }
}
