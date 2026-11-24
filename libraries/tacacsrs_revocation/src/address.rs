//! Destination address checks for CRL fetches.
//!
//! A CRL URL comes from a server certificate. A hostile certificate can name an
//! internal service, so the verifier checks each resolved address before it
//! connects.

use std::net::{IpAddr, SocketAddr};

use anyhow::{Result, bail};

/// Rejects addresses that a CRL fetch must never reach.
///
/// Loopback, link-local (including the 169.254.169.254 metadata service and
/// `fe80::/10`), unspecified, multicast, and broadcast addresses are always
/// rejected. RFC 1918 and unique local (`fc00::/7`) addresses are rejected
/// unless `allow_private` is set.
pub(crate) fn check_address(address: SocketAddr, allow_private: bool) -> Result<()> {
    let ip = address.ip().to_canonical();
    let reason = match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_unspecified() || v4.octets()[0] == 0 {
                Some("unspecified")
            } else if v4.is_multicast() {
                Some("multicast")
            } else if v4.is_broadcast() {
                Some("broadcast")
            } else if !allow_private && v4.is_private() {
                Some("private")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            let first = v6.segments()[0];
            if v6.is_loopback() {
                Some("loopback")
            } else if first & 0xffc0 == 0xfe80 {
                Some("link-local")
            } else if v6.is_unspecified() {
                Some("unspecified")
            } else if v6.is_multicast() {
                Some("multicast")
            } else if !allow_private && first & 0xfe00 == 0xfc00 {
                Some("private")
            } else {
                None
            }
        }
    };
    if let Some(reason) = reason {
        bail!("CRL fetches cannot use the {reason} address {ip}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(text: &str, allow_private: bool) -> bool {
        check_address(SocketAddr::new(text.parse().unwrap(), 80), allow_private).is_ok()
    }

    #[test]
    fn rejects_internal_addresses() {
        for address in [
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
        ] {
            assert!(!check(address, true), "{address} must be rejected");
        }
    }

    #[test]
    fn private_addresses_need_permission() {
        for address in [
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "fd00::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!check(address, false), "{address} must be rejected");
            assert!(check(address, true), "{address} must be allowed");
        }
        assert!(check("93.184.216.34", false));
        assert!(check("2001:db8::1", false));
    }
}
