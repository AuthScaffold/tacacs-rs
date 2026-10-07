use std::net::{IpAddr, Ipv6Addr};

use anyhow::{Context, ensure};

/// Parses a TACACS+ host and port string.
///
/// The function uses `default_port` only when the port is absent.
///
/// # Errors
///
/// Returns an error for an empty host, malformed brackets, or an invalid explicit port.
pub fn parse_host_port(addr: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    ensure!(!addr.is_empty(), "server address must not be empty");
    if let Some(rest) = addr.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .context("IPv6 address is missing a closing bracket")?;
        host.parse::<Ipv6Addr>()
            .context("invalid bracketed IPv6 address")?;
        let port = if suffix.is_empty() {
            default_port
        } else {
            suffix
                .strip_prefix(':')
                .context("unexpected data after bracketed IPv6 address")?
                .parse::<u16>()
                .context("invalid explicit server port")?
        };
        return Ok((host.to_owned(), port));
    }
    ensure!(!addr.contains(['[', ']']), "invalid brackets in server address");
    if addr.parse::<IpAddr>().is_ok() {
        return Ok((addr.to_owned(), default_port));
    }
    if let Some((host, port)) = addr.split_once(':') {
        ensure!(!host.is_empty(), "server host must not be empty");
        return Ok((
            host.to_owned(),
            port.parse::<u16>()
                .context("invalid explicit server port")?,
        ));
    }
    Ok((addr.to_owned(), default_port))
}

#[cfg(test)]
mod tests {
    use super::parse_host_port;

    #[test]
    fn parses_host_port() {
        assert_eq!(
            parse_host_port("192.0.2.10:4949", 49).unwrap(),
            ("192.0.2.10".to_owned(), 4949)
        );
    }

    #[test]
    fn uses_default_port() {
        assert_eq!(parse_host_port("192.0.2.10", 49).unwrap(), ("192.0.2.10".to_owned(), 49));
    }

    #[test]
    fn parses_bracketed_ipv6() {
        assert_eq!(
            parse_host_port("[2001:db8::1]:4949", 49).unwrap(),
            ("2001:db8::1".to_owned(), 4949)
        );
    }
}
