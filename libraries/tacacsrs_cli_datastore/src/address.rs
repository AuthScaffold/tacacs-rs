/// Parses a TACACS+ host and port string.
///
/// The function returns `default_port` when the string has no valid port.
#[must_use]
pub fn parse_host_port(addr: &str, default_port: u16) -> (String, u16) {
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some((host, after_bracket)) = rest.split_once(']') {
            let port = after_bracket
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(default_port);
            return (host.to_owned(), port);
        }
    }

    if addr.matches(':').count() == 1 {
        if let Some((host, port_str)) = addr.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return (host.to_owned(), port);
            }
        }
    }

    (addr.to_owned(), default_port)
}

#[cfg(test)]
mod tests {
    use super::parse_host_port;

    #[test]
    fn parses_host_port() {
        assert_eq!(parse_host_port("192.0.2.10:4949", 49), ("192.0.2.10".to_owned(), 4949));
    }

    #[test]
    fn uses_default_port() {
        assert_eq!(parse_host_port("192.0.2.10", 49), ("192.0.2.10".to_owned(), 49));
    }

    #[test]
    fn parses_bracketed_ipv6() {
        assert_eq!(parse_host_port("[2001:db8::1]:4949", 49), ("2001:db8::1".to_owned(), 4949));
    }
}
