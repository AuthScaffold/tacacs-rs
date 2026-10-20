//! TACACS+ server destination resolution and TCP connection setup.
//!
//! This module resolves a configured host name to socket addresses off the
//! runtime worker threads, then connects to the first reachable destination. An
//! optional [`ConnectionGuard`] checks each destination before connect and the
//! connected socket before any TLS or TACACS+ traffic.

use std::borrow::Cow;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::num::NonZeroU16;

use anyhow::{Context as _, ensure};

use crate::endpoint::ConnectionGuard;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Host {
    Dns(String),
    Ip(IpAddr),
}

/// A validated DNS or IP host with an explicit nonzero outbound port.
///
/// Construction performs no DNS or network I/O. DNS names retain their spelling
/// and optional trailing dot. Labels follow the YANG `inet:domain-name` character set.
/// Scoped IPv6 addresses are not portable and are rejected.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ServerAddress {
    host: Host,
    port: NonZeroU16,
}

impl ServerAddress {
    /// Uses separate host and port fields without parsing a combined address.
    ///
    /// The host must not contain brackets or an IPv6 zone ID.
    ///
    /// # Errors
    /// Rejects invalid DNS/IP hosts, noncanonical numeric addresses, and port zero.
    pub fn new(host: &str, port: u16) -> anyhow::Result<Self> {
        let port = NonZeroU16::new(port).context("outbound server port must not be zero")?;
        ensure!(!host.contains('%'), "scoped server addresses are not supported");
        let host = match host.parse::<IpAddr>() {
            Ok(address) => Host::Ip(address),
            Err(_) => {
                let name = host.strip_suffix('.').unwrap_or(host);
                ensure!(!name.is_empty() && name.len() <= 253, "invalid DNS server host");
                ensure!(
                    name.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && !label.starts_with('-')
                            && !label.ends_with('-')
                            && label.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
                            })
                    }),
                    "invalid DNS server host"
                );
                ensure!(
                    !name.split('.').all(|label| {
                        label.bytes().all(|byte| byte.is_ascii_digit())
                            || label
                                .strip_prefix("0x")
                                .or_else(|| label.strip_prefix("0X"))
                                .is_some_and(|digits| {
                                    !digits.is_empty()
                                        && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                                })
                    }),
                    "numeric server hosts must use canonical IP address syntax"
                );
                Host::Dns(host.to_owned())
            }
        };
        Ok(Self { host, port })
    }

    /// Parses a string entry with a caller-selected default port.
    ///
    /// Bare IPv6 is always a whole host. Use brackets to specify its port.
    ///
    /// # Errors
    /// Rejects empty hosts, invalid brackets, malformed ports, port zero, and zone IDs.
    pub fn parse(input: &str, default_port: u16) -> anyhow::Result<Self> {
        if let Some(rest) = input.strip_prefix('[') {
            let (host, suffix) = rest
                .split_once(']')
                .context("IPv6 address is missing a closing bracket")?;
            host.parse::<Ipv6Addr>()
                .context("invalid bracketed IPv6 address")?;
            let port = if suffix.is_empty() {
                default_port
            } else {
                parse_port(
                    suffix
                        .strip_prefix(':')
                        .context("unexpected data after bracketed IPv6 address")?,
                )?
            };
            return Self::new(host, port);
        }
        ensure!(!input.contains(['[', ']', '%']), "invalid brackets or zone ID in server address");
        if input.parse::<IpAddr>().is_ok() {
            return Self::new(input, default_port);
        }
        match input.split_once(':') {
            Some((host, port)) => Self::new(host, parse_port(port)?),
            None => Self::new(input, default_port),
        }
    }

    /// Returns the host without brackets or a port.
    #[must_use]
    pub fn host(&self) -> Cow<'_, str> {
        match &self.host {
            Host::Dns(name) => Cow::Borrowed(name),
            Host::Ip(address) => Cow::Owned(address.to_string()),
        }
    }

    /// Returns the explicit outbound port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port.get()
    }

    fn resolve(&self) -> anyhow::Result<Vec<SocketAddr>> {
        let addresses = match &self.host {
            Host::Ip(address) => vec![SocketAddr::new(*address, self.port())],
            Host::Dns(name) => (name.as_str(), self.port()).to_socket_addrs()?.collect(),
        };
        Ok(addresses.into_iter().map(canonical_destination).collect())
    }
}

fn canonical_destination(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V6(ipv6) => ipv6
            .ip()
            .to_ipv4_mapped()
            .map(|ipv4| SocketAddr::new(ipv4.into(), ipv6.port()))
            .unwrap_or(address),
        SocketAddr::V4(_) => address,
    }
}

impl TryFrom<SocketAddr> for ServerAddress {
    type Error = anyhow::Error;

    fn try_from(address: SocketAddr) -> anyhow::Result<Self> {
        if let SocketAddr::V6(address) = address {
            ensure!(address.scope_id() == 0, "scoped server addresses are not supported");
        }
        Ok(Self {
            host: Host::Ip(address.ip()),
            port: NonZeroU16::new(address.port())
                .context("outbound server port must not be zero")?,
        })
    }
}

impl fmt::Display for ServerAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Ip(IpAddr::V6(address)) => write!(formatter, "[{address}]:{}", self.port),
            Host::Ip(address) => write!(formatter, "{address}:{}", self.port),
            Host::Dns(name) => write!(formatter, "{name}:{}", self.port),
        }
    }
}

fn parse_port(port: &str) -> anyhow::Result<u16> {
    ensure!(
        !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()),
        "invalid explicit server port"
    );
    port.parse().context("invalid explicit server port")
}

/// Establishes a TCP connection to a TACACS+ server.
///
/// Attempts to connect to each resolved address in order until one succeeds.
///
/// # Errors
///
/// Returns an error if all connection attempts fail.
pub(crate) async fn connect_tcp(
    address: &ServerAddress,
    guard: Option<&dyn ConnectionGuard>,
    binding: &crate::LocalBinding,
) -> anyhow::Result<tokio::net::TcpStream> {
    connect_resolved(resolve_server_addresses(address), guard, binding).await
}

#[cfg(test)]
async fn connect_after_resolution(
    resolution: impl std::future::Future<Output = anyhow::Result<Vec<SocketAddr>>> + Send,
    guard: Option<&dyn ConnectionGuard>,
) -> anyhow::Result<tokio::net::TcpStream> {
    connect_resolved(resolution, guard, &crate::LocalBinding::default()).await
}

async fn connect_resolved(
    resolution: impl std::future::Future<Output = anyhow::Result<Vec<SocketAddr>>> + Send,
    guard: Option<&dyn ConnectionGuard>,
    binding: &crate::LocalBinding,
) -> anyhow::Result<tokio::net::TcpStream> {
    let mut last_error = None;
    for server_address in resolution.await? {
        if !binding.matches_family(server_address) {
            continue;
        }
        if let Some(guard) = guard {
            guard.check_destination(server_address)?;
        }
        match crate::binding::connect(server_address, binding).await {
            Ok(stream) => {
                if let Some(guard) = guard {
                    guard.check_connected(
                        stream
                            .peer_addr()
                            .context("inspect connected TACACS+ peer")?,
                        stream
                            .local_addr()
                            .context("inspect connected TACACS+ local address")?,
                    )?;
                }
                log::info!(
                    target: "tacacsrs_networking::destination::connect_tcp",
                    "Connected to TACACS+ server {server_address}");
                return Ok(stream);
            }
            Err(e) => {
                log::error!(
                    target: "tacacsrs_networking::destination::connect_tcp",
                    "Failed to connect to TACACS+ server {server_address}: {e}");
                last_error = Some(e);
            }
        }
    }

    match last_error {
        Some(error) => Err(error).context("Failed to connect to any TACACS+ server address"),
        None => Err(anyhow::Error::msg("Failed to connect to any TACACS+ server address")),
    }
}

/// Resolves server addresses off the runtime threads.
///
/// `ToSocketAddrs` blocks, so resolving inline would stall every task sharing
/// the worker thread.
async fn resolve_server_addresses(address: &ServerAddress) -> anyhow::Result<Vec<SocketAddr>> {
    let address = address.clone();
    tokio::task::spawn_blocking(move || address.resolve())
        .await
        .context("The TACACS+ address resolution task failed")?
}

#[cfg(test)]
mod tests {
    use super::ServerAddress;

    #[test]
    fn address_parser_preserves_hosts_and_explicit_ports_without_io() {
        for (input, host, explicit_port) in [
            ("server.example", "server.example", None),
            ("server.example.", "server.example.", None),
            ("server.example:4949", "server.example", Some(4949)),
            ("127.0.0.1", "127.0.0.1", None),
            ("127.0.0.1:4949", "127.0.0.1", Some(4949)),
            ("[2001:db8::1]", "2001:db8::1", None),
            ("[2001:db8::1]:4949", "2001:db8::1", Some(4949)),
            ("2001:db8::1", "2001:db8::1", None),
            ("::1:49", "::1:49", None),
            ("::ffff:127.0.0.1", "::ffff:127.0.0.1", None),
            ("[::ffff:127.0.0.1]:300", "::ffff:127.0.0.1", Some(300)),
        ] {
            for default_port in [49, 300] {
                let address = ServerAddress::parse(input, default_port).unwrap();
                assert_eq!(address.host(), host, "{input}");
                assert_eq!(address.port(), explicit_port.unwrap_or(default_port), "{input}");
                assert_eq!(ServerAddress::parse(&address.to_string(), 1).unwrap(), address);
                assert_eq!(ServerAddress::new(host, address.port()).unwrap(), address);
            }
        }
    }

    #[test]
    fn outbound_addresses_reject_zero_ports_and_scoped_hosts() {
        for input in [
            "localhost:0",
            "127.0.0.1:0",
            "[::1]:0",
            "fe80::1%eth0",
            "host%zone",
            "[fe80::1%3]:49",
        ] {
            assert!(ServerAddress::parse(input, 49).is_err(), "must reject {input}");
        }
        assert!(ServerAddress::new("localhost", 0).is_err());
        assert!(ServerAddress::parse("localhost", 0).is_err());
        assert!(ServerAddress::parse("localhost:49", 0).is_ok());
        let scoped = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            49,
            0,
            1,
        ));
        assert!(ServerAddress::try_from(scoped).is_err());
        assert!(ServerAddress::try_from("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .is_err());
    }

    #[test]
    fn address_parser_rejects_noncanonical_numeric_hosts() {
        for host in [
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "127.000.000.001",
            "0x7f000001",
            "0X7F.0.0.1",
            "256.0.0.1",
            "127.0.0.1.",
        ] {
            assert!(ServerAddress::new(host, 49).is_err(), "must reject {host}");
            assert!(ServerAddress::parse(host, 49).is_err(), "must reject {host}");
            assert!(
                ServerAddress::parse(&format!("{host}:49"), 300).is_err(),
                "must reject {host}:49"
            );
        }
        for host in ["123.example", "123.example.", "0x7f.example", "server123"] {
            assert_eq!(ServerAddress::new(host, 49).unwrap().host(), host);
        }
    }

    #[test]
    fn schema_valid_underscore_dns_names_are_accepted() {
        for host in ["tacacs_server.example", "_tacacs._tcp.example.", "bad_host"] {
            assert_eq!(ServerAddress::new(host, 49).unwrap().host(), host);
            assert_eq!(
                ServerAddress::parse(&format!("{host}:300"), 49)
                    .unwrap()
                    .port(),
                300
            );
        }
    }

    #[test]
    fn address_parser_rejects_malformed_hosts_brackets_and_ports() {
        for input in [
            "",
            ":49",
            "[]",
            "[]:49",
            "[::1",
            "::1]",
            "[localhost]:49",
            "[127.0.0.1]:49",
            "[::1]extra",
            "[::1]::49",
            "[::1]:",
            "[::1]:invalid",
            "[::1]:65536",
            "host:",
            "host:invalid",
            "host:65536",
            "host:-1",
            "host:+49",
            "host: 49",
            "host:49:50",
            "bad host",
            "-host",
            "host-",
            "host..example",
            ".",
            "a/b",
            "a\0b",
            "\u{e9}.example",
        ] {
            assert!(ServerAddress::parse(input, 49).is_err(), "must reject {input:?}");
        }
        assert!(ServerAddress::new("[::1]", 49).is_err());
        assert!(ServerAddress::new(&"a".repeat(64), 49).is_err());
        assert!(ServerAddress::parse("host:65535", 49).is_ok());
    }

    #[test]
    fn canonical_destinations_preserve_order_ports_and_native_ipv6_metadata() {
        use std::net::{SocketAddr, SocketAddrV6};

        let ipv4 = "192.0.2.1:49".parse::<SocketAddr>().unwrap();
        let scoped_ipv6 =
            SocketAddr::V6(SocketAddrV6::new("fe80::1".parse().unwrap(), 300, 0x12345, 7));
        let mapped_ipv6 = "[::ffff:192.0.2.1]:4949".parse().unwrap();
        let compatible_ipv6 = "[::192.0.2.1]:49".parse().unwrap();
        let addresses = [ipv4, scoped_ipv6, mapped_ipv6, compatible_ipv6, ipv4];

        assert_eq!(
            addresses.map(super::canonical_destination),
            [
                ipv4,
                scoped_ipv6,
                "192.0.2.1:4949".parse().unwrap(),
                compatible_ipv6,
                ipv4
            ]
        );
    }

    #[test]
    fn mapped_ipv6_resolves_to_native_ipv4_without_changing_input() {
        for (host, expected) in [
            ("::ffff:127.0.0.1", "127.0.0.1:49"),
            ("::ffff:192.0.2.1", "192.0.2.1:49"),
        ] {
            let address = ServerAddress::new(host, 49).unwrap();
            assert_eq!(address.resolve().unwrap(), vec![expected.parse().unwrap()]);
            assert_eq!(address.host(), host);
            assert_eq!(address.to_string(), format!("[{host}]:49"));
        }
        let native_ipv6 = ServerAddress::new("2001:db8::1", 49).unwrap();
        assert_eq!(native_ipv6.resolve().unwrap(), vec!["[2001:db8::1]:49".parse().unwrap()]);
    }

    #[tokio::test]
    async fn repeated_connections_check_literal_dns_ipv6_and_mapped_destinations() {
        use std::sync::Mutex;
        use super::{ConnectionGuard, SocketAddr};

        #[derive(Default)]
        struct Observed {
            destinations: Mutex<Vec<SocketAddr>>,
            connected: Mutex<Vec<SocketAddr>>,
        }

        impl ConnectionGuard for Observed {
            fn check_destination(&self, destination: SocketAddr) -> anyhow::Result<()> {
                self.destinations.lock().unwrap().push(destination);
                Ok(())
            }

            fn check_connected(&self, peer: SocketAddr, _: SocketAddr) -> anyhow::Result<()> {
                assert!(self.destinations.lock().unwrap().contains(&peer));
                self.connected.lock().unwrap().push(peer);
                Ok(())
            }
        }

        for host in ["127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"] {
            let bind_host = if host == "::1" {
                "::1"
            } else {
                "127.0.0.1"
            };
            let listener = tokio::net::TcpListener::bind((bind_host, 0)).await.unwrap();
            let address = ServerAddress::new(host, listener.local_addr().unwrap().port()).unwrap();
            let ipv6_listener = if host == "localhost" {
                Some(
                    tokio::net::TcpListener::bind(("::1", address.port()))
                        .await
                        .unwrap(),
                )
            } else {
                None
            };
            let guard = Observed::default();
            for _ in 0..2 {
                let (connected, accepted) =
                    tokio::time::timeout(std::time::Duration::from_secs(2), async {
                        let binding = crate::LocalBinding::default();
                        tokio::try_join!(
                            super::connect_tcp(&address, Some(&guard), &binding),
                            async {
                                let accepted = match &ipv6_listener {
                                    Some(ipv6_listener) => tokio::select! {
                                        accepted = listener.accept() => accepted,
                                        accepted = ipv6_listener.accept() => accepted,
                                    },
                                    None => listener.accept().await,
                                };
                                accepted.map_err(anyhow::Error::from)
                            }
                        )
                    })
                    .await
                    .unwrap_or_else(|_| panic!("guard exchange timed out for {host}"))
                    .unwrap_or_else(|error| panic!("guard exchange failed for {host}: {error:#}"));
                assert_eq!(
                    connected.peer_addr().unwrap(),
                    accepted.0.local_addr().unwrap(),
                    "{host}"
                );
                drop(connected);
                drop(accepted);
            }
            assert_eq!(guard.connected.lock().unwrap().len(), 2, "{host}");
            assert!(guard.destinations.lock().unwrap().len() >= 2, "{host}");
            assert_eq!(address.host(), host);
        }
    }

    #[tokio::test]
    async fn all_failed_addresses_preserve_last_native_error() {
        use super::connect_after_resolution;

        let failed_address = "127.0.0.1:0".parse().unwrap();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            connect_after_resolution(std::future::ready(Ok(vec![failed_address])), None),
        )
        .await
        .expect("the invalid native destination must finish")
        .unwrap_err();

        assert_eq!(error.to_string(), "Failed to connect to any TACACS+ server address");
        assert!(error
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some()));
    }

    #[tokio::test]
    async fn failed_address_does_not_prevent_later_success() {
        use super::connect_after_resolution;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listening_address = listener.local_addr().unwrap();
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            connect_after_resolution(
                std::future::ready(Ok(vec!["127.0.0.1:0".parse().unwrap(), listening_address])),
                None,
            ),
        )
        .await
        .expect("the available native destination must finish")
        .unwrap();

        assert_eq!(stream.peer_addr().unwrap(), listening_address);
    }

    #[tokio::test]
    async fn empty_resolution_has_no_native_error_cause() {
        use super::{SocketAddr, connect_after_resolution};

        let error =
            connect_after_resolution(std::future::ready(Ok(Vec::<SocketAddr>::new())), None)
                .await
                .unwrap_err();

        assert_eq!(error.to_string(), "Failed to connect to any TACACS+ server address");
        assert!(!error
            .chain()
            .any(|cause| cause.downcast_ref::<std::io::Error>().is_some()));
    }

    #[tokio::test]
    async fn changed_resolution_cannot_bypass_destination_guard() {
        use super::{ConnectionGuard, SocketAddr, connect_after_resolution};

        struct Exclude(SocketAddr);
        impl ConnectionGuard for Exclude {
            fn check_destination(&self, destination: SocketAddr) -> anyhow::Result<()> {
                anyhow::ensure!(destination != self.0, "excluded destination");
                Ok(())
            }
            fn check_connected(&self, peer: SocketAddr, _: SocketAddr) -> anyhow::Result<()> {
                self.check_destination(peer)
            }
        }
        let allowed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let excluded = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let guard = Exclude(excluded.local_addr().unwrap());
        let initial = async { Ok(vec![allowed.local_addr().unwrap()]) };
        drop(
            connect_after_resolution(initial, Some(&guard))
                .await
                .unwrap(),
        );
        let changed = async { Ok(vec![excluded.local_addr().unwrap()]) };
        assert!(connect_after_resolution(changed, Some(&guard))
            .await
            .is_err());
        let mapped = ServerAddress::new("::ffff:127.0.0.1", guard.0.port()).unwrap();
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            super::connect_tcp(&mapped, Some(&guard), &crate::LocalBinding::default()),
        )
        .await
        .expect("the mapped destination must reach the guard")
        .unwrap_err();
        assert_eq!(error.to_string(), "excluded destination");
        assert!(tokio::time::timeout(std::time::Duration::from_millis(25), excluded.accept())
            .await
            .is_err());
    }
}
