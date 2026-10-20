//! Native local binding values for each TCP connection.
//!
//! Source-interface selection derives an address without forcing egress.
//! Linux egress selection binds one device. Its VRF supplies the routing table.
//! Best-effort fallback applies only to unavailable local constraints.

#[cfg(any(test, not(target_os = "linux")))]
use std::io;
use std::net::{IpAddr, SocketAddr};

use anyhow::{ensure, Context};
use tokio::net::{TcpSocket, TcpStream};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(all(test, target_os = "linux"))]
mod tests_linux;

/// Response to an unavailable local source, device, capability, or route.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BindingPolicy {
    /// Warn and retry without unavailable constraints on a fresh socket.
    #[default]
    BestEffort,
    /// Fail without relaxing any requested constraint.
    Strict,
}

/// A local address choice, independent of the egress device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceBinding {
    /// Bind this explicit local IP address.
    Ip(IpAddr),
    /// Derive a same-family address from this interface on every connection.
    ///
    /// This implements RFC 9950 source-interface semantics. It does not force egress.
    Interface(String),
}

/// Validated local constraints derived from canonical configuration.
///
/// Names refer to Linux network devices, not network namespaces.
/// Construction does not query the host. Each connection reads current resources.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalBinding {
    source: Option<SourceBinding>,
    egress_interface: Option<String>,
    vrf: Option<String>,
    policy: BindingPolicy,
}

impl LocalBinding {
    /// Constructs local constraints without opening a socket.
    ///
    /// Source addresses must be unicast and concrete. Device names use Linux's
    /// 15-byte limit and cannot contain path separators, whitespace, or NUL.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed addresses or device names.
    pub fn new(
        source: Option<SourceBinding>,
        egress_interface: Option<&str>,
        vrf: Option<&str>,
        policy: BindingPolicy,
    ) -> anyhow::Result<Self> {
        let source = source.map(|source| match source {
            SourceBinding::Ip(ip) => SourceBinding::Ip(ip.to_canonical()),
            source => source,
        });
        match &source {
            Some(SourceBinding::Ip(ip)) => {
                ensure!(
                    !ip.is_unspecified()
                        && !ip.is_multicast()
                        && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast()),
                    "source-ip must be a concrete unicast IP address"
                );
            }
            Some(SourceBinding::Interface(name)) => validate_device_name(name)?,
            None => {}
        }
        for name in egress_interface.into_iter().chain(vrf) {
            validate_device_name(name)?;
        }
        Ok(Self {
            source,
            egress_interface: egress_interface.map(str::to_owned),
            vrf: vrf.map(str::to_owned),
            policy,
        })
    }

    /// Returns the local source choice.
    #[must_use]
    pub fn source(&self) -> Option<&SourceBinding> {
        self.source.as_ref()
    }

    /// Returns the device that forces egress, if configured.
    #[must_use]
    pub fn egress_interface(&self) -> Option<&str> {
        self.egress_interface.as_deref()
    }

    /// Returns the requested Linux VRF device, if configured.
    #[must_use]
    pub fn vrf(&self) -> Option<&str> {
        self.vrf.as_deref()
    }

    /// Returns the local failure policy.
    #[must_use]
    pub const fn policy(&self) -> BindingPolicy {
        self.policy
    }

    pub(crate) fn matches_family(&self, address: SocketAddr) -> bool {
        !matches!(self.source, Some(SourceBinding::Ip(ip)) if ip.is_ipv4() != address.is_ipv4())
    }

    fn constrained(&self) -> bool {
        self.source.is_some() || self.egress_interface.is_some() || self.vrf.is_some()
    }

    fn relax(&mut self, scope: Scope) {
        match scope {
            #[cfg(target_os = "linux")]
            Scope::Source => self.source = None,
            #[cfg(target_os = "linux")]
            Scope::Egress => self.egress_interface = None,
            #[cfg(target_os = "linux")]
            Scope::Vrf => {
                // An interface retains its VRF even after its explicit VRF request disappears.
                // Remove the dependent interface choices together with the VRF.
                self.egress_interface = None;
                if self.vrf.take().is_some()
                    && matches!(self.source, Some(SourceBinding::Interface(_)))
                {
                    self.source = None;
                }
            }
            #[cfg(target_os = "linux")]
            Scope::Route => {
                if self.egress_interface.is_some() {
                    self.relax(Scope::Egress);
                } else if self.vrf.is_some() {
                    self.relax(Scope::Vrf);
                } else {
                    self.source = None;
                }
            }
            #[cfg(not(target_os = "linux"))]
            Scope::All => {
                self.source = None;
                self.egress_interface = None;
                self.vrf = None;
            }
        }
    }
}

fn validate_device_name(name: &str) -> anyhow::Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 15
            && !matches!(name, "." | "..")
            && !name
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || matches!(byte, 0 | b'/' | b':')),
        "invalid Linux device name in local binding"
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum Scope {
    #[cfg(target_os = "linux")]
    Source,
    #[cfg(target_os = "linux")]
    Egress,
    #[cfg(target_os = "linux")]
    Vrf,
    #[cfg(target_os = "linux")]
    Route,
    #[cfg(not(target_os = "linux"))]
    All,
}

#[derive(Debug)]
struct Unavailable {
    scope: Scope,
    cause: anyhow::Error,
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Local {:?} constraint unavailable: {}", self.scope, self.cause)
    }
}

impl std::error::Error for Unavailable {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

fn unavailable(scope: Scope, cause: impl Into<anyhow::Error>) -> anyhow::Error {
    Unavailable {
        scope,
        cause: cause.into(),
    }
    .into()
}

pub(crate) async fn connect(
    destination: SocketAddr,
    binding: &LocalBinding,
) -> anyhow::Result<TcpStream> {
    let mut current = binding.clone();
    // Each relaxation removes a source, egress, or VRF constraint, or its dependencies.
    // Three relaxations suffice. No path resets the caller's shared deadline.
    for _ in 0..4 {
        match attempt(destination, &current).await {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                if current.policy != BindingPolicy::BestEffort || !current.constrained() {
                    return Err(error);
                }
                let Some(unavailable) = error.downcast_ref::<Unavailable>() else {
                    return Err(error);
                };
                log::warn!(
                    "TACACS+ local binding fallback for {destination}: {unavailable}. Retrying with reduced local constraints"
                );
                current.relax(unavailable.scope);
            }
        }
    }
    anyhow::bail!("local binding fallback limit exceeded")
}

async fn attempt(destination: SocketAddr, binding: &LocalBinding) -> anyhow::Result<TcpStream> {
    let socket = if destination.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .context("create TACACS+ TCP socket")?;
    if binding.constrained() {
        #[cfg(target_os = "linux")]
        linux::apply(&socket, destination, binding).await?;
        #[cfg(not(target_os = "linux"))]
        return Err(unavailable(
            Scope::All,
            io::Error::new(io::ErrorKind::Unsupported, "local binding requires Linux"),
        ));
    }
    // TCP errors can originate at a remote router. They never prove local route absence.
    socket.connect(destination).await.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_names_and_sources_fail_without_host_access() {
        for name in [
            "",
            ".",
            "..",
            "../eth0",
            "a/b",
            "a\0b",
            "a b",
            "a:b",
            "0123456789abcdef",
        ] {
            assert!(LocalBinding::new(None, Some(name), None, BindingPolicy::BestEffort).is_err());
        }
        for ip in ["0.0.0.0", "::", "224.0.0.1", "ff02::1"] {
            assert!(LocalBinding::new(
                Some(SourceBinding::Ip(ip.parse().unwrap())),
                None,
                None,
                BindingPolicy::BestEffort
            )
            .is_err());
        }
    }

    #[tokio::test]
    async fn explicit_source_reaches_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let binding = LocalBinding::new(
            Some(SourceBinding::Ip("127.0.0.1".parse().unwrap())),
            None,
            None,
            BindingPolicy::Strict,
        )
        .unwrap();
        #[cfg(target_os = "linux")]
        {
            let stream = connect(listener.local_addr().unwrap(), &binding)
                .await
                .unwrap();
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.ip(), stream.local_addr().unwrap().ip());
            assert_eq!(peer.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
        }
        #[cfg(not(target_os = "linux"))]
        assert!(connect(listener.local_addr().unwrap(), &binding)
            .await
            .is_err());
    }
}
