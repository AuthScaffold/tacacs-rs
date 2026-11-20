//! Connection-time proxy loop exclusion using actual listener state.
//!
//! The guard knows the configured proxy target and each bound TCP proxy
//! address. During an endpoint move, the old and the new listener are both
//! bound for a short time. The guard checks each upstream destination against
//! every bound address. It fails closed while the configured TCP target has
//! no bound listener.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::{Context, ensure};

use tacacsrs_config::local_services::ListenerEndpoint;
use tacacsrs_networking::ConnectionGuard;

/// The proxy target of the active local services.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ProxyGuardTarget {
    /// The proxy is disabled.
    Inactive,
    /// The proxy is enabled, and its TCP endpoint is not known yet.
    Waiting,
    /// The proxy listens on a TCP endpoint.
    Tcp(SocketAddr),
    /// The proxy listens on a Unix domain socket.
    Unix,
}

impl ProxyGuardTarget {
    pub(crate) fn from_endpoint(endpoint: Option<&ListenerEndpoint>) -> Self {
        match endpoint {
            Some(ListenerEndpoint::Tcp(address)) => Self::Tcp(*address),
            Some(ListenerEndpoint::Unix(_)) => Self::Unix,
            None => Self::Inactive,
        }
    }
}

#[derive(Debug)]
struct GuardState {
    target: ProxyGuardTarget,
    bound: Vec<(u64, SocketAddr)>,
    next_id: u64,
}

impl GuardState {
    fn bound_addresses(&self) -> anyhow::Result<Vec<SocketAddr>> {
        match self.target {
            ProxyGuardTarget::Waiting => {
                anyhow::bail!("Proxy listener must bind before upstream connections open")
            }
            ProxyGuardTarget::Tcp(configured) => ensure!(
                self.bound
                    .iter()
                    .any(|(_, address)| matches_configured(configured, *address)),
                "Proxy listener must bind before upstream connections open"
            ),
            ProxyGuardTarget::Inactive | ProxyGuardTarget::Unix => {}
        }
        Ok(self.bound.iter().map(|(_, address)| *address).collect())
    }
}

fn matches_configured(configured: SocketAddr, address: SocketAddr) -> bool {
    address.port() != 0
        && address.ip().to_canonical() == configured.ip().to_canonical()
        && (configured.port() == 0 || configured.port() == address.port())
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyLoopGuard {
    state: Arc<RwLock<GuardState>>,
}

impl ProxyLoopGuard {
    #[cfg(test)]
    pub(crate) fn new(endpoint: Option<&ListenerEndpoint>) -> Self {
        Self::with_target(ProxyGuardTarget::from_endpoint(endpoint))
    }

    pub(crate) fn with_target(target: ProxyGuardTarget) -> Self {
        Self {
            state: Arc::new(RwLock::new(GuardState {
                target,
                bound: Vec::new(),
                next_id: 0,
            })),
        }
    }

    /// Sets the proxy target of new local services.
    ///
    /// Existing bindings stay checked until their listeners stop.
    pub(crate) fn configure(&self, target: ProxyGuardTarget) {
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .target = target;
    }

    pub(crate) fn bind(&self, address: SocketAddr) -> anyhow::Result<ProxyListenerBinding> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ProxyGuardTarget::Tcp(configured) = state.target else {
            anyhow::bail!("Proxy listener guard is not configured for a TCP endpoint");
        };
        ensure!(
            matches_configured(configured, address),
            "Bound proxy endpoint does not match listener configuration"
        );
        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);
        state.bound.push((id, address));
        Ok(ProxyListenerBinding {
            guard: self.clone(),
            id,
        })
    }

    pub(super) fn bound_endpoints(&self) -> anyhow::Result<Vec<SocketAddr>> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bound_addresses()
    }

    fn check_with_addresses(&self, target: SocketAddr, addresses: &[IpAddr]) -> anyhow::Result<()> {
        for bound in self.bound_endpoints()? {
            ensure!(
                !ListenerEndpoint::Tcp(bound).covers_tcp_destination(target, addresses),
                "Upstream connection targets the local TACACS+ proxy"
            );
        }
        Ok(())
    }
}

impl ConnectionGuard for ProxyLoopGuard {
    fn check_destination(&self, destination: SocketAddr) -> anyhow::Result<()> {
        let bound = self.bound_endpoints()?;
        let same_port: Vec<_> = bound
            .iter()
            .filter(|address| address.port() == destination.port())
            .collect();
        if same_port.is_empty() {
            return Ok(());
        }
        ensure!(
            !destination.ip().to_canonical().is_unspecified(),
            "Upstream connection destination must be specified"
        );
        let addresses = if same_port
            .iter()
            .any(|address| address.ip().to_canonical().is_unspecified())
        {
            if_addrs::get_if_addrs()
                .context("read interfaces for connection-time proxy loop validation")?
                .into_iter()
                .map(|interface| interface.ip())
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        self.check_with_addresses(destination, &addresses)
    }

    fn check_connected(&self, peer: SocketAddr, local: SocketAddr) -> anyhow::Result<()> {
        self.check_with_addresses(peer, &[local.ip()])?;
        self.check_destination(peer)
    }
}

/// One bound proxy listener address. Drop removes the address from the guard.
pub(crate) struct ProxyListenerBinding {
    guard: ProxyLoopGuard,
    id: u64,
}

impl Drop for ProxyListenerBinding {
    fn drop(&mut self) {
        self.guard
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .bound
            .retain(|(id, _)| *id != self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_and_closed_listeners_fail_closed() {
        let configured = ListenerEndpoint::Tcp("127.0.0.1:0".parse().unwrap());
        let guard = ProxyLoopGuard::new(Some(&configured));
        let destination = "192.0.2.20:49".parse().unwrap();
        assert!(guard.check_destination(destination).is_err());
        let binding = guard.bind("127.0.0.1:45678".parse().unwrap()).unwrap();
        assert!(guard.check_destination(destination).is_ok());
        assert!(guard
            .check_destination("127.0.0.1:45678".parse().unwrap())
            .is_err());
        drop(binding);
        assert!(guard.check_destination(destination).is_err());
    }

    #[test]
    fn waiting_listener_fails_closed_until_it_binds() {
        let guard = ProxyLoopGuard::with_target(ProxyGuardTarget::Waiting);
        let destination = "192.0.2.20:49".parse().unwrap();
        assert!(guard.check_destination(destination).is_err());
        assert!(guard.bind("127.0.0.1:49".parse().unwrap()).is_err());
        guard.configure(ProxyGuardTarget::Tcp("127.0.0.1:49".parse().unwrap()));
        assert!(guard.check_destination(destination).is_err());
        let _binding = guard.bind("127.0.0.1:49".parse().unwrap()).unwrap();
        assert!(guard.check_destination(destination).is_ok());
        assert!(guard
            .check_destination("127.0.0.1:49".parse().unwrap())
            .is_err());
    }

    #[test]
    fn interface_changes_and_connected_local_address_are_rechecked() {
        let configured = ListenerEndpoint::Tcp("0.0.0.0:49".parse().unwrap());
        let guard = ProxyLoopGuard::new(Some(&configured));
        let _binding = guard.bind("0.0.0.0:49".parse().unwrap()).unwrap();
        let destination = "192.0.2.20:49".parse::<SocketAddr>().unwrap();
        assert!(guard.check_with_addresses(destination, &[]).is_ok());
        assert!(guard
            .check_with_addresses(destination, &[destination.ip()])
            .is_err());
        assert!(guard
            .check_connected(destination, "192.0.2.20:50000".parse().unwrap())
            .is_err());
        assert!(guard
            .check_destination("[::ffff:127.0.0.1]:49".parse().unwrap())
            .is_err());
    }

    #[test]
    fn a_moved_proxy_checks_the_old_and_the_new_binding_until_the_old_one_stops() {
        let guard =
            ProxyLoopGuard::with_target(ProxyGuardTarget::Tcp("127.0.0.1:49".parse().unwrap()));
        let old = guard.bind("127.0.0.1:49".parse().unwrap()).unwrap();
        guard.configure(ProxyGuardTarget::Tcp("127.0.0.1:4949".parse().unwrap()));
        assert!(
            guard
                .check_destination("192.0.2.20:49".parse().unwrap())
                .is_err(),
            "the new target must bind before upstream connections open"
        );
        let _new = guard.bind("127.0.0.1:4949".parse().unwrap()).unwrap();
        for bound in ["127.0.0.1:49", "127.0.0.1:4949"] {
            assert!(guard.check_destination(bound.parse().unwrap()).is_err());
        }
        drop(old);
        assert!(guard
            .check_destination("127.0.0.1:49".parse().unwrap())
            .is_ok());
        guard.configure(ProxyGuardTarget::Inactive);
        assert!(guard
            .check_destination("127.0.0.1:4949".parse().unwrap())
            .is_err());
    }

    #[test]
    fn services_without_tcp_proxy_do_not_restrict_upstream_connections() {
        let guard = ProxyLoopGuard::new(None);
        assert!(guard
            .check_destination("127.0.0.1:49".parse().unwrap())
            .is_ok());
    }
}
