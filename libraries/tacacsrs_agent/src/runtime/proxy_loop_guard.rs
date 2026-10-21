//! Connection-time proxy loop exclusion using actual listener state.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};

use anyhow::{Context, ensure};

use tacacsrs_config::local_services::ListenerEndpoint;
use tacacsrs_networking::ConnectionGuard;

#[derive(Debug, Clone, Copy)]
enum ProxyListenerState {
    Inactive,
    Pending(SocketAddr),
    Bound(SocketAddr),
    Closed,
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyLoopGuard {
    state: Arc<RwLock<ProxyListenerState>>,
}

impl ProxyLoopGuard {
    pub(crate) fn new(endpoint: Option<&ListenerEndpoint>) -> Self {
        let state = match endpoint {
            Some(ListenerEndpoint::Tcp(address)) => ProxyListenerState::Pending(*address),
            _ => ProxyListenerState::Inactive,
        };
        Self {
            state: Arc::new(RwLock::new(state)),
        }
    }

    pub(crate) fn bind(&self, address: SocketAddr) -> anyhow::Result<ProxyListenerBinding> {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ProxyListenerState::Pending(configured) = *state else {
            anyhow::bail!("Proxy listener guard is not awaiting a bind");
        };
        ensure!(
            address.port() != 0
                && address.ip().to_canonical() == configured.ip().to_canonical()
                && (configured.port() == 0 || configured.port() == address.port()),
            "Bound proxy endpoint does not match listener configuration"
        );
        *state = ProxyListenerState::Bound(address);
        Ok(ProxyListenerBinding {
            guard: self.clone(),
        })
    }

    pub(super) fn bound_endpoint(&self) -> anyhow::Result<Option<SocketAddr>> {
        let state = *self
            .state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match state {
            ProxyListenerState::Inactive => Ok(None),
            ProxyListenerState::Bound(address) => Ok(Some(address)),
            ProxyListenerState::Pending(_) => {
                anyhow::bail!("Proxy listener must bind before upstream connections open")
            }
            ProxyListenerState::Closed => anyhow::bail!("Proxy listener has closed"),
        }
    }

    fn check_with_addresses(&self, target: SocketAddr, addresses: &[IpAddr]) -> anyhow::Result<()> {
        if let Some(bound) = self.bound_endpoint()? {
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
        let Some(bound) = self.bound_endpoint()? else {
            return Ok(());
        };
        if destination.port() != bound.port() {
            return Ok(());
        }
        ensure!(
            !destination.ip().to_canonical().is_unspecified(),
            "Upstream connection destination must be specified"
        );
        let addresses = if bound.ip().to_canonical().is_unspecified() {
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

pub(crate) struct ProxyListenerBinding {
    guard: ProxyLoopGuard,
}

impl Drop for ProxyListenerBinding {
    fn drop(&mut self) {
        *self
            .guard
            .state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = ProxyListenerState::Closed;
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
    fn services_without_tcp_proxy_do_not_restrict_upstream_connections() {
        let guard = ProxyLoopGuard::new(None);
        assert!(guard
            .check_destination("127.0.0.1:49".parse().unwrap())
            .is_ok());
    }
}
