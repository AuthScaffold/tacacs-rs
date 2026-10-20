//! Source-aware policy checks for VRF-master and source-only sockets.
//!
//! Physical-device routing uses the real bound TCP socket instead. IPv6
//! RTM_GETROUTE does not apply a socket's strict-device flag with an explicit
//! source, so it cannot prove that a physical TCP egress is unavailable.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{ensure, Context};
use futures_util::TryStreamExt;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteType,
};

use crate::binding::{unavailable, Scope};

// IANA IP protocol number for TCP. Both lookups must use TCP policy rules.
const IPPROTO_TCP: u8 = 6;

/// The lookup device and routing table of a Linux VRF.
pub(super) struct Vrf {
    pub(super) index: u32,
    pub(super) table: u32,
}

/// Policy inputs for a VRF-master socket or an unbound source-only socket.
pub(super) struct PolicyContext {
    pub(super) vrf: Option<Vrf>,
    pub(super) source_scope: Scope,
}

impl PolicyContext {
    pub(super) async fn select_source(
        &self,
        handle: &rtnetlink::Handle,
        destination: SocketAddr,
        local_port: u16,
    ) -> anyhow::Result<SocketAddr> {
        let unspecified = if destination.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        let route = self
            .lookup(handle, destination, SocketAddr::new(unspecified, local_port))
            .await?;
        self.verify_table_and_type(&route)?;
        let source = route
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::PrefSource(RouteAddress::Inet(source)) => Some(IpAddr::V4(*source)),
                RouteAttribute::PrefSource(RouteAddress::Inet6(source)) => {
                    Some(IpAddr::V6(*source))
                }
                _ => None,
            })
            .context("kernel route lookup did not identify an automatic source address")?;
        ensure!(
            source.is_ipv4() == destination.is_ipv4()
                && !source.is_unspecified()
                && !source.is_multicast(),
            "kernel route lookup returned an invalid automatic source address"
        );
        let mut source = SocketAddr::new(source, 0);
        if let SocketAddr::V6(ref mut source) = source {
            if source.ip().is_unicast_link_local() {
                let index = route
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        RouteAttribute::Oif(index) if *index != 0 => Some(*index),
                        _ => None,
                    })
                    .context("kernel route lookup omitted the link-local source interface")?;
                source.set_scope_id(index);
            }
        }
        Ok(source)
    }

    pub(super) async fn verify(
        &self,
        handle: &rtnetlink::Handle,
        destination: SocketAddr,
        local: SocketAddr,
    ) -> anyhow::Result<()> {
        ensure!(
            !local.ip().is_unspecified() && local.port() != 0,
            "TCP policy inputs must be pinned before VRF table validation"
        );
        self.verify_table_and_type(&self.lookup(handle, destination, local).await?)
    }

    async fn lookup(
        &self,
        handle: &rtnetlink::Handle,
        destination: SocketAddr,
        local: SocketAddr,
    ) -> anyhow::Result<RouteMessage> {
        let mut message = RouteMessage::default();
        message.header.address_family = if destination.is_ipv4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        };
        message.header.destination_prefix_length = if destination.is_ipv4() {
            32
        } else {
            128
        };
        message.header.flags = RouteFlags::LookupTable;
        message
            .attributes
            .push(RouteAttribute::Destination(destination.ip().into()));
        message
            .attributes
            .push(RouteAttribute::IpProto(IPPROTO_TCP));
        message
            .attributes
            .push(RouteAttribute::Dport(destination.port()));
        if !local.ip().is_unspecified() {
            message.header.source_prefix_length = message.header.destination_prefix_length;
            message
                .attributes
                .push(RouteAttribute::Source(local.ip().into()));
        }
        if local.port() != 0 {
            message.attributes.push(RouteAttribute::Sport(local.port()));
        }
        if let Some(vrf) = &self.vrf {
            message.attributes.push(RouteAttribute::Oif(vrf.index));
        }
        handle
            .route()
            .get(message)
            .execute()
            .try_next()
            .await
            .map_err(|error| match error {
                rtnetlink::Error::NetlinkError(message) => {
                    let error = message.to_io();
                    if error.kind() == io::ErrorKind::AddrNotAvailable {
                        unavailable(self.source_scope, error)
                    } else if matches!(
                        error.kind(),
                        io::ErrorKind::NetworkUnreachable
                            | io::ErrorKind::HostUnreachable
                            | io::ErrorKind::NotFound
                            | io::ErrorKind::NetworkDown
                    ) {
                        unavailable(Scope::Route, error)
                    } else {
                        anyhow::Error::new(error).context("inspect TCP policy routing")
                    }
                }
                error => anyhow::Error::new(error).context("inspect TCP policy routing"),
            })?
            .context("TCP policy lookup returned no result")
    }

    fn verify_table_and_type(&self, route: &RouteMessage) -> anyhow::Result<()> {
        let table = route
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Table(table) => Some(*table),
                _ => None,
            })
            .unwrap_or(u32::from(route.header.table));
        if self.vrf.as_ref().is_some_and(|vrf| table != vrf.table) {
            return Err(unavailable(
                Scope::Route,
                io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "No local route in the selected VRF. The lookup fell through to another table",
                ),
            ));
        }
        if !matches!(route.header.kind, RouteType::Unicast | RouteType::Local) {
            return Err(unavailable(
                Scope::Route,
                io::Error::new(
                    io::ErrorKind::NetworkUnreachable,
                    "The local policy route does not permit unicast traffic",
                ),
            ));
        }
        Ok(())
    }
}
