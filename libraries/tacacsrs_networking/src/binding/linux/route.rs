//! Kernel source selection and resolved route checks for a pinned TCP tuple.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{ensure, Context};
use futures_util::TryStreamExt;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteNextHopFlags, RouteType,
};

use crate::binding::{unavailable, Scope};

// IANA IP protocol number for TCP. Both lookups must use TCP policy rules.
const IPPROTO_TCP: u8 = 6;

/// One socket device binding, not an interface plus a second VRF binding.
#[derive(Clone, Copy)]
pub(super) enum Device {
    Interface(u32),
    Vrf(u32),
}

impl Device {
    fn index(self) -> u32 {
        match self {
            Self::Interface(index) | Self::Vrf(index) => index,
        }
    }
}

/// Runtime kernel facts and the source constraint that can be relaxed.
pub(super) struct RoutingContext {
    pub(super) device: Option<Device>,
    pub(super) vrf_table: Option<u32>,
    pub(super) source_scope: Scope,
}

impl RoutingContext {
    /// Selects a kernel source before the TCP socket receives an address or port.
    pub(super) async fn select_source(
        &self,
        handle: &rtnetlink::Handle,
        destination: SocketAddr,
    ) -> anyhow::Result<SocketAddr> {
        let unspecified = if destination.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        // Resolved lookups supply the selected source and output device.
        // FIB-match replies can instead describe a whole route or ECMP group.
        let route = self
            .lookup(handle, destination, SocketAddr::new(unspecified, 0))
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
                let index = output_interface(&route)
                    .filter(|index| *index != 0)
                    .context("kernel route lookup omitted the link-local source interface")?;
                source.set_scope_id(index);
            }
        }
        Ok(source)
    }

    /// Verifies the exact source and port that the TCP socket now owns.
    pub(super) async fn verify(
        &self,
        handle: &rtnetlink::Handle,
        destination: SocketAddr,
        local: SocketAddr,
    ) -> anyhow::Result<()> {
        ensure!(
            !local.ip().is_unspecified() && local.port() != 0,
            "TCP routing inputs must be pinned before final route validation"
        );
        let route = self.lookup(handle, destination, local).await?;
        self.verify_table_and_type(&route)?;
        // Local delivery has no physical egress. The VRF table check still applies.
        if route.header.kind != RouteType::Local {
            if let Some(Device::Interface(expected)) = self.device {
                verify_egress(&route, expected)?;
            }
        }
        Ok(())
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
        // LookupTable requests the actual selected table, not a default table label.
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
        if let Some(device) = self.device {
            message.attributes.push(RouteAttribute::Oif(device.index()));
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
                        unavailable_route(error)
                    } else {
                        anyhow::Error::new(error).context("inspect the local TCP route")
                    }
                }
                error => anyhow::Error::new(error).context("inspect the local TCP route"),
            })?
            .context("local route lookup returned no result")
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
        if self.vrf_table.is_some_and(|expected| table != expected) {
            return Err(unavailable_route(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "No local route in the selected VRF. The lookup fell through to another table",
            )));
        }
        if !matches!(route.header.kind, RouteType::Unicast | RouteType::Local) {
            return Err(unavailable_route(io::Error::new(
                io::ErrorKind::NetworkUnreachable,
                "The local FIB route does not permit unicast traffic",
            )));
        }
        Ok(())
    }
}

fn unavailable_route(cause: impl Into<anyhow::Error>) -> anyhow::Error {
    unavailable(Scope::Route, cause)
}

fn output_interface(route: &RouteMessage) -> Option<u32> {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Oif(index) => Some(*index),
            _ => None,
        })
}

fn verify_egress(route: &RouteMessage, expected: u32) -> anyhow::Result<()> {
    if let Some(hops) = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::MultiPath(hops) => Some(hops),
            _ => None,
        })
    {
        // A multipath reply does not identify the chosen hop.
        // Accept only when every live outcome has the required interface.
        let mut matching = false;
        let mut other = false;
        for hop in hops
            .iter()
            .filter(|hop| !hop.flags.contains(RouteNextHopFlags::Dead))
        {
            ensure!(hop.interface_index != 0, "multipath route omitted an output interface");
            if hop.interface_index == expected {
                matching = true;
            } else {
                other = true;
            }
        }
        if matching && other {
            anyhow::bail!("mixed-device multipath cannot prove the selected TCP egress");
        }
        if matching {
            return Ok(());
        }
    } else {
        let actual =
            output_interface(route).context("resolved route omitted its output interface")?;
        ensure!(actual != 0, "resolved route omitted its output interface");
        if actual == expected {
            return Ok(());
        }
    }
    Err(unavailable_route(io::Error::new(
        io::ErrorKind::NetworkUnreachable,
        "The local FIB route uses a different output interface",
    )))
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::route::RouteNextHop;

    use super::*;

    #[test]
    fn physical_output_metadata_requires_the_bound_interface() {
        let mut route = RouteMessage::default();
        route.header.kind = RouteType::Unicast;
        route.attributes.push(RouteAttribute::Oif(7));
        verify_egress(&route, 7).unwrap();
        assert!(verify_egress(&route, 8)
            .unwrap_err()
            .downcast_ref::<crate::binding::Unavailable>()
            .is_some());
    }

    #[test]
    fn unresolved_multipath_requires_all_live_hops_not_one_eligible_hop() {
        let hop = |index, flags| {
            let mut hop = RouteNextHop::default();
            hop.interface_index = index;
            hop.flags = flags;
            hop
        };
        let mut route = RouteMessage::default();
        route.attributes.push(RouteAttribute::MultiPath(vec![
            hop(7, RouteNextHopFlags::empty()),
            hop(7, RouteNextHopFlags::empty()),
            hop(8, RouteNextHopFlags::Dead),
        ]));
        verify_egress(&route, 7).unwrap();
        assert!(verify_egress(&route, 8)
            .unwrap_err()
            .downcast_ref::<crate::binding::Unavailable>()
            .is_some());
        route.attributes = vec![RouteAttribute::MultiPath(vec![
            hop(7, RouteNextHopFlags::empty()),
            hop(8, RouteNextHopFlags::empty()),
        ])];
        let error = verify_egress(&route, 7).unwrap_err();
        assert!(error.to_string().contains("mixed-device multipath"));
        assert!(error
            .downcast_ref::<crate::binding::Unavailable>()
            .is_none());
        route.attributes = vec![RouteAttribute::MultiPath(vec![
            hop(7, RouteNextHopFlags::empty()),
            hop(8, RouteNextHopFlags::Linkdown),
        ])];
        assert!(verify_egress(&route, 7)
            .unwrap_err()
            .downcast_ref::<crate::binding::Unavailable>()
            .is_none());
        route.attributes.clear();
        assert!(verify_egress(&route, 7)
            .unwrap_err()
            .downcast_ref::<crate::binding::Unavailable>()
            .is_none());
        route.attributes.push(RouteAttribute::Oif(0));
        assert!(verify_egress(&route, 7)
            .unwrap_err()
            .downcast_ref::<crate::binding::Unavailable>()
            .is_none());
    }
}
