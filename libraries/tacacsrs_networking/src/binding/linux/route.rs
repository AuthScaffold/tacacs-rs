//! Separate policy-table and physical-device checks for bound TCP sockets.
//!
//! The source-bearing query uses the socket's device and TCP tuple to check
//! policy rules. Source-free full-route and resolved queries check physical egress.
//! IPv6 source-bearing queries do not model strict physical-device selection.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{ensure, Context};
use futures_util::TryStreamExt;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteMessage, RouteNextHopFlags, RouteType,
};

use crate::binding::{unavailable, Scope};

// IANA IP protocol number for TCP. All lookups must use TCP policy rules.
const IPPROTO_TCP: u8 = 6;

/// Policy inputs from the actual socket binding.
pub(super) struct PolicyContext {
    pub(super) device: Option<u32>,
    pub(super) vrf_table: Option<u32>,
    pub(super) source_scope: Scope,
}

impl PolicyContext {
    pub(super) async fn verify_member(
        &self,
        handle: &rtnetlink::Handle,
        destination: SocketAddr,
        local_port: u16,
        member: u32,
    ) -> anyhow::Result<()> {
        let local = unspecified_source(destination, local_port);
        // Older kernels can ignore the member constraint during ECMP selection.
        // A source-free hash can then differ from the pinned TCP source hash.
        let full_route = self
            .lookup_with_flags(handle, destination, local, RouteFlags::FibMatch)
            .await?;
        self.verify_table_and_type(&full_route)?;
        verify_full_egress(&full_route, member)?;
        let route = self.lookup(handle, destination, local).await?;
        self.verify_table_and_type(&route)?;
        verify_egress(&route, member)
    }

    pub(super) async fn select_source(
        &self,
        handle: &rtnetlink::Handle,
        destination: SocketAddr,
        local_port: u16,
    ) -> anyhow::Result<SocketAddr> {
        let route = self
            .lookup(handle, destination, unspecified_source(destination, local_port))
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
        self.lookup_with_flags(handle, destination, local, RouteFlags::empty())
            .await
    }

    async fn lookup_with_flags(
        &self,
        handle: &rtnetlink::Handle,
        destination: SocketAddr,
        local: SocketAddr,
        flags: RouteFlags,
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
        message.header.flags = RouteFlags::LookupTable | flags;
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
            message.attributes.push(RouteAttribute::Oif(device));
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
        if self.vrf_table.is_some_and(|expected| table != expected) {
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

fn unspecified_source(destination: SocketAddr, port: u16) -> SocketAddr {
    let ip = if destination.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    SocketAddr::new(ip, port)
}

fn verify_full_egress(route: &RouteMessage, expected: u32) -> anyhow::Result<()> {
    ensure!(
        !route.header.flags.contains(RouteFlags::Cloned),
        "FIB-match lookup returned a resolved route instead of a full route"
    );
    ensure!(
        !route
            .attributes
            .iter()
            .any(|attribute| matches!(attribute, RouteAttribute::NhId(_))),
        "nexthop-ID route cannot prove the selected TCP egress"
    );
    verify_egress(route, expected)
}

fn verify_egress(route: &RouteMessage, expected: u32) -> anyhow::Result<()> {
    // Local delivery has no physical output interface.
    if route.header.kind == RouteType::Local {
        return Ok(());
    }
    if let Some(hops) = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::MultiPath(hops) => Some(hops),
            _ => None,
        })
    {
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
        ensure!(
            !(matching && other),
            "mixed-device multipath cannot prove the selected TCP egress"
        );
        if matching {
            return Ok(());
        }
    } else {
        let actual = route
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                RouteAttribute::Oif(index) if *index != 0 => Some(*index),
                _ => None,
            })
            .context("resolved route omitted its output interface")?;
        if actual == expected {
            return Ok(());
        }
    }
    Err(unavailable(
        Scope::Route,
        io::Error::new(
            io::ErrorKind::NetworkUnreachable,
            "The local FIB route uses a different output interface",
        ),
    ))
}

#[cfg(test)]
mod tests {
    use rtnetlink::packet_route::route::RouteNextHop;

    use super::*;

    #[test]
    fn older_kernel_resolved_ecmp_hop_does_not_prove_full_egress() {
        let mut resolved = RouteMessage::default();
        resolved.header.kind = RouteType::Unicast;
        resolved.header.flags = RouteFlags::Cloned;
        resolved.attributes.push(RouteAttribute::Oif(7));
        verify_egress(&resolved, 7).unwrap();
        assert!(verify_full_egress(&resolved, 7).is_err());

        let mut full = RouteMessage::default();
        full.header.kind = RouteType::Unicast;
        let mut member = RouteNextHop::default();
        member.interface_index = 7;
        let mut other = member.clone();
        other.interface_index = 8;
        full.attributes
            .push(RouteAttribute::MultiPath(vec![member.clone(), other]));
        assert!(verify_full_egress(&full, 7)
            .unwrap_err()
            .to_string()
            .contains("mixed-device multipath"));
        full.attributes = vec![RouteAttribute::MultiPath(vec![member])];
        verify_full_egress(&full, 7).unwrap();
        full.attributes = vec![RouteAttribute::Oif(7), RouteAttribute::NhId(42)];
        assert!(verify_full_egress(&full, 7)
            .unwrap_err()
            .to_string()
            .contains("nexthop-ID"));
        full.attributes.clear();
        assert!(verify_full_egress(&full, 7).is_err());
    }

    #[test]
    fn older_kernel_member_rewrite_cannot_approve_another_member() {
        let mut route = RouteMessage::default();
        route.header.kind = RouteType::Unicast;
        route.header.table = 100;
        route.attributes.push(RouteAttribute::Oif(8));
        let context = PolicyContext {
            device: Some(7),
            vrf_table: Some(100),
            source_scope: Scope::Source,
        };
        context.verify_table_and_type(&route).unwrap();
        assert!(verify_egress(&route, 7)
            .unwrap_err()
            .downcast_ref::<crate::binding::Unavailable>()
            .is_some());
        verify_egress(&route, 8).unwrap();
        route.attributes.clear();
        assert!(verify_egress(&route, 7).is_err());
        route.attributes.push(RouteAttribute::Oif(0));
        assert!(verify_egress(&route, 7).is_err());
        route.header.kind = RouteType::Local;
        verify_egress(&route, 7).unwrap();
    }

    #[test]
    fn unresolved_multipath_requires_every_live_hop_to_match() {
        let hop = |index, flags| {
            let mut hop = RouteNextHop::default();
            hop.interface_index = index;
            hop.flags = flags;
            hop
        };
        let mut route = RouteMessage::default();
        for flags in [RouteNextHopFlags::empty(), RouteNextHopFlags::Linkdown] {
            route.attributes = vec![RouteAttribute::MultiPath(vec![
                hop(7, RouteNextHopFlags::empty()),
                hop(8, flags),
            ])];
            let error = verify_egress(&route, 7).unwrap_err();
            assert!(error.to_string().contains("mixed-device multipath"));
            assert!(error
                .downcast_ref::<crate::binding::Unavailable>()
                .is_none());
        }
        route.attributes = vec![RouteAttribute::MultiPath(vec![
            hop(7, RouteNextHopFlags::empty()),
            hop(8, RouteNextHopFlags::Dead),
        ])];
        verify_egress(&route, 7).unwrap();
        assert!(verify_egress(&route, 8).is_err());
        for hops in [
            vec![],
            vec![hop(8, RouteNextHopFlags::Dead)],
            vec![hop(0, RouteNextHopFlags::empty())],
        ] {
            route.attributes = vec![RouteAttribute::MultiPath(hops)];
            assert!(verify_egress(&route, 7).is_err());
        }
    }
}
