//! Separate policy-table and physical-device checks for bound TCP sockets.
//!
//! The source-bearing query uses the socket's device and TCP tuple to check
//! policy rules and physical egress. IPv6 source-free queries can supplement
//! physical evidence, but cannot override the pinned flow's policy table.

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
        local: SocketAddr,
        member: u32,
    ) -> anyhow::Result<()> {
        let full_route = self
            .lookup_with_flags(handle, destination, local, RouteFlags::FibMatch)
            .await?;
        self.verify_table_and_type(&full_route)?;
        let route = self.lookup(handle, destination, local).await?;
        self.verify_table_and_type(&route)?;
        let error = match verify_full_egress(&full_route, member) {
            Ok(()) => return verify_egress(&route, member),
            Err(error) if destination.is_ipv4() => return Err(error),
            Err(error) => error,
        };
        // Ambiguous ECMP and incomplete replies never become alternate evidence.
        if error
            .downcast_ref::<crate::binding::Unavailable>()
            .is_none()
        {
            return Err(error);
        }
        Self::verify_source_independent(&full_route)?;
        // A source-bearing IPv6 query lacks the socket's strict-device flag.
        // Source-free evidence is useful only within the pinned policy table.
        let local = unspecified_source(destination, local.port());
        let physical = match self
            .lookup_with_flags(handle, destination, local, RouteFlags::FibMatch)
            .await
        {
            Ok(route) => route,
            Err(error) => {
                return Err(Self::source_free_error(
                    handle,
                    error,
                    destination,
                    &full_route,
                    member,
                )
                .await);
            }
        };
        ensure!(
            route_table(&physical) == route_table(&full_route),
            "IPv6 physical egress is unverifiable across source-dependent policy tables"
        );
        self.verify_table_and_type(&physical)?;
        verify_full_egress(&physical, member)?;
        let resolved = self
            .lookup(handle, destination, local)
            .await
            .map_err(|error| anyhow::anyhow!("IPv6 physical egress is unverifiable: {error}"))?;
        ensure!(
            route_table(&resolved) == route_table(&full_route),
            "IPv6 physical egress is unverifiable across source-dependent policy tables"
        );
        verify_egress(&resolved, member)
    }

    fn verify_source_independent(route: &RouteMessage) -> anyhow::Result<()> {
        ensure!(
            route.header.source_prefix_length == 0,
            "IPv6 source-specific route cannot prove the requested physical egress"
        );
        Ok(())
    }

    async fn source_free_error(
        handle: &rtnetlink::Handle,
        error: anyhow::Error,
        destination: SocketAddr,
        pinned: &RouteMessage,
        member: u32,
    ) -> anyhow::Error {
        // Without source rules, the two queries have identical policy inputs.
        // Otherwise, source-free absence does not prove absence for the TCP flow.
        match handle
            .rule()
            .get(rtnetlink::IpVersion::V6)
            .execute()
            .try_collect::<Vec<_>>()
            .await
        {
            Ok(rules) if rules.iter().all(|rule| rule.header.src_len == 0) => {}
            _ => {
                return anyhow::anyhow!(
                    "IPv6 physical egress is unverifiable with source-dependent policy: {error}"
                )
            }
        }
        // A legacy member rewrite can also cause a source-free lookup error.
        // Do not call that a missing route when a member route exists.
        let mut request = RouteMessage::default();
        request.header.address_family = AddressFamily::Inet6;
        match handle
            .route()
            .get(request)
            .execute()
            .try_collect::<Vec<_>>()
            .await
        {
            Ok(routes)
                if !routes.iter().any(|route| {
                    route_table(route) == route_table(pinned)
                        && ipv6_destination_matches(route, destination.ip())
                        && verify_egress(route, member).err().is_none_or(|error| {
                            error
                                .downcast_ref::<crate::binding::Unavailable>()
                                .is_none()
                        })
                }) =>
            {
                error
            }
            _ => anyhow::anyhow!(
                "IPv6 physical egress is unverifiable despite an available member route: {error}"
            ),
        }
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
        let table = route_table(route);
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

fn route_table(route: &RouteMessage) -> u32 {
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(route.header.table))
}

fn ipv6_destination_matches(route: &RouteMessage, destination: IpAddr) -> bool {
    let IpAddr::V6(destination) = destination else {
        return true;
    };
    let length = route.header.destination_prefix_length;
    if length == 0 || length > 128 {
        return true;
    }
    route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Destination(RouteAddress::Inet6(prefix)) => Some(
                u128::from(*prefix) >> (128 - length) == u128::from(destination) >> (128 - length),
            ),
            _ => None,
        })
        .unwrap_or(true)
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
    fn source_specific_alternate_member_is_not_source_free_evidence() {
        let mut pinned = RouteMessage::default();
        pinned.header.kind = RouteType::Unicast;
        pinned.header.table = 100;
        pinned.header.source_prefix_length = 64;
        pinned.attributes = vec![
            RouteAttribute::Source("2001:db8:1::".parse::<Ipv6Addr>().unwrap().into()),
            RouteAttribute::Oif(8),
        ];
        let mut source_free = pinned.clone();
        source_free.header.source_prefix_length = 0;
        source_free.attributes = vec![RouteAttribute::Oif(7)];
        verify_full_egress(&source_free, 7).unwrap();
        assert!(verify_full_egress(&pinned, 7).is_err());
        let error = PolicyContext::verify_source_independent(&pinned).unwrap_err();
        assert!(error.to_string().contains("source-specific route"));
        assert!(error
            .downcast_ref::<crate::binding::Unavailable>()
            .is_none());
        PolicyContext::verify_source_independent(&source_free).unwrap();
        verify_full_egress(&pinned, 8).unwrap();
    }

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
