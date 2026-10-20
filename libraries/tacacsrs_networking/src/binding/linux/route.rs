//! No-send FIB lookups for local route availability and VRF isolation.

use std::io;
use std::net::SocketAddr;

use anyhow::Context;
use futures_util::TryStreamExt;
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::route::{RouteAttribute, RouteFlags, RouteMessage, RouteType};

use crate::binding::{unavailable, Scope};

// IANA IP protocol number for TCP. The lookup must use TCP policy rules.
const IPPROTO_TCP: u8 = 6;

pub(super) async fn verify(
    handle: &rtnetlink::Handle,
    destination: SocketAddr,
    local: SocketAddr,
    device: Option<u32>,
    vrf_table: Option<u32>,
) -> anyhow::Result<()> {
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
    message.header.flags = RouteFlags::FibMatch | RouteFlags::LookupTable;
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
    if let Some(device) = device {
        message.attributes.push(RouteAttribute::Oif(device));
    }
    let route = handle
        .route()
        .get(message)
        .execute()
        .try_next()
        .await
        .map_err(|error| match error {
            rtnetlink::Error::NetlinkError(message) => {
                let error = message.to_io();
                if error.kind() == io::ErrorKind::AddrNotAvailable {
                    unavailable(
                        if local.ip().is_unspecified() {
                            Scope::Route
                        } else {
                            Scope::Source
                        },
                        error,
                    )
                } else if matches!(
                    error.kind(),
                    io::ErrorKind::NetworkUnreachable
                        | io::ErrorKind::HostUnreachable
                        | io::ErrorKind::NotFound
                        | io::ErrorKind::NetworkDown
                ) {
                    unavailable(Scope::Route, error)
                } else {
                    anyhow::Error::new(error).context("inspect the local TCP route")
                }
            }
            error => anyhow::Error::new(error).context("inspect the local TCP route"),
        })?
        .context("local route lookup returned no result")?;
    let table = route
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            RouteAttribute::Table(table) => Some(*table),
            _ => None,
        })
        .unwrap_or(u32::from(route.header.table));
    if vrf_table.is_some_and(|expected| table != expected) {
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
                "The local FIB route does not permit unicast traffic",
            ),
        ));
    }
    Ok(())
}
