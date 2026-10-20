//! Linux device discovery through read-only, namespace-local route netlink.

use std::io;
use std::net::{IpAddr, SocketAddr};

use anyhow::ensure;
use futures_util::TryStreamExt;
use rtnetlink::packet_route::address::{AddressAttribute, AddressFlags, AddressMessage};
use rtnetlink::packet_route::link::{
    InfoData, InfoKind, InfoVrf, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use tokio::net::TcpSocket;

use super::{unavailable, LocalBinding, Scope, SourceBinding};

mod route;

pub(super) async fn apply(
    socket: &TcpSocket,
    destination: SocketAddr,
    binding: &LocalBinding,
) -> anyhow::Result<()> {
    let discovery_scope = if binding.egress_interface.is_some() {
        Some(Scope::Egress)
    } else if binding.vrf.is_some() {
        Some(Scope::Vrf)
    } else if matches!(binding.source, Some(SourceBinding::Interface(_))) {
        Some(Scope::Source)
    } else {
        None
    };
    let (connection, handle, _) = match rtnetlink::new_connection() {
        Ok(connection) => connection,
        Err(error) => match discovery_scope {
            Some(scope) => return Err(unavailable(scope, error)),
            None => {
                log::warn!("Local route inspection unavailable. Retaining the source binding without route fallback: {error}");
                let source = match binding.source {
                    Some(SourceBinding::Ip(ip)) => Some(SocketAddr::new(ip, 0)),
                    _ => None,
                };
                return bind_source(socket, source, Scope::Source);
            }
        },
    };
    // Cancellation drops both the netlink socket and its requests.
    tokio::select! {
        result = discover(socket, destination, binding, &handle) => result,
        () = connection => anyhow::bail!("local interface and route discovery stopped"),
    }
}

async fn discover(
    socket: &TcpSocket,
    destination: SocketAddr,
    binding: &LocalBinding,
    handle: &rtnetlink::Handle,
) -> anyhow::Result<()> {
    let vrf = match &binding.vrf {
        Some(name) => {
            let link = get_link(handle, name, Scope::Vrf).await?;
            ensure!(is_vrf(&link), "vrf-instance names a device that is not a VRF");
            Some(link)
        }
        None => None,
    };
    let egress = match &binding.egress_interface {
        Some(name) => {
            let link = get_link(handle, name, Scope::Egress).await?;
            verify_membership(&link, vrf.as_ref())?;
            Some(link)
        }
        None => None,
    };
    let implicit_vrf = if vrf.is_none() {
        match egress.as_ref() {
            Some(link) if is_vrf(link) => Some(link.clone()),
            Some(link) => match link
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    LinkAttribute::Controller(index) => Some(*index),
                    _ => None,
                }) {
                Some(index) => {
                    let master = handle
                        .link()
                        .get()
                        .match_index(index)
                        .execute()
                        .try_next()
                        .await
                        .map_err(|error| unavailable(Scope::Egress, netlink_error(error)))?
                        .ok_or_else(|| {
                            unavailable(
                                Scope::Egress,
                                anyhow::anyhow!("egress master device does not exist"),
                            )
                        })?;
                    if is_vrf(&master) && !master.header.flags.contains(LinkFlags::Up) {
                        return Err(unavailable(
                            Scope::Egress,
                            io::Error::new(io::ErrorKind::NetworkDown, "egress VRF device is down"),
                        ));
                    }
                    is_vrf(&master).then_some(master)
                }
                None => None,
            },
            None => None,
        }
    } else {
        None
    };
    let effective_vrf = vrf.as_ref().or(implicit_vrf.as_ref());
    let vrf_table = effective_vrf.map(vrf_table).transpose()?;
    let source = match &binding.source {
        Some(SourceBinding::Ip(ip)) => Some(SocketAddr::new(*ip, 0)),
        Some(SourceBinding::Interface(name)) => {
            let link = get_link(handle, name, Scope::Source).await?;
            verify_membership(&link, vrf.as_ref())?;
            let addresses: Vec<_> = handle
                .address()
                .get()
                .set_link_index_filter(link.header.index)
                .execute()
                .try_collect()
                .await
                .map_err(|error| unavailable(Scope::Source, netlink_error(error)))?;
            Some(select_source(&addresses, destination, link.header.index).ok_or_else(|| {
                unavailable(
                    Scope::Source,
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "source-interface has no usable address for the destination family",
                    ),
                )
            })?)
        }
        None => None,
    };
    // SO_BINDTODEVICE stores one device. Bind the member interface, not its VRF,
    // after membership checks. Linux then derives its associated VRF.
    if let Some(device) = binding
        .egress_interface
        .as_deref()
        .or(binding.vrf.as_deref())
    {
        socket
            .bind_device(Some(device.as_bytes()))
            .map_err(|error| {
                unavailable(
                    if egress.is_some() {
                        Scope::Egress
                    } else {
                        Scope::Vrf
                    },
                    error,
                )
            })?;
    }
    let device = egress.as_ref().or(vrf.as_ref()).map(|link| {
        if is_vrf(link) {
            route::Device::Vrf(link.header.index)
        } else {
            route::Device::Interface(link.header.index)
        }
    });
    let context = route::RoutingContext {
        device,
        vrf_table,
        source_scope: if binding.source.is_some() {
            Scope::Source
        } else {
            Scope::Route
        },
    };
    let source = match source {
        Some(source) => source,
        None => context.select_source(handle, destination).await?,
    };
    // A concrete bind prevents TCP from choosing a source and repeating policy
    // routing with inputs that differ from the verified flow.
    bind_source(socket, Some(source), context.source_scope)?;
    let local = socket.local_addr()?;
    match context.verify(handle, destination, local).await {
        Ok(()) => Ok(()),
        Err(error) if error.downcast_ref::<super::Unavailable>().is_some() => Err(error),
        Err(error) if device.is_none() => {
            // The source binding remains enforceable without a route query.
            // An inconclusive query never permits route-based fallback.
            log::warn!("Local route inspection failed. Retaining the source binding without route fallback: {error}");
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn bind_source(socket: &TcpSocket, source: Option<SocketAddr>, scope: Scope) -> anyhow::Result<()> {
    if let Some(source) = source {
        socket.bind(source).map_err(|error| {
            if matches!(
                error.kind(),
                io::ErrorKind::AddrNotAvailable | io::ErrorKind::PermissionDenied
            ) {
                unavailable(scope, error)
            } else {
                error.into()
            }
        })?;
    }
    Ok(())
}

fn is_vrf(link: &LinkMessage) -> bool {
    link.attributes.iter().any(|attribute| {
        matches!(attribute,
            LinkAttribute::LinkInfo(info) if info.contains(&LinkInfo::Kind(InfoKind::Vrf))
        )
    })
}

fn vrf_table(link: &LinkMessage) -> anyhow::Result<u32> {
    link.attributes
        .iter()
        .find_map(|attribute| match attribute {
            LinkAttribute::LinkInfo(info) => info.iter().find_map(|info| match info {
                LinkInfo::Data(InfoData::Vrf(data)) => data.iter().find_map(|data| match data {
                    InfoVrf::TableId(table) => Some(*table),
                    _ => None,
                }),
                _ => None,
            }),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("VRF routing table metadata is unavailable"))
}

fn verify_membership(link: &LinkMessage, vrf: Option<&LinkMessage>) -> anyhow::Result<()> {
    if let Some(vrf) = vrf {
        ensure!(
            link.header.index == vrf.header.index
                || link
                    .attributes
                    .contains(&LinkAttribute::Controller(vrf.header.index)),
            "interface does not belong to the configured vrf-instance"
        );
    }
    Ok(())
}

async fn get_link(
    handle: &rtnetlink::Handle,
    name: &str,
    scope: Scope,
) -> anyhow::Result<LinkMessage> {
    let link = handle
        .link()
        .get()
        .match_name(name.to_owned())
        .execute()
        .try_next()
        .await
        .map_err(|error| unavailable(scope, netlink_error(error)))?
        .ok_or_else(|| {
            unavailable(
                scope,
                io::Error::new(io::ErrorKind::NotFound, "local device does not exist"),
            )
        })?;
    if !link.header.flags.contains(LinkFlags::Up) {
        return Err(unavailable(
            scope,
            io::Error::new(io::ErrorKind::NetworkDown, "local device is down"),
        ));
    }
    Ok(link)
}

fn netlink_error(error: rtnetlink::Error) -> anyhow::Error {
    match error {
        rtnetlink::Error::NetlinkError(message) => message.to_io().into(),
        _ => anyhow::anyhow!("local interface discovery failed").context(error),
    }
}

fn select_source(
    addresses: &[AddressMessage],
    destination: SocketAddr,
    index: u32,
) -> Option<SocketAddr> {
    let mut candidates = Vec::new();
    for address in addresses {
        let flags = address
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Flags(flags) => Some(*flags),
                _ => None,
            })
            .unwrap_or_else(|| {
                AddressFlags::from_bits_retain(u32::from(address.header.flags.bits()))
            });
        if flags.intersects(
            AddressFlags::Tentative | AddressFlags::Dadfailed | AddressFlags::Deprecated,
        ) {
            continue;
        }
        // IPv4 point-to-point interfaces can report the peer in IFA_ADDRESS.
        let ip = address
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                AddressAttribute::Local(ip) => Some(*ip),
                _ => None,
            })
            .or_else(|| {
                address
                    .attributes
                    .iter()
                    .find_map(|attribute| match attribute {
                        AddressAttribute::Address(ip) => Some(*ip),
                        _ => None,
                    })
            });
        if let Some(ip) = ip {
            if ip.is_ipv4() != destination.is_ipv4() || ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            if let IpAddr::V6(ip) = ip {
                if ip.is_unicast_link_local()
                    != matches!(destination.ip(), IpAddr::V6(ip) if ip.is_unicast_link_local())
                {
                    continue;
                }
            }
            candidates.push(ip);
        }
    }
    // Stable selection avoids dependence on netlink enumeration order.
    candidates.sort_unstable();
    candidates.first().map(|ip| {
        let mut source = SocketAddr::new(*ip, 0);
        if let SocketAddr::V6(ref mut address) = source {
            if address.ip().is_unicast_link_local() {
                address.set_scope_id(index);
            }
        }
        source
    })
}
