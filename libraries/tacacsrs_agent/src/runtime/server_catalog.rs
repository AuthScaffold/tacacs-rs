//! Runtime extraction of configured TACACS+ upstream servers.

use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt, TacacsPlusServerType};

pub(crate) const REQUIRED_SERVER_TYPES: TacacsPlusServerType = TacacsPlusServerType::AUTHENTICATION
    .union(TacacsPlusServerType::AUTHORIZATION)
    .union(TacacsPlusServerType::ACCOUNTING);

pub(crate) fn enumerate_supported_servers(
    config: &tacacsrs_config::TacacsPlus,
) -> anyhow::Result<Vec<TacacsPlusServer>> {
    let servers = tacacsrs_config::enumerate_servers(config)?;
    Ok(servers
        .into_iter()
        .filter(|server| server.supports_server_type(REQUIRED_SERVER_TYPES))
        .collect::<Vec<_>>())
}
