//! Runtime extraction of configured TACACS+ servers.

use tacacsrs_config::TacacsPlusServer;
#[cfg(test)]
use tacacsrs_config::TacacsPlusServerType;

#[cfg(test)]
pub(crate) const REQUIRED_SERVER_TYPES: TacacsPlusServerType = TacacsPlusServerType::AUTHENTICATION
    .union(TacacsPlusServerType::AUTHORIZATION)
    .union(TacacsPlusServerType::ACCOUNTING);

pub(crate) fn enumerate_supported_servers(
    config: &tacacsrs_config::TacacsPlus,
) -> anyhow::Result<Vec<TacacsPlusServer>> {
    tacacsrs_config::enumerate_servers(config)
}
