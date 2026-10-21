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
    options: &tacacsrs_config::ValidationOptions,
) -> anyhow::Result<Vec<TacacsPlusServer>> {
    if !config.server.is_empty() {
        tacacsrs_config::validation::validate_config_with_options(config, options)?;
    }
    let servers = tacacsrs_config::enumerate_servers(config)?;
    tacacsrs_config::prepare::validate_materialized_servers(servers.iter(), options)?;
    Ok(servers)
}
