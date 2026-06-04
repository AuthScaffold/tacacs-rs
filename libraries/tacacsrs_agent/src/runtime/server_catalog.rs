//! Runtime validation and extraction of configured TACACS+ upstream servers.

use anyhow::bail;
use tacacsrs_config::{TacacsPlusServer, TacacsPlusServerExt, TacacsPlusServerType};

use crate::config::ServiceConfig;

pub(crate) fn enumerate_accounting_servers(
    config: &ServiceConfig,
) -> anyhow::Result<Vec<TacacsPlusServer>> {
    let servers = tacacsrs_config::enumerate_servers(&config.tacacs_plus)?;
    let accounting_servers = servers
        .into_iter()
        .filter(|server| server.supports_server_type(TacacsPlusServerType::ACCOUNTING))
        .collect::<Vec<_>>();

    if accounting_servers.is_empty() {
        bail!("At least one accounting-capable TACACS+ server must be configured");
    }

    Ok(accounting_servers)
}
