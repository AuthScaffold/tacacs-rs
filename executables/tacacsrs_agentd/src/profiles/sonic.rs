//! SONiC datastore, forwarder, and credential registration.

use std::sync::Arc;
use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_provider::{CredentialProvider, SourceBundle};
use tacacsrs_sonic::{SonicConfigDb, SonicConnection, SonicForwarderSettings};

use crate::cli::{Cli, ServiceMode};
use crate::credential_provider;
use crate::local_services;
use super::SelectedProfile;

fn connection(cli: &Cli) -> SonicConnection {
    let mut settings = SonicConnection::default();
    if let Some(url) = cli.matches.get_one::<String>("sonic_redis_url") {
        settings.url.clone_from(url);
    }
    if let Some(db) = cli.matches.get_one::<i64>("sonic_redis_db") {
        settings.db_index = *db;
    }
    settings
}

pub(crate) fn credentials(cli: &Cli) -> CredentialProvider {
    tacacsrs_sonic::credentials(&connection(cli))
}

pub(crate) fn local_services_from_cli(
    cli: &Cli,
    forwarder: Option<SonicForwarderSettings>,
) -> anyhow::Result<LocalServices> {
    anyhow::ensure!(
        cli.service_mode
            .is_none_or(|mode| mode == ServiceMode::Both),
        "SONiC central-agent mode requires --service-mode both"
    );
    let forwarder = forwarder
        .ok_or_else(|| anyhow::anyhow!("SONiC listener configuration requires a forwarder row"))?;
    if let Some(endpoint) = &cli.proxy_endpoint {
        anyhow::ensure!(
            endpoint.parse::<std::net::SocketAddr>().ok() == Some(forwarder.socket_address()),
            "CLI proxy endpoint conflicts with TACPLUS_FORWARDER|global"
        );
    }
    local_services::from_cli(cli, forwarder.local_services())
}

pub(crate) fn parse(cli: Cli) -> anyhow::Result<SelectedProfile> {
    anyhow::ensure!(
        cli.service_mode
            .is_none_or(|mode| mode == ServiceMode::Both),
        "SONiC central-agent mode requires --service-mode both"
    );
    Ok(SelectedProfile::from_cli(cli, |cli| async move {
        let settings = connection(&cli);
        let credentials = credential_provider::build(&cli, credentials(&cli)).await?;
        let forwarder = tacacsrs_sonic::wait_for_forwarder(&settings).await;
        Ok(SourceBundle {
            local_services: local_services_from_cli(&cli, Some(forwarder))?,
            datastore: Arc::new(SonicConfigDb::with_bound_forwarder(settings, forwarder)),
            credentials,
            companions: Vec::new(),
        })
    }))
}
