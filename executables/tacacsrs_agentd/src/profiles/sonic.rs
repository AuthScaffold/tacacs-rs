//! SONiC datastore, forwarder, and credential registration.

use std::sync::Arc;
use std::time::Duration;

use tacacsrs_config::tacacsrs::LocalServices;
use tacacsrs_credential_resolution::CredentialChangeSource;
use tacacsrs_sonic::{
    SonicConfigDb, SonicConnection, SonicForwarderSettings, SonicCredentialChangeSource,
    SonicCredentialResolver, SonicCredentialRoots, SonicCredentialPolicy,
};

use crate::cli::{Cli, ServiceMode};
use crate::credential_provider::{self, CredentialProvider};
use crate::local_services;
use super::{SelectedProfile, SourceComponents};

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
    let resolver = Arc::new(SonicCredentialResolver::reloadable(
        SonicCredentialRoots::default(), SonicCredentialPolicy::production_from_root_group(),
    ));
    let settings = connection(cli);
    let changes = settings.credential_watch_root.map(|root| {
        Arc::new(SonicCredentialChangeSource::new(root, settings.debounce)) as Arc<dyn CredentialChangeSource>
    });
    (Some(resolver), changes)
}

pub(crate) fn local_services_from_cli(
    cli: &Cli,
    forwarder: Option<SonicForwarderSettings>,
) -> anyhow::Result<LocalServices> {
    anyhow::ensure!(cli.service_mode.is_none_or(|mode| mode == ServiceMode::Both),
        "SONiC central-agent mode requires --service-mode both");
    let forwarder = forwarder.ok_or_else(|| anyhow::anyhow!("SONiC listener configuration requires a forwarder row"))?;
    if let Some(endpoint) = &cli.proxy_endpoint {
        anyhow::ensure!(endpoint.parse::<std::net::SocketAddr>().ok() == Some(forwarder.socket_address()),
            "CLI proxy endpoint conflicts with TACPLUS_FORWARDER|global");
    }
    local_services::from_cli(cli, forwarder.local_services())
}

pub(crate) fn parse(cli: Cli) -> anyhow::Result<SelectedProfile> {
    anyhow::ensure!(cli.service_mode.is_none_or(|mode| mode == ServiceMode::Both),
        "SONiC central-agent mode requires --service-mode both");
    Ok(SelectedProfile::from_cli(cli, |cli| async move {
        let settings = connection(&cli);
        let credentials = credential_provider::build(&cli, credentials(&cli)).await?;
        let mut delay = Duration::from_millis(250);
        let forwarder = loop {
            match settings.load_forwarder_settings().await {
                Ok(forwarder) => break forwarder,
                Err(_) => {
                    log::warn!("SONiC forwarder configuration is unavailable. The daemon retries before it binds.");
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2).min(Duration::from_secs(30));
                }
            }
        };
        Ok(SourceComponents {
            local_services: local_services_from_cli(&cli, Some(forwarder))?,
            datastore: Arc::new(SonicConfigDb::with_bound_forwarder(settings, forwarder)),
            credentials,
            host_services: Vec::new(),
        })
    }))
}
