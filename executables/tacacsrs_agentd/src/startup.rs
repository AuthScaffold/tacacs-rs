//! Shared construction from registered, canonical profile inputs.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;

use tacacsrs_agent::{RuntimeHealthPublisher, RuntimePolicy, ServiceConfig, TacacsClientService};
use tacacsrs_config::source::policy::{PolicyChange, PolicyFile, PolicyObservation};

use crate::config_filter::config_filter_from_local_services;
use crate::host_integration::HostIntegration;
use crate::profiles::{PolicySource, SelectedProfile};
use crate::statistics::StatisticsFile;
use crate::supervision::PreparedService;

pub(crate) async fn prepare_service(profile: SelectedProfile) -> anyhow::Result<PreparedService> {
    let statistics_file = match profile.statistics_file {
        Some(path) => Some(
            StatisticsFile::new(
                &path,
                &profile
                    .protected_inputs
                    .iter()
                    .map(PathBuf::as_path)
                    .collect::<Vec<_>>(),
            )
            .await?,
        ),
        None => None,
    };
    let host_integration = HostIntegration::from_environment(profile.process.host_integration)?;
    let components = profile.prepare.await?;
    let prepared =
        tacacsrs_config::local_services::prepare_local_services(&components.local_services)?;
    if let Some(statistics) = &statistics_file {
        if let Some(path) = prepared.client_api() {
            statistics.protect_listener(path).await?;
        }
        if let Some(tacacsrs_config::local_services::ListenerEndpoint::Unix(path)) =
            prepared.tacacs_proxy()
        {
            statistics.protect_listener(path).await?;
        }
    }
    let (runtime_policy, policy_observation) = match profile.policy {
        PolicySource::Canonical(policy) => (RuntimePolicy::try_from(&policy)?, None),
        PolicySource::File(path) => {
            let source = PolicyFile::new(&path)?;
            let mut observation = source.observe().await?;
            let Some(PolicyChange::Changed(policy)) = observation.next().await? else {
                anyhow::bail!("Initial runtime policy was rejected");
            };
            (RuntimePolicy::try_from(policy.as_ref())?, Some(observation))
        }
    };
    let config_filter = config_filter_from_local_services(&components.local_services)?;
    let config = ServiceConfig {
        local_services: components.local_services,
        validation_options: components.datastore.validation_options(),
        runtime_policy,
        certificate_verification: profile.certificate_verification,
    };
    let health = RuntimeHealthPublisher::new(config.enabled_services());
    let service = Arc::new(
        TacacsClientService::new(config, health.clone())
            .context("Failed to build TACACS+ client service configuration")?,
    );
    Ok(PreparedService {
        datastore: components.datastore,
        service,
        health,
        config_filter,
        credential_provider: components.credentials,
        host_integration,
        policy_observation,
        statistics_file,
        host_services: components.host_services,
    })
}
