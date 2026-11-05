//! Environment-only KubeSONiC composition and optional registration supervision.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::ValueEnum;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use tacacsrs_agent::{
    RuntimeHealthPublisher, RuntimeHealthSnapshot, RuntimePolicy, ServiceConfig,
    TacacsClientService,
};
use tacacsrs_config::source::ConfigDatastore;
use tacacsrs_kubesonic::credentials::MountedCredentials;
use tacacsrs_kubesonic::datastore::KubeSonicConfigDb;
use tacacsrs_kubesonic::environment::Environment;
use tacacsrs_kubesonic::registration::LoopbackRegistration;
use tacacsrs_networking::CertificateVerification;

use crate::cli::HostIntegrationMode;
use crate::config_filter::config_filter_from_local_services;
use crate::host_integration::HostIntegration;
use crate::statistics::StatisticsFile;
use crate::supervision::PreparedService;

pub(crate) struct Registrar {
    row: LoopbackRegistration,
    retry: Duration,
}

pub(crate) async fn prepare(input: Environment) -> anyhow::Result<PreparedService> {
    let loopback = if input.loopback.enabled {
        let endpoint: SocketAddr = input
            .local_services
            .tacacs_proxy_endpoint
            .as_deref()
            .context("Registration requires a proxy endpoint")?
            .parse()?;
        Some(Registrar {
            row: LoopbackRegistration::new(
                input.source.clone(),
                input.loopback.priority,
                endpoint.port(),
            ),
            retry: input.loopback.retry_interval,
        })
    } else {
        None
    };
    let statistics_file = if let Some(path) = &input.process.statistics_file {
        let protected = [
            input.credentials.certificate.as_path(),
            input.credentials.key.as_path(),
            input.credentials.ca_file.as_path(),
            input.credentials.ca_directory.as_path(),
        ];
        let statistics = StatisticsFile::new(path, &protected).await?;
        let prepared =
            tacacsrs_config::local_services::prepare_local_services(&input.local_services)?;
        if let Some(path) = prepared.client_api() {
            statistics.protect_listener(path).await?;
        }
        if let Some(tacacsrs_config::local_services::ListenerEndpoint::Unix(path)) =
            prepared.tacacs_proxy()
        {
            statistics.protect_listener(path).await?;
        }
        Some(statistics)
    } else {
        None
    };
    let datastore = Arc::new(KubeSonicConfigDb::new(input.source)?);
    let provider = Arc::new(MountedCredentials::new(input.credentials));
    let config_filter = config_filter_from_local_services(&input.local_services)?;
    let config = ServiceConfig {
        local_services: input.local_services,
        validation_options: datastore.validation_options(),
        runtime_policy: RuntimePolicy::try_from(&input.runtime_policy)?,
        certificate_verification: CertificateVerification::Required,
    };
    let health = RuntimeHealthPublisher::new(config.enabled_services());
    let service = Arc::new(TacacsClientService::new(config, health.clone())?);
    let host_mode = HostIntegrationMode::from_str(&input.process.host_integration, false)
        .map_err(|_| anyhow::anyhow!("Invalid KubeSONiC host integration mode"))?;
    Ok(PreparedService {
        datastore,
        service,
        health,
        config_filter,
        credential_provider: (Some(provider.clone()), Some(provider)),
        host_integration: HostIntegration::from_environment(host_mode)?,
        policy_observation: None,
        statistics_file,
        loopback,
    })
}

pub(crate) async fn run_registration(
    registrar: Option<Registrar>,
    mut health: watch::Receiver<RuntimeHealthSnapshot>,
    cancellation: CancellationToken,
) -> anyhow::Result<()> {
    let Some(mut registrar) = registrar else {
        cancellation.cancelled().await;
        return Ok(());
    };
    let mut initialized = false;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let ready = health.borrow_and_update().is_readiness_serving();
        let operation = async {
            if !initialized {
                registrar.row.remove_stale().await?;
                initialized = true;
            }
            if cancellation.is_cancelled() {
                return Ok(());
            }
            registrar.row.reconcile(ready).await
        };
        if operation.await.is_err() {
            log::warn!("Loopback registration is unavailable; retrying");
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            changed = health.changed() => { changed.context("Runtime health publisher stopped")?; }
            () = tokio::time::sleep(registrar.retry) => {}
        }
    }
    registrar
        .row
        .cleanup()
        .await
        .context("Failed to clean up the owned loopback row")
}
