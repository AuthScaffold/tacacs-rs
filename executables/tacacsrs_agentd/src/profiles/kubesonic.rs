//! Environment-only KubeSONiC composition and optional registration supervision.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::ValueEnum;
use futures_util::FutureExt;
use tacacsrs_kubesonic::credentials::MountedCredentials;
use tacacsrs_kubesonic::datastore::KubeSonicConfigDb;
use tacacsrs_kubesonic::environment::Environment;
use tacacsrs_kubesonic::registration::LoopbackRegistration;
use tacacsrs_networking::CertificateVerification;

use crate::cli::{Cli, HostIntegrationMode};
use crate::host_service::{HostContext, HostService};
use crate::process::{Logging, ProcessOptions};
use super::{PolicySource, SelectedProfile, SourceComponents};

pub(crate) struct Registrar {
    row: LoopbackRegistration,
    retry: Duration,
}

pub(crate) fn parse(_cli: Cli) -> anyhow::Result<SelectedProfile> {
    from_environment(Environment::from_process()?)
}

fn from_environment(input: Environment) -> anyhow::Result<SelectedProfile> {
    let process = ProcessOptions {
        worker_threads: input.process.worker_threads,
        host_integration: HostIntegrationMode::from_str(&input.process.host_integration, false)
            .map_err(|_| anyhow::anyhow!("Invalid KubeSONiC host integration mode"))?,
        logging: Logging::explicit(input.process.log_filter, &input.process.log_style)?,
    };
    let protected_inputs = vec![
        input.credentials.certificate.clone(), input.credentials.key.clone(),
        input.credentials.ca_file.clone(), input.credentials.ca_directory.clone(),
    ];
    let host_services: Vec<Box<dyn HostService>> = if input.loopback.enabled {
        let endpoint: SocketAddr = input
            .local_services
            .tacacs_proxy_endpoint
            .as_deref()
            .context("Registration requires a proxy endpoint")?
            .parse()?;
        vec![Box::new(Registrar {
            row: LoopbackRegistration::new(
                input.source.clone(),
                input.loopback.priority,
                endpoint.port(),
            ),
            retry: input.loopback.retry_interval,
        })]
    } else {
        Vec::new()
    };
    Ok(SelectedProfile {
        process,
        statistics_file: input.process.statistics_file,
        protected_inputs,
        policy: PolicySource::Canonical(input.runtime_policy),
        certificate_verification: CertificateVerification::Required,
        prepare: async move {
            let datastore = Arc::new(KubeSonicConfigDb::new(input.source)?);
            let provider = Arc::new(MountedCredentials::new(input.credentials));
            Ok(SourceComponents {
                datastore,
                credentials: (Some(provider.clone()), Some(provider)),
                local_services: input.local_services,
                host_services,
            })
        }.boxed(),
    })
}

#[async_trait::async_trait]
impl HostService for Registrar {
    fn name(&self) -> &'static str { "Loopback registration" }

    async fn run(mut self: Box<Self>, context: HostContext) -> anyhow::Result<()> {
    let HostContext { mut health, cancellation } = context;
    let mut initialized = false;
    loop {
        if cancellation.is_cancelled() {
            break;
        }
        let ready = health.borrow_and_update().is_readiness_serving();
        let operation = async {
            if !initialized {
                self.row.remove_stale().await?;
                initialized = true;
            }
            if cancellation.is_cancelled() {
                return Ok(());
            }
            self.row.reconcile(ready).await
        };
        if operation.await.is_err() {
            log::warn!("Loopback registration is unavailable; retrying");
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => break,
            changed = health.changed() => { changed.context("Runtime health publisher stopped")?; }
            () = tokio::time::sleep(self.retry) => {}
        }
    }
    self.row
        .cleanup()
        .await
        .context("Failed to clean up the owned loopback row")
}
}
