//! Environment-only KubeSONiC process and source selection.

use clap::ValueEnum;
use futures_util::FutureExt;
use tacacsrs_kubesonic::environment::Environment;
use tacacsrs_networking::CertificateVerification;

use crate::cli::{Cli, HostIntegrationMode};
use crate::process::{Logging, ProcessOptions};
use super::{PolicySource, SelectedProfile};

pub(crate) fn parse(_cli: Cli) -> anyhow::Result<SelectedProfile> {
    from_environment(Environment::from_process()?)
}

fn from_environment(input: Environment) -> anyhow::Result<SelectedProfile> {
    let process = ProcessOptions {
        worker_threads: input.process.worker_threads,
        host_integration: HostIntegrationMode::from_str(&input.process.host_integration, false)
            .map_err(|_| anyhow::anyhow!("Invalid KubeSONiC host integration mode"))?,
        logging: Logging::explicit(input.process.log_filter.clone(), &input.process.log_style)?,
    };
    let protected_inputs = vec![
        input.credentials.certificate.clone(),
        input.credentials.key.clone(),
        input.credentials.ca_file.clone(),
        input.credentials.ca_directory.clone(),
    ];
    Ok(SelectedProfile {
        process,
        statistics_file: input.process.statistics_file.clone(),
        protected_inputs,
        policy: PolicySource::Canonical(input.runtime_policy.clone()),
        certificate_verification: CertificateVerification::Required,
        prepare: async move { tacacsrs_kubesonic::prepare(input) }.boxed(),
    })
}
