//! Environment-only KubeSONiC process and source selection.

use clap::ValueEnum;

use tacacsrs_agent::PolicyInput;
use tacacsrs_agent::components::HttpEvidenceSettings;
use tacacsrs_kubesonic::environment::Environment;
use tacacsrs_networking::CertificateVerification;

use super::SelectedProfile;
use crate::cli::{Cli, HostIntegrationMode};
use crate::components::HostInputs;
use crate::process::{Logging, ProcessOptions};

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
    let host = HostInputs {
        process,
        statistics_file: input.process.statistics_file.clone(),
        upstream_watchdog_interval: input.process.upstream_watchdog_interval,
        protected_inputs: vec![
            input.credentials.certificate.clone(),
            input.credentials.key.clone(),
            input.credentials.ca_file.clone(),
            input.credentials.ca_directory.clone(),
        ],
        http_evidence: HttpEvidenceSettings::default(),
    };
    let policy = PolicyInput::Canonical(input.runtime_policy.clone());
    SelectedProfile::new(
        host,
        policy,
        CertificateVerification::Required,
        tacacsrs_kubesonic::components(input)?,
    )
}
