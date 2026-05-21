//! Platform abstraction layer for session process mediation.

#[cfg_attr(all(target_os = "linux", target_arch = "x86_64"), path = "linux/mod.rs")]
#[cfg_attr(not(all(target_os = "linux", target_arch = "x86_64")), path = "mock.rs")]
mod imp;

use tacacsrs_agent_client::IpcEndpoint;

use crate::cli::Cli;

pub(crate) fn run_session(cli: Cli, service_endpoint: IpcEndpoint) -> anyhow::Result<()> {
    imp::run_session(cli, service_endpoint)
}
