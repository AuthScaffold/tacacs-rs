//! Mock PAL backend for targets that cannot mediate sessions with seccomp.

use anyhow::bail;
use tacacsrs_agent_client::IpcEndpoint;

use crate::cli::Cli;

/// Accepts the portable CLI contract but refuses to pretend to supervise processes.
pub(crate) fn run_session(cli: Cli, service_endpoint: IpcEndpoint) -> anyhow::Result<()> {
    let Cli { command, user, .. } = cli;
    let request = (command, user, service_endpoint);

    bail!(
        "session-wrapper process mediation is only supported on Linux x86_64; \
         mock PAL parsed command {:?} for user {:?} via {:?}, \
         but did not execute it",
        request.0,
        request.1,
        request.2,
    );
}
