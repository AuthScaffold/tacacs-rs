//! Selection of the host-wide components of the daemon.
//!
//! A host-wide component is an optional part of the daemon that does not
//! depend on the selected source, for example systemd notification. The
//! components are in `tacacsrs_agent::components`. Selection reads only
//! [`HostInputs`], gives each component its settings, and makes no I/O.
//!
//! To add a host-wide component, add its selection function to
//! [`HOST_COMPONENTS`].

use std::path::PathBuf;
use std::time::Duration;

use tacacsrs_agent::components::{
    ClientApiComponent, HttpCredentialComponent, HttpEvidenceSettings,
    InvalidSourceShutdownComponent, StatisticsComponent, SystemdComponent, SystemdMode,
    UpstreamWatchdogComponent,
};
use tacacsrs_composition::Component;

use crate::cli::HostIntegrationMode;
use crate::process::ProcessOptions;

/// Process inputs that host-wide component selection reads.
pub(crate) struct HostInputs {
    pub(crate) process: ProcessOptions,
    pub(crate) statistics_file: Option<PathBuf>,
    pub(crate) upstream_watchdog_interval: Option<Duration>,
    pub(crate) protected_inputs: Vec<PathBuf>,
    pub(crate) http_evidence: HttpEvidenceSettings,
}

/// Selects one host-wide component, or none.
pub(crate) type Select = fn(&HostInputs) -> anyhow::Result<Option<Box<dyn Component>>>;

/// The host-wide components, in registration order.
pub(crate) const HOST_COMPONENTS: &[Select] = &[
    select_systemd,
    select_statistics,
    select_client_api,
    select_http_evidence,
    select_upstream_watchdog,
    select_invalid_source_shutdown,
];

/// Selects systemd notification unless the mode is `none`.
#[expect(clippy::unnecessary_wraps, reason = "Every selection function has the Select signature")]
fn select_systemd(host: &HostInputs) -> anyhow::Result<Option<Box<dyn Component>>> {
    let mode = match host.process.host_integration {
        HostIntegrationMode::None => return Ok(None),
        HostIntegrationMode::Auto => SystemdMode::Auto,
        HostIntegrationMode::Systemd => SystemdMode::Required,
    };
    Ok(Some(Box::new(SystemdComponent::new(mode))))
}

/// Selects statistics publication when a statistics file is configured.
#[expect(clippy::unnecessary_wraps, reason = "Every selection function has the Select signature")]
fn select_statistics(host: &HostInputs) -> anyhow::Result<Option<Box<dyn Component>>> {
    Ok(host.statistics_file.as_ref().map(|path| {
        Box::new(StatisticsComponent::new(path.clone(), host.protected_inputs.clone()))
            as Box<dyn Component>
    }))
}

/// Selects the client API listener. It binds only when the local services
/// enable the client API.
#[expect(clippy::unnecessary_wraps, reason = "Every selection function has the Select signature")]
fn select_client_api(_: &HostInputs) -> anyhow::Result<Option<Box<dyn Component>>> {
    Ok(Some(Box::new(ClientApiComponent)))
}

/// Selects the HTTP credential evidence layer when a source is registered.
#[expect(clippy::unnecessary_wraps, reason = "Every selection function has the Select signature")]
fn select_http_evidence(host: &HostInputs) -> anyhow::Result<Option<Box<dyn Component>>> {
    Ok((!host.http_evidence.is_empty()).then(|| {
        Box::new(HttpCredentialComponent::new(host.http_evidence.clone())) as Box<dyn Component>
    }))
}

/// Selects the upstream watchdog when a probe interval is configured.
fn select_upstream_watchdog(host: &HostInputs) -> anyhow::Result<Option<Box<dyn Component>>> {
    host.upstream_watchdog_interval
        .map(|interval| {
            UpstreamWatchdogComponent::new(interval)
                .map(|component| Box::new(component) as Box<dyn Component>)
        })
        .transpose()
}

/// Selects the shutdown on a final source rejection.
///
/// The daemon always selects this component. A static configuration that the
/// runtime rejects cannot change, so the process exits with a failure status.
#[expect(clippy::unnecessary_wraps, reason = "Every selection function has the Select signature")]
fn select_invalid_source_shutdown(_: &HostInputs) -> anyhow::Result<Option<Box<dyn Component>>> {
    Ok(Some(Box::new(InvalidSourceShutdownComponent)))
}

/// Selects the host-wide components.
///
/// # Errors
/// Returns a selection error.
pub(crate) fn select(host: &HostInputs) -> anyhow::Result<Vec<Box<dyn Component>>> {
    let mut components = Vec::new();
    for select in HOST_COMPONENTS {
        components.extend(select(host)?);
    }
    Ok(components)
}
