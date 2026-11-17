//! Process adapters composed around the source-driven agent runtime.

use std::path::PathBuf;

use tokio_util::sync::CancellationToken;

use tacacsrs_agent::{AgentRuntime, RuntimeInputs, RuntimePeer};
use tacacsrs_config::local_services::ListenerEndpoint;

use crate::client_api_listener;
use crate::host_integration::HostIntegration;
use crate::profiles::SelectedProfile;
use crate::statistics::StatisticsFile;

pub(crate) async fn run_until(
    profile: SelectedProfile,
    stop: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    let cancellation = CancellationToken::new();
    let _cancel_on_drop = cancellation.clone().drop_guard();
    let application = async {
        let prepared = tokio::select! {
            biased;
            () = cancellation.cancelled() => return Ok(()),
            prepared = prepare_service(profile) => prepared?,
        };
        let (runtime, peers) = prepared;
        let listeners = client_api_listener::client_api_listeners(runtime.service());
        runtime
            .run_until(cancellation.cancelled(), listeners, peers)
            .await
    };
    tokio::pin!(application);
    tokio::select! {
        biased;
        signal = stop => {
            cancellation.cancel();
            signal.and(application.await)
        },
        result = &mut application => result,
    }
}

pub(crate) async fn prepare_service(
    profile: SelectedProfile,
) -> anyhow::Result<(AgentRuntime, Vec<RuntimePeer>)> {
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
    let runtime = AgentRuntime::prepare(RuntimeInputs {
        source: profile.prepare.await?,
        policy: profile.policy,
        certificate_verification: profile.certificate_verification,
    })
    .await?;
    let prepared = runtime.prepared_local_services();
    if let Some(statistics) = &statistics_file {
        if let Some(path) = prepared.client_api() {
            statistics.protect_listener(path).await?;
        }
        if let Some(ListenerEndpoint::Unix(path)) = prepared.tacacs_proxy() {
            statistics.protect_listener(path).await?;
        }
    }
    let mut peers = vec![RuntimePeer::new("Host integration", move |context| {
        host_integration.run(context.health, context.cancellation)
    })];
    if let Some(file) = statistics_file {
        let service = runtime.service().clone();
        peers.push(RuntimePeer::new("Operational statistics", move |context| {
            file.run(service, context.cancellation)
        }));
    }
    Ok((runtime, peers))
}
