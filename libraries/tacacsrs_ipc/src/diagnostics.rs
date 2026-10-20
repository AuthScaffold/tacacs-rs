//! Bounded read-only operational data over the existing local IPC channel.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::{IpcEndpoint, proto};

/// Maximum UTF-8 JSON payload, leaving room for protobuf framing within the IPC limit.
pub const MAX_STATISTICS_BYTES: usize = 120 * 1024;

/// Host-supplied read-only operational snapshot. Implementations must bound copying and serialization.
pub trait DiagnosticsProvider: Send + Sync + 'static {
    /// Returns one generation-bound JSON document without upstream I/O.
    /// # Errors
    /// Returns an error for an invalid selection or an unavailable/bounded-out snapshot.
    fn statistics_json(&self, server: Option<&str>, maximum_bytes: usize)
        -> anyhow::Result<String>;
}

/// Reusable local diagnostics channel, independent of the AAA operation client.
#[derive(Debug, Clone)]
pub struct DiagnosticsClient {
    channel: tonic::transport::Channel,
}

impl DiagnosticsClient {
    /// Connects to a local agent endpoint.
    /// # Errors
    /// Returns an error if the local channel cannot be established.
    pub async fn connect(endpoint: IpcEndpoint) -> anyhow::Result<Self> {
        Ok(Self {
            channel: endpoint.connect_channel().await?,
        })
    }

    /// Fetches RFC 7951 operational JSON, optionally filtered by exact server name.
    /// # Errors
    /// Returns an error for rejected selection, unavailable service, or oversized output.
    pub async fn statistics_json(&self, server: Option<&str>) -> anyhow::Result<String> {
        let mut client = proto::diagnostics_client::DiagnosticsClient::new(self.channel.clone())
            .max_decoding_message_size(MAX_STATISTICS_BYTES + 1024);
        let result = client
            .statistics(proto::StatisticsRequest {
                server: server.map(str::to_owned),
            })
            .await?
            .into_inner()
            .yang_json;
        anyhow::ensure!(
            result.len() <= MAX_STATISTICS_BYTES,
            "Diagnostics response exceeds the byte limit"
        );
        Ok(result)
    }
}

pub(crate) struct DiagnosticsService(pub(crate) Option<Arc<dyn DiagnosticsProvider>>);

#[tonic::async_trait]
impl proto::diagnostics_server::Diagnostics for DiagnosticsService {
    async fn statistics(
        &self,
        request: Request<proto::StatisticsRequest>,
    ) -> Result<Response<proto::StatisticsReply>, Status> {
        let selection = request.into_inner().server;
        if selection
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > 1024)
        {
            return Err(Status::invalid_argument("Server name must contain 1 to 1024 bytes"));
        }
        let provider = self
            .0
            .as_ref()
            .ok_or_else(|| Status::unimplemented("Diagnostics are not supported by this host"))?;
        let json = provider
            .statistics_json(selection.as_deref(), MAX_STATISTICS_BYTES)
            .map_err(|_| {
                Status::failed_precondition(
                    "Statistics unavailable: unknown server or snapshot limits exceeded",
                )
            })?;
        if json.len() > MAX_STATISTICS_BYTES {
            return Err(Status::resource_exhausted("Diagnostics response exceeds the byte limit"));
        }
        Ok(Response::new(proto::StatisticsReply { yang_json: json }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::diagnostics_server::Diagnostics;

    struct Snapshot;
    impl DiagnosticsProvider for Snapshot {
        fn statistics_json(
            &self,
            server: Option<&str>,
            maximum_bytes: usize,
        ) -> anyhow::Result<String> {
            assert_eq!(maximum_bytes, MAX_STATISTICS_BYTES);
            match server {
                Some("large") => Ok(" ".repeat(MAX_STATISTICS_BYTES + 1)),
                Some("primary") => Ok("{}".to_owned()),
                _ => anyhow::bail!("private-provider-secret\n{}", "x".repeat(MAX_STATISTICS_BYTES)),
            }
        }
    }

    #[tokio::test]
    async fn diagnostics_are_filtered_and_bounded() {
        let service = DiagnosticsService(Some(Arc::new(Snapshot)));
        let query = |name: &str| {
            Request::new(proto::StatisticsRequest {
                server: Some(name.to_owned()),
            })
        };
        assert_eq!(
            service
                .statistics(query("primary"))
                .await
                .unwrap()
                .into_inner()
                .yang_json,
            "{}"
        );
        assert_eq!(
            service.statistics(query("large")).await.unwrap_err().code(),
            tonic::Code::ResourceExhausted
        );
        assert_eq!(
            service.statistics(query("")).await.unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
        let failure = service.statistics(query("missing")).await.unwrap_err();
        assert_eq!(failure.code(), tonic::Code::FailedPrecondition);
        assert!(!failure.message().contains("private-provider-secret"));
        assert!(!failure.message().contains('\n'));
        assert!(failure.message().len() < 256);
        assert_eq!(
            DiagnosticsService(None)
                .statistics(query("primary"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unimplemented
        );
    }
}
