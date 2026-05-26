//! Shared operation helpers for [`ServiceState`].

use std::sync::atomic::Ordering;

use tacacsrs_config::TacacsPlusServerExt;
use tacacsrs_networking::SingleConnectionState;

use super::ServiceState;
use crate::upstream::UpstreamConnection;

impl ServiceState {
    pub(in crate::service::state) fn note_dedicated_single_connect_result(
        &self,
        index: usize,
        address: &str,
        single_connect_supported: bool,
    ) {
        if single_connect_supported
            && !self.servers[index]
                .single_connection_supported
                .swap(true, Ordering::Relaxed)
        {
            log::info!(
                "Server {address} supports single-connection mode; \
                 switching to shared connections for future requests",
            );
        }
    }

    /// Inspects the single-connection negotiation result on `connection` and
    /// updates the per-server flag in either direction.
    ///
    /// - [`Supported`](SingleConnectionState::Supported) → enables the shared
    ///   cached-connection path for future requests.
    /// - [`NotSupported`](SingleConnectionState::NotSupported) → reverts to
    ///   dedicated per-request connections (e.g. the server withdrew support
    ///   for traffic-shifting).
    /// - `Initial` / `Negotiating` — no actionable information yet.
    pub(in crate::service::state) async fn check_single_connection_negotiation(
        &self,
        index: usize,
        connection: &dyn UpstreamConnection,
    ) {
        match connection.single_connection_state().await {
            SingleConnectionState::Supported
                if !self.servers[index]
                    .single_connection_supported
                    .swap(true, Ordering::Relaxed) =>
            {
                log::info!(
                    "Server {} supports single-connection mode; \
                         switching to shared connections for future requests",
                    self.servers[index].server.socket_address(),
                );
            }
            SingleConnectionState::NotSupported
                if self.servers[index]
                    .single_connection_supported
                    .swap(false, Ordering::Relaxed) =>
            {
                log::info!(
                    "Server {} revoked single-connection support; \
                         switching to dedicated connections for future requests",
                    self.servers[index].server.socket_address(),
                );
            }
            // Initial or Negotiating — no actionable information yet.
            _ => {}
        }
    }
}
