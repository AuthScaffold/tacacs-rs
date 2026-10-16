//! Internal runtime services.
//!
//! Each child module owns one service boundary for
//! [`crate::runtime::TacacsClientService`]. The boundaries are the local client
//! API and the raw TACACS+ proxy.

pub(crate) mod client_api;
pub(crate) mod tacacs_proxy;

/// Platform-specific listener settings shared by runtime services.
#[derive(Clone, Copy)]
pub(crate) struct ListenerOptions {
    socket_mode: u32,
    pub(crate) max_connections: usize,
    pub(crate) max_client_api_streams: u32,
    pub(crate) connection_lifetime: std::time::Duration,
}

impl ListenerOptions {
    pub(crate) fn new(prepared: &tacacsrs_config::local_services::PreparedLocalServices) -> Self {
        Self {
            socket_mode: prepared.unix_socket_mode(),
            max_connections: prepared.max_connections(),
            max_client_api_streams: prepared.max_client_api_streams(),
            connection_lifetime: prepared.connection_lifetime(),
        }
    }

    pub(crate) fn socket_mode(self) -> u32 {
        self.socket_mode
    }
}
