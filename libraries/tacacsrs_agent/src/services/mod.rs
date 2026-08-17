//! Internal runtime services.
//!
//! Each child module owns one service boundary for
//! [`crate::runtime::TacacsClientService`]. The boundaries are the local client
//! API and the raw TACACS+ proxy.

use crate::config::ServiceConfig;

pub(crate) mod client_api;
pub(crate) mod tacacs_proxy;

/// Platform-specific listener settings shared by runtime services.
#[derive(Clone, Copy)]
pub(crate) struct ListenerOptions {
    #[cfg(unix)]
    socket_mode: u32,
}

impl ListenerOptions {
    pub(crate) fn from_config(config: &ServiceConfig) -> Self {
        #[cfg(unix)]
        {
            Self {
                socket_mode: config.socket_mode,
            }
        }

        #[cfg(not(unix))]
        {
            let _ = config;
            Self {}
        }
    }

    #[cfg(unix)]
    pub(crate) fn socket_mode(self) -> u32 {
        self.socket_mode
    }
}
