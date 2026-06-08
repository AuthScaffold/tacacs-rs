//! Minimal systemd status notifications for the agent daemon.

use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

/// Thin wrapper around the `systemd-notify` helper.
///
/// The daemon only uses this when `NOTIFY_SOCKET` is present, which means it
/// is running under a `Type=notify` unit. Initial empty-config startup sends a
/// status line without `READY=1`, keeping the unit in `activating` until a
/// TACACS+ server appears in the datastore.
#[derive(Debug, Default)]
pub(crate) struct SystemdNotifier {
    enabled: bool,
    ready_sent: AtomicBool,
}

impl SystemdNotifier {
    pub(crate) fn from_env() -> Self {
        Self {
            enabled: std::env::var_os("NOTIFY_SOCKET").is_some(),
            ready_sent: AtomicBool::new(false),
        }
    }

    pub(crate) fn publish_server_state(&self, server_count: usize) {
        if !self.enabled {
            return;
        }

        if server_count == 0 {
            self.notify(
                false,
                "Waiting for TACACS+ servers that support authentication, authorization, and accounting from SONiC ConfigDB",
            );
            return;
        }

        let ready = !self.ready_sent.swap(true, Ordering::AcqRel);
        let status = format!(
            "Serving with {server_count} TACACS+ upstream server(s) supporting authentication, authorization, and accounting"
        );
        self.notify(ready, &status);
    }

    fn notify(&self, ready: bool, status: &str) {
        let mut command = Command::new("systemd-notify");
        command.arg("--pid=parent");
        command.arg(format!("--status={status}"));
        if ready {
            command.arg("--ready");
        }

        match command.status() {
            Ok(exit_status) if exit_status.success() => {}
            Ok(exit_status) => {
                log::warn!(
                    "systemd-notify exited with status {exit_status} while publishing status '{status}'"
                );
            }
            Err(error) => {
                log::warn!(
                    "Failed to execute systemd-notify while publishing status '{status}': {error}"
                );
            }
        }
    }
}