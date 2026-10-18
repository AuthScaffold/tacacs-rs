//! Process signal registration for host-driven shutdown.
//!
//! The daemon registers SIGINT and SIGTERM once before it starts the async
//! bootstrap. [`ProcessSignals::wait`] resolves when either signal arrives. No
//! detached task observes the signals; the host owns the returned future.

use anyhow::Context;

/// Owns the registered SIGINT and SIGTERM streams for the process lifetime.
pub(crate) struct ProcessSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

impl ProcessSignals {
    /// Registers the termination signals before the async runtime starts work.
    ///
    /// # Errors
    /// Returns an error if the process cannot register a signal handler.
    pub(crate) fn register() -> anyhow::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt()).context("register SIGINT handler")?,
            terminate: signal(SignalKind::terminate()).context("register SIGTERM handler")?,
        })
    }

    /// Resolves when the host sends SIGINT or SIGTERM.
    ///
    /// # Errors
    /// Returns an error if a signal stream ends unexpectedly.
    pub(crate) async fn wait(mut self) -> anyhow::Result<()> {
        tokio::select! {
            signal = self.interrupt.recv() => { signal.context("SIGINT stream ended")?; }
            signal = self.terminate.recv() => { signal.context("SIGTERM stream ended")?; }
        }
        log::info!("Shutdown requested by the host");
        Ok(())
    }
}
