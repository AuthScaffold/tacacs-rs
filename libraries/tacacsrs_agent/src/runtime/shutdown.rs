//! Process shutdown signal handling for the long-lived agent runtime.

/// Waits for a process termination signal that should stop the service from
/// accepting new IPC clients.
///
/// Unix builds listen for both `SIGTERM` and Ctrl-C. Other platforms fall back
/// to Ctrl-C only.
pub(crate) async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        if let Ok(mut terminate_signal) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    log::info!("Received Ctrl-C; initiating graceful shutdown");
                }
                _ = terminate_signal.recv() => {
                    log::info!("Received SIGTERM; initiating graceful shutdown");
                }
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
            log::info!("Received Ctrl-C; initiating graceful shutdown");
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        log::info!("Received Ctrl-C; initiating graceful shutdown");
    }
}
