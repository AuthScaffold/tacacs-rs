//! Classification of connection driver failures during shutdown joins.
//!
//! A multiplexed connection driver ends with an error when the transport or the
//! peer fails, for example after a truncated reply. Before the driver returns
//! that error, it logs the failure and closes every active session with it.
//! [`ConnectionFailure`] marks that delivered error so that an owner can tell it
//! apart from a task panic or another shutdown failure.

use std::fmt;

/// Marks a connection failure that the driver already delivered to its sessions.
///
/// The marker is added as `anyhow` context to the driver result. Use
/// [`ConnectionFailure::is_delivered`] to test an error from a shutdown join.
/// A join returns an unmarked error before a marked error, so a marked result
/// means that no other failure occurred in the joined scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionFailure;

impl ConnectionFailure {
    /// Returns `true` if `error` is only a connection failure that the driver delivered.
    #[must_use]
    pub fn is_delivered(error: &anyhow::Error) -> bool {
        error.downcast_ref::<Self>().is_some()
    }
}

impl fmt::Display for ConnectionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the TACACS+ connection failed")
    }
}

/// Keeps the most significant shutdown failure in `slot`.
///
/// An unmarked error replaces a delivered [`ConnectionFailure`]. Otherwise the
/// first error stays.
pub(crate) fn record_failure(slot: &mut Option<anyhow::Error>, error: anyhow::Error) {
    match slot {
        Some(current)
            if ConnectionFailure::is_delivered(current)
                && !ConnectionFailure::is_delivered(&error) =>
        {
            *current = error;
        }
        Some(_) => {}
        None => *slot = Some(error),
    }
}

/// Combines two join results and keeps the most significant failure.
pub(crate) fn combine_results(
    first: anyhow::Result<()>,
    second: anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut failure = None;
    for result in [first, second] {
        if let Err(error) = result {
            record_failure(&mut failure, error);
        }
    }
    failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivered() -> anyhow::Error {
        anyhow::anyhow!("failed to read TACACS+ packet header").context(ConnectionFailure)
    }

    #[test]
    fn marker_survives_outer_context() {
        let error = delivered().context("join upstream connection");

        assert!(ConnectionFailure::is_delivered(&error));
        assert!(!ConnectionFailure::is_delivered(&anyhow::anyhow!("join failed")));
    }

    #[test]
    fn unmarked_failure_replaces_delivered_failure() {
        let mut slot = None;
        record_failure(&mut slot, delivered());
        record_failure(&mut slot, anyhow::anyhow!("driver task panicked"));
        record_failure(&mut slot, delivered());

        let error = slot.expect("a failure was recorded");
        assert!(!ConnectionFailure::is_delivered(&error));
        assert_eq!(error.to_string(), "driver task panicked");
    }

    #[test]
    fn combined_results_prefer_unmarked_failure() {
        let combined = combine_results(Err(delivered()), Err(anyhow::anyhow!("join failed")));
        assert_eq!(combined.unwrap_err().to_string(), "join failed");

        let combined = combine_results(Ok(()), Err(delivered()));
        assert!(ConnectionFailure::is_delivered(&combined.unwrap_err()));
    }
}
