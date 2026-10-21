//! Single-connection capability state.

/// State of single-connection mode negotiation with the server.
///
/// The `TAC_PLUS_SINGLE_CONNECT_FLAG` in a response indicates whether the
/// TACACS+ server supports single-connection mode.
/// Until the first response arrives, support is unknown.
///
/// RFC 8907 makes the flag relevant only to the first request and first reply
/// on a connection. Later flag values do not change the negotiated state.
/// If a shared connection ends, the owning client clears the cached connection,
/// returns to `Initial`, and probes the next fresh connection. This matters for
/// load-balanced server pools because the next backend can have different
/// single-connection support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SingleConnectionState {
    /// No session has been created yet. The first session can be created.
    #[default]
    Initial,
    /// A session has been created, and the first response has not arrived yet.
    Negotiating,
    /// The server supports single-connection mode.
    Supported,
    /// The server did not confirm single-connection mode in the first reply.
    NotSupported,
}

pub(crate) struct NegotiationState {
    inner: std::sync::Mutex<(SingleConnectionState, u64)>,
}

impl NegotiationState {
    pub(crate) fn new(state: SingleConnectionState) -> Self {
        Self {
            inner: std::sync::Mutex::new((state, 0)),
        }
    }

    pub(crate) fn snapshot(&self) -> SingleConnectionState {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .0
    }

    pub(crate) fn begin(&self) -> Option<u64> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(
            state.0,
            SingleConnectionState::Negotiating | SingleConnectionState::NotSupported
        ) {
            return None;
        }
        state.1 = state.1.wrapping_add(1);
        state.0 = SingleConnectionState::Negotiating;
        Some(state.1)
    }

    pub(crate) fn update(&self, value: SingleConnectionState) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.1 = state.1.wrapping_add(1);
        state.0 = value;
    }

    pub(crate) fn abandon(&self, epoch: u64) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.1 == epoch && state.0 == SingleConnectionState::Negotiating {
            state.0 = SingleConnectionState::Initial;
        }
    }

    pub(crate) fn settle(&self, epoch: u64, supported: bool, publish: impl FnOnce()) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.1 == epoch && state.0 == SingleConnectionState::Negotiating {
            publish();
            state.0 = if supported {
                SingleConnectionState::Supported
            } else {
                SingleConnectionState::NotSupported
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abandoned_or_stale_probes_cannot_overwrite_newer_results() {
        for supported in [false, true] {
            let state = NegotiationState::new(SingleConnectionState::Initial);
            let previous_epoch = state.begin().unwrap();
            state.abandon(previous_epoch);
            assert_eq!(state.snapshot(), SingleConnectionState::Initial);
            let current = state.begin().unwrap();
            state.abandon(previous_epoch);
            state.settle(previous_epoch, true, || panic!("stale probes must not publish"));
            assert_eq!(state.snapshot(), SingleConnectionState::Negotiating);
            state.settle(current, supported, || {});
            state.abandon(current);
            assert_eq!(
                state.snapshot(),
                if supported {
                    SingleConnectionState::Supported
                } else {
                    SingleConnectionState::NotSupported
                }
            );
        }
    }
}
