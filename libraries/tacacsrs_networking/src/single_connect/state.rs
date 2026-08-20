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
