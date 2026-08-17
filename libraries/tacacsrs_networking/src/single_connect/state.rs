//! Single-connection capability state.

/// State of single-connection mode negotiation with the server.
///
/// The `TAC_PLUS_SINGLE_CONNECT_FLAG` in a response indicates whether the
/// TACACS+ server supports single-connection mode.
/// Until the first response arrives, support is unknown.
///
/// Graceful shutdown is signaled when a server removes the single-connect flag
/// from response packets after previously supporting it. The client stops
/// creating sessions on that connection, lets existing sessions drain, and then
/// closes the connection.
///
/// A transport disconnect is different from a graceful single-connection
/// shutdown. If a shared connection ends while this state is still `Supported`,
/// the owning client clears the cached connection, returns to `Initial`, and probes the
/// next fresh connection. This matters for load-balanced server pools: the next
/// backend can have different single-connection support. Thus, the client asks
/// again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SingleConnectionState {
    /// No session has been created yet. The first session can be created.
    #[default]
    Initial,
    /// A session has been created, and the first response has not arrived yet.
    Negotiating,
    /// The server supports single-connection mode.
    Supported,
    /// The server does not support single-connection mode or requested a drain.
    NotSupported,
}
