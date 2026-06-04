//! Single-connection capability state.

/// Represents the state of single-connection mode negotiation with the server.
///
/// TACACS+ servers may or may not support single-connection mode. This is
/// indicated by the `TAC_PLUS_SINGLE_CONNECT_FLAG` in the response packet.
/// Until the first response arrives, support is unknown.
///
/// Graceful shutdown is signaled when a server removes the single-connect flag
/// from response packets after previously supporting it. The client stops
/// creating sessions on that connection, lets existing sessions drain, and then
/// closes the stream.
///
/// A transport disconnect is different from a graceful single-connection
/// shutdown. If a shared stream ends while this state is still `Supported`, the
/// owning client clears the cached stream, returns to `Initial`, and probes the
/// next fresh connection. This matters for load-balanced server pools: the next
/// backend might have different single-connection support, so the client asks
/// again instead of assuming the previous answer still applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SingleConnectionState {
    /// No session has been created yet. The first session can be created.
    #[default]
    Initial,
    /// A session has been created, and the first response has not arrived yet.
    Negotiating,
    /// Server supports single-connection mode.
    Supported,
    /// Server does not support single-connection mode, or asked us to drain.
    NotSupported,
}
