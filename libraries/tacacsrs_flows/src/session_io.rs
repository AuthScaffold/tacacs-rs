use async_trait::async_trait;
use tacacsrs_messages::packet::Packet;

/// Minimal session I/O interface for protocol flows.
///
/// This trait abstracts the session operations that TACACS+ protocol flows
/// need, without coupling them to a concrete session or networking implementation.
///
/// Implementors provide:
/// - A unique session identifier
/// - Monotonically-increasing (odd) sequence numbers
/// - Packet send/receive over the session's duplex channel
/// - Session completion lifecycle
///
/// # Example
///
/// ```ignore
/// use tacacsrs_flows::ClientSessionIo;
///
/// async fn example_flow(session: &dyn ClientSessionIo) -> anyhow::Result<()> {
///     let seq = session.next_sequence_number().await;
///     // ... build and send a packet ...
///     Ok(())
/// }
/// ```
#[async_trait]
pub trait ClientSessionIo: Send + Sync {
    /// Returns the TACACS+ session ID.
    fn session_id(&self) -> u32;

    /// Returns the next client sequence number and advances the counter.
    ///
    /// Client sequence numbers are odd (1, 3, 5, …).
    async fn next_sequence_number(&self) -> u8;

    /// Returns `true` if the session has already completed or its channel is closed.
    async fn is_complete(&self) -> bool;

    /// Marks the session as complete and performs any cleanup.
    async fn complete(&self);

    /// Sends a packet to the remote peer through the session's channel.
    async fn send_packet(&self, packet: Packet) -> anyhow::Result<()>;

    /// Receives the next packet from the remote peer.
    ///
    /// Returns `None` if the channel is closed.
    async fn receive_packet(&self) -> Option<Packet>;
}
