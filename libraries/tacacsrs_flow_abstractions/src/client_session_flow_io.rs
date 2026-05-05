use async_trait::async_trait;
use tacacsrs_messages::packet::Packet;

/// Minimal client-side session I/O contract required by all TACACS+ client flows.
#[async_trait]
pub trait ClientSessionFlowIoTrait {
    async fn is_complete(&self) -> bool;
    async fn next_sequence_number(&self) -> u8;
    fn session_id(&self) -> u32;
    async fn send_packet(&self, packet: Packet) -> anyhow::Result<()>;
    async fn receive_packet(&self) -> anyhow::Result<Packet>;
    async fn complete(&self);
}
