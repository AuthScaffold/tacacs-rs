use async_trait::async_trait;
use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
use tacacsrs_messages::packet::Packet;

use crate::session::Session;

#[async_trait]
impl ClientSessionFlowIoTrait for Session {
    async fn is_complete(&self) -> bool {
        self.is_complete().await
    }

    async fn next_sequence_number(&self) -> u8 {
        self.next_sequence_number().await
    }

    fn session_id(&self) -> u32 {
        self.session_id()
    }

    async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
        self.duplex_channel.sender.send(packet).await?;
        Ok(())
    }

    async fn receive_packet(&self) -> anyhow::Result<Packet> {
        let mut reader_lock = self.duplex_channel.receiver.write().await;
        match reader_lock.recv().await {
            Some(response) => Ok(response),
            None => Err(anyhow::Error::msg("Failed to receive response")),
        }
    }

    async fn complete(&self) {
        self.complete().await;
    }
}
