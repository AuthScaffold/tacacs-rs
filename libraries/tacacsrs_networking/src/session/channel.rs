use tacacsrs_messages::packet::Packet;
use tokio::sync::RwLock;

pub(crate) struct DuplexChannel {
    sender: tokio::sync::mpsc::Sender<Packet>,
    receiver: RwLock<tokio::sync::mpsc::Receiver<Packet>>,
}

impl DuplexChannel {
    #[must_use]
    pub(crate) fn new(
        session_receiver: tokio::sync::mpsc::Receiver<Packet>,
        tcp_sender: tokio::sync::mpsc::Sender<Packet>,
    ) -> Self {
        Self {
            sender: tcp_sender,
            receiver: session_receiver.into(),
        }
    }

    pub(super) async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
        self.sender.send(packet).await?;
        Ok(())
    }

    pub(super) async fn receive_packet(&self) -> anyhow::Result<Packet> {
        let mut reader_lock = self.receiver.write().await;
        match reader_lock.recv().await {
            Some(response) => Ok(response),
            None => Err(anyhow::Error::msg("Failed to receive a TACACS+ response")),
        }
    }

    #[cfg(test)]
    pub(super) async fn close_receiver(&self) {
        self.receiver.write().await.close();
    }
}
