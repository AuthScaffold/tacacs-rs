use tacacsrs_messages::packet::Packet;
use tokio::sync::RwLock;

pub struct DuplexChannel
{
    pub sender: tokio::sync::mpsc::Sender<Packet>,
    pub receiver: RwLock<tokio::sync::mpsc::Receiver<Packet>>,
}


impl DuplexChannel
{
    pub fn new(session_receiver: tokio::sync::mpsc::Receiver<Packet>, tcp_sender: tokio::sync::mpsc::Sender<Packet>) -> Self
    {
        Self
        {
            sender: tcp_sender,
            receiver: session_receiver.into(),
        }
    }
}