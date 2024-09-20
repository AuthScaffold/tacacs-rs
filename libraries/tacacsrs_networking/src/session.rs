use tokio::sync::RwLock;

use crate::duplex_channel::DuplexChannel;


pub struct Session
{
    pub session_id: u32,
    pub duplex_channel: DuplexChannel,

    pub current_sequence_number: RwLock<u8>,
    pub session_complete: RwLock<bool>
}


impl Session
{
    pub fn new(session_id: u32, duplex_channel: DuplexChannel) -> Self
    {
        Self
        {
            session_id,
            duplex_channel,
            current_sequence_number: 1_u8.into(),
            session_complete: false.into()
        }
    }

    pub fn session_id(&self) -> u32
    {
        self.session_id
    }

    pub async fn next_sequence_number(&self) -> u8
    {
        let mut sequence_number_lock = self.current_sequence_number.write().await;
        let sequence_number = *sequence_number_lock;
        *sequence_number_lock = sequence_number.wrapping_add(2);

        sequence_number
    }

    pub async fn complete(&self)
    {
        let mut session_complete_lock = self.session_complete.write().await;
        *session_complete_lock = true;
    }

    pub async fn is_complete(&self) -> bool
    {
        let session_complete_lock = self.session_complete.read().await;
        *session_complete_lock
    }
}
