use tokio::sync::RwLock;

use crate::duplex_channel::DuplexChannel;


pub struct Session
{
    pub session_id: u32,
    pub duplex_channel: DuplexChannel,

    pub outgoing_sequence_number: RwLock<u8>
}


impl Session
{
    pub fn new(session_id: u32, duplex_channel: DuplexChannel) -> Self
    {
        Self
        {
            session_id,
            duplex_channel,
            outgoing_sequence_number: 1_u8.into()
        }
    }

    pub fn session_id(&self) -> u32
    {
        self.session_id
    }
}
