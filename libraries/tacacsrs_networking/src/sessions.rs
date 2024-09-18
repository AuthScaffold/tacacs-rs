use crate::duplex_channel::DuplexChannel;


pub struct Session
{
    pub session_id: u32,

    // channel will close when one side is dropped
    pub duplex_channel: DuplexChannel
}


impl Session
{
    pub fn session_id(&self) -> u32
    {
        self.session_id
    }
}
