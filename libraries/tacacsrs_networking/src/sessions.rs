use tacacsrs_messages::enumerations::TacacsType;
use tacacsrs_messages::packet::Packet;


// for some other good ideas check https://github.com/http-rs/async-session/blob/main/src/memory_store.rs

pub struct QueueEntry
{
    pub packet: Packet,
    pub callback: tokio::sync::oneshot::Sender<anyhow::Result<Packet>>,
}

pub struct Session
{
    pub sequence_number: u32,
    pub session_id: u32,
    pub tacacs_type: TacacsType,
    pub queue_entry: std::sync::Mutex<Option<QueueEntry>>
}


impl Session
{
    pub fn new(session_id : u32, tacacs_type: TacacsType) -> Self
    {
        Self
        {
            sequence_number: 0,
            session_id,
            tacacs_type,
            queue_entry: None.into()
        }
    }

    pub fn session_id(&self) -> u32
    {
        self.session_id
    }

    pub fn seq_no(&self) -> u32
    {
        self.sequence_number
    }
}
