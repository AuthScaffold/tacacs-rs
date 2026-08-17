//! TACACS+ packet framing and obfuscation.
//!
//! The codec module converts asynchronous byte streams to and from
//! structured [`Packet`](tacacsrs_messages::packet::Packet) values. Transport
//! modules provide bytes; session and connection modules work in packets.

mod reader;
mod writer;

pub use reader::{PacketReadResult, PacketReader};
pub use writer::{PacketWriteResult, PacketWriter};
