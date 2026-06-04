//! TACACS+ packet framing and obfuscation.
//!
//! The codec module owns conversion between asynchronous byte streams and
//! structured [`Packet`](tacacsrs_messages::packet::Packet) values. Transport
//! modules provide bytes; session and connection modules work in packets.

mod reader;
mod writer;

pub(crate) use reader::{PacketReadResult, PacketReader, PacketReaderTrait};
pub(crate) use writer::{PacketWriteResult, PacketWriter, PacketWriterTrait};
