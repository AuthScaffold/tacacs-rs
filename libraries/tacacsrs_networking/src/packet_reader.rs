use async_trait::async_trait;
use tacacsrs_messages::constants::TACACS_HEADER_LENGTH;
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;
use tacacsrs_messages::{header::Header, packet::Packet};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Result of reading a packet from the stream.
pub enum PacketReadResult {
    /// Successfully read and parsed a packet.
    Success(Packet),
    /// Failed to read header from stream (connection closed or error).
    HeaderReadError(std::io::Error),
    /// Failed to parse header bytes.
    HeaderParseError(anyhow::Error),
    /// Failed to read body from stream.
    BodyReadError { session_id: u32, error: std::io::Error },
    /// Failed to create packet from header and body.
    PacketCreateError { session_id: u32, error: anyhow::Error },
}

/// Trait for reading TACACS+ packets from a stream.
/// 
/// This trait abstracts the packet reading logic to allow for dependency injection
/// and easier testing. Implementations can provide custom behavior for reading,
/// parsing, and deobfuscating packets.
#[async_trait]
pub trait PacketReaderTrait: Send + Sync {
    /// Reads a single packet from the provided reader.
    /// 
    /// This method will:
    /// 1. Read the TACACS+ header (12 bytes)
    /// 2. Parse the header to determine body length
    /// 3. Read the body
    /// 4. Create and optionally deobfuscate the packet
    /// 
    /// # Arguments
    /// * `reader` - A mutable reference to a boxed async reader
    /// 
    /// # Returns
    /// A `PacketReadResult` indicating success or the type of failure encountered.
    async fn read_packet(
        &self,
        reader: &mut (dyn AsyncRead + Unpin + Send),
    ) -> PacketReadResult;
}

/// Default implementation of `PacketReaderTrait` for reading TACACS+ packets.
/// 
/// Handles reading packets from any async reader, including optional deobfuscation
/// using the provided key.
pub struct PacketReader {
    obfuscation_key: Option<Vec<u8>>,
}

impl PacketReader {
    /// Creates a new `PacketReader` with an optional obfuscation key.
    /// 
    /// # Arguments
    /// * `obfuscation_key` - Optional key used to deobfuscate incoming packets.
    ///   If `None`, packets are assumed to be unencrypted.
    pub fn new(obfuscation_key: Option<Vec<u8>>) -> Self {
        Self { obfuscation_key }
    }
}

#[async_trait]
impl PacketReaderTrait for PacketReader {
    async fn read_packet(
        &self,
        reader: &mut (dyn AsyncRead + Unpin + Send),
    ) -> PacketReadResult {
        // Read header
        let mut header_buffer = [0_u8; TACACS_HEADER_LENGTH];
        if let Err(e) = reader.read_exact(&mut header_buffer).await {
            return PacketReadResult::HeaderReadError(e);
        }

        // Parse header
        let header = match Header::from_bytes(&header_buffer) {
            Ok(header) => header,
            Err(e) => return PacketReadResult::HeaderParseError(e),
        };

        let session_id = header.session_id;

        log::info!(
            target: "tacacsrs_networking::packet_reader::read_packet",
            "Received header with session id: {}. Loading body of length {}",
            session_id, header.length
        );

        // Read body
        let mut body_buffer = vec![0_u8; header.length as usize];
        if let Err(e) = reader.read_exact(&mut body_buffer).await {
            return PacketReadResult::BodyReadError {
                session_id,
                error: e,
            };
        }

        log::info!(
            target: "tacacsrs_networking::packet_reader::read_packet",
            "Received body for session id: {}",
            session_id
        );

        // Create packet
        let mut packet = match Packet::new(header, body_buffer) {
            Ok(packet) => packet,
            Err(e) => {
                return PacketReadResult::PacketCreateError {
                    session_id,
                    error: e,
                }
            }
        };

        // Deobfuscate if needed
        let is_packet_deobfuscated = packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        if let Some(key) = &self.obfuscation_key {
            if !is_packet_deobfuscated {
                packet = packet.to_deobfuscated(key);
                log::info!(
                    target: "tacacsrs_networking::packet_reader::read_packet",
                    "Deobfuscated packet for session id: {}",
                    session_id
                );
            }
        }

        PacketReadResult::Success(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tacacsrs_messages::enumerations::{TacacsFlags, TacacsType, TacacsMajorVersion, TacacsMinorVersion};

    fn create_test_header(session_id: u32, body_length: u32, flags: TacacsFlags) -> Header {
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAuthentication,
            seq_no: 1,
            flags,
            session_id,
            length: body_length,
        }
    }

    #[tokio::test]
    async fn test_read_packet_success_unencrypted() {
        let header = create_test_header(12345, 4, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let header_bytes = header.to_bytes();
        let body = vec![0x01, 0x02, 0x03, 0x04];

        let mut data = Vec::new();
        data.extend_from_slice(&header_bytes);
        data.extend_from_slice(&body);

        let mut reader = Cursor::new(data);
        let packet_reader = PacketReader::new(None);

        match packet_reader.read_packet(&mut reader).await {
            PacketReadResult::Success(packet) => {
                assert_eq!(packet.header().session_id, 12345);
                assert_eq!(packet.body(), &body);
            }
            _ => panic!("Expected Success result"),
        }
    }

    #[tokio::test]
    async fn test_read_packet_header_read_error() {
        // Empty reader - will fail to read header
        let mut reader = Cursor::new(Vec::new());
        let packet_reader = PacketReader::new(None);

        match packet_reader.read_packet(&mut reader).await {
            PacketReadResult::HeaderReadError(_) => {}
            _ => panic!("Expected HeaderReadError result"),
        }
    }

    #[tokio::test]
    async fn test_read_packet_body_read_error() {
        // Header says body is 100 bytes, but we only provide header
        let header = create_test_header(12345, 100, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let header_bytes = header.to_bytes();

        let mut reader = Cursor::new(header_bytes.to_vec());
        let packet_reader = PacketReader::new(None);

        match packet_reader.read_packet(&mut reader).await {
            PacketReadResult::BodyReadError { session_id, .. } => {
                assert_eq!(session_id, 12345);
            }
            _ => panic!("Expected BodyReadError result"),
        }
    }
}
