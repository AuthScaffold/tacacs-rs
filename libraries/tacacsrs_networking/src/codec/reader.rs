use tacacsrs_messages::constants::{TACACS_HEADER_LENGTH, TACACS_MAX_BODY_LENGTH};
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;
use tacacsrs_messages::{header::Header, packet::Packet};
use tokio::io::{AsyncRead, AsyncReadExt};

/// Result of reading a packet from a connection.
#[derive(Debug)]
pub enum PacketReadResult {
    /// The packet was read and parsed.
    Success(Packet),
    /// Reading the header failed because the connection closed or an error occurred.
    HeaderReadError(std::io::Error),
    /// Parsing the header bytes failed.
    HeaderParseError(anyhow::Error),
    /// Body length exceeds maximum allowed size.
    BodyLengthExceeded {
        /// The session ID from the rejected packet.
        session_id: u32,
        /// The body length that exceeded the limit.
        body_length: u32,
        /// The maximum allowed body length.
        max_length: u32,
    },
    /// Reading the body from the connection failed.
    BodyReadError {
        session_id: u32,
        error: std::io::Error,
    },
    /// Creating the packet from the header and body failed.
    PacketCreateError {
        session_id: u32,
        error: anyhow::Error,
    },
}

/// Reads TACACS+ packets, including optional body deobfuscation.
pub struct PacketReader {
    obfuscation_key: Option<Vec<u8>>,
}

impl PacketReader {
    /// Creates a `PacketReader` with an optional obfuscation key.
    ///
    /// # Arguments
    /// * `obfuscation_key` - Optional key used to deobfuscate incoming packets.
    ///   If `None`, packets are assumed to be unencrypted.
    #[must_use]
    pub const fn new(obfuscation_key: Option<Vec<u8>>) -> Self {
        Self { obfuscation_key }
    }
}

impl PacketReader {
    /// Reads and decodes one TACACS+ packet from `reader`.
    pub async fn read_packet<Reader>(&self, reader: &mut Reader) -> PacketReadResult
    where
        Reader: AsyncRead + Unpin + ?Sized,
    {
        // Read the header.
        let mut header_buffer = [0_u8; TACACS_HEADER_LENGTH];
        if let Err(e) = reader.read_exact(&mut header_buffer).await {
            return PacketReadResult::HeaderReadError(e);
        }

        // Parse the header.
        let header = match Header::from_bytes(&header_buffer) {
            Ok(header) => header,
            Err(e) => return PacketReadResult::HeaderParseError(e),
        };

        let session_id = header.session_id;

        // Check the body length before allocation. This check prevents:
        // 1. Memory-exhaustion denial-of-service attacks from malicious peers.
        // 2. Truncation on 32-bit platforms when the length is cast to usize.
        if header.length > TACACS_MAX_BODY_LENGTH {
            log::warn!(
                target: "tacacsrs_networking::codec::reader::read_packet",
                "Rejected packet with excessive body length: session ID {}, body length {}, maximum {}",
                session_id, header.length, TACACS_MAX_BODY_LENGTH
            );
            return PacketReadResult::BodyLengthExceeded {
                session_id,
                body_length: header.length,
                max_length: TACACS_MAX_BODY_LENGTH,
            };
        }

        log::trace!(
            target: "tacacsrs_networking::codec::reader::read_packet",
            "Received header for session ID {}. Reading a body of {} bytes",
            session_id, header.length
        );

        // The check above makes this cast safe. TACACS_MAX_BODY_LENGTH (65536)
        // fits in usize on all supported platforms.
        let body_length = header.length as usize;

        // Read the body.
        let mut body_buffer = vec![0_u8; body_length];
        if let Err(e) = reader.read_exact(&mut body_buffer).await {
            return PacketReadResult::BodyReadError {
                session_id,
                error: e,
            };
        }

        log::trace!(
            target: "tacacsrs_networking::codec::reader::read_packet",
            "Received body for session ID {session_id}"
        );

        // Create the packet.
        let mut packet = match Packet::new(header, body_buffer) {
            Ok(packet) => packet,
            Err(e) => {
                return PacketReadResult::PacketCreateError {
                    session_id,
                    error: e,
                }
            }
        };

        // Deobfuscate the packet when necessary.
        let is_packet_deobfuscated = packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        if let Some(key) = &self.obfuscation_key {
            if !is_packet_deobfuscated {
                packet = packet.to_deobfuscated(key);
                log::trace!(
                    target: "tacacsrs_networking::codec::reader::read_packet",
                    "Deobfuscated packet for session ID {session_id}"
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
    use tacacsrs_messages::enumerations::{
        TacacsFlags, TacacsType, TacacsMajorVersion, TacacsMinorVersion,
    };

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
            _ => panic!("expected a successful packet read"),
        }
    }

    #[tokio::test]
    async fn test_read_packet_header_read_error() {
        // An empty reader cannot provide a header.
        let mut reader = Cursor::new(Vec::new());
        let packet_reader = PacketReader::new(None);

        match packet_reader.read_packet(&mut reader).await {
            PacketReadResult::HeaderReadError(_) => {}
            _ => panic!("expected HeaderReadError"),
        }
    }

    #[tokio::test]
    async fn test_read_packet_body_read_error() {
        // The header specifies a 100-byte body, but the reader contains only the header.
        let header = create_test_header(12345, 100, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let header_bytes = header.to_bytes();

        let mut reader = Cursor::new(header_bytes.to_vec());
        let packet_reader = PacketReader::new(None);

        match packet_reader.read_packet(&mut reader).await {
            PacketReadResult::BodyReadError { session_id, .. } => {
                assert_eq!(session_id, 12345);
            }
            _ => panic!("expected BodyReadError"),
        }
    }

    #[tokio::test]
    async fn test_read_packet_body_length_exceeded() {
        use tacacsrs_messages::constants::TACACS_MAX_BODY_LENGTH;

        // Create a header with a body length that exceeds the maximum.
        let excessive_length = TACACS_MAX_BODY_LENGTH + 1;
        let header =
            create_test_header(12345, excessive_length, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let header_bytes = header.to_bytes();

        let mut reader = Cursor::new(header_bytes.to_vec());
        let packet_reader = PacketReader::new(None);

        match packet_reader.read_packet(&mut reader).await {
            PacketReadResult::BodyLengthExceeded {
                session_id,
                body_length,
                max_length,
            } => {
                assert_eq!(session_id, 12345);
                assert_eq!(body_length, excessive_length);
                assert_eq!(max_length, TACACS_MAX_BODY_LENGTH);
            }
            _ => panic!("expected BodyLengthExceeded"),
        }
    }

    #[tokio::test]
    async fn test_read_packet_max_allowed_body_length() {
        use tacacsrs_messages::constants::TACACS_MAX_BODY_LENGTH;

        // Make sure that the maximum body length is accepted.
        let header = create_test_header(
            12345,
            TACACS_MAX_BODY_LENGTH,
            TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
        );
        let header_bytes = header.to_bytes();

        // Create a body with the maximum length.
        let body = vec![0x42_u8; TACACS_MAX_BODY_LENGTH as usize];

        let mut data = Vec::new();
        data.extend_from_slice(&header_bytes);
        data.extend_from_slice(&body);

        let mut reader = Cursor::new(data);
        let packet_reader = PacketReader::new(None);

        match packet_reader.read_packet(&mut reader).await {
            PacketReadResult::Success(packet) => {
                assert_eq!(packet.header().session_id, 12345);
                assert_eq!(packet.body().len(), TACACS_MAX_BODY_LENGTH as usize);
            }
            _ => panic!("expected success for the maximum body length"),
        }
    }
}
