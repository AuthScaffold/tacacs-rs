use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::Packet;
use tacacsrs_messages::packet::PacketTrait;
use tokio::io::{AsyncWrite, AsyncWriteExt};

/// Result of writing a packet to a connection.
#[derive(Debug)]
pub enum PacketWriteResult {
    /// The packet was written.
    Success,
    /// Writing the packet failed.
    WriteError(std::io::Error),
}

/// Writes TACACS+ packets, including optional body obfuscation.
pub struct PacketWriter {
    obfuscation_key: Option<Vec<u8>>,
}

impl PacketWriter {
    /// Creates a `PacketWriter` with an optional obfuscation key.
    ///
    /// # Arguments
    /// * `obfuscation_key` - Optional key used to obfuscate outgoing packets.
    ///   If `None`, packets are sent unencrypted.
    #[must_use]
    pub const fn new(obfuscation_key: Option<Vec<u8>>) -> Self {
        Self { obfuscation_key }
    }

    /// Returns the configured packet obfuscation key, if one is present.
    #[must_use]
    pub fn obfuscation_key(&self) -> Option<&[u8]> {
        self.obfuscation_key.as_deref()
    }

    /// Applies configured TACACS+ body obfuscation in place.
    #[must_use]
    pub fn prepare_packet(&self, mut packet: Packet) -> Packet {
        let session_id = packet.header().session_id;
        let is_packet_deobfuscated = packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);

        if let Some(key) = &self.obfuscation_key {
            if is_packet_deobfuscated {
                packet = packet.to_obfuscated(key);
                log::trace!(
                    target: "tacacsrs_networking::codec::writer::prepare_packet",
                    "Obfuscated packet for session id {session_id}"
                );
            }
        }

        packet
    }

    /// Encodes and writes one TACACS+ packet without allocating a combined
    /// header-and-body buffer.
    pub async fn write_packet<Writer>(
        &self,
        writer: &mut Writer,
        packet: Packet,
    ) -> PacketWriteResult
    where
        Writer: AsyncWrite + Unpin + ?Sized,
    {
        let packet = self.prepare_packet(packet);
        let header = packet.header().to_bytes();

        if let Err(error) = writer.write_all(&header).await {
            return PacketWriteResult::WriteError(error);
        }
        match writer.write_all(packet.body()).await {
            Ok(()) => PacketWriteResult::Success,
            Err(error) => PacketWriteResult::WriteError(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tacacsrs_messages::enumerations::{
        TacacsFlags, TacacsType, TacacsMajorVersion, TacacsMinorVersion,
    };
    use tacacsrs_messages::header::Header;

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

    #[allow(clippy::cast_possible_truncation)] // test data is small
    fn create_test_packet(session_id: u32, body: Vec<u8>, flags: TacacsFlags) -> Packet {
        let header = create_test_header(session_id, body.len() as u32, flags);
        Packet::new(header, body).unwrap()
    }

    #[tokio::test]
    async fn test_write_packet_success() {
        let packet = create_test_packet(
            12345,
            vec![0x01, 0x02, 0x03, 0x04],
            TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
        );
        let expected_bytes = packet.to_bytes();

        let mut buffer = Cursor::new(Vec::new());
        let packet_writer = PacketWriter::new(None);

        match packet_writer.write_packet(&mut buffer, packet).await {
            PacketWriteResult::Success => {
                assert_eq!(buffer.into_inner(), expected_bytes);
            }
            PacketWriteResult::WriteError(error) => panic!("expected success: {error}"),
        }
    }

    #[tokio::test]
    async fn test_prepare_packet_no_obfuscation_key() {
        let body = vec![0x01, 0x02, 0x03, 0x04];
        let packet =
            create_test_packet(12345, body.clone(), TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let packet_writer = PacketWriter::new(None);

        let prepared = packet_writer.prepare_packet(packet);

        // Without an obfuscation key, the packet must not change.
        assert!(prepared
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(prepared.body(), &body);
    }

    #[tokio::test]
    async fn test_prepare_packet_with_obfuscation_key() {
        let body = vec![0x01, 0x02, 0x03, 0x04];
        let packet =
            create_test_packet(12345, body.clone(), TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let obfuscation_key = b"test_key".to_vec();
        let packet_writer = PacketWriter::new(Some(obfuscation_key));

        let prepared = packet_writer.prepare_packet(packet);

        // With an obfuscation key, the flag is removed and the body changes.
        assert!(!prepared
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_ne!(prepared.body(), &body); // Obfuscation changes the body.
    }

    #[tokio::test]
    async fn test_prepare_packet_already_obfuscated() {
        let body = vec![0x01, 0x02, 0x03, 0x04];
        // A packet without the unencrypted flag is already obfuscated.
        let packet = create_test_packet(12345, body.clone(), TacacsFlags::empty());
        let obfuscation_key = b"test_key".to_vec();
        let packet_writer = PacketWriter::new(Some(obfuscation_key));

        let prepared = packet_writer.prepare_packet(packet);

        // Do not obfuscate an obfuscated packet again.
        assert!(!prepared
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(prepared.body(), &body); // The body must not change.
    }
}
