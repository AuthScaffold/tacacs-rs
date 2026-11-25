use std::fmt;
use std::num::NonZeroU32;
use std::sync::Arc;

use tacacsrs_protocol::constants::{TACACS_HEADER_LENGTH, TACACS_MAX_BODY_LENGTH};
use tacacsrs_protocol::enumerations::TacacsFlags;
use tacacsrs_protocol::packet::PacketTrait;
use tacacsrs_protocol::{header::Header, packet::Packet};
use tokio::io::{AsyncRead, AsyncReadExt};
use tacacsrs_secrets::SecretBytes;

const DEFAULT_PACKET_BODY_LIMIT: NonZeroU32 = match NonZeroU32::new(TACACS_MAX_BODY_LENGTH) {
    Some(limit) => limit,
    None => unreachable!(),
};

#[derive(Clone)]
enum PacketBodyLimitSource {
    Fixed(NonZeroU32),
    Dynamic(Arc<dyn Fn() -> NonZeroU32 + Send + Sync>),
}

/// Upper bound on decoded TACACS+ packet body bytes accepted by [`PacketReader`].
///
/// Standalone callers use [`PacketBodyLimit::default`] or [`PacketBodyLimit::fixed`].
/// Long-lived services use [`PacketBodyLimit::dynamic`] so established
/// single-connection transports apply runtime policy updates without reconnecting.
#[derive(Clone)]
pub struct PacketBodyLimit(PacketBodyLimitSource);

impl PacketBodyLimit {
    /// Creates a fixed packet body byte limit.
    #[must_use]
    pub const fn fixed(max_bytes: NonZeroU32) -> Self {
        Self(PacketBodyLimitSource::Fixed(max_bytes))
    }

    /// Creates a limit backed by a live runtime policy source.
    #[must_use]
    pub fn dynamic(source: impl Fn() -> NonZeroU32 + Send + Sync + 'static) -> Self {
        Self(PacketBodyLimitSource::Dynamic(Arc::new(source)))
    }

    /// Returns the active maximum packet body length in bytes.
    #[must_use]
    pub fn get(&self) -> u32 {
        match &self.0 {
            PacketBodyLimitSource::Fixed(limit) => limit.get(),
            PacketBodyLimitSource::Dynamic(source) => source().get(),
        }
    }
}

impl Default for PacketBodyLimit {
    fn default() -> Self {
        Self::fixed(DEFAULT_PACKET_BODY_LIMIT)
    }
}

impl fmt::Debug for PacketBodyLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("PacketBodyLimit")
            .field(&self.get())
            .finish()
    }
}

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
    obfuscation_key: Option<SecretBytes>,
    max_body_length: PacketBodyLimit,
    counters: Option<crate::ServerCounters>,
}

impl PacketReader {
    /// Creates a `PacketReader` with an optional obfuscation key.
    /// The reader retains the protected key owner until it drops.
    ///
    /// # Arguments
    /// * `obfuscation_key` - Optional key used to deobfuscate incoming packets.
    ///   If `None`, packets are assumed to be unencrypted.
    #[must_use]
    pub const fn new(obfuscation_key: Option<SecretBytes>) -> Self {
        Self {
            obfuscation_key,
            max_body_length: PacketBodyLimit::fixed(DEFAULT_PACKET_BODY_LIMIT),
            counters: None,
        }
    }

    /// Sets the maximum body length accepted when reading packets.
    #[must_use]
    pub fn with_max_body_length(mut self, max_body_length: PacketBodyLimit) -> Self {
        self.max_body_length = max_body_length;
        self
    }

    pub(crate) fn with_counters(mut self, counters: Option<crate::ServerCounters>) -> Self {
        self.counters = counters;
        self
    }

    pub(crate) fn record_io_error(&self, error: &std::io::Error) {
        if let Some(counters) = &self.counters {
            counters.io_error(error, false);
        }
    }
}

impl PacketReader {
    /// Reads and decodes one TACACS+ packet from `reader`.
    pub async fn read_packet<Reader>(&self, reader: &mut Reader) -> PacketReadResult
    where
        Reader: AsyncRead + Unpin + ?Sized,
    {
        let result = self.read_packet_inner(reader).await;
        if let Some(counters) = &self.counters {
            match &result {
                PacketReadResult::HeaderReadError(error)
                | PacketReadResult::BodyReadError { error, .. } => self.record_io_error(error),
                PacketReadResult::Success(_) => {}
                _ => counters.disconnect_reason(crate::DisconnectReason::MalformedPacket),
            }
        }
        result
    }

    async fn read_packet_inner<Reader>(&self, reader: &mut Reader) -> PacketReadResult
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
        let correlation = tacacsrs_protocol::header::wire_correlation(session_id);
        let max_body_length = self.max_body_length.get();

        // Check the body length before allocation. This check prevents:
        // 1. Memory-exhaustion denial-of-service attacks from malicious peers.
        // 2. Allocation panics on 32-bit platforms or oversized frames.
        if header.length > max_body_length {
            log::warn!(
                target: "tacacsrs_networking::codec::reader::read_packet",
                "Rejected packet with excessive body length: correlation {}, body length {}, maximum {}",
                correlation, header.length, max_body_length
            );
            return PacketReadResult::BodyLengthExceeded {
                session_id,
                body_length: header.length,
                max_length: max_body_length,
            };
        }

        log::trace!(
            target: "tacacsrs_networking::codec::reader::read_packet",
            "Received header for correlation {}. Reading a body of {} bytes",
            correlation, header.length
        );

        let Ok(body_length) = usize::try_from(header.length) else {
            return PacketReadResult::BodyLengthExceeded {
                session_id,
                body_length: header.length,
                max_length: max_body_length,
            };
        };

        // Read the body without panicking on allocator or address-space exhaustion.
        let mut body_buffer = Vec::new();
        if let Err(error) = body_buffer.try_reserve_exact(body_length) {
            return PacketReadResult::PacketCreateError {
                session_id,
                error: anyhow::Error::new(error).context("failed to allocate TACACS+ packet body"),
            };
        }
        body_buffer.resize(body_length, 0);
        if let Err(e) = reader.read_exact(&mut body_buffer).await {
            return PacketReadResult::BodyReadError {
                session_id,
                error: e,
            };
        }

        log::trace!(
            target: "tacacsrs_networking::codec::reader::read_packet",
            "Received body for correlation {correlation}"
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
                packet = packet.to_deobfuscated(key.expose_secret());
                log::trace!(
                    target: "tacacsrs_networking::codec::reader::read_packet",
                    "Deobfuscated packet for correlation {correlation}"
                );
            }
        }

        if let Some(counters) = &self.counters {
            counters.record(crate::statistics::CounterEvent::MessageReceived);
            if crate::statistics::reply_classification(&packet).is_some_and(|(error, _)| error) {
                counters.record(crate::statistics::CounterEvent::ErrorReceived);
            }
        }
        PacketReadResult::Success(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tacacsrs_protocol::enumerations::{
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

    #[test]
    fn owned_key_debug_is_redacted() {
        let sentinel = b"reader-owned-key-sentinel";
        let key = SecretBytes::new(sentinel.to_vec());
        let allocation = key.expose_secret().as_ptr();
        let reader = PacketReader::new(Some(key));
        let owned: &SecretBytes = reader.obfuscation_key.as_ref().unwrap();
        assert!(owned.expose_secret().as_ptr() == allocation);
        assert!(owned.expose_secret() == sentinel);
        for output in [
            format!("{:?}", reader.obfuscation_key),
            format!("{:#?}", reader.obfuscation_key),
        ] {
            assert!(!output.contains(&format!("{sentinel:?}")), "Debug exposed key bytes");
            assert!(!output.contains(&format!("{sentinel:#?}")), "Debug exposed key bytes");
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
        use tacacsrs_protocol::constants::TACACS_MAX_BODY_LENGTH;

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
        use tacacsrs_protocol::constants::TACACS_MAX_BODY_LENGTH;

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

    #[tokio::test]
    async fn test_read_packet_honors_dynamic_packet_body_limit() {
        use std::sync::atomic::{AtomicU32, Ordering};

        let live_limit = Arc::new(AtomicU32::new(8192));
        let source = Arc::clone(&live_limit);
        let packet_reader =
            PacketReader::new(None).with_max_body_length(PacketBodyLimit::dynamic(move || {
                NonZeroU32::new(source.load(Ordering::Acquire)).unwrap()
            }));

        let large_length = 80 * 1024_u32;
        let header = create_test_header(777, large_length, TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG);
        let mut rejected_reader = Cursor::new(header.to_bytes().to_vec());
        assert!(matches!(
            packet_reader.read_packet(&mut rejected_reader).await,
            PacketReadResult::BodyLengthExceeded {
                session_id: 777,
                body_length,
                max_length: 8192,
            } if body_length == large_length
        ));

        live_limit.store(128 * 1024, Ordering::Release);
        let mut frame = header.to_bytes().to_vec();
        frame.resize(TACACS_HEADER_LENGTH + large_length as usize, 0x33);
        let mut accepted_reader = Cursor::new(frame);
        match packet_reader.read_packet(&mut accepted_reader).await {
            PacketReadResult::Success(packet) => {
                assert_eq!(packet.header().session_id, 777);
                assert_eq!(packet.body().len(), large_length as usize);
            }
            other => panic!("expected raised dynamic limit to accept frame, got {other:?}"),
        }
    }
}
