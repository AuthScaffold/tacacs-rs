//! TACACS+ packet I/O helpers for the raw proxy.

use std::future::Future;
use std::pin::Pin;
use std::pin::pin;
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::Duration;

use anyhow::{Context, bail};
use bytes::{Buf, BytesMut};
use futures_util::StreamExt;
use tacacsrs_protocol::constants::{TACACS_HEADER_LENGTH, TACACS_MAX_BODY_LENGTH};
use tacacsrs_protocol::enumerations::TacacsFlags;
use tacacsrs_protocol::header::Header;
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_networking::{PacketWriteResult, PacketWriter};
use tacacsrs_secrets::SecretBytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;
use tokio_util::codec::{Decoder, FramedRead};

use super::error::ProxyConnectionError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DownstreamObfuscation {
    Unobfuscated,
    Obfuscated,
}

pub(super) struct DownstreamPacket {
    pub(super) packet: Packet,
    pub(super) reply_obfuscation: DownstreamObfuscation,
}

/// Cancellation-safe packet reader for one downstream proxy client.
///
/// The connection loop polls [`next_packet`](Self::next_packet) inside
/// `select!`. Every partially read byte is stored in this struct rather than in
/// the returned future, so a losing `select!` branch cannot discard bytes and
/// desynchronise the TACACS+ frame boundary.
pub(super) struct DownstreamReader<Stream> {
    stream: FramedRead<ReadWindow<Stream>, DownstreamCodec>,
    obfuscation_key: Option<SecretBytes>,
    timeout: Duration,
    deadline: Option<Instant>,
}

struct DownstreamCodec;

const READ_WINDOW: usize = 8192;

struct ReadWindow<Stream>(Stream);

impl<Stream: AsyncRead + Unpin> AsyncRead for ReadWindow<Stream> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let limit = buffer.remaining().min(READ_WINDOW);
        let mut limited = ReadBuf::new(buffer.initialize_unfilled_to(limit));
        let result = Pin::new(&mut self.0).poll_read(context, &mut limited);
        let count = limited.filled().len();
        buffer.advance(count);
        result
    }
}

impl Decoder for DownstreamCodec {
    type Item = Packet;
    type Error = anyhow::Error;

    fn decode(&mut self, bytes: &mut BytesMut) -> anyhow::Result<Option<Packet>> {
        if bytes.len() < TACACS_HEADER_LENGTH {
            return Ok(None);
        }
        let header = Header::from_bytes(&bytes[..TACACS_HEADER_LENGTH])
            .context("Failed to parse TACACS+ proxy header")?;
        if header.length > TACACS_MAX_BODY_LENGTH {
            bail!(
                "TACACS+ proxy packet for session {:#x} declares body length {}, which exceeds the maximum of {}",
                header.session_id,
                header.length,
                TACACS_MAX_BODY_LENGTH,
            );
        }
        let length = TACACS_HEADER_LENGTH + header.length as usize;
        if bytes.len() < length {
            bytes.reserve(length - bytes.len());
            return Ok(None);
        }
        let session_id = header.session_id;
        let body = if length > READ_WINDOW {
            let mut frame = std::mem::replace(bytes, BytesMut::with_capacity(READ_WINDOW));
            bytes.extend_from_slice(&frame[length..]);
            frame.truncate(length);
            frame.advance(TACACS_HEADER_LENGTH);
            Vec::from(frame)
        } else {
            let frame = bytes.split_to(length);
            frame[TACACS_HEADER_LENGTH..].to_vec()
        };
        Packet::new(header, body)
            .with_context(|| {
                format!("Failed to create TACACS+ proxy packet for session {session_id:#x}")
            })
            .map(Some)
    }

    fn decode_eof(&mut self, bytes: &mut BytesMut) -> anyhow::Result<Option<Packet>> {
        if let Some(packet) = self.decode(bytes)? {
            return Ok(Some(packet));
        }
        if bytes.len() < TACACS_HEADER_LENGTH {
            bail!("Failed to read TACACS+ proxy header: early eof");
        }
        bail!("Failed to read a TACACS+ proxy body: early eof");
    }
}

impl<Stream> DownstreamReader<Stream>
where
    Stream: AsyncRead + Unpin + Send,
{
    pub(super) fn new(
        stream: Stream,
        timeout: Duration,
        obfuscation_key: Option<SecretBytes>,
    ) -> Self {
        Self {
            stream: FramedRead::new(ReadWindow(stream), DownstreamCodec),
            obfuscation_key,
            timeout,
            deadline: None,
        }
    }

    /// Reads the next complete downstream packet.
    ///
    /// The read deadline covers one whole packet, so a client cannot hold the
    /// connection open by sending a frame one byte at a time.
    pub(super) async fn next_packet(&mut self) -> Result<DownstreamPacket, ProxyConnectionError> {
        // Buffered bytes often already hold a whole packet. Completing here
        // avoids arming and disarming a timer for every request.
        if let Some(result) = self.poll_read_frame_once() {
            self.deadline = None;
            return result.map_err(ProxyConnectionError::Downstream);
        }

        let deadline = *self
            .deadline
            .get_or_insert_with(|| Instant::now() + self.timeout);
        let timeout = self.timeout;

        match tokio::time::timeout_at(deadline, self.read_frame()).await {
            Ok(Ok(packet)) => {
                self.deadline = None;
                Ok(packet)
            }
            Ok(Err(error)) => Err(ProxyConnectionError::Downstream(error)),
            Err(_) => Err(ProxyConnectionError::Downstream(anyhow::anyhow!(
                "No downstream TACACS+ packet arrived within {timeout:?}"
            ))),
        }
    }

    /// Polls one read attempt without registering a real waker.
    ///
    /// Partial progress stays in `self`, so discarding the future is safe.
    fn poll_read_frame_once(&mut self) -> Option<anyhow::Result<DownstreamPacket>> {
        let mut context = TaskContext::from_waker(Waker::noop());
        match pin!(self.read_frame()).poll(&mut context) {
            Poll::Ready(result) => Some(result),
            Poll::Pending => None,
        }
    }

    async fn read_frame(&mut self) -> anyhow::Result<DownstreamPacket> {
        let mut packet = match self.stream.next().await {
            Some(Ok(packet)) => packet,
            Some(Err(error)) if error.is::<std::io::Error>() => {
                return Err(error).context(
                    if self.stream.read_buffer().len() < TACACS_HEADER_LENGTH {
                        "Failed to read TACACS+ proxy header"
                    } else {
                        "Failed to read a TACACS+ proxy body"
                    },
                );
            }
            Some(Err(error)) => return Err(error),
            None => bail!("Failed to read TACACS+ proxy header: early eof"),
        };
        let session_id = packet.header().session_id;
        let reply_obfuscation = if packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG)
        {
            DownstreamObfuscation::Unobfuscated
        } else {
            DownstreamObfuscation::Obfuscated
        };

        log::debug!(
            "Read a downstream TACACS+ proxy packet: session_id={:#x}, seq_no={}, type={}, flags={:?}, body_length={}, obfuscated={}",
            packet.header().session_id,
            packet.header().seq_no,
            packet.header().tacacs_type,
            packet.header().flags,
            packet.body().len(),
            reply_obfuscation == DownstreamObfuscation::Obfuscated,
        );

        if reply_obfuscation == DownstreamObfuscation::Obfuscated {
            if let Some(key) = &self.obfuscation_key {
                log::debug!(
                    "Deobfuscating a downstream TACACS+ proxy packet body for session {session_id:#x}"
                );
                packet = packet.to_deobfuscated(key.expose_secret());
            }
        }

        Ok(DownstreamPacket {
            packet,
            reply_obfuscation,
        })
    }
}

pub(super) async fn write_downstream_packet<Stream>(
    writer: &PacketWriter,
    stream: &mut Stream,
    packet: Packet,
    obfuscation: DownstreamObfuscation,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncWrite + Unpin + Send,
{
    let result = match obfuscation {
        DownstreamObfuscation::Obfuscated => writer.write_packet(stream, packet).await,
        DownstreamObfuscation::Unobfuscated => {
            PacketWriter::new(None).write_packet(stream, packet).await
        }
    };

    match result {
        PacketWriteResult::Success => Ok(()),
        PacketWriteResult::WriteError(error) => Err(ProxyConnectionError::Downstream(
            anyhow::Error::new(error).context("Failed to write a TACACS+ proxy reply downstream"),
        )),
    }
}

#[cfg(test)]
mod evaluation_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::io::AsyncWriteExt;
    use tacacsrs_protocol::enumerations::{TacacsMajorVersion, TacacsMinorVersion, TacacsType};

    fn frame(length: usize) -> Vec<u8> {
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: 1,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: 17,
                length: u32::try_from(length).unwrap(),
            },
            vec![0x42; length],
        )
        .unwrap()
        .to_bytes()
    }

    struct ObservedInput {
        input: std::io::Cursor<Vec<u8>>,
        largest_request: Arc<Mutex<usize>>,
        terminal_error: bool,
    }

    impl AsyncRead for ObservedInput {
        fn poll_read(
            mut self: Pin<&mut Self>,
            context: &mut TaskContext<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let mut largest = self.largest_request.lock().unwrap();
            *largest = (*largest).max(buffer.remaining());
            drop(largest);
            if self.terminal_error
                && self.input.position() == u64::try_from(self.input.get_ref().len()).unwrap()
            {
                return Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
            }
            Pin::new(&mut self.input).poll_read(context, buffer)
        }
    }

    fn observed(input: Vec<u8>) -> (ObservedInput, Arc<Mutex<usize>>) {
        let largest_request = Arc::new(Mutex::new(0));
        (
            ObservedInput {
                input: std::io::Cursor::new(input),
                largest_request: largest_request.clone(),
                terminal_error: false,
            },
            largest_request,
        )
    }

    #[tokio::test]
    async fn repaired_adapter_bounds_read_requests_after_maximum_packet() {
        let mut bytes = frame(TACACS_MAX_BODY_LENGTH as usize);
        let mut bad_header = frame(0);
        bad_header[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        bytes.extend(bad_header);
        bytes.extend(vec![0x42; 100_000]);
        let (input, largest) = observed(bytes);
        let mut reader = DownstreamReader::new(input, Duration::from_secs(1), None);
        assert_eq!(
            reader.next_packet().await.unwrap().packet.body().len(),
            TACACS_MAX_BODY_LENGTH as usize
        );
        assert_eq!(reader.stream.read_buffer().capacity(), READ_WINDOW);
        assert!(reader.next_packet().await.is_err());
        assert_eq!(*largest.lock().unwrap(), READ_WINDOW);
        assert_eq!(reader.stream.read_buffer().capacity(), READ_WINDOW);
    }

    #[tokio::test]
    async fn repaired_adapter_preserves_coalesced_bytes_after_body_handoff() {
        let mut bytes = frame(17);
        bytes.extend(frame(TACACS_MAX_BODY_LENGTH as usize));
        bytes.extend(frame(19));
        let (input, _) = observed(bytes);
        let mut reader = DownstreamReader::new(input, Duration::from_secs(1), None);
        for length in [17, TACACS_MAX_BODY_LENGTH as usize, 19] {
            let packet = reader.next_packet().await.unwrap().packet;
            assert_eq!(packet.body(), vec![0x42; length]);
        }
    }

    #[test]
    fn repaired_handoff_transfers_large_allocation_instead_of_copying_it() {
        let mut bytes = BytesMut::from(frame(TACACS_MAX_BODY_LENGTH as usize).as_slice());
        let pointer = bytes.as_ptr();
        let original_capacity = bytes.capacity();
        let packet = DownstreamCodec.decode(&mut bytes).unwrap().unwrap();
        assert_eq!(packet.body().as_ptr(), pointer);
        assert_eq!(bytes.capacity(), READ_WINDOW);
        println!(
            "repaired handoff: transferred capacity={original_capacity}, retained read capacity={}",
            bytes.capacity()
        );
    }

    #[test]
    fn simple_split_conversion_still_copies_while_reader_retains_shared_tail() {
        let mut bytes = BytesMut::from(frame(TACACS_MAX_BODY_LENGTH as usize).as_slice());
        let frame_capacity = bytes.capacity();
        let mut owned = bytes.split_to(bytes.len());
        owned.advance(TACACS_HEADER_LENGTH);
        let pointer = owned.as_ptr();
        let body = Vec::from(owned);
        assert_ne!(body.as_ptr(), pointer);
        assert_eq!(body.capacity(), TACACS_MAX_BODY_LENGTH as usize);
        assert_eq!(bytes.len(), 0);
        println!(
            "simple split: frame allocation capacity={frame_capacity}, copied body capacity={}, simultaneous byte-owner capacity={}",
            body.capacity(),
            frame_capacity + body.capacity()
        );
    }

    #[tokio::test]
    async fn repaired_adapter_preserves_io_and_eof_error_stages() {
        for count in [0, 6, 12, 14] {
            for terminal_error in [false, true] {
                let (mut input, _) = observed(frame(4)[..count].to_vec());
                input.terminal_error = terminal_error;
                let mut reader = DownstreamReader::new(input, Duration::from_secs(1), None);
                let error = match reader.next_packet().await {
                    Err(ProxyConnectionError::Downstream(error)) => error.to_string(),
                    _ => panic!("expected a downstream read error"),
                };
                let expected = if count < 12 {
                    "Failed to read TACACS+ proxy header"
                } else {
                    "Failed to read a TACACS+ proxy body"
                };
                assert!(error.contains(expected), "{error}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn repaired_adapter_keeps_cancellation_state_and_original_deadline() {
        for split in [6, 14] {
            let bytes = frame(4);
            let (mut sender, input) = tokio::io::duplex(128);
            let mut reader = DownstreamReader::new(input, Duration::from_secs(1), None);
            sender.write_all(&bytes[..split]).await.unwrap();
            assert!(poll_once(&mut reader).is_pending());
            let deadline = reader.deadline.unwrap();
            assert_eq!(reader.stream.read_buffer().len(), split);
            tokio::time::advance(Duration::from_millis(500)).await;
            assert!(poll_once(&mut reader).is_pending());
            assert_eq!(reader.deadline, Some(deadline));
            sender.write_all(&bytes[split..]).await.unwrap();
            assert_eq!(reader.next_packet().await.unwrap().packet.to_bytes(), bytes);
            assert!(reader.deadline.is_none());
        }

        fn poll_once<Stream: AsyncRead + Unpin + Send>(
            reader: &mut DownstreamReader<Stream>,
        ) -> Poll<Result<DownstreamPacket, ProxyConnectionError>> {
            pin!(reader.next_packet()).poll(&mut TaskContext::from_waker(Waker::noop()))
        }
    }
}
