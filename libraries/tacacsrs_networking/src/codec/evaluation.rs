//! Isolated characterization of Tokio-util at the existing packet I/O seam.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite, LengthDelimitedCodec};

use tacacsrs_protocol::constants::{TACACS_HEADER_LENGTH, TACACS_MAX_BODY_LENGTH};
use tacacsrs_protocol::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_protocol::header::Header;
use tacacsrs_protocol::packet::{Packet, PacketTrait};

use super::{PacketReadResult, PacketReader, PacketWriteResult, PacketWriter};

#[derive(Debug)]
enum DecodeError {
    HeaderIo(io::Error),
    HeaderParse,
    Oversized(u32),
    BodyIo(u32, io::Error),
}

impl From<io::Error> for DecodeError {
    fn from(error: io::Error) -> Self {
        Self::HeaderIo(error)
    }
}

// This adapter validates protocol headers before the framing buffer can grow.
// It keeps packet ownership and the existing header/body EOF distinction.
struct PacketCodec;

impl Decoder for PacketCodec {
    type Item = Packet;
    type Error = DecodeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Packet>, DecodeError> {
        if src.len() < TACACS_HEADER_LENGTH {
            return Ok(None);
        }
        let header = Header::from_bytes(&src[..TACACS_HEADER_LENGTH])
            .map_err(|_| DecodeError::HeaderParse)?;
        if header.length > TACACS_MAX_BODY_LENGTH {
            return Err(DecodeError::Oversized(header.length));
        }
        let length = TACACS_HEADER_LENGTH + header.length as usize;
        if src.len() < length {
            src.reserve(length - src.len());
            return Ok(None);
        }
        let frame = src.split_to(length);
        let packet = Packet::new(header, frame[TACACS_HEADER_LENGTH..].to_vec())
            .map_err(|_| DecodeError::HeaderParse)?;
        Ok(Some(packet))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> Result<Option<Packet>, DecodeError> {
        if let Some(packet) = self.decode(src)? {
            return Ok(Some(packet));
        }
        let error = io::Error::from(io::ErrorKind::UnexpectedEof);
        if src.len() < TACACS_HEADER_LENGTH {
            Err(DecodeError::HeaderIo(error))
        } else {
            let header = Header::from_bytes(&src[..TACACS_HEADER_LENGTH])
                .map_err(|_| DecodeError::HeaderParse)?;
            Err(DecodeError::BodyIo(header.session_id, error))
        }
    }
}

impl Encoder<Packet> for PacketCodec {
    type Error = io::Error;

    fn encode(&mut self, packet: Packet, dst: &mut BytesMut) -> io::Result<()> {
        dst.extend_from_slice(&packet.to_bytes());
        Ok(())
    }
}

fn packet(session_id: u32, length: usize) -> Packet {
    Packet::new(header(session_id, u32::try_from(length).unwrap()), vec![0x42; length]).unwrap()
}

fn header(session_id: u32, length: u32) -> Header {
    Header {
        major_version: TacacsMajorVersion::TacacsPlusMajor1,
        minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
        tacacs_type: TacacsType::TacPlusAccounting,
        seq_no: 1,
        flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        session_id,
        length,
    }
}

#[derive(Default)]
struct ReadFacts {
    bytes: usize,
    largest_request: usize,
    calls: usize,
}

struct ProbeReader {
    data: Vec<u8>,
    position: usize,
    chunk: usize,
    facts: Arc<Mutex<ReadFacts>>,
    terminal_error: Option<io::ErrorKind>,
}

impl ProbeReader {
    fn new(data: Vec<u8>, chunk: usize) -> (Self, Arc<Mutex<ReadFacts>>) {
        let facts = Arc::new(Mutex::new(ReadFacts::default()));
        (
            Self {
                data,
                position: 0,
                chunk,
                facts: facts.clone(),
                terminal_error: None,
            },
            facts,
        )
    }
}

impl AsyncRead for ProbeReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = buffer
            .remaining()
            .min(self.chunk)
            .min(self.data.len() - self.position);
        {
            let mut facts = self.facts.lock().unwrap();
            facts.largest_request = facts.largest_request.max(buffer.remaining());
            facts.bytes += count;
            facts.calls += 1;
        }
        if count == 0 {
            return Poll::Ready(self.terminal_error.map_or(Ok(()), |kind| Err(kind.into())));
        }
        buffer.put_slice(&self.data[self.position..self.position + count]);
        self.position += count;
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct WriteFacts {
    bytes: Vec<u8>,
    allowance: usize,
    chunk: usize,
    calls: usize,
    flush_pending: bool,
    fail: bool,
}

struct ProbeWriter(Arc<Mutex<WriteFacts>>);

impl AsyncWrite for ProbeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut facts = self.0.lock().unwrap();
        facts.calls += 1;
        if facts.fail {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if facts.allowance == 0 {
            return Poll::Pending;
        }
        let count = buffer.len().min(facts.allowance).min(facts.chunk);
        facts.bytes.extend_from_slice(&buffer[..count]);
        facts.allowance -= count;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.0.lock().unwrap().flush_pending {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn writer(allowance: usize, chunk: usize) -> (ProbeWriter, Arc<Mutex<WriteFacts>>) {
    let facts = Arc::new(Mutex::new(WriteFacts {
        allowance,
        chunk,
        ..WriteFacts::default()
    }));
    (ProbeWriter(facts.clone()), facts)
}

fn poll_once<F: std::future::Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    future.poll(&mut Context::from_waker(Waker::noop()))
}

#[tokio::test]
async fn oversized_header_checks_precede_advertised_size_reservation() {
    for length in [TACACS_MAX_BODY_LENGTH + 1, u32::MAX] {
        let bytes = header(17, length).to_bytes().to_vec();
        let (input, facts) = ProbeReader::new(bytes.clone(), usize::MAX);
        let mut framed = FramedRead::new(input, PacketCodec);
        assert_eq!(framed.read_buffer().capacity(), 8192);
        assert!(matches!(
            framed.next().await,
            Some(Err(DecodeError::Oversized(actual))) if actual == length
        ));
        assert_eq!(framed.read_buffer().capacity(), 8192);
        assert_eq!(facts.lock().unwrap().bytes, TACACS_HEADER_LENGTH);
        let (mut old, old_facts) = ProbeReader::new(bytes, usize::MAX);
        assert!(matches!(
            PacketReader::new(None).read_packet(&mut old).await,
            PacketReadResult::BodyLengthExceeded { body_length, .. } if body_length == length
        ));
        assert_eq!(old_facts.lock().unwrap().largest_request, TACACS_HEADER_LENGTH);
    }
}

#[tokio::test]
async fn stock_length_codec_reserves_before_protocol_validation() {
    let mut codec = LengthDelimitedCodec::builder()
        .length_field_offset(8)
        .length_field_length(4)
        .length_adjustment(12)
        .num_skip(0)
        .max_frame_length(TACACS_MAX_BODY_LENGTH as usize)
        .new_codec();
    let mut bytes = header(17, TACACS_MAX_BODY_LENGTH).to_bytes();
    bytes[0] = 0;
    assert!(Header::from_bytes(&bytes).is_err());
    let mut buffer = BytesMut::from(bytes.as_slice());
    assert!(codec.decode(&mut buffer).unwrap().is_none());
    assert!(buffer.capacity() >= TACACS_HEADER_LENGTH + TACACS_MAX_BODY_LENGTH as usize);
}

#[tokio::test]
async fn fragmented_and_coalesced_frames_preserve_header_and_body() {
    for chunk in [1, 5, 12, 8192] {
        let first = packet(17, 37);
        let second = packet(18, 0);
        let mut bytes = first.to_bytes();
        bytes.extend(second.to_bytes());
        let (input, facts) = ProbeReader::new(bytes, chunk);
        let mut framed = FramedRead::new(input, PacketCodec);
        let one = framed.next().await.unwrap().unwrap();
        let two = framed.next().await.unwrap().unwrap();
        assert_eq!(one.to_bytes(), first.to_bytes());
        assert_eq!(two.to_bytes(), second.to_bytes());
        if chunk == 8192 {
            assert_eq!(facts.lock().unwrap().calls, 1);
        }
    }
}

#[tokio::test]
async fn body_read_error_loses_stage_without_an_io_adapter() {
    let (mut input, _) = ProbeReader::new(header(17, 4).to_bytes().to_vec(), 12);
    input.terminal_error = Some(io::ErrorKind::ConnectionReset);
    let mut framed = FramedRead::new(input, PacketCodec);
    assert!(matches!(
        framed.next().await,
        Some(Err(DecodeError::HeaderIo(error))) if error.kind() == io::ErrorKind::ConnectionReset
    ));
    let (mut old, _) = ProbeReader::new(header(17, 4).to_bytes().to_vec(), 12);
    old.terminal_error = Some(io::ErrorKind::ConnectionReset);
    assert!(matches!(
        PacketReader::new(None).read_packet(&mut old).await,
        PacketReadResult::BodyReadError { session_id: 17, error }
            if error.kind() == io::ErrorKind::ConnectionReset
    ));
}

#[tokio::test]
async fn eof_classification_requires_the_custom_decoder() {
    for count in [0, 6, 12, 14] {
        let bytes = packet(17, 4).to_bytes()[..count].to_vec();
        let (input, _) = ProbeReader::new(bytes, 2);
        let mut framed = FramedRead::new(input, PacketCodec);
        let result = framed.next().await.unwrap();
        if count < 12 {
            assert!(matches!(
                result,
                Err(DecodeError::HeaderIo(error)) if error.kind() == io::ErrorKind::UnexpectedEof
            ));
        } else {
            assert!(matches!(
                result,
                Err(DecodeError::BodyIo(17, error)) if error.kind() == io::ErrorKind::UnexpectedEof
            ));
        }
    }
}

#[tokio::test]
async fn cancelled_next_retains_partial_header_and_body() {
    use tokio::io::AsyncWriteExt;
    for split in [6, 14] {
        let (mut sender, receiver) = tokio::io::duplex(128);
        let bytes = packet(17, 4).to_bytes();
        sender.write_all(&bytes[..split]).await.unwrap();
        let mut framed = FramedRead::new(receiver, PacketCodec);
        {
            let mut next = std::pin::pin!(framed.next());
            assert!(poll_once(next.as_mut()).is_pending());
        }
        assert_eq!(framed.read_buffer().len(), split);
        sender.write_all(&bytes[split..]).await.unwrap();
        assert_eq!(framed.next().await.unwrap().unwrap().to_bytes(), bytes);
    }
}

#[tokio::test]
async fn maximum_frame_retains_a_large_prefetch_window_on_reuse() {
    let mut bytes = packet(17, TACACS_MAX_BODY_LENGTH as usize).to_bytes();
    bytes.extend(header(18, u32::MAX).to_bytes());
    bytes.extend(vec![0x42; 100_000]);
    let (input, facts) = ProbeReader::new(bytes, usize::MAX);
    let mut framed = FramedRead::new(input, PacketCodec);
    assert_eq!(framed.next().await.unwrap().unwrap().body().len(), TACACS_MAX_BODY_LENGTH as usize);
    let before = facts.lock().unwrap().bytes;
    assert!(matches!(framed.next().await, Some(Err(DecodeError::Oversized(u32::MAX)))));
    let after = facts.lock().unwrap().bytes;
    println!(
        "reused FramedRead: extra read={}, largest request={}, retained capacity={}",
        after - before,
        facts.lock().unwrap().largest_request,
        framed.read_buffer().capacity()
    );
    assert!(after - before > 8192);
}

#[tokio::test]
async fn existing_buffer_reads_only_eight_kib_before_rejecting_the_next_header() {
    let mut bytes = packet(17, TACACS_MAX_BODY_LENGTH as usize).to_bytes();
    bytes.extend(header(18, u32::MAX).to_bytes());
    bytes.extend(vec![0x42; 100_000]);
    let (input, facts) = ProbeReader::new(bytes, usize::MAX);
    let mut input = tokio::io::BufReader::new(input);
    let reader = PacketReader::new(None);
    assert!(matches!(reader.read_packet(&mut input).await, PacketReadResult::Success(_)));
    let before = facts.lock().unwrap().bytes;
    facts.lock().unwrap().largest_request = 0;
    assert!(matches!(
        reader.read_packet(&mut input).await,
        PacketReadResult::BodyLengthExceeded {
            body_length: u32::MAX,
            ..
        }
    ));
    let facts = facts.lock().unwrap();
    assert_eq!(facts.bytes - before, 8192);
    assert_eq!(facts.largest_request, 8192);
    println!(
        "existing buffered reader: extra read={}, largest request={}",
        facts.bytes - before,
        facts.largest_request
    );
}

#[tokio::test]
async fn contiguous_and_partial_writes_preserve_wire_bytes() {
    for chunk in [1, 5, usize::MAX] {
        let (output, facts) = writer(usize::MAX, chunk);
        let mut framed = FramedWrite::new(output, PacketCodec);
        let packet = packet(17, 37);
        let bytes = packet.to_bytes();
        framed.send(packet).await.unwrap();
        assert_eq!(facts.lock().unwrap().bytes, bytes);
        if chunk == usize::MAX {
            assert_eq!(facts.lock().unwrap().calls, 1);
        }
    }
}

#[tokio::test]
async fn cancelled_send_keeps_unwritten_bytes_and_later_reuse_sends_them() {
    for allowance in [0, 5, 16] {
        let (output, facts) = writer(allowance, usize::MAX);
        facts.lock().unwrap().flush_pending = allowance == 16;
        let mut framed = FramedWrite::new(output, PacketCodec);
        let bytes = packet(17, 4).to_bytes();
        {
            let mut send = std::pin::pin!(framed.send(packet(17, 4)));
            assert!(poll_once(send.as_mut()).is_pending());
        }
        assert_eq!(facts.lock().unwrap().bytes, bytes[..allowance]);
        assert_eq!(framed.write_buffer(), &bytes[allowance..]);
        {
            let mut facts = facts.lock().unwrap();
            facts.allowance = usize::MAX;
            facts.flush_pending = false;
        }
        let second = packet(18, 2).to_bytes();
        framed.send(packet(18, 2)).await.unwrap();
        let mut expected = bytes;
        expected.extend(second);
        assert_eq!(facts.lock().unwrap().bytes, expected);
    }
}

#[tokio::test]
async fn cancelled_send_drop_keeps_only_the_already_written_prefix() {
    for allowance in [0, 5, 16] {
        let (output, facts) = writer(allowance, usize::MAX);
        facts.lock().unwrap().flush_pending = allowance == 16;
        let mut framed = FramedWrite::new(output, PacketCodec);
        {
            let mut send = std::pin::pin!(framed.send(packet(17, 4)));
            assert!(poll_once(send.as_mut()).is_pending());
        }
        assert_eq!(framed.write_buffer().len(), 16 - allowance);
        drop(framed);
        assert_eq!(facts.lock().unwrap().bytes, packet(17, 4).to_bytes()[..allowance]);
    }
}

#[tokio::test]
async fn existing_message_counter_counts_complete_writes_not_sink_flushes() {
    let counters = crate::ServerCounters::default();
    let old = PacketWriter::new(None).with_counters(Some(counters.clone()));
    let (mut output, facts) = writer(usize::MAX, usize::MAX);
    facts.lock().unwrap().flush_pending = true;
    assert!(matches!(
        old.write_packet(&mut output, packet(17, 4)).await,
        PacketWriteResult::Success
    ));
    assert_eq!(counters.snapshot().messages_sent, 1);
    assert_eq!(facts.lock().unwrap().bytes.len(), 16);
    let (output, facts) = writer(usize::MAX, usize::MAX);
    facts.lock().unwrap().flush_pending = true;
    let mut framed = FramedWrite::new(output, PacketCodec);
    {
        let mut send = std::pin::pin!(framed.send(packet(17, 4)));
        assert!(poll_once(send.as_mut()).is_pending());
    }
    assert_eq!(facts.lock().unwrap().bytes.len(), 16);
    assert!(framed.write_buffer().is_empty());
}

#[tokio::test]
async fn existing_cancelled_write_does_not_count_a_partial_packet() {
    let counters = crate::ServerCounters::default();
    let old = PacketWriter::new(None).with_counters(Some(counters.clone()));
    let (mut output, facts) = writer(5, usize::MAX);
    {
        let mut send = std::pin::pin!(old.write_packet(&mut output, packet(17, 4)));
        assert!(poll_once(send.as_mut()).is_pending());
    }
    assert_eq!(counters.snapshot().messages_sent, 0);
    assert_eq!(facts.lock().unwrap().bytes.len(), 5);
}

#[test]
fn primary_futures_remain_send() {
    fn assert_send(_: impl Send) {}
    let (reader, _) = ProbeReader::new(Vec::new(), 1);
    let mut reader = FramedRead::new(reader, PacketCodec);
    assert_send(reader.next());
    let (writer, _) = writer(0, 1);
    let mut writer = FramedWrite::new(writer, PacketCodec);
    assert_send(writer.send(packet(17, 4)));
}
