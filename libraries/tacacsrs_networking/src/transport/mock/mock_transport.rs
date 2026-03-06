//! Mock transport implementation for TACACS+ tests.
//!
//! This transport can be passed directly to [`crate::connection::TacacsConnection::run`].
//! It captures request packets written by the connection, matches configured replies,
//! and enqueues reply bytes for the read half.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};

use tacacsrs_messages::constants::TACACS_HEADER_LENGTH;
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};

use crate::transport::abstractions::Transport;
use crate::transport::mock::mock_transport_coordinator::MockTransportCoordinator;

#[derive(Clone, Debug)]
pub(crate) struct ReplyConfig {
    pub(crate) bytes: Vec<u8>,
    pub(crate) delay: Option<Duration>,
}

#[derive(Debug, Default)]
pub(crate) struct MockState {
    pub(crate) replies: HashMap<u32, HashMap<u8, ReplyConfig>>,
    pub(crate) requests: HashMap<u32, HashMap<u8, Packet>>,
    pub(crate) write_buffer: Vec<u8>,
}

/// A mock transport that implements [`Transport`] for integration testing.
#[derive(Clone, Debug)]
pub struct MockTransport {
    state: Arc<Mutex<MockState>>,
    read_tx: mpsc::UnboundedSender<Vec<u8>>,
    read_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>>,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    /// Creates a new mock transport.
    pub fn new() -> Self {
        let (read_tx, read_rx) = mpsc::unbounded_channel();
        Self {
            state: Arc::new(Mutex::new(MockState::default())),
            read_tx,
            read_rx: Arc::new(Mutex::new(Some(read_rx))),
        }
    }

    /// Returns a coordinator handle for configuring and inspecting this transport.
    pub fn coordinator(&self) -> MockTransportCoordinator {
        MockTransportCoordinator {
            state: Arc::clone(&self.state),
        }
    }
}


impl Transport for MockTransport {
    type ReadHalf = MockReadHalf;
    type WriteHalf = MockWriteHalf;

    fn split(self) -> (Self::ReadHalf, Self::WriteHalf) {
        let mut rx_guard = self
            .read_rx
            .try_lock()
            .expect("mock transport split called concurrently or receiver already locked");
        let read_rx = rx_guard
            .take()
            .expect("mock transport split called more than once");

        (
            MockReadHalf {
                read_rx,
                pending: Vec::new(),
            },
            MockWriteHalf {
                state: Arc::clone(&self.state),
                read_tx: self.read_tx,
            },
        )
    }
}

pub struct MockReadHalf {
    read_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    pending: Vec<u8>,
}

impl AsyncRead for MockReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.pending.is_empty() {
            match Pin::new(&mut self.read_rx).poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(bytes)) => {
                    self.pending = bytes;
                }
            }
        }

        let to_copy = buf.remaining().min(self.pending.len());
        buf.put_slice(&self.pending[..to_copy]);
        self.pending.drain(..to_copy);
        Poll::Ready(Ok(()))
    }
}

pub struct MockWriteHalf {
    state: Arc<Mutex<MockState>>,
    read_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncWrite for MockWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut state = match this.state.try_lock() {
            Ok(state) => state,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        state.write_buffer.extend_from_slice(buf);

        loop {
            if state.write_buffer.len() < TACACS_HEADER_LENGTH {
                break;
            }

            let header = Header::from_bytes(&state.write_buffer[..TACACS_HEADER_LENGTH])
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let packet_len = TACACS_HEADER_LENGTH + header.length as usize;

            if state.write_buffer.len() < packet_len {
                break;
            }

            let packet_bytes = state.write_buffer.drain(..packet_len).collect::<Vec<u8>>();
            let request = Packet::from_bytes(&packet_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

            let session_id = request.header().session_id;
            let request_seq = request.header().seq_no;
            let reply_seq = request_seq.saturating_add(1);

            state
                .requests
                .entry(session_id)
                .or_default()
                .insert(request_seq, request);

            let reply = state
                .replies
                .get_mut(&session_id)
                .and_then(|reply_map| reply_map.remove(&reply_seq));

            if let Some(reply_config) = reply {
                let tx = this.read_tx.clone();
                if let Some(delay) = reply_config.delay {
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = tx.send(reply_config.bytes);
                    });
                } else {
                    let _ = tx.send(reply_config.bytes);
                }
            }
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
