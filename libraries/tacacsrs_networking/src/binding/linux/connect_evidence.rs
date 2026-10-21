//! Evidence from the same TCP socket after a failed connection attempt.
//!
//! A fresh socket with zero transmitted segments cannot receive a legitimate
//! remote TCP/ICMP connection error. Unknown or truncated evidence is not proof.

use std::io;
use std::mem::size_of;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use anyhow::Context;
use tokio::net::TcpSocket;

// Linux UAPI struct tcp_info has a stable prefix on 32-bit and 64-bit targets.
// tcpi_segs_out occupies bytes 136..140. Do not depend on libc's struct version.
const SEGMENTS_OUT_OFFSET: usize = 136;
const SEGMENTS_OUT_END: usize = SEGMENTS_OUT_OFFSET + size_of::<u32>();

#[derive(Debug, PartialEq, Eq)]
struct IncompleteCounter {
    returned: usize,
}

impl std::fmt::Display for IncompleteCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "kernel TCP_INFO reply does not contain the transmitted-segment counter ({} bytes, {} required)", self.returned, SEGMENTS_OUT_END)
    }
}

impl std::error::Error for IncompleteCounter {}

pub(crate) struct ConnectEvidence {
    socket: OwnedFd,
}

impl ConnectEvidence {
    pub(crate) fn new(socket: &TcpSocket) -> anyhow::Result<Self> {
        Ok(Self {
            socket: socket
                .as_fd()
                .try_clone_to_owned()
                .context("retain TCP socket for local routing evidence")?,
        })
    }

    pub(crate) fn no_segments_sent(&self) -> anyhow::Result<bool> {
        Ok(read_segments_out(self.socket.as_fd())? == 0)
    }
}

#[allow(unsafe_code)]
fn read_segments_out(socket: BorrowedFd<'_>) -> anyhow::Result<u32> {
    let mut bytes = [0_u8; SEGMENTS_OUT_END];
    let mut length: libc::socklen_t = bytes
        .len()
        .try_into()
        .context("TCP_INFO buffer exceeds the socket option size limit")?;
    // SAFETY: The borrowed descriptor remains open during this call. Both pointers
    // refer to writable buffers of the declared lengths. getsockopt copies bytes
    // into them and does not retain either pointer. No typed tcp_info is assumed.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            bytes.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error()).context("inspect failed TCP connection evidence");
    }
    segments_out(&bytes, length.try_into().context("invalid TCP_INFO reply length")?)
}

fn segments_out(bytes: &[u8], returned: usize) -> anyhow::Result<u32> {
    anyhow::ensure!(returned <= bytes.len(), "kernel TCP_INFO reply exceeds the supplied buffer");
    if returned < SEGMENTS_OUT_END {
        return Err(IncompleteCounter { returned }.into());
    }
    let value = bytes
        .get(SEGMENTS_OUT_OFFSET..SEGMENTS_OUT_END)
        .context("TCP_INFO buffer omits the transmitted-segment counter")?;
    Ok(u32::from_ne_bytes(value.try_into()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_or_unknown_replies_never_prove_zero_segments() {
        let bytes = [0; SEGMENTS_OUT_END];
        for returned in [0, 4, 104, SEGMENTS_OUT_END - 1] {
            let error = segments_out(&bytes, returned).unwrap_err();
            assert_eq!(
                error.downcast_ref::<IncompleteCounter>(),
                Some(&IncompleteCounter { returned }),
            );
        }
        assert!(segments_out(&bytes, bytes.len() + 1).is_err());
        assert!(segments_out(&bytes[..SEGMENTS_OUT_END - 1], SEGMENTS_OUT_END).is_err());
    }

    #[test]
    fn complete_counter_distinguishes_no_send_from_remote_error_evidence() {
        let mut bytes = [0; SEGMENTS_OUT_END];
        assert_eq!(segments_out(&bytes, SEGMENTS_OUT_END).unwrap(), 0);
        // This independent ABI fixture also detects a changed parser offset.
        bytes[136..140].copy_from_slice(&1_u32.to_ne_bytes());
        assert_eq!(segments_out(&bytes, SEGMENTS_OUT_END).unwrap(), 1);
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn real_socket_evidence_survives_socket_ownership_transfer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        let evidence = ConnectEvidence::new(&socket).unwrap();
        let before = evidence.no_segments_sent();
        let stream = socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        let connected = evidence.no_segments_sent();
        drop(stream);
        let closed = evidence.no_segments_sent();
        match before {
            Ok(no_segments) => {
                assert!(no_segments);
                assert!(!connected.unwrap());
                assert!(!closed.unwrap());
            }
            Err(error) => {
                // QEMU 7.2 linux-user limits SOL_TCP replies to a four-byte int.
                // Exercise ownership transfer, but require the precise unsupported
                // result at every stage. No other socket or parser error passes.
                let incomplete = error.downcast_ref::<IncompleteCounter>().unwrap();
                assert!(incomplete.returned < SEGMENTS_OUT_END);
                for result in [connected, closed] {
                    assert_eq!(
                        result.unwrap_err().downcast_ref::<IncompleteCounter>(),
                        Some(incomplete),
                    );
                }
                eprintln!("TCP_INFO transmitted-segment evidence is unsupported: {error}. Local routing fallback remains disabled for failed connections.");
            }
        }
    }
}
