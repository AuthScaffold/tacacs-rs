//! Evidence from the same TCP socket after a failed connection attempt.
//!
//! A fresh socket with zero transmitted segments cannot receive a legitimate
//! remote TCP/ICMP connection error. Unknown or truncated evidence is not proof.

use std::io;
use std::mem::{offset_of, size_of};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use anyhow::Context;
use tokio::net::TcpSocket;

const SEGMENTS_OUT_OFFSET: usize = offset_of!(libc::tcp_info, tcpi_segs_out);
const SEGMENTS_OUT_END: usize = SEGMENTS_OUT_OFFSET + size_of::<u32>();

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
    let mut bytes = [0_u8; size_of::<libc::tcp_info>()];
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
    anyhow::ensure!(
        returned <= bytes.len() && returned >= SEGMENTS_OUT_END,
        "kernel TCP_INFO reply does not contain the transmitted-segment counter"
    );
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
        let bytes = [0; size_of::<libc::tcp_info>()];
        for returned in [0, SEGMENTS_OUT_END - 1, bytes.len() + 1] {
            assert!(segments_out(&bytes, returned).is_err());
        }
        assert!(segments_out(&bytes[..SEGMENTS_OUT_END - 1], SEGMENTS_OUT_END).is_err());
    }

    #[test]
    fn complete_counter_distinguishes_no_send_from_remote_error_evidence() {
        // Linux adds fields after the stable TCP_INFO prefix. Both 32-bit and
        // 64-bit Linux ABIs place tcpi_segs_out at byte 136.
        assert_eq!(SEGMENTS_OUT_OFFSET, 136);
        let mut bytes = [0; size_of::<libc::tcp_info>()];
        assert_eq!(segments_out(&bytes, SEGMENTS_OUT_END).unwrap(), 0);
        bytes[SEGMENTS_OUT_OFFSET..SEGMENTS_OUT_END].copy_from_slice(&1_u32.to_ne_bytes());
        assert_eq!(segments_out(&bytes, SEGMENTS_OUT_END).unwrap(), 1);
    }

    #[cfg(not(miri))]
    #[tokio::test]
    async fn real_socket_evidence_survives_socket_ownership_transfer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpSocket::new_v4().unwrap();
        let evidence = ConnectEvidence::new(&socket).unwrap();
        assert!(evidence.no_segments_sent().unwrap());
        let stream = socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (_peer, _) = listener.accept().await.unwrap();
        assert!(!evidence.no_segments_sent().unwrap());
        drop(stream);
        assert!(!evidence.no_segments_sent().unwrap());
    }
}
