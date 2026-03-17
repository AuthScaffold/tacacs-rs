use anyhow::Context;
use serde::{de::DeserializeOwned, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Reads a single length-prefixed JSON message from the IPC stream.
///
/// # Errors
///
/// Returns an error if the frame length, payload, or JSON decoding fails.
pub async fn read_message<R, T>(reader: &mut R) -> anyhow::Result<T>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let length = reader
        .read_u32()
        .await
        .context("Failed to read IPC frame length")?;
    let mut payload = vec![0; length as usize];
    reader
        .read_exact(&mut payload)
        .await
        .context("Failed to read IPC frame payload")?;

    serde_json::from_slice(&payload).context("Failed to decode IPC JSON payload")
}

/// Writes a single length-prefixed JSON message to the IPC stream.
///
/// # Errors
///
/// Returns an error if JSON encoding fails, the message is too large for a
/// 32-bit frame length, or the stream write/flush operations fail.
pub async fn write_message<W, T>(writer: &mut W, message: &T) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = serde_json::to_vec(message).context("Failed to encode IPC JSON payload")?;
    let payload_len =
        u32::try_from(payload.len()).context("IPC payload exceeds maximum frame length")?;
    writer
        .write_u32(payload_len)
        .await
        .context("Failed to write IPC frame length")?;
    writer
        .write_all(&payload)
        .await
        .context("Failed to write IPC frame payload")?;
    writer.flush().await.context("Failed to flush IPC frame")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{AccountingOperation, ServiceRequest};

    #[tokio::test]
    async fn test_round_trip_codec() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        let message = ServiceRequest::Accounting(AccountingOperation {
            user: "alice".to_owned(),
            port: "tty1".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            command: "show".to_owned(),
            command_arguments: vec!["users".to_owned()],
            custom_flag_1: true,
            custom_flag_2: false,
            session_id: Some(42),
        });

        write_message(&mut client, &message).await.unwrap();
        let decoded: ServiceRequest = read_message(&mut server).await.unwrap();
        assert_eq!(decoded, message);
    }
}
