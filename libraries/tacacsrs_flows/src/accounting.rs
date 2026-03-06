//! Client-side TACACS+ Accounting flow.
//!
//! This module implements the single-turn Accounting request/reply exchange.
//! It constructs the appropriate TACACS+ packet, sends it through the session,
//! and parses the reply.
//!
//! # Usage
//!
//! ```ignore
//! use tacacsrs_flows::accounting::send_accounting_request;
//! use tacacsrs_messages::accounting::request::AccountingRequest;
//! use tacacsrs_messages::enumerations::TacacsFlags;
//!
//! let reply = send_accounting_request(&session, request, TacacsFlags::empty()).await?;
//! ```

use log::info;
use tacacsrs_messages::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_messages::enumerations::{
    TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::Packet;
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_messages::packet::PacketTrait;

use crate::ClientSessionIo;

/// Sends an accounting request with default flags (`TAC_PLUS_UNENCRYPTED_FLAG`).
///
/// This is a convenience wrapper around [`send_accounting_request_with_flags`]
/// that uses no additional custom flags.
pub async fn send_accounting_request(
    session: &dyn ClientSessionIo,
    request: AccountingRequest,
) -> anyhow::Result<AccountingReply> {
    send_accounting_request_with_flags(session, request, TacacsFlags::empty()).await
}
/// Sends an accounting request with custom flags added to the header.
///
/// Constructs a TACACS+ Accounting packet using the session's sequence number
/// and session ID, sends it, waits for the reply, and marks the session complete.
///
/// # Arguments
///
/// * `session` - The session I/O interface to use for sending/receiving.
/// * `request` - The accounting request body.
/// * `custom_flags` - Additional flags to OR into the packet header
///   (e.g., `TAC_PLUS_CUSTOM_FLAG_1`, `TAC_PLUS_CUSTOM_FLAG_2`).
///
/// # Errors
///
/// Returns an error if:
/// - The session is already complete.
/// - Packet construction fails.
/// - Sending fails.
/// - No reply is received (channel closed).
/// - Reply body parsing fails.
pub async fn send_accounting_request_with_flags(
    session: &dyn ClientSessionIo,
    request: AccountingRequest,
    custom_flags: TacacsFlags,
) -> anyhow::Result<AccountingReply> {
    if session.is_complete().await {
        return Err(anyhow::Error::msg("Session is already complete"));
    }

    let sequence_number = session.next_sequence_number().await;
    let data = request.to_bytes();
    let flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | custom_flags;

    let packet = Packet::new(
        Header {
            major_version: TacacsMajorVersion::TacacsPlusMajor1,
            minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: TacacsType::TacPlusAccounting,
            seq_no: sequence_number,
            flags,
            session_id: session.session_id(),
            length: data.len() as u32,
        },
        data,
    )?;

    info!(
        target: "tacacsrs_flows::accounting",
        "Sending Accounting Request with sequence number {} for session {} (flags: {:?})",
        sequence_number, session.session_id(), flags
    );

    session.send_packet(packet).await?;

    let response = match session.receive_packet().await {
        Some(response) => response,
        None => return Err(anyhow::Error::msg("Failed to receive response")),
    };

    let reply = AccountingReply::from_bytes(response.body())?;

    session.complete().await;

    info!(
        target: "tacacsrs_flows::accounting",
        "Received Accounting Reply. Session now complete"
    );

    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use tokio::sync::Mutex;

    use tacacsrs_messages::enumerations::*;
    use tacacsrs_messages::traits::TacacsBodyTrait;

    /// Lightweight in-process mock of [`ClientSessionIo`] for testing flows
    /// without any networking infrastructure.
    struct MockSessionIo {
        id: u32,
        seq: AtomicU8,
        completed: AtomicBool,
        reply_packet: Mutex<Option<Packet>>,
        sent: Mutex<Vec<Packet>>,
    }

    impl MockSessionIo {
        fn new(id: u32) -> Self {
            Self {
                id,
                seq: AtomicU8::new(1),
                completed: AtomicBool::new(false),
                reply_packet: Mutex::new(None),
                sent: Mutex::new(Vec::new()),
            }
        }

        async fn set_reply(&self, reply: &AccountingReply, seq_no: u8, session_id: u32) {
            let data = reply.to_bytes();
            let packet = Packet::new(
                tacacsrs_messages::header::Header {
                    major_version: TacacsMajorVersion::TacacsPlusMajor1,
                    minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                    tacacs_type: TacacsType::TacPlusAccounting,
                    seq_no,
                    flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                    session_id,
                    length: data.len() as u32,
                },
                data,
            )
            .unwrap();
            *self.reply_packet.lock().await = Some(packet);
        }
    }

    #[async_trait]
    impl ClientSessionIo for MockSessionIo {
        fn session_id(&self) -> u32 {
            self.id
        }

        async fn next_sequence_number(&self) -> u8 {
            self.seq.fetch_add(2, Ordering::Relaxed)
        }

        async fn is_complete(&self) -> bool {
            self.completed.load(Ordering::Relaxed)
        }

        async fn complete(&self) {
            self.completed.store(true, Ordering::Relaxed);
        }

        async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
            self.sent.lock().await.push(packet);
            Ok(())
        }

        async fn receive_packet(&self) -> Option<Packet> {
            self.reply_packet.lock().await.take()
        }
    }

    #[tokio::test]
    async fn test_accounting_flow_send_and_receive() {
        let mock = MockSessionIo::new(42);
        let expected_reply = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "OK".to_string(),
            data: "".to_string(),
        };
        mock.set_reply(&expected_reply, 2, 42).await;

        let request = AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "testuser".to_string(),
            port: "tty0".to_string(),
            rem_address: "10.0.0.1".to_string(),
            args: vec!["service=shell".to_string()],
        };

        let reply = send_accounting_request(&mock, request).await.unwrap();

        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        assert_eq!(reply.server_msg, "OK");
        assert!(mock.is_complete().await, "session should be marked complete");
        assert_eq!(mock.sent.lock().await.len(), 1, "one packet should have been sent");
    }

    #[tokio::test]
    async fn test_accounting_flow_with_custom_flags() {
        let mock = MockSessionIo::new(99);
        let expected_reply = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "flagged".to_string(),
            data: "".to_string(),
        };
        mock.set_reply(&expected_reply, 2, 99).await;

        let request = AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "admin".to_string(),
            port: "tty1".to_string(),
            rem_address: "10.0.0.2".to_string(),
            args: vec![],
        };

        let reply = send_accounting_request_with_flags(
            &mock,
            request,
            TacacsFlags::TAC_PLUS_CUSTOM_FLAG_1,
        )
        .await
        .unwrap();

        assert_eq!(reply.server_msg, "flagged");

        // Verify the sent packet has the custom flag set
        let sent = mock.sent.lock().await;
        let sent_header = sent[0].header();
        assert!(sent_header.flags.contains(TacacsFlags::TAC_PLUS_CUSTOM_FLAG_1));
        assert!(sent_header.flags.contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
    }

    #[tokio::test]
    async fn test_accounting_flow_errors_when_session_complete() {
        let mock = MockSessionIo::new(1);
        mock.complete().await;

        let request = AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "x".to_string(),
            port: "x".to_string(),
            rem_address: "x".to_string(),
            args: vec![],
        };

        let err = send_accounting_request(&mock, request).await.unwrap_err();
        assert!(err.to_string().contains("already complete"));
    }

    #[tokio::test]
    async fn test_accounting_flow_errors_when_no_reply() {
        let mock = MockSessionIo::new(1);
        // Don't set any reply — receive_packet will return None

        let request = AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "x".to_string(),
            port: "x".to_string(),
            rem_address: "x".to_string(),
            args: vec![],
        };

        let err = send_accounting_request(&mock, request).await.unwrap_err();
        assert!(err.to_string().contains("Failed to receive response"));
    }
}
