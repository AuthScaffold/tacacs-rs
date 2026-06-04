use async_trait::async_trait;
use log::info;
use tacacsrs_flow_abstractions::accounting::{build_accounting_packet, parse_accounting_reply};
use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
use tacacsrs_messages::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_messages::enumerations::TacacsFlags;
use tacacsrs_messages::packet::PacketTrait;

/// Fixed TACACS+ client accounting flow.
///
/// Implement this on owned session handles that can provide
/// [`ClientSessionFlowIoTrait`]. Flow methods consume the session handle so a
/// completed session cannot be reused for another flow.
///
/// ```compile_fail
/// # use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
/// # use tacacsrs_flows::accounting::AccountingFlow;
/// # use tacacsrs_messages::accounting::request::AccountingRequest;
/// # async fn cannot_reuse_after_flow<S>(
/// #     session: S,
/// #     request: AccountingRequest,
/// # ) -> anyhow::Result<()>
/// # where
/// #     S: AccountingFlow,
/// # {
/// let _reply = session.send_accounting_request(request).await?;
/// let _session_id = session.session_id();
/// # Ok(())
/// # }
/// ```
#[async_trait]
pub trait AccountingFlow: ClientSessionFlowIoTrait + Sized + Send {
    /// Sends an accounting request with default flags (`TAC_PLUS_UNENCRYPTED_FLAG`)
    async fn send_accounting_request(
        self,
        request: AccountingRequest,
    ) -> anyhow::Result<AccountingReply> {
        self.send_accounting_request_with_flags(request, TacacsFlags::empty())
            .await
    }

    /// Sends an accounting request with custom flags added to the header
    ///
    /// # Arguments
    ///
    /// * `request` - The accounting request to send
    /// * `custom_flags` - Additional flags to set on the packet header
    async fn send_accounting_request_with_flags(
        self,
        request: AccountingRequest,
        custom_flags: TacacsFlags,
    ) -> anyhow::Result<AccountingReply> {
        if self.is_complete().await {
            return Err(anyhow::Error::msg("Session is already complete"));
        }

        let sequence_number = self.next_sequence_number().await;
        let packet =
            build_accounting_packet(self.session_id(), sequence_number, &request, custom_flags)?;
        let flags = packet.header().flags;

        info!(
            target: "tacacsrs_flows::accounting",
            "Sending Accounting Request with sequence number {} for session {} (flags: {:?})",
            sequence_number, self.session_id(), flags
        );

        self.send_packet(packet).await?;
        let response = self.receive_packet().await?;
        let reply = parse_accounting_reply(&response)?;

        self.complete().await;

        info!(
            target: "tacacsrs_flows::accounting",
            "Received Accounting Reply. Session now complete"
        );

        Ok(reply)
    }
}

impl<T> AccountingFlow for T where T: ClientSessionFlowIoTrait + Sized + Send {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tacacsrs_messages::enumerations::{
        TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
        TacacsAuthenticationService, TacacsAuthenticationType, TacacsMajorVersion,
        TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::packet::Packet;
    use tacacsrs_messages::traits::TacacsBodyTrait;
    use tokio::sync::Mutex;

    struct TestIo {
        session_id: u32,
        state: Arc<TestIoState>,
    }

    struct TestIoState {
        next_seq: Mutex<u8>,
        complete: Mutex<bool>,
        sent_packets: Mutex<Vec<Packet>>,
        inbound_packets: Mutex<VecDeque<Packet>>,
    }

    impl TestIo {
        fn new(session_id: u32, inbound_packets: VecDeque<Packet>) -> Self {
            Self {
                session_id,
                state: Arc::new(TestIoState {
                    next_seq: Mutex::new(1),
                    complete: Mutex::new(false),
                    sent_packets: Mutex::new(Vec::new()),
                    inbound_packets: Mutex::new(inbound_packets),
                }),
            }
        }
    }

    #[async_trait]
    impl ClientSessionFlowIoTrait for TestIo {
        async fn is_complete(&self) -> bool {
            *self.state.complete.lock().await
        }

        async fn next_sequence_number(&self) -> u8 {
            let mut seq = self.state.next_seq.lock().await;
            let current = *seq;
            *seq = current.wrapping_add(2);
            current
        }

        fn session_id(&self) -> u32 {
            self.session_id
        }

        async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
            self.state.sent_packets.lock().await.push(packet);
            Ok(())
        }

        async fn receive_packet(&self) -> anyhow::Result<Packet> {
            self.state
                .inbound_packets
                .lock()
                .await
                .pop_front()
                .ok_or_else(|| anyhow::Error::msg("Failed to receive response"))
        }

        async fn complete(&self) {
            *self.state.complete.lock().await = true;
        }
    }

    #[tokio::test]
    async fn test_send_accounting_request_flow() -> anyhow::Result<()> {
        let request = AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "admin".to_owned(),
            port: "test".to_owned(),
            rem_address: "1.1.1.1".to_owned(),
            args: vec!["service=shell".to_owned(), "cmd=test".to_owned()],
        };

        let accounting_reply = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "Test".to_owned(),
            data: String::new(),
        };
        let reply_bytes = accounting_reply.to_bytes()?;
        let reply_length = u32::try_from(reply_bytes.len())
            .map_err(|_| anyhow::Error::msg("Accounting reply payload exceeds u32 length"))?;

        let reply_packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: 42,
                length: reply_length,
            },
            reply_bytes,
        )?;

        let io = TestIo::new(42, VecDeque::from([reply_packet]));
        let state = io.state.clone();
        let reply = io.send_accounting_request(request).await?;

        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);

        let sent_packets = state.sent_packets.lock().await;
        assert_eq!(sent_packets.len(), 1);
        assert_eq!(sent_packets[0].header().session_id, 42);
        assert_eq!(sent_packets[0].header().seq_no, 1);
        assert_eq!(sent_packets[0].header().tacacs_type, TacacsType::TacPlusAccounting);
        assert!(*state.complete.lock().await);

        Ok(())
    }
}
