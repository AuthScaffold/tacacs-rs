use async_trait::async_trait;
use log::info;
use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
use tacacsrs_messages::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_messages::enumerations::{TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType};
use tacacsrs_messages::header::Header;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_messages::traits::TacacsBodyTrait;

/// Fixed TACACS+ client accounting flow.
///
/// Implement this on any type that can provide [`ClientSessionFlowIoTrait`].
#[async_trait]
pub trait AccountingFlowTrait: ClientSessionFlowIoTrait {
    /// Sends an accounting request with default flags (`TAC_PLUS_UNENCRYPTED_FLAG`)
    async fn send_accounting_request(
        &self,
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
        &self,
        request: AccountingRequest,
        custom_flags: TacacsFlags,
    ) -> anyhow::Result<AccountingReply> {
        if self.is_complete().await {
            return Err(anyhow::Error::msg("Session is already complete"));
        }

        let sequence_number = self.next_sequence_number().await;
        let data = request.to_bytes();
        let length = u32::try_from(data.len())
            .map_err(|_| anyhow::Error::msg("Accounting request payload exceeds u32 length"))?;
        let flags = TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | custom_flags;

        let packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: sequence_number,
                flags,
                session_id: self.session_id(),
                length,
            },
            data,
        )?;

        info!(
            target: "tacacsrs_flows::accounting",
            "Sending Accounting Request with sequence number {} for session {} (flags: {:?})",
            sequence_number, self.session_id(), flags
        );

        self.send_packet(packet).await?;
        let response = self.receive_packet().await?;
        let reply = AccountingReply::from_bytes(response.body())?;

        self.complete().await;

        info!(
            target: "tacacsrs_flows::accounting",
            "Received Accounting Reply. Session now complete"
        );

        Ok(reply)
    }
}

impl<T> AccountingFlowTrait for T where T: ClientSessionFlowIoTrait + ?Sized {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use tacacsrs_messages::enumerations::{
        TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
        TacacsAuthenticationService, TacacsAuthenticationType,
    };
    use tacacsrs_networking::connection::TacacsConnection;
    use tacacsrs_networking::traits::SessionManagementTrait;
    use tacacsrs_networking::transport::mock::MockTransport;
    use tokio::sync::Mutex;

    struct TestIo {
        session_id: u32,
        next_seq: Mutex<u8>,
        complete: Mutex<bool>,
        sent_packets: Mutex<Vec<Packet>>,
        inbound_packets: Mutex<VecDeque<Packet>>,
    }

    impl TestIo {
        fn new(session_id: u32, inbound_packets: VecDeque<Packet>) -> Self {
            Self {
                session_id,
                next_seq: Mutex::new(1),
                complete: Mutex::new(false),
                sent_packets: Mutex::new(Vec::new()),
                inbound_packets: Mutex::new(inbound_packets),
            }
        }
    }

    #[async_trait]
    impl ClientSessionFlowIoTrait for TestIo {
        async fn is_complete(&self) -> bool {
            *self.complete.lock().await
        }

        async fn next_sequence_number(&self) -> u8 {
            let mut seq = self.next_seq.lock().await;
            let current = *seq;
            *seq = current.wrapping_add(2);
            current
        }

        fn session_id(&self) -> u32 {
            self.session_id
        }

        async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
            self.sent_packets.lock().await.push(packet);
            Ok(())
        }

        async fn receive_packet(&self) -> anyhow::Result<Packet> {
            self.inbound_packets
                .lock()
                .await
                .pop_front()
                .ok_or_else(|| anyhow::Error::msg("Failed to receive response"))
        }

        async fn complete(&self) {
            *self.complete.lock().await = true;
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
        let reply_bytes = accounting_reply.to_bytes();
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
        let reply = io.send_accounting_request(request).await?;

        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);

        let sent_packets = io.sent_packets.lock().await;
        assert_eq!(sent_packets.len(), 1);
        assert_eq!(sent_packets[0].header().session_id, 42);
        assert_eq!(sent_packets[0].header().seq_no, 1);
        assert_eq!(sent_packets[0].header().tacacs_type, TacacsType::TacPlusAccounting);
        assert!(io.is_complete().await);

        Ok(())
    }

    #[tokio::test]
    async fn test_send_accounting_request_with_session_adapter() -> anyhow::Result<()> {
        let mock_transport = MockTransport::new();
        let mock_control = mock_transport.coordinator();
        let tacacs_connection = Arc::new(TacacsConnection::new(None));
        tacacs_connection.run(mock_transport).await?;

        let session = tacacs_connection.create_session().await?;
        let session_id = session.session_id();

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

        mock_control
            .accounting_reply(&session, 2, &accounting_reply)
            .send()
            .await?;

        let reply = session.send_accounting_request(request).await?;
        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        assert!(session.is_complete().await);

        let requests = mock_control.get_requests_for_session(session_id).await?;
        let sent_packet = requests
            .get(&1)
            .ok_or_else(|| anyhow::Error::msg("Missing accounting request packet with seq 1"))?;
        assert_eq!(sent_packet.header().session_id, session_id);
        assert_eq!(sent_packet.header().seq_no, 1);
        assert_eq!(sent_packet.header().tacacs_type, TacacsType::TacPlusAccounting);

        let sent_request = AccountingRequest::from_bytes(sent_packet.body())?;
        assert_eq!(sent_request.user, "admin");
        assert_eq!(sent_request.args, vec!["service=shell", "cmd=test"]);

        Ok(())
    }
}
