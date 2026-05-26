use async_trait::async_trait;
use log::info;
use tacacsrs_flow_abstractions::authorization::{build_authorization_packet, parse_authorization_reply};
use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
use tacacsrs_messages::authorization::{reply::AuthorizationReply, request::AuthorizationRequest};
use tacacsrs_messages::packet::PacketTrait;

/// Fixed TACACS+ client authorization flow.
///
/// Implement this on any type that can provide [`ClientSessionFlowIoTrait`].
#[async_trait]
pub trait AuthorizationFlow: ClientSessionFlowIoTrait {
    /// Sends an authorization request with default flags (`TAC_PLUS_UNENCRYPTED_FLAG`).
    async fn send_authorization_request(
        &self,
        request: AuthorizationRequest,
    ) -> anyhow::Result<AuthorizationReply> {
        if self.is_complete().await {
            return Err(anyhow::Error::msg("Session is already complete"));
        }

        let sequence_number = self.next_sequence_number().await;
        let packet = build_authorization_packet(self.session_id(), sequence_number, &request)?;
        let flags = packet.header().flags;

        info!(
            target: "tacacsrs_flows::authorization",
            "Sending Authorization Request with sequence number {} for session {} (flags: {:?})",
            sequence_number, self.session_id(), flags
        );

        self.send_packet(packet).await?;
        let response = self.receive_packet().await?;
        let reply = parse_authorization_reply(&response)?;

        self.complete().await;

        info!(
            target: "tacacsrs_flows::authorization",
            "Received Authorization Reply. Session now complete"
        );

        Ok(reply)
    }
}

impl<T> AuthorizationFlow for T where T: ClientSessionFlowIoTrait + ?Sized {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use tacacsrs_messages::enumerations::{
        TacacsAuthenticationMethod, TacacsAuthenticationService, TacacsAuthenticationType,
        TacacsAuthorizationStatus, TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::packet::Packet;
    use tacacsrs_messages::traits::TacacsBodyTrait;
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

    fn authorization_request() -> AuthorizationRequest {
        AuthorizationRequest {
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus,
            priv_lvl: 15,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeAscii,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcLogin,
            user: "admin".to_owned(),
            port: "test".to_owned(),
            rem_address: "1.1.1.1".to_owned(),
            args: vec!["service=shell".to_owned(), "cmd=show".to_owned()],
        }
    }

    fn authorization_reply() -> AuthorizationReply {
        AuthorizationReply {
            status: TacacsAuthorizationStatus::TacPlusPassAdd,
            server_msg: "Authorized".to_owned(),
            data: String::new(),
            args: vec!["priv-lvl=15".to_owned()],
        }
    }

    #[tokio::test]
    async fn test_send_authorization_request_flow() -> anyhow::Result<()> {
        let request = authorization_request();
        let authorization_reply = authorization_reply();
        let reply_bytes = authorization_reply.to_bytes()?;
        let reply_length = u32::try_from(reply_bytes.len())
            .map_err(|_| anyhow::Error::msg("Authorization reply payload exceeds u32 length"))?;

        let reply_packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAuthorisation,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id: 42,
                length: reply_length,
            },
            reply_bytes,
        )?;

        let io = TestIo::new(42, VecDeque::from([reply_packet]));
        let reply = io.send_authorization_request(request).await?;

        assert_eq!(reply.status, TacacsAuthorizationStatus::TacPlusPassAdd);
        assert_eq!(reply.args, vec!["priv-lvl=15"]);

        let sent_packets = io.sent_packets.lock().await;
        assert_eq!(sent_packets.len(), 1);
        assert_eq!(sent_packets[0].header().session_id, 42);
        assert_eq!(sent_packets[0].header().seq_no, 1);
        assert_eq!(sent_packets[0].header().tacacs_type, TacacsType::TacPlusAuthorisation);
        assert!(io.is_complete().await);

        Ok(())
    }

    #[tokio::test]
    async fn test_send_authorization_request_with_session_adapter() -> anyhow::Result<()> {
        let mock_transport = MockTransport::new();
        let mock_control = mock_transport.coordinator();
        let tacacs_connection = Arc::new(TacacsConnection::new(None));
        tacacs_connection.run(mock_transport).await?;

        let session = tacacs_connection.create_session().await?;
        let session_id = session.session_id();
        let request = authorization_request();
        let authorization_reply = authorization_reply();

        mock_control
            .authorization_reply(&session, 2, &authorization_reply)
            .send()
            .await?;

        let reply = session.send_authorization_request(request).await?;
        assert_eq!(reply.status, TacacsAuthorizationStatus::TacPlusPassAdd);
        assert_eq!(reply.args, vec!["priv-lvl=15"]);
        assert!(session.is_complete().await);

        let requests = mock_control.get_requests_for_session(session_id).await?;
        let sent_packet = requests
            .get(&1)
            .ok_or_else(|| anyhow::Error::msg("Missing authorization request packet with seq 1"))?;
        assert_eq!(sent_packet.header().session_id, session_id);
        assert_eq!(sent_packet.header().seq_no, 1);
        assert_eq!(sent_packet.header().tacacs_type, TacacsType::TacPlusAuthorisation);

        let sent_request = AuthorizationRequest::from_bytes(sent_packet.body())?;
        assert_eq!(sent_request.user, "admin");
        assert_eq!(sent_request.args, vec!["service=shell", "cmd=show"]);

        Ok(())
    }
}
