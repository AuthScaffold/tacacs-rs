//! Compatibility shim for the accounting session flow.
//!
//! The accounting flow implementation has moved to [`tacacsrs_flows::accounting`].
//! This module provides a trait-based wrapper for backward compatibility.

use async_trait::async_trait;
use tacacsrs_messages::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_messages::enumerations::TacacsFlags;

use crate::session::Session;

/// Trait for sending accounting requests through a [`Session`].
///
/// This delegates to [`tacacsrs_flows::accounting`] under the hood.
/// New code should prefer calling the flow functions directly.
#[async_trait]
pub trait AccountingSessionTrait {
    /// Sends an accounting request with default flags (TAC_PLUS_UNENCRYPTED_FLAG)
    async fn send_accounting_request(
        &self,
        request: AccountingRequest,
    ) -> anyhow::Result<AccountingReply>;

    /// Sends an accounting request with custom flags added to the header
    ///
    /// # Arguments
    ///
    /// * `request` - The accounting request to send
    /// * `custom_flags` - Additional flags to set on the packet header (e.g., TAC_PLUS_CUSTOM_FLAG_1, TAC_PLUS_CUSTOM_FLAG_2)
    async fn send_accounting_request_with_flags(
        &self,
        request: AccountingRequest,
        custom_flags: TacacsFlags,
    ) -> anyhow::Result<AccountingReply>;
}

#[async_trait]
impl AccountingSessionTrait for Session {
    async fn send_accounting_request(
        &self,
        request: AccountingRequest,
    ) -> anyhow::Result<AccountingReply> {
        tacacsrs_flows::accounting::send_accounting_request(self, request).await
    }

    async fn send_accounting_request_with_flags(
        &self,
        request: AccountingRequest,
        custom_flags: TacacsFlags,
    ) -> anyhow::Result<AccountingReply> {
        tacacsrs_flows::accounting::send_accounting_request_with_flags(self, request, custom_flags)
            .await
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tacacsrs_messages::enumerations::*;

    use crate::connection::TacacsConnection;
    use crate::transport::mock::MockTransport;
    use crate::traits::SessionManagementTrait;
    use test_log::test;
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::packet::Packet;
    use tacacsrs_messages::traits::TacacsBodyTrait;


    #[test(tokio::test)]
    async fn test_send_accounting_request() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mock_transport = MockTransport::new();
        let mock_control = mock_transport.coordinator();
        let tacacs_connection = Arc::new(TacacsConnection::new(None));
        tacacs_connection.run(mock_transport).await?;

        let session = tacacs_connection.create_session().await?;

        let accounting_request = AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "admin".to_string(),
            port: "test".to_string(),
            rem_address: "1.1.1.1".to_string(),
            args: vec![
                "service=shell".to_string(),
                "task_id=123".to_string(),
                "cmd=test".to_string(),
            ],
        };

        let accounting_reply = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "Test".to_string(),
            data: "".to_string(),
        };

        mock_control
            .add_accounting_reply(&session, 2, &accounting_reply)
            .await?;

        let reply = session.send_accounting_request(accounting_request).await?;

        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);


        let requests = mock_control
            .get_requests_for_session(session.session_id)
            .await?;
        assert_eq!(requests.len(), 1, "The number of requests for the session was not as expected");

        let replies = mock_control
            .get_replies_for_session(session.session_id)
            .await?;
        assert_eq!(
            replies.len(),
            0,
            "There was replies registered to session when they should have all been removed"
        );


        Ok(())
    }

    #[test(tokio::test)]
    async fn test_send_accounting_request_with_delay() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mock_transport = MockTransport::new();
        let mock_control = mock_transport.coordinator();
        let tacacs_connection = Arc::new(TacacsConnection::new(None));
        tacacs_connection.run(mock_transport).await?;

        let session = tacacs_connection.create_session().await?;

        let accounting_request = AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "admin".to_string(),
            port: "test".to_string(),
            rem_address: "1.1.1.1".to_string(),
            args: vec![
                "service=shell".to_string(),
                "task_id=123".to_string(),
                "cmd=test".to_string(),
            ],
        };

        let accounting_reply = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "Test".to_string(),
            data: "".to_string(),
        };

        // Configure reply with a delay
        mock_control
            .add_accounting_reply_with_delay(
                &session,
                2,
                &accounting_reply,
                Duration::from_millis(100),
            )
            .await?;

        let start = Instant::now();
        let reply = session.send_accounting_request(accounting_request).await?;
        let elapsed = start.elapsed();

        assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        assert!(
            elapsed >= Duration::from_millis(100),
            "Expected at least 100ms delay but got {:?}",
            elapsed
        );

        Ok(())
    }

    #[test(tokio::test)]
    async fn test_concurrent_sessions() -> anyhow::Result<()> {
        let _ = env_logger::builder().is_test(true).try_init();

        let mock_transport = MockTransport::new();
        let mock_control = mock_transport.coordinator();
        let tacacs_connection = Arc::new(TacacsConnection::new(None));
        tacacs_connection.run(mock_transport).await?;

        // Create first session
        let session1 = tacacs_connection.create_session().await?;

        let accounting_request1 = AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "user1".to_string(),
            port: "test1".to_string(),
            rem_address: "1.1.1.1".to_string(),
            args: vec!["service=shell".to_string()],
        };

        let accounting_reply1 = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "Reply1".to_string(),
            data: "".to_string(),
        };

        // Configure first reply with single connect flag to enable multiple sessions
        let data = accounting_reply1.to_bytes();
        let reply_packet = Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type: TacacsType::TacPlusAccounting,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG
                    | TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                session_id: session1.session_id,
                length: data.len() as u32,
            },
            data,
        )?;
        mock_control.add_reply(reply_packet).await?;

        // Send first request - this will set single connection state to Supported
        let reply1 = session1
            .send_accounting_request(accounting_request1)
            .await?;
        assert_eq!(reply1.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);

        // Now we can create a second session since single connection mode is supported
        let session2 = tacacs_connection.create_session().await?;

        let accounting_request2 = AccountingRequest {
            flags: TacacsAccountingFlags::START,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: "user2".to_string(),
            port: "test2".to_string(),
            rem_address: "2.2.2.2".to_string(),
            args: vec!["service=shell".to_string()],
        };

        let accounting_reply2 = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "Reply2".to_string(),
            data: "".to_string(),
        };

        // Configure reply for second session with delay
        mock_control
            .add_accounting_reply_with_delay(
                &session2,
                2,
                &accounting_reply2,
                Duration::from_millis(50),
            )
            .await?;

        // Send second request
        let reply2 = session2
            .send_accounting_request(accounting_request2)
            .await?;

        assert_eq!(reply2.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        assert_eq!(reply2.server_msg, "Reply2");

        // Verify requests were tracked for both sessions
        let requests1 = mock_control
            .get_requests_for_session(session1.session_id)
            .await?;
        assert_eq!(requests1.len(), 1);

        let requests2 = mock_control
            .get_requests_for_session(session2.session_id)
            .await?;
        assert_eq!(requests2.len(), 1);

        Ok(())
    }
}
