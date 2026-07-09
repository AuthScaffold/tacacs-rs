//! Upstream bridge for raw TACACS+ proxy connections.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
use tacacsrs_messages::packet::PacketTrait;
use tacacsrs_networking::PacketWriter;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;

use self::error::ProxyConnectionError;
use self::packet_io::{read_downstream_packet, read_upstream_packet, write_downstream_packet};
use self::reply_action::{ReplyAction, reply_action};
use self::session_mapping::rewrite_session_id;
use crate::config::ProxyDownstreamObfuscation;
use crate::runtime::RequestGuard;
use crate::upstream::manager::{BoundServer, UpstreamManager};

mod error;
mod packet_io;
mod reply_action;
mod session_mapping;

/// Bridges raw TACACS+ proxy streams onto managed upstream sessions.
#[derive(Clone)]
pub(super) struct UpstreamBridge {
    upstream_manager: Arc<UpstreamManager>,
    downstream_obfuscation: Arc<RwLock<ProxyDownstreamObfuscation>>,
}

impl UpstreamBridge {
    /// Creates a raw proxy upstream bridge over the shared upstream manager.
    pub(super) fn new(
        upstream_manager: Arc<UpstreamManager>,
        downstream_obfuscation: Arc<RwLock<ProxyDownstreamObfuscation>>,
    ) -> Self {
        Self {
            upstream_manager,
            downstream_obfuscation,
        }
    }

    pub(super) async fn handle_connection<Stream>(
        &self,
        stream: Stream,
        peer_label: String,
        _request_guard: RequestGuard,
    ) -> anyhow::Result<()>
    where
        Stream: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let bound_server = match self.upstream_manager.bind_server_for_new_session().await {
            Ok(bound_server) => bound_server,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "Failed to bind TACACS+ proxy client {peer_label} to an upstream server"
                    )
                });
            }
        };

        log::debug!(
            "Proxying TACACS+ client {peer_label} via {} (server index {})",
            bound_server.connection.server_address(),
            bound_server.index,
        );

        let downstream_obfuscation = self.downstream_obfuscation.read().await.clone();
        let result = proxy_bound_connection(stream, &bound_server, downstream_obfuscation).await;

        match result {
            Ok(()) => Ok(()),
            Err(ProxyConnectionError::Upstream(error)) => {
                self.upstream_manager
                    .note_bound_server_failure(&bound_server)
                    .await;
                Err(error)
            }
            Err(ProxyConnectionError::Downstream(error)) => Err(error),
        }
    }
}

async fn proxy_bound_connection<Stream>(
    stream: Stream,
    bound_server: &BoundServer,
    downstream_obfuscation: ProxyDownstreamObfuscation,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send,
{
    let timeout = bound_server.timeout_duration();
    let obfuscation_key = downstream_obfuscation_key(&downstream_obfuscation);
    let upstream_session = match bound_server.connection.create_raw_session().await {
        Ok(upstream_session) => upstream_session,
        Err(error) => {
            return Err(ProxyConnectionError::Upstream(
                error.context("Failed to create upstream proxy session"),
            ));
        }
    };

    proxy_connection_with_session(stream, timeout, obfuscation_key, &upstream_session).await
}

fn downstream_obfuscation_key(
    downstream_obfuscation: &ProxyDownstreamObfuscation,
) -> Option<Vec<u8>> {
    match downstream_obfuscation {
        ProxyDownstreamObfuscation::Unobfuscated => None,
        ProxyDownstreamObfuscation::SharedSecret(shared_secret) => Some(shared_secret.as_str()),
    }
    .map(|secret| secret.as_bytes().to_vec())
}

async fn proxy_connection_with_session<Stream, Session>(
    mut stream: Stream,
    timeout: Duration,
    obfuscation_key: Option<Vec<u8>>,
    upstream_session: &Session,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send,
    Session: ClientSessionFlowIoTrait + Sync + ?Sized,
{
    let writer = PacketWriter::new(obfuscation_key.clone());
    let result = proxy_connection_loop(
        &mut stream,
        timeout,
        obfuscation_key.as_deref(),
        &writer,
        upstream_session,
    )
    .await;

    upstream_session.complete().await;
    result
}

async fn proxy_connection_loop<Stream, Session>(
    stream: &mut Stream,
    timeout: Duration,
    downstream_obfuscation_key: Option<&[u8]>,
    writer: &PacketWriter,
    upstream_session: &Session,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send,
    Session: ClientSessionFlowIoTrait + Sync + ?Sized,
{
    let mut downstream_session_id = None;
    let upstream_session_id = upstream_session.session_id();

    loop {
        let downstream_packet =
            match read_downstream_packet(stream, timeout, downstream_obfuscation_key).await {
                Ok(packet) => packet,
                Err(error) => return Err(error),
            };
        let downstream_reply_obfuscation = downstream_packet.reply_obfuscation;
        let downstream_packet = downstream_packet.packet;

        let packet_session_id = downstream_packet.header().session_id;
        match downstream_session_id {
            Some(expected) if expected != packet_session_id => {
                return Err(ProxyConnectionError::Downstream(anyhow::anyhow!(
                    "TACACS+ proxy connection attempted session id {packet_session_id:#x} after starting session {expected:#x}"
                )));
            }
            Some(_) => {}
            None => {
                downstream_session_id = Some(packet_session_id);
            }
        }

        let downstream_session_id = downstream_session_id.expect("session id was just set");
        let upstream_packet = match rewrite_session_id(downstream_packet, upstream_session_id) {
            Ok(packet) => packet,
            Err(error) => {
                return Err(ProxyConnectionError::Downstream(error));
            }
        };

        if let Err(error) = upstream_session.send_packet(upstream_packet).await {
            return Err(ProxyConnectionError::Upstream(
                error.context("Failed to send proxied packet upstream"),
            ));
        }

        let upstream_reply = match read_upstream_packet(upstream_session, timeout).await {
            Ok(packet) => packet,
            Err(error) => return Err(error),
        };

        let action = reply_action(&upstream_reply);
        let downstream_reply = match rewrite_session_id(upstream_reply, downstream_session_id) {
            Ok(packet) => packet,
            Err(error) => return Err(ProxyConnectionError::Upstream(error)),
        };
        write_downstream_packet(writer, stream, downstream_reply, downstream_reply_obfuscation)
            .await?;

        match action {
            ReplyAction::Continue => {}
            ReplyAction::Complete => {
                return Ok(());
            }
            ReplyAction::Unsupported(status) => {
                log::warn!("Closing TACACS+ proxy session after unsupported reply status {status}");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::time::Duration;

    use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
    use tacacsrs_messages::accounting::reply::AccountingReply;
    use tacacsrs_messages::authentication::reply::AuthenticationReply;
    use tacacsrs_messages::enumerations::{
        TacacsAccountingStatus, TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus,
        TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::packet::{Packet, PacketTrait};
    use tacacsrs_messages::traits::TacacsBodyTrait;
    use tacacsrs_networking::{PacketReadResult, PacketReader, PacketReaderTrait};
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct FakeProxySession {
        complete: AtomicBool,
        next_sequence_number: AtomicU8,
        received_packets: Mutex<Vec<Packet>>,
        replies: Mutex<VecDeque<Packet>>,
        session_id: u32,
    }

    impl FakeProxySession {
        fn new(session_id: u32, replies: Vec<Packet>) -> Self {
            Self {
                complete: AtomicBool::new(false),
                next_sequence_number: AtomicU8::new(1),
                received_packets: Mutex::default(),
                replies: Mutex::new(replies.into()),
                session_id,
            }
        }
    }

    #[async_trait::async_trait]
    impl ClientSessionFlowIoTrait for FakeProxySession {
        async fn is_complete(&self) -> bool {
            self.complete.load(Ordering::Acquire)
        }

        async fn next_sequence_number(&self) -> u8 {
            self.next_sequence_number.fetch_add(2, Ordering::AcqRel)
        }

        fn session_id(&self) -> u32 {
            self.session_id
        }

        async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
            self.received_packets.lock().await.push(packet);
            Ok(())
        }

        async fn receive_packet(&self) -> anyhow::Result<Packet> {
            self.replies
                .lock()
                .await
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("missing fake proxy reply"))
        }

        async fn complete(&self) {
            self.complete.store(true, Ordering::Release);
        }
    }

    async fn write_packet(stream: &mut tokio::io::DuplexStream, packet: &Packet) {
        stream
            .write_all(&packet.to_bytes())
            .await
            .expect("packet should write");
    }

    async fn read_packet(stream: &mut tokio::io::DuplexStream) -> Packet {
        let reader = PacketReader::new(None);
        match reader.read_packet(stream).await {
            PacketReadResult::Success(packet) => packet,
            _ => panic!("packet should read"),
        }
    }

    fn test_packet(tacacs_type: TacacsType, session_id: u32, body: Vec<u8>) -> Packet {
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id,
                length: u32::try_from(body.len()).unwrap(),
            },
            body,
        )
        .unwrap()
    }

    fn accounting_reply_body(status: TacacsAccountingStatus) -> Vec<u8> {
        AccountingReply {
            status,
            server_msg: "ok".to_owned(),
            data: "display".to_owned(),
        }
        .to_bytes()
        .unwrap()
    }

    fn authentication_reply_body(status: TacacsAuthenticationStatus) -> Vec<u8> {
        AuthenticationReply {
            status,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: "ok".to_owned(),
            data: vec![1, 2, 3],
        }
        .to_bytes()
        .unwrap()
    }

    #[test]
    fn downstream_obfuscation_uses_no_key_for_unobfuscated_clients() {
        assert_eq!(downstream_obfuscation_key(&ProxyDownstreamObfuscation::Unobfuscated), None);
    }

    #[test]
    fn downstream_obfuscation_uses_configured_proxy_secret() {
        assert_eq!(
            downstream_obfuscation_key(&ProxyDownstreamObfuscation::SharedSecret(
                "local-proxy-secret".to_owned(),
            ),)
            .as_deref(),
            Some(b"local-proxy-secret".as_slice())
        );
    }

    #[tokio::test]
    async fn proxy_connection_maps_session_id_and_preserves_body() {
        let downstream_session_id = 0x1111_2222;
        let upstream_session_id = 0x3333_4444;
        let request = test_packet(
            TacacsType::TacPlusAccounting,
            downstream_session_id,
            b"request-body".to_vec(),
        );
        let reply_body = accounting_reply_body(TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        let upstream_reply =
            test_packet(TacacsType::TacPlusAccounting, upstream_session_id, reply_body.clone());
        let fake_session = FakeProxySession::new(upstream_session_id, vec![upstream_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &request).await;

        proxy_connection_with_session(proxy_stream, Duration::from_secs(1), None, &fake_session)
            .await
            .expect("proxy connection should complete");

        let (received_len, received_session_id, received_body) = {
            let received_packets = fake_session.received_packets.lock().await;
            (
                received_packets.len(),
                received_packets[0].header().session_id,
                received_packets[0].body().clone(),
            )
        };
        assert_eq!(received_len, 1);
        assert_eq!(received_session_id, upstream_session_id);
        assert_eq!(received_body.as_slice(), request.body().as_slice());
        assert!(fake_session.is_complete().await);

        let downstream_reply = read_packet(&mut client_stream).await;
        assert_eq!(downstream_reply.header().session_id, downstream_session_id);
        assert_eq!(downstream_reply.body(), &reply_body);
    }

    #[tokio::test]
    async fn proxy_connection_preserves_unobfuscated_downstream_reply() {
        let downstream_session_id = 0x1111_2222;
        let upstream_session_id = 0x3333_4444;
        let secret = "proxy-secret";
        let request = test_packet(
            TacacsType::TacPlusAccounting,
            downstream_session_id,
            b"request-body".to_vec(),
        );
        let reply_body = accounting_reply_body(TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        let upstream_reply =
            test_packet(TacacsType::TacPlusAccounting, upstream_session_id, reply_body.clone());
        let fake_session = FakeProxySession::new(upstream_session_id, vec![upstream_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &request).await;

        proxy_connection_with_session(
            proxy_stream,
            Duration::from_secs(1),
            Some(secret.as_bytes().to_vec()),
            &fake_session,
        )
        .await
        .expect("proxy connection should complete");

        let downstream_reply = read_packet(&mut client_stream).await;
        assert!(downstream_reply
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(downstream_reply.header().session_id, downstream_session_id);
        assert_eq!(downstream_reply.body(), &reply_body);
    }

    #[tokio::test]
    async fn proxy_connection_preserves_obfuscated_downstream_reply() {
        let downstream_session_id = 0x1111_2222;
        let upstream_session_id = 0x3333_4444;
        let secret = "proxy-secret";
        let request_body = b"request-body".to_vec();
        let request =
            test_packet(TacacsType::TacPlusAccounting, downstream_session_id, request_body.clone())
                .to_obfuscated(secret.as_bytes());
        let reply_body = accounting_reply_body(TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        let upstream_reply =
            test_packet(TacacsType::TacPlusAccounting, upstream_session_id, reply_body.clone());
        let fake_session = FakeProxySession::new(upstream_session_id, vec![upstream_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &request).await;

        proxy_connection_with_session(
            proxy_stream,
            Duration::from_secs(1),
            Some(secret.as_bytes().to_vec()),
            &fake_session,
        )
        .await
        .expect("proxy connection should complete");

        let (received_len, received_session_id, received_flags, received_body) = {
            let received_packets = fake_session.received_packets.lock().await;
            (
                received_packets.len(),
                received_packets[0].header().session_id,
                received_packets[0].header().flags,
                received_packets[0].body().clone(),
            )
        };
        assert_eq!(received_len, 1);
        assert_eq!(received_session_id, upstream_session_id);
        assert!(received_flags.contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(received_body, request_body);

        let raw_downstream_reply = read_packet(&mut client_stream).await;
        assert!(!raw_downstream_reply
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG));
        assert_eq!(raw_downstream_reply.header().session_id, downstream_session_id);

        let downstream_reply = raw_downstream_reply.to_deobfuscated(secret.as_bytes());
        assert_eq!(downstream_reply.body(), &reply_body);
    }

    #[tokio::test]
    async fn proxy_connection_rejects_second_downstream_session_id() {
        let downstream_session_id = 0x1111_2222;
        let upstream_session_id = 0x3333_4444;
        let first_request = test_packet(
            TacacsType::TacPlusAuthentication,
            downstream_session_id,
            b"first".to_vec(),
        );
        let second_request =
            test_packet(TacacsType::TacPlusAuthentication, 0x5555_6666, b"second".to_vec());
        let continue_reply = test_packet(
            TacacsType::TacPlusAuthentication,
            upstream_session_id,
            authentication_reply_body(TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass),
        );
        let fake_session = FakeProxySession::new(upstream_session_id, vec![continue_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &first_request).await;
        write_packet(&mut client_stream, &second_request).await;

        let result = proxy_connection_with_session(
            proxy_stream,
            Duration::from_secs(1),
            None,
            &fake_session,
        )
        .await;

        match result {
            Err(ProxyConnectionError::Downstream(error)) => {
                assert!(error.to_string().contains("attempted session id"));
            }
            _ => panic!("expected downstream session-id rejection"),
        }

        let (received_len, received_session_id) = {
            let received_packets = fake_session.received_packets.lock().await;
            (received_packets.len(), received_packets[0].header().session_id)
        };
        assert_eq!(received_len, 1);
        assert_eq!(received_session_id, upstream_session_id);
        assert!(fake_session.is_complete().await);
    }
}
