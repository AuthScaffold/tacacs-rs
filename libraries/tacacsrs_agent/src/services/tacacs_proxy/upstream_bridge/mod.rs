//! Server bridge for raw TACACS+ proxy connections.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tacacsrs_protocol::packet::PacketTrait;
use tacacsrs_networking::PacketWriter;
use tacacsrs_secrets::SecretBytes;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use self::error::ProxyConnectionError;
use self::error_reply::local_error_reply;
use self::packet_io::{DownstreamReader, write_downstream_packet};
use self::session::{
    ProxyConversationProvider, SessionPacket, SessionReply, UpstreamConversationProvider,
    run_proxy_session,
};
#[cfg(test)]
use self::reply_action::{ReplyAction, reply_action};
#[cfg(test)]
use self::session::ProxyConversation;
#[cfg(test)]
use self::session_mapping::rewrite_session_id;
use crate::config::{PolicyService, PreparedProxyPolicy};
use crate::runtime::RequestGuard;
use crate::upstream::OperationRouter;
use crate::upstream::manager::UpstreamManager;
use crate::upstream::UpstreamConnection;
use tacacsrs_networking::routed::EndpointConnector;

mod error;
mod error_reply;
mod packet_io;
mod reply_action;
mod session;
mod session_mapping;

const SESSION_QUEUE_CAPACITY: usize = 8;

/// Maps raw TACACS+ proxy streams to managed server sessions.
pub(super) struct UpstreamBridge<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    upstream_manager: Arc<UpstreamManager<Connector>>,
}

impl<Connector: EndpointConnector> Clone for UpstreamBridge<Connector> {
    fn clone(&self) -> Self {
        Self {
            upstream_manager: self.upstream_manager.clone(),
        }
    }
}

impl<Connector: EndpointConnector> UpstreamBridge<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    /// Creates a raw proxy bridge for the shared upstream manager.
    pub(super) fn new(upstream_manager: Arc<UpstreamManager<Connector>>) -> Self {
        Self { upstream_manager }
    }

    pub(super) async fn handle_connection<Stream>(
        &self,
        stream: Stream,
        peer_label: String,
        _request_guard: RequestGuard,
    ) -> anyhow::Result<()>
    where
        Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let transport = self.upstream_manager.proxy_transport_settings();
        let router =
            OperationRouter::new(Arc::clone(&self.upstream_manager), PolicyService::TacacsProxy);
        log::debug!("Accepted TACACS+ proxy client {peer_label}");
        proxy_multiplexed_connection(
            stream,
            transport.read_timeout(),
            downstream_obfuscation_key(transport.downstream_obfuscation())?,
            Arc::new(UpstreamConversationProvider::new(router)),
        )
        .await
        .map_err(|error| match error {
            ProxyConnectionError::Upstream(error) | ProxyConnectionError::Downstream(error) => {
                error
            }
        })
    }
}

fn downstream_obfuscation_key(
    downstream_obfuscation: &PreparedProxyPolicy,
) -> anyhow::Result<Option<SecretBytes>> {
    Ok(downstream_obfuscation
        .shared_secret()?
        .map(|secret| SecretBytes::new(secret.expose_secret().as_bytes().to_vec())))
}

async fn proxy_multiplexed_connection<Stream, Provider>(
    stream: Stream,
    timeout: Duration,
    obfuscation_key: Option<SecretBytes>,
    provider: Arc<Provider>,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    Provider: ProxyConversationProvider,
{
    let (reader, writer) = tokio::io::split(stream);
    let mut downstream = DownstreamReader::new(reader, timeout, obfuscation_key.clone());
    let (reply_sender, reply_receiver) =
        mpsc::channel(crate::config::default_concurrent_request_limit());
    let writer_task = run_downstream_writer(writer, obfuscation_key, reply_receiver);
    tokio::pin!(writer_task);
    let mut session_senders = HashMap::<u32, mpsc::Sender<SessionPacket>>::new();
    let mut session_tasks = JoinSet::new();

    let result = loop {
        tokio::select! {
            biased;
            writer_result = &mut writer_task => {
                break writer_result;
            }
            session_result = session_tasks.join_next(), if !session_tasks.is_empty() => {
                let Some(session_result) = session_result else { continue };
                match session_result {
                    Ok((session_id, Ok(()))) => {
                        session_senders.remove(&session_id);
                    }
                    Ok((session_id, Err(error))) => {
                        session_senders.remove(&session_id);
                        break Err(error);
                    }
                    Err(error) => {
                        break Err(ProxyConnectionError::Upstream(
                            anyhow::Error::new(error).context("The server TACACS+ session task failed"),
                        ));
                    }
                }
            }
            packet_result = downstream.next_packet() => {
                let received = match packet_result {
                    Ok(packet) => packet,
                    Err(error) => break Err(error),
                };
                let session_id = received.packet.header().session_id;
                let packet = SessionPacket {
                    advertise_single_connect: received.packet.header().flags.contains(
                        tacacsrs_protocol::enumerations::TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                    ),
                    packet: received.packet,
                    reply_obfuscation: received.reply_obfuscation,
                };

                if let Some(sender) = session_senders.get(&session_id) {
                    if sender.try_send(packet).is_err() {
                        break Err(ProxyConnectionError::Downstream(anyhow::anyhow!(
                            "Downstream TACACS+ session {session_id:#x} has a full or closed packet queue",
                        )));
                    }
                    continue;
                }

                let operation = crate::upstream::OperationKind::try_from(packet.packet.header().tacacs_type)
                    .expect("each packet type maps to an operation");
                let routing = provider.capture_request(operation);
                let reservation = match provider.reserve(&routing, packet.packet.body().len()) {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        let reply = match local_error_reply(&packet.packet, &error.to_string()) {
                            Ok(reply) => reply,
                            Err(error) => break Err(ProxyConnectionError::Downstream(error)),
                        };
                        if reply_sender.try_send(SessionReply {
                            packet: reply, obfuscation: packet.reply_obfuscation,
                            deadline: provider.deadline(&routing), delivered: None,
                        }).is_err() {
                            break Err(ProxyConnectionError::Downstream(anyhow::anyhow!("The downstream TACACS+ reply queue is full")));
                        }
                        continue;
                    }
                };
                let (session_sender, session_receiver) = mpsc::channel(SESSION_QUEUE_CAPACITY);
                session_sender
                    .send(packet)
                    .await
                    .expect("the new session receiver must be active");
                session_senders.insert(session_id, session_sender);
                let provider = Arc::clone(&provider);
                let reply_sender = reply_sender.clone();
                session_tasks.spawn(async move {
                    let result = run_proxy_session(
                        session_id,
                        timeout,
                        provider.as_ref(),
                        routing,
                        reservation,
                        session_receiver,
                        reply_sender,
                    )
                    .await;
                    (session_id, result)
                });
            }
        }
    };

    session_tasks.shutdown().await;
    result
}

async fn run_downstream_writer<Writer>(
    mut writer: Writer,
    obfuscation_key: Option<SecretBytes>,
    mut replies: mpsc::Receiver<SessionReply>,
) -> Result<(), ProxyConnectionError>
where
    Writer: AsyncWrite + Unpin + Send,
{
    let packet_writer = PacketWriter::new(obfuscation_key);
    while let Some(reply) = replies.recv().await {
        reply
            .deadline
            .run(write_downstream_packet(
                &packet_writer,
                &mut writer,
                reply.packet,
                reply.obfuscation,
            ))
            .await
            .map_err(|error| ProxyConnectionError::Downstream(error.into()))??;
        if let Some(delivered) = reply.delivered {
            let _received = delivered.send(());
        }
    }
    Ok(())
}

#[cfg(test)]
async fn proxy_connection_with_conversation<Stream, Conversation>(
    stream: Stream,
    timeout: Duration,
    obfuscation_key: Option<SecretBytes>,
    upstream_conversation: &mut Conversation,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send,
    Conversation: ProxyConversation + ?Sized,
{
    let writer = PacketWriter::new(obfuscation_key.clone());
    let (reader, mut write_half) = tokio::io::split(stream);
    let mut downstream = DownstreamReader::new(reader, timeout, obfuscation_key);
    let result = proxy_connection_loop(
        &mut downstream,
        &mut write_half,
        timeout,
        &writer,
        upstream_conversation,
    )
    .await;

    upstream_conversation.complete().await;
    result
}

#[cfg(test)]
async fn proxy_connection_loop<Reader, Writer, Conversation>(
    downstream: &mut DownstreamReader<Reader>,
    stream: &mut Writer,
    timeout: Duration,
    writer: &PacketWriter,
    upstream_conversation: &mut Conversation,
) -> Result<(), ProxyConnectionError>
where
    Reader: AsyncRead + Unpin + Send,
    Writer: AsyncWrite + Unpin + Send,
    Conversation: ProxyConversation + ?Sized,
{
    let mut downstream_session_id = None;
    let upstream_session_id = upstream_conversation.session_id().ok_or_else(|| {
        ProxyConnectionError::Upstream(anyhow::anyhow!(
            "The TACACS+ server session completed before the proxy session started"
        ))
    })?;

    loop {
        let downstream_packet = match downstream.next_packet().await {
            Ok(packet) => packet,
            Err(error) => return Err(error),
        };
        let downstream_reply_obfuscation = downstream_packet.reply_obfuscation;
        let downstream_packet = downstream_packet.packet;

        let packet_session_id = downstream_packet.header().session_id;
        match downstream_session_id {
            Some(expected) if expected != packet_session_id => {
                return Err(ProxyConnectionError::Downstream(anyhow::anyhow!(
                    "TACACS+ proxy connection used session ID {packet_session_id:#x} after it started session {expected:#x}"
                )));
            }
            Some(_) => {}
            None => {
                downstream_session_id = Some(packet_session_id);
            }
        }

        let downstream_session_id =
            downstream_session_id.expect("the downstream session ID must be set");
        let upstream_packet = rewrite_session_id(downstream_packet, upstream_session_id);

        let upstream_reply =
            tokio::time::timeout(timeout, upstream_conversation.round_trip(upstream_packet))
                .await
                .map_err(|_| {
                    ProxyConnectionError::Upstream(anyhow::anyhow!(
                        "The TACACS+ server did not complete a round trip within {timeout:?}"
                    ))
                })?
                .map_err(|error| {
                    ProxyConnectionError::Upstream(
                        error.context("Failed to complete a TACACS+ server round trip"),
                    )
                })?;

        let action = reply_action(&upstream_reply);
        let downstream_reply = rewrite_session_id(upstream_reply, downstream_session_id);
        write_downstream_packet(writer, stream, downstream_reply, downstream_reply_obfuscation)
            .await?;

        match action {
            ReplyAction::Continue => {}
            ReplyAction::Complete => {
                return Ok(());
            }
            ReplyAction::Unsupported(status) => {
                log::warn!("Closing the TACACS+ proxy session because reply status {status} is not supported");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use tacacsrs_protocol::accounting::reply::AccountingReply;
    use tacacsrs_protocol::authentication::reply::AuthenticationReply;
    use tacacsrs_protocol::enumerations::{
        TacacsAccountingStatus, TacacsAuthenticationReplyFlags, TacacsAuthenticationStatus,
        TacacsFlags, TacacsMajorVersion, TacacsMinorVersion, TacacsType,
    };
    use tacacsrs_protocol::header::Header;
    use tacacsrs_protocol::packet::{Packet, PacketTrait};
    use tacacsrs_protocol::body::TacacsBodyTrait;
    use tacacsrs_networking::{PacketReadResult, PacketReader};
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;

    use super::*;
    use crate::config::{FailoverStrategy, OperationPolicies, PolicyService, RuntimePolicy};
    use crate::upstream::{AdmissionError, AdmissionPermit, OperationKind};
    use tacacsrs_networking::retry::FailoverPlan;

    #[derive(Default)]
    struct FakeProxySession {
        complete: AtomicBool,
        received_packets: Mutex<Vec<Packet>>,
        replies: Mutex<VecDeque<Packet>>,
        session_id: u32,
        reply_delay: Duration,
        completions: Option<Arc<AtomicUsize>>,
    }

    impl FakeProxySession {
        fn new(session_id: u32, replies: Vec<Packet>) -> Self {
            Self {
                complete: AtomicBool::new(false),
                received_packets: Mutex::default(),
                replies: Mutex::new(replies.into()),
                session_id,
                reply_delay: Duration::ZERO,
                completions: None,
            }
        }

        fn with_reply_delay(mut self, reply_delay: Duration) -> Self {
            self.reply_delay = reply_delay;
            self
        }

        /// Counts every `complete` call so a test can observe session cleanup.
        fn with_completion_counter(mut self, completions: Arc<AtomicUsize>) -> Self {
            self.completions = Some(completions);
            self
        }

        fn is_complete(&self) -> bool {
            self.complete.load(Ordering::Acquire)
        }
    }

    #[async_trait]
    impl ProxyConversation for FakeProxySession {
        fn session_id(&self) -> Option<u32> {
            (!self.is_complete()).then_some(self.session_id)
        }

        async fn round_trip(&mut self, packet: Packet) -> anyhow::Result<Packet> {
            self.received_packets.lock().await.push(packet);
            if !self.reply_delay.is_zero() {
                tokio::time::sleep(self.reply_delay).await;
            }
            self.replies
                .lock()
                .await
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("The fake proxy reply is missing"))
        }

        async fn complete(&mut self) {
            self.complete.store(true, Ordering::Release);
            if let Some(completions) = &self.completions {
                completions.fetch_add(1, Ordering::AcqRel);
            }
        }
    }

    struct FakeConversationProvider {
        conversations: Mutex<VecDeque<FakeProxySession>>,
        strategy: FailoverStrategy,
        eligible_server_count: usize,
        opened: AtomicUsize,
        admission: tacacsrs_networking::admission::AdmissionPool,
    }

    impl FakeConversationProvider {
        fn new(conversations: Vec<FakeProxySession>) -> Self {
            Self {
                conversations: Mutex::new(conversations.into()),
                strategy: FailoverStrategy::DeferredFailover,
                eligible_server_count: 1,
                opened: AtomicUsize::new(0),
                admission: tacacsrs_networking::admission::AdmissionPool::new(64),
            }
        }

        fn ordered(conversations: Vec<FakeProxySession>) -> Self {
            Self {
                conversations: Mutex::new(conversations.into()),
                strategy: FailoverStrategy::OrderedSafeRetry,
                eligible_server_count: 2,
                opened: AtomicUsize::new(0),
                admission: tacacsrs_networking::admission::AdmissionPool::new(64),
            }
        }

        fn opened(&self) -> usize {
            self.opened.load(Ordering::Acquire)
        }
    }

    #[async_trait]
    impl ProxyConversationProvider for FakeConversationProvider {
        type Conversation = FakeProxySession;
        type Request = (FailoverPlan, tacacsrs_networking::RequestDeadline);
        type Reservation = tacacsrs_networking::admission::AdmissionReservation;

        fn reserve(
            &self,
            request: &Self::Request,
            _body_length: usize,
        ) -> Result<Self::Reservation, AdmissionError> {
            self.admission
                .reserve(request.1)
                .map_err(|_| AdmissionError::Full)
        }

        fn capture_request(&self, _operation: OperationKind) -> Self::Request {
            let policy = RuntimePolicy::new(
                FailoverStrategy::default(),
                self.strategy,
                OperationPolicies::default(),
                Duration::from_secs(30),
            )
            .expect("test policy");
            (
                policy.failover_plan(PolicyService::TacacsProxy, self.eligible_server_count),
                tacacsrs_networking::RequestDeadline::after(Duration::from_secs(30)).unwrap(),
            )
        }

        fn deadline(&self, request: &Self::Request) -> tacacsrs_networking::RequestDeadline {
            request.1
        }

        async fn open_conversation(
            &self,
            _request: &Self::Request,
        ) -> anyhow::Result<Self::Conversation> {
            self.opened.fetch_add(1, Ordering::AcqRel);
            self.conversations
                .lock()
                .await
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("The fake proxy session is missing"))
        }

        async fn admit(
            &self,
            _request: &Self::Request,
            reservation: Self::Reservation,
        ) -> Result<Option<AdmissionPermit>, AdmissionError> {
            reservation
                .wait()
                .await
                .map(Some)
                .map_err(|_| AdmissionError::CapacityTimeout {
                    wait_timeout: Duration::from_secs(30),
                })
        }

        fn validate_body_length(
            &self,
            _request: &Self::Request,
            _body_length: usize,
        ) -> Result<(), AdmissionError> {
            Ok(())
        }

        fn failover_plan(&self, request: &Self::Request) -> FailoverPlan {
            request.0
        }
    }

    async fn write_packet(stream: &mut (impl AsyncWrite + Unpin), packet: &Packet) {
        stream
            .write_all(&packet.to_bytes())
            .await
            .expect("the packet write must succeed");
    }

    async fn read_packet(stream: &mut (impl AsyncRead + Unpin)) -> Packet {
        let reader = PacketReader::new(None);
        match reader.read_packet(stream).await {
            PacketReadResult::Success(packet) => packet,
            _ => panic!("the packet read must succeed"),
        }
    }

    fn test_packet(tacacs_type: TacacsType, session_id: u32, body: Vec<u8>) -> Packet {
        test_packet_with_sequence(tacacs_type, session_id, 2, TacacsFlags::empty(), body)
    }

    fn test_packet_with_sequence(
        tacacs_type: TacacsType,
        session_id: u32,
        seq_no: u8,
        flags: TacacsFlags,
        body: Vec<u8>,
    ) -> Packet {
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type,
                seq_no,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG | flags,
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

    fn native_server(listener: &tokio::net::TcpListener) -> tacacsrs_config::TacacsPlusServer {
        let address = listener.local_addr().unwrap();
        tacacsrs_config::TacacsPlusServer {
            name: address.to_string(),
            server_type: crate::runtime::REQUIRED_SERVER_TYPES,
            address: address.ip().to_string(),
            port: address.port(),
            timeout: 5,
            single_connection: false,
            shared_secret: None,
            domain_name: None,
            sni_enabled: None,
            client_identity: None,
            server_authentication: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
        }
    }

    async fn write_authentication_reply(
        stream: &mut (impl AsyncWrite + Unpin),
        request: &Packet,
        status: TacacsAuthenticationStatus,
    ) {
        write_packet(
            stream,
            &test_packet_with_sequence(
                TacacsType::TacPlusAuthentication,
                request.header().session_id,
                request.header().seq_no + 1,
                TacacsFlags::empty(),
                authentication_reply_body(status),
            ),
        )
        .await;
    }

    #[test]
    fn downstream_obfuscation_uses_no_key_for_unobfuscated_clients() {
        assert_eq!(downstream_obfuscation_key(&PreparedProxyPolicy::unobfuscated()).unwrap(), None);
        assert!(downstream_obfuscation_key(&PreparedProxyPolicy::unavailable()).is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn session_flood_is_rejected_before_task_admission_and_cancel_releases_reservations() {
        let mut provider = FakeConversationProvider::new(vec![
            FakeProxySession::new(100, vec![]).with_reply_delay(Duration::from_secs(20))
        ]);
        provider.admission = tacacsrs_networking::admission::AdmissionPool::new(1);
        let provider = Arc::new(provider);
        let (mut peer, stream) = tokio::io::duplex(4096);
        let proxy = tokio::spawn(proxy_multiplexed_connection(
            stream,
            Duration::from_secs(30),
            None,
            provider.clone(),
        ));
        for session_id in 1..=3 {
            write_packet(
                &mut peer,
                &test_packet_with_sequence(
                    TacacsType::TacPlusAccounting,
                    session_id,
                    1,
                    TacacsFlags::empty(),
                    vec![1],
                ),
            )
            .await;
        }
        let reply = read_packet(&mut peer).await;
        assert_eq!(reply.header().session_id, 3);
        assert_eq!(
            AccountingReply::from_packet(&reply).unwrap().status,
            TacacsAccountingStatus::TacPlusAcctStatusError
        );
        assert!(provider.opened() <= 1);
        assert!(provider
            .admission
            .reserve(tacacsrs_networking::RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .is_err());
        drop(peer);
        assert!(proxy.await.unwrap().is_err());
        provider
            .admission
            .acquire(tacacsrs_networking::RequestDeadline::after(Duration::from_secs(1)).unwrap())
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_downstream_write_stops_at_the_request_deadline() {
        let (writer, _peer) = tokio::io::duplex(1);
        let (sender, receiver) = mpsc::channel(1);
        let deadline = tacacsrs_networking::RequestDeadline::after(Duration::from_secs(1)).unwrap();
        sender
            .send(SessionReply {
                packet: test_packet(TacacsType::TacPlusAccounting, 1, vec![1; 64]),
                obfuscation: packet_io::DownstreamObfuscation::Unobfuscated,
                deadline,
                delivered: None,
            })
            .await
            .unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            run_downstream_writer(writer, None, receiver),
        )
        .await;
        assert!(result.is_ok(), "the writer must stop before the outer test bound");
        assert!(result.unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn final_reply_holds_admission_until_physical_delivery() {
        let mut provider = FakeConversationProvider::new(vec![FakeProxySession::new(
            10,
            vec![test_packet(
                TacacsType::TacPlusAccounting,
                10,
                accounting_reply_body(TacacsAccountingStatus::TacPlusAcctStatusSuccess),
            )],
        )]);
        provider.admission = tacacsrs_networking::admission::AdmissionPool::new(1);
        let routing = provider.capture_request(OperationKind::Accounting);
        let reservation = provider.reserve(&routing, 1).unwrap();
        let (packets, receiver) = mpsc::channel(1);
        let (replies, mut delivered) = mpsc::channel(1);
        packets
            .send(SessionPacket {
                packet: test_packet_with_sequence(
                    TacacsType::TacPlusAccounting,
                    1,
                    1,
                    TacacsFlags::empty(),
                    vec![1],
                ),
                reply_obfuscation: packet_io::DownstreamObfuscation::Unobfuscated,
                advertise_single_connect: false,
            })
            .await
            .unwrap();
        let session = run_proxy_session(
            1,
            Duration::from_secs(30),
            &provider,
            routing,
            reservation,
            receiver,
            replies,
        );
        tokio::pin!(session);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(session.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        let reply = delivered.recv().await.unwrap();
        let deadline = tacacsrs_networking::RequestDeadline::after(Duration::from_secs(1)).unwrap();
        let next = provider.admission.acquire(deadline);
        tokio::pin!(next);
        std::future::poll_fn(|context| {
            assert!(std::future::Future::poll(next.as_mut(), context).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        reply.delivered.unwrap().send(()).unwrap();
        session.await.unwrap();
        next.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn expired_reply_emits_no_bytes_and_drops_acknowledgement() {
        use tokio::io::AsyncReadExt;

        let (writer, mut peer) = tokio::io::duplex(256);
        let (sender, receiver) = mpsc::channel(1);
        let (acknowledge, delivered) = tokio::sync::oneshot::channel();
        sender
            .send(SessionReply {
                packet: test_packet(TacacsType::TacPlusAccounting, 1, vec![1; 64]),
                obfuscation: packet_io::DownstreamObfuscation::Unobfuscated,
                deadline: tacacsrs_networking::RequestDeadline::after(Duration::ZERO).unwrap(),
                delivered: Some(acknowledge),
            })
            .await
            .unwrap();
        assert!(run_downstream_writer(writer, None, receiver).await.is_err());
        assert!(delivered.await.is_err());
        assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn proxy_continuation_deadline_survives_reload_and_releases_capacity() {
        use tokio::io::AsyncReadExt;
        use crate::config::RequestLimits;
        use crate::runtime::{ProxyLoopGuard, RuntimeHealthPublisher};
        use crate::upstream::NetworkUpstreamConnector;
        use crate::EnabledServices;

        tokio::time::timeout(Duration::from_secs(3), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let manager = Arc::new(UpstreamManager::new(
                vec![native_server(&listener)],
                NetworkUpstreamConnector::new(ProxyLoopGuard::new(None)).erased(),
                Duration::from_secs(30),
                RuntimeHealthPublisher::new(EnabledServices::TACACS_PROXY),
            ));
            let policy = |duration| {
                let limits = RequestLimits::new(1024, 1)
                    .unwrap()
                    .with_request_timeout(duration)
                    .unwrap();
                RuntimePolicy::new(
                    FailoverStrategy::default(),
                    FailoverStrategy::default(),
                    OperationPolicies::new(limits, limits, limits),
                    Duration::from_secs(30),
                )
                .unwrap()
            };
            manager.reload_runtime_policy(policy(Duration::from_millis(500)));
            let provider = Arc::new(UpstreamConversationProvider::new(OperationRouter::new(
                manager.clone(),
                PolicyService::TacacsProxy,
            )));
            let (mut downstream, stream) = tokio::io::duplex(4096);
            let proxy = tokio::spawn(proxy_multiplexed_connection(
                stream,
                Duration::from_secs(10),
                None,
                provider.clone(),
            ));
            write_packet(
                &mut downstream,
                &test_packet_with_sequence(
                    TacacsType::TacPlusAuthentication,
                    1,
                    1,
                    TacacsFlags::empty(),
                    vec![1],
                ),
            )
            .await;
            let (mut upstream, _) = listener.accept().await.unwrap();
            let request = read_packet(&mut upstream).await;
            write_authentication_reply(
                &mut upstream,
                &request,
                TacacsAuthenticationStatus::TacPlusAuthenStatusGetdata,
            )
            .await;
            read_packet(&mut downstream).await;
            manager.reload_runtime_policy(policy(Duration::from_secs(10)));
            assert!(
                proxy.await.unwrap().is_err(),
                "waiting for a continuation must consume the captured budget"
            );
            assert_eq!(upstream.read(&mut [0; 1]).await.unwrap(), 0);
            let next = provider.capture_request(OperationKind::Authentication);
            provider
                .admit(&next, provider.reserve(&next, 1).unwrap())
                .await
                .unwrap();
            assert_eq!(
                next.bind().await.unwrap().index,
                0,
                "downstream waiting must not open the upstream circuit"
            );
        })
        .await
        .expect("expired proxy conversation must release its transport and capacity");
    }

    #[tokio::test]
    async fn proxy_retry_and_continuation_keep_captured_generation() {
        use crate::config::RequestLimits;
        use crate::runtime::{ProxyLoopGuard, RuntimeHealthPublisher};
        use crate::upstream::NetworkUpstreamConnector;
        use crate::EnabledServices;

        tokio::time::timeout(Duration::from_secs(5), async {
            let primary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backup = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let replacement = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let policy = |strategy, maximum| {
                let limits = RequestLimits::new(maximum, 2).unwrap();
                RuntimePolicy::new(
                    FailoverStrategy::default(),
                    strategy,
                    OperationPolicies::new(limits, limits, limits),
                    Duration::from_secs(30),
                )
                .unwrap()
            };
            let manager = Arc::new(UpstreamManager::new(
                vec![native_server(&primary), native_server(&backup)],
                NetworkUpstreamConnector::new(ProxyLoopGuard::new(None)).erased(),
                Duration::from_secs(30),
                RuntimeHealthPublisher::new(EnabledServices::TACACS_PROXY),
            ));
            manager.reload_runtime_policy(policy(FailoverStrategy::OrderedSafeRetry, 1024));
            let provider = Arc::new(UpstreamConversationProvider::new(OperationRouter::new(
                Arc::clone(&manager),
                PolicyService::TacacsProxy,
            )));
            let (mut client, downstream) = tokio::io::duplex(4096);
            let proxy = tokio::spawn(proxy_multiplexed_connection(
                downstream,
                Duration::from_secs(5),
                None,
                provider,
            ));
            let packet_type = TacacsType::TacPlusAuthentication;
            write_packet(
                &mut client,
                &test_packet_with_sequence(packet_type, 1, 1, TacacsFlags::empty(), vec![1]),
            )
            .await;
            let (mut primary_peer, _) = primary.accept().await.unwrap();
            let first = read_packet(&mut primary_peer).await;

            manager
                .reload_servers(vec![native_server(&replacement)])
                .await
                .unwrap();
            manager.reload_runtime_policy(policy(FailoverStrategy::DeferredFailover, 128));
            write_authentication_reply(
                &mut primary_peer,
                &first,
                TacacsAuthenticationStatus::TacPlusAuthenStatusError,
            )
            .await;

            let (mut backup_peer, _) = backup.accept().await.unwrap();
            let retried = read_packet(&mut backup_peer).await;
            assert_eq!(retried.body(), first.body());
            write_authentication_reply(
                &mut backup_peer,
                &retried,
                TacacsAuthenticationStatus::TacPlusAuthenStatusGetdata,
            )
            .await;
            let challenge = read_packet(&mut client).await;
            assert_eq!(challenge.header().session_id, 1);
            write_packet(
                &mut client,
                &test_packet_with_sequence(packet_type, 1, 3, TacacsFlags::empty(), vec![1; 512]),
            )
            .await;
            let continued = read_packet(&mut backup_peer).await;
            assert_eq!(continued.header().session_id, retried.header().session_id);
            assert_eq!(continued.body().len(), 512);
            write_authentication_reply(
                &mut backup_peer,
                &continued,
                TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            )
            .await;
            assert_eq!(read_packet(&mut client).await.header().seq_no, 4);

            write_packet(
                &mut client,
                &test_packet_with_sequence(packet_type, 2, 1, TacacsFlags::empty(), vec![1]),
            )
            .await;
            let (mut replacement_peer, _) = replacement.accept().await.unwrap();
            let next = read_packet(&mut replacement_peer).await;
            write_authentication_reply(
                &mut replacement_peer,
                &next,
                TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            )
            .await;
            assert_eq!(read_packet(&mut client).await.header().session_id, 2);
            drop(client);
            let _closed = proxy.await.unwrap();
        })
        .await
        .expect("proxy reload scenario must finish");
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "Keep both native timeout scenarios and their cleanup in one test."
    )]
    async fn expired_proxy_round_trip_routes_the_next_request_to_backup() {
        use crate::config::RequestLimits;
        use crate::runtime::{ProxyLoopGuard, RuntimeHealthPublisher};
        use crate::upstream::NetworkUpstreamConnector;
        use crate::EnabledServices;

        for continuation in [false, true] {
            tokio::time::timeout(Duration::from_secs(3), async {
                let primary = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let backup = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let manager = Arc::new(UpstreamManager::new(
                    vec![native_server(&primary), native_server(&backup)],
                    NetworkUpstreamConnector::new(ProxyLoopGuard::new(None)).erased(),
                    Duration::from_secs(30),
                    RuntimeHealthPublisher::new(EnabledServices::TACACS_PROXY),
                ));
                let limits = RequestLimits::new(1024, 2)
                    .unwrap()
                    .with_request_timeout(Duration::from_millis(200))
                    .unwrap();
                manager.reload_runtime_policy(
                    RuntimePolicy::new(
                        FailoverStrategy::default(),
                        FailoverStrategy::default(),
                        OperationPolicies::new(limits, limits, limits),
                        Duration::from_secs(30),
                    )
                    .unwrap(),
                );
                let provider = Arc::new(UpstreamConversationProvider::new(OperationRouter::new(
                    manager,
                    PolicyService::TacacsProxy,
                )));
                let (mut client, downstream) = tokio::io::duplex(4096);
                let proxy = tokio::spawn(proxy_multiplexed_connection(
                    downstream,
                    Duration::from_secs(5),
                    None,
                    provider.clone(),
                ));
                write_packet(
                    &mut client,
                    &test_packet_with_sequence(
                        TacacsType::TacPlusAuthentication,
                        1,
                        1,
                        TacacsFlags::empty(),
                        vec![1],
                    ),
                )
                .await;
                let (mut upstream, _) = primary.accept().await.unwrap();
                let request = read_packet(&mut upstream).await;
                if continuation {
                    write_authentication_reply(
                        &mut upstream,
                        &request,
                        TacacsAuthenticationStatus::TacPlusAuthenStatusGetdata,
                    )
                    .await;
                    read_packet(&mut client).await;
                    write_packet(
                        &mut client,
                        &test_packet_with_sequence(
                            TacacsType::TacPlusAuthentication,
                            1,
                            3,
                            TacacsFlags::empty(),
                            vec![1],
                        ),
                    )
                    .await;
                    read_packet(&mut upstream).await;
                }
                assert!(proxy.await.unwrap().is_err());
                let unexpected_backup = backup.accept();
                tokio::pin!(unexpected_backup);
                std::future::poll_fn(|context| {
                    assert!(
                        std::future::Future::poll(unexpected_backup.as_mut(), context).is_pending(),
                        "expired request must not be replayed"
                    );
                    std::task::Poll::Ready(())
                })
                .await;
                let (mut next_client, downstream) = tokio::io::duplex(4096);
                let next_proxy = tokio::spawn(proxy_multiplexed_connection(
                    downstream,
                    Duration::from_secs(5),
                    None,
                    provider,
                ));
                write_packet(
                    &mut next_client,
                    &test_packet_with_sequence(
                        TacacsType::TacPlusAuthentication,
                        2,
                        1,
                        TacacsFlags::empty(),
                        vec![1],
                    ),
                )
                .await;
                let (mut peer, _) = backup.accept().await.unwrap();
                let request = read_packet(&mut peer).await;
                write_authentication_reply(
                    &mut peer,
                    &request,
                    TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
                )
                .await;
                assert_eq!(read_packet(&mut next_client).await.header().session_id, 2);
                drop(next_client);
                assert!(next_proxy.await.unwrap().is_err());
            })
            .await
            .expect("proxy timeout and failover must finish");
        }
    }

    #[test]
    fn downstream_obfuscation_uses_configured_proxy_secret() {
        let policy = tacacsrs_config::proxy_policy::prepare_proxy_policy(
            &tacacsrs_config::tacacsrs::LocalServices {
                tacacs_proxy_enabled: true,
                proxy_credential_source: tacacsrs_config::tacacsrs::ProxyCredentialSource::Inline,
                proxy_shared_secret: Some(tacacsrs_secrets::SecretString::new(
                    "local-proxy-secret".to_owned(),
                )),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let key = downstream_obfuscation_key(&policy).unwrap().unwrap();
        assert!(key.expose_secret() == b"local-proxy-secret");
    }

    #[test]
    fn downstream_key_capture_and_clone_debug_is_redacted() {
        let sentinel = "proxy-downstream-key-debug-sentinel";
        let policy = tacacsrs_config::proxy_policy::prepare_proxy_policy(
            &tacacsrs_config::tacacsrs::LocalServices {
                tacacs_proxy_enabled: true,
                proxy_credential_source: tacacsrs_config::tacacsrs::ProxyCredentialSource::Inline,
                proxy_shared_secret: Some(tacacsrs_secrets::SecretString::new(sentinel.to_owned())),
                ..Default::default()
            },
            None,
        )
        .unwrap();
        let captured = downstream_obfuscation_key(&policy).unwrap();
        let cloned = captured.clone();
        drop(captured);
        drop(policy);
        let protected: &SecretBytes = cloned.as_ref().unwrap();
        assert!(protected.expose_secret() == sentinel.as_bytes());
        for output in [
            format!("{cloned:?}"),
            format!("{cloned:#?}"),
            format!("{:?}", vec![&cloned]),
            format!("{:#?}", vec![&cloned]),
        ] {
            assert!(!output.contains(sentinel), "Debug exposed a downstream key");
            assert!(
                !output.contains(&format!("{:?}", sentinel.as_bytes())),
                "Debug exposed downstream key bytes"
            );
            assert!(
                !output.contains(&format!("{:#?}", sentinel.as_bytes())),
                "Debug exposed downstream key bytes"
            );
        }
    }

    #[tokio::test]
    async fn multiplexed_proxy_routes_out_of_order_session_replies() {
        let first_downstream_id = 0x1111_2222;
        let second_downstream_id = 0x3333_4444;
        let first_upstream_id = 0x5555_6666;
        let second_upstream_id = 0x7777_8888;
        let reply_body = accounting_reply_body(TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        let provider = Arc::new(FakeConversationProvider::new(vec![
            FakeProxySession::new(
                first_upstream_id,
                vec![test_packet(
                    TacacsType::TacPlusAccounting,
                    first_upstream_id,
                    reply_body.clone(),
                )],
            )
            .with_reply_delay(Duration::from_millis(50)),
            FakeProxySession::new(
                second_upstream_id,
                vec![test_packet(
                    TacacsType::TacPlusAccounting,
                    second_upstream_id,
                    reply_body,
                )],
            ),
        ]));
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);
        let proxy_task = tokio::spawn(proxy_multiplexed_connection(
            proxy_stream,
            Duration::from_secs(1),
            None,
            Arc::clone(&provider),
        ));

        for session_id in [first_downstream_id, second_downstream_id] {
            write_packet(
                &mut client_stream,
                &test_packet_with_sequence(
                    TacacsType::TacPlusAccounting,
                    session_id,
                    1,
                    TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                    b"request".to_vec(),
                ),
            )
            .await;
        }

        let first_reply = read_packet(&mut client_stream).await;
        let second_reply = read_packet(&mut client_stream).await;
        assert_eq!(first_reply.header().session_id, second_downstream_id);
        assert_eq!(second_reply.header().session_id, first_downstream_id);
        assert!(first_reply
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));
        assert!(second_reply
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG));

        proxy_task.abort();
    }

    #[tokio::test]
    async fn multiplexed_proxy_keeps_framing_when_a_session_ends_mid_header() {
        let first_downstream_id = 0x1111_2222;
        let second_downstream_id = 0x3333_4444;
        let first_upstream_id = 0x5555_6666;
        let second_upstream_id = 0x7777_8888;
        let reply_body = accounting_reply_body(TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        let provider = Arc::new(FakeConversationProvider::new(vec![
            FakeProxySession::new(
                first_upstream_id,
                vec![test_packet(
                    TacacsType::TacPlusAccounting,
                    first_upstream_id,
                    reply_body.clone(),
                )],
            )
            .with_reply_delay(Duration::from_millis(150)),
            FakeProxySession::new(
                second_upstream_id,
                vec![test_packet(
                    TacacsType::TacPlusAccounting,
                    second_upstream_id,
                    reply_body,
                )],
            ),
        ]));
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);
        let proxy_task = tokio::spawn(proxy_multiplexed_connection(
            proxy_stream,
            Duration::from_secs(5),
            None,
            Arc::clone(&provider),
        ));

        write_packet(
            &mut client_stream,
            &test_packet_with_sequence(
                TacacsType::TacPlusAccounting,
                first_downstream_id,
                1,
                TacacsFlags::empty(),
                b"first".to_vec(),
            ),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Park the downstream read mid-header, then let the first session end.
        let second_request = test_packet_with_sequence(
            TacacsType::TacPlusAccounting,
            second_downstream_id,
            1,
            TacacsFlags::empty(),
            b"second".to_vec(),
        )
        .to_bytes();
        client_stream
            .write_all(&second_request[..6])
            .await
            .expect("the partial header write must succeed");
        tokio::time::sleep(Duration::from_millis(250)).await;
        client_stream
            .write_all(&second_request[6..])
            .await
            .expect("the remaining request write must succeed");

        let first_reply = read_packet(&mut client_stream).await;
        let second_reply = read_packet(&mut client_stream).await;
        assert_eq!(first_reply.header().session_id, first_downstream_id);
        assert_eq!(second_reply.header().session_id, second_downstream_id);

        proxy_task.abort();
    }

    #[tokio::test]
    async fn multiplexed_proxy_preserves_multi_turn_ascii_conversation() {
        let downstream_id = 0x1111_2222;
        let upstream_id = 0x3333_4444;
        let provider = Arc::new(FakeConversationProvider::new(vec![FakeProxySession::new(
            upstream_id,
            vec![
                test_packet(
                    TacacsType::TacPlusAuthentication,
                    upstream_id,
                    authentication_reply_body(
                        TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
                    ),
                ),
                test_packet_with_sequence(
                    TacacsType::TacPlusAuthentication,
                    upstream_id,
                    4,
                    TacacsFlags::empty(),
                    authentication_reply_body(TacacsAuthenticationStatus::TacPlusAuthenStatusPass),
                ),
            ],
        )]));
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);
        let proxy_task = tokio::spawn(proxy_multiplexed_connection(
            proxy_stream,
            Duration::from_secs(1),
            None,
            Arc::clone(&provider),
        ));

        write_packet(
            &mut client_stream,
            &test_packet_with_sequence(
                TacacsType::TacPlusAuthentication,
                downstream_id,
                1,
                TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                b"start".to_vec(),
            ),
        )
        .await;
        let prompt = read_packet(&mut client_stream).await;
        assert_eq!(
            AuthenticationReply::status_from_packet(&prompt),
            Some(TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass as u8)
        );

        write_packet(
            &mut client_stream,
            &test_packet_with_sequence(
                TacacsType::TacPlusAuthentication,
                downstream_id,
                3,
                TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
                b"continue".to_vec(),
            ),
        )
        .await;
        let terminal = read_packet(&mut client_stream).await;
        assert_eq!(terminal.header().seq_no, 4);
        assert_eq!(
            AuthenticationReply::status_from_packet(&terminal),
            Some(TacacsAuthenticationStatus::TacPlusAuthenStatusPass as u8)
        );
        assert_eq!(provider.opened(), 1);

        proxy_task.abort();
    }

    #[tokio::test]
    async fn ordered_proxy_retry_uses_the_next_server_after_authentication_error() {
        let downstream_id = 0x1111_2222;
        let first_upstream_id = 0x3333_4444;
        let second_upstream_id = 0x5555_6666;
        let provider = Arc::new(FakeConversationProvider::ordered(vec![
            FakeProxySession::new(
                first_upstream_id,
                vec![test_packet(
                    TacacsType::TacPlusAuthentication,
                    first_upstream_id,
                    authentication_reply_body(TacacsAuthenticationStatus::TacPlusAuthenStatusError),
                )],
            ),
            FakeProxySession::new(
                second_upstream_id,
                vec![test_packet(
                    TacacsType::TacPlusAuthentication,
                    second_upstream_id,
                    authentication_reply_body(TacacsAuthenticationStatus::TacPlusAuthenStatusPass),
                )],
            ),
        ]));
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);
        let proxy_task = tokio::spawn(proxy_multiplexed_connection(
            proxy_stream,
            Duration::from_secs(1),
            None,
            Arc::clone(&provider),
        ));

        write_packet(
            &mut client_stream,
            &test_packet_with_sequence(
                TacacsType::TacPlusAuthentication,
                downstream_id,
                1,
                TacacsFlags::empty(),
                b"start".to_vec(),
            ),
        )
        .await;
        let reply = read_packet(&mut client_stream).await;

        assert_eq!(
            AuthenticationReply::status_from_packet(&reply),
            Some(TacacsAuthenticationStatus::TacPlusAuthenStatusPass as u8)
        );
        assert_eq!(provider.opened(), 2);
        proxy_task.abort();
    }

    #[tokio::test]
    async fn ordered_proxy_retry_closes_the_abandoned_upstream_session() {
        let downstream_id = 0x1111_2222;
        let first_upstream_id = 0x3333_4444;
        let second_upstream_id = 0x5555_6666;
        let completions = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(FakeConversationProvider::ordered(vec![
            FakeProxySession::new(
                first_upstream_id,
                vec![test_packet(
                    TacacsType::TacPlusAuthentication,
                    first_upstream_id,
                    authentication_reply_body(TacacsAuthenticationStatus::TacPlusAuthenStatusError),
                )],
            )
            .with_completion_counter(Arc::clone(&completions)),
            FakeProxySession::new(
                second_upstream_id,
                vec![test_packet(
                    TacacsType::TacPlusAuthentication,
                    second_upstream_id,
                    authentication_reply_body(TacacsAuthenticationStatus::TacPlusAuthenStatusPass),
                )],
            ),
        ]));
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);
        let proxy_task = tokio::spawn(proxy_multiplexed_connection(
            proxy_stream,
            Duration::from_secs(1),
            None,
            Arc::clone(&provider),
        ));

        write_packet(
            &mut client_stream,
            &test_packet_with_sequence(
                TacacsType::TacPlusAuthentication,
                downstream_id,
                1,
                TacacsFlags::empty(),
                b"start".to_vec(),
            ),
        )
        .await;
        let _reply = read_packet(&mut client_stream).await;

        assert_eq!(
            completions.load(Ordering::Acquire),
            1,
            "the failover executor must close the rejected upstream session"
        );
        proxy_task.abort();
    }

    #[tokio::test]
    async fn ordered_proxy_does_not_replay_uncertain_requests() {
        for packet_type in [
            TacacsType::TacPlusAuthentication,
            TacacsType::TacPlusAuthorisation,
            TacacsType::TacPlusAccounting,
        ] {
            let downstream_id = 0x1111_2222;
            let first_upstream_id = 0x3333_4444;
            let second_upstream_id = 0x5555_6666;
            let provider = Arc::new(FakeConversationProvider::ordered(vec![
                FakeProxySession::new(first_upstream_id, Vec::new()),
                FakeProxySession::new(second_upstream_id, Vec::new()),
            ]));
            let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);
            let proxy_task = tokio::spawn(proxy_multiplexed_connection(
                proxy_stream,
                Duration::from_secs(1),
                None,
                Arc::clone(&provider),
            ));

            write_packet(
                &mut client_stream,
                &test_packet_with_sequence(
                    packet_type,
                    downstream_id,
                    1,
                    TacacsFlags::empty(),
                    b"record".to_vec(),
                ),
            )
            .await;

            assert!(tokio::time::timeout(Duration::from_secs(2), proxy_task)
                .await
                .unwrap()
                .expect("proxy task joins")
                .is_err());
            assert_eq!(provider.opened(), 1);
        }
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
        let mut fake_session = FakeProxySession::new(upstream_session_id, vec![upstream_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &request).await;

        proxy_connection_with_conversation(
            proxy_stream,
            Duration::from_secs(1),
            None,
            &mut fake_session,
        )
        .await
        .expect("the proxy connection must complete");

        let (received_len, received_session_id, received_body) = {
            let received_packets = fake_session.received_packets.lock().await;
            (
                received_packets.len(),
                received_packets[0].header().session_id,
                received_packets[0].body().to_vec(),
            )
        };
        assert_eq!(received_len, 1);
        assert_eq!(received_session_id, upstream_session_id);
        assert_eq!(received_body.as_slice(), request.body());
        assert!(fake_session.is_complete());

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
        let mut fake_session = FakeProxySession::new(upstream_session_id, vec![upstream_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &request).await;

        proxy_connection_with_conversation(
            proxy_stream,
            Duration::from_secs(1),
            Some(SecretBytes::new(secret.as_bytes().to_vec())),
            &mut fake_session,
        )
        .await
        .expect("the proxy connection must complete");

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
        let mut fake_session = FakeProxySession::new(upstream_session_id, vec![upstream_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &request).await;

        proxy_connection_with_conversation(
            proxy_stream,
            Duration::from_secs(1),
            Some(SecretBytes::new(secret.as_bytes().to_vec())),
            &mut fake_session,
        )
        .await
        .expect("the proxy connection must complete");

        let (received_len, received_session_id, received_flags, received_body) = {
            let received_packets = fake_session.received_packets.lock().await;
            (
                received_packets.len(),
                received_packets[0].header().session_id,
                received_packets[0].header().flags,
                received_packets[0].body().to_vec(),
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
        let mut fake_session = FakeProxySession::new(upstream_session_id, vec![continue_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &first_request).await;
        write_packet(&mut client_stream, &second_request).await;

        let result = proxy_connection_with_conversation(
            proxy_stream,
            Duration::from_secs(1),
            None,
            &mut fake_session,
        )
        .await;

        match result {
            Err(ProxyConnectionError::Downstream(error)) => {
                assert!(error.to_string().contains("used session ID"));
            }
            _ => panic!("the proxy must reject the downstream session ID"),
        }

        let (received_len, received_session_id) = {
            let received_packets = fake_session.received_packets.lock().await;
            (received_packets.len(), received_packets[0].header().session_id)
        };
        assert_eq!(received_len, 1);
        assert_eq!(received_session_id, upstream_session_id);
        assert!(fake_session.is_complete());
    }
}
