//! Per-session admission, routing, retry, and pinning.
//!
//! The proxy retries only its first packet. Once a server returns a valid
//! reply, the session pins that conversation. A multi-packet authentication
//! exchange cannot move to another server without losing protocol state.
//!
//! This module does not read the failover strategy. It builds one
//! [`tacacsrs_networking::retry::FailoverPlan`] and gives one [`ProxyAttempt`] to the
//! shared failover executor.

use std::time::Duration;

use async_trait::async_trait;
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_networking::{ClientConversation, RequestDeadline};
use tacacsrs_networking::retry::{
    Attempt, AttemptDisposition, FailoverAttempt, FailoverOutcome, FailoverPlan, run_with_failover,
};
use tokio::sync::{mpsc, oneshot};

use super::error::ProxyConnectionError;
use super::error_reply::local_error_reply;
use super::packet_io;
use super::reply_action::{ReplyAction, is_error_reply, reply_action};
use super::session_mapping::rewrite_session_id;
use crate::upstream::{AdmissionError, AdmissionPermit, OperationKind, OperationRouter, RequestRouting};
use crate::upstream::manager::BoundServer;
use crate::upstream::UpstreamConnection;
use tacacsrs_networking::routed::EndpointConnector;

/// One TACACS+ conversation with a selected upstream server.
#[async_trait]
pub(super) trait ProxyConversation: Send + Sync {
    /// Returns the upstream session identifier while the session is open.
    fn session_id(&self) -> Option<u32>;

    /// Returns the round-trip timeout of the selected server.
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// Sends one packet and waits for the matching reply.
    async fn round_trip(&mut self, packet: Packet) -> anyhow::Result<Packet>;

    /// Releases the upstream session.
    async fn complete(&mut self);

    /// Records that the selected server answered correctly.
    async fn note_success(&self) {}

    /// Records that the selected server failed this conversation.
    async fn note_failure(&self) {}
}

/// Source of upstream conversations, admission, and retry plans for the proxy.
///
/// The production implementation delegates to [`OperationRouter`]. Tests supply
/// a double. No method has a default implementation: a double that silently
/// skips admission would hide a production contract.
#[async_trait]
pub(super) trait ProxyConversationProvider: Send + Sync + 'static {
    /// Conversation type produced by this provider.
    type Conversation: ProxyConversation;
    /// Immutable routing inputs captured for the first packet and its continuations.
    type Request: Send + Sync;
    type Reservation: Send + Sync;

    fn capture_request(&self, operation: OperationKind) -> Self::Request;

    fn deadline(&self, request: &Self::Request) -> RequestDeadline;

    fn reserve(
        &self,
        request: &Self::Request,
        body_length: usize,
    ) -> Result<Self::Reservation, AdmissionError>;

    /// Selects a server and opens a conversation for one operation.
    async fn open_conversation(
        &self,
        request: &Self::Request,
    ) -> anyhow::Result<Self::Conversation>;

    /// Waits for shared operation capacity and validates the request size.
    async fn admit(
        &self,
        request: &Self::Request,
        reservation: Self::Reservation,
    ) -> Result<Option<AdmissionPermit>, AdmissionError>;

    /// Validates one continuing packet without acquiring another permit.
    fn validate_body_length(
        &self,
        request: &Self::Request,
        body_length: usize,
    ) -> Result<(), AdmissionError>;

    /// Builds the retry plan for one proxy request.
    fn failover_plan(&self, request: &Self::Request) -> FailoverPlan;
}

/// Provides proxy conversations through the shared upstream router.
pub(super) struct UpstreamConversationProvider<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    router: OperationRouter<Connector>,
}

impl<Connector: EndpointConnector> UpstreamConversationProvider<Connector> {
    pub(super) const fn new(router: OperationRouter<Connector>) -> Self {
        Self { router }
    }
}

/// A proxy conversation bound to one server, operation, and routing generation.
pub(super) struct ManagedProxyConversation<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    bound_server: BoundServer<Connector>,
    conversation: ClientConversation,
}

#[async_trait]
impl<Connector: EndpointConnector> ProxyConversationProvider
    for UpstreamConversationProvider<Connector>
where
    Connector::Connection: UpstreamConnection,
{
    type Conversation = ManagedProxyConversation<Connector>;
    type Request = RequestRouting<Connector>;
    type Reservation = tacacsrs_networking::admission::AdmissionReservation;

    fn reserve(
        &self,
        request: &Self::Request,
        body_length: usize,
    ) -> Result<Self::Reservation, AdmissionError> {
        request.reserve(body_length)
    }

    fn capture_request(&self, operation: OperationKind) -> Self::Request {
        self.router.capture_request(operation)
    }

    fn deadline(&self, request: &Self::Request) -> RequestDeadline {
        request.deadline()
    }

    async fn open_conversation(
        &self,
        request: &Self::Request,
    ) -> anyhow::Result<Self::Conversation> {
        let bound_server = request.bind().await?;
        let mut observation = bound_server.observe_failure();
        match bound_server.connection.open_conversation().await {
            Ok(conversation) => {
                observation.disarm();
                Ok(ManagedProxyConversation {
                    bound_server,
                    conversation,
                })
            }
            Err(error) => {
                bound_server.note_failure().await;
                Err(error)
            }
        }
    }

    async fn admit(
        &self,
        request: &Self::Request,
        reservation: Self::Reservation,
    ) -> Result<Option<AdmissionPermit>, AdmissionError> {
        request.admit_reserved(reservation).await.map(Some)
    }

    fn validate_body_length(
        &self,
        request: &Self::Request,
        body_length: usize,
    ) -> Result<(), AdmissionError> {
        request.validate_body_length(body_length)
    }

    fn failover_plan(&self, request: &Self::Request) -> FailoverPlan {
        request.failover_plan()
    }
}

#[async_trait]
impl<Connector: EndpointConnector> ProxyConversation for ManagedProxyConversation<Connector> {
    fn session_id(&self) -> Option<u32> {
        self.conversation.session_id()
    }

    fn timeout(&self) -> Option<Duration> {
        Some(self.bound_server.timeout_duration())
    }

    async fn round_trip(&mut self, packet: Packet) -> anyhow::Result<Packet> {
        let mut observation = self.bound_server.observe_failure();
        let result = self.conversation.round_trip(packet).await;
        if result.is_ok() {
            observation.disarm();
        }
        result
    }

    async fn complete(&mut self) {
        self.conversation.complete().await;
    }

    async fn note_success(&self) {
        self.bound_server.note_success().await;
    }

    async fn note_failure(&self) {
        self.bound_server.note_failure().await;
    }
}

pub(super) struct SessionPacket {
    pub(super) packet: Packet,
    pub(super) reply_obfuscation: packet_io::DownstreamObfuscation,
    pub(super) advertise_single_connect: bool,
}

pub(super) struct SessionReply {
    pub(super) packet: Packet,
    pub(super) obfuscation: packet_io::DownstreamObfuscation,
    pub(super) deadline: RequestDeadline,
    pub(super) delivered: Option<oneshot::Sender<()>>,
}

/// The first proxy packet, which is the only packet failover can replay.
struct ProxyAttempt<'session, Provider: ProxyConversationProvider> {
    provider: &'session Provider,
    routing: &'session Provider::Request,
    operation: OperationKind,
    /// Held only while another attempt can still replay this packet.
    request: Option<Packet>,
    max_attempts: usize,
    fallback_timeout: Duration,
}

#[async_trait]
impl<Provider> FailoverAttempt for ProxyAttempt<'_, Provider>
where
    Provider: ProxyConversationProvider,
{
    type Value = (Provider::Conversation, Packet);
    type Error = anyhow::Error;

    async fn attempt(&mut self, attempt_index: usize) -> Attempt<Self::Value, Self::Error> {
        log::debug!(
            "Sending the first proxy {} packet upstream (attempt {})",
            self.operation.name(),
            attempt_index + 1,
        );
        let mut conversation = match self.provider.open_conversation(self.routing).await {
            Ok(conversation) => conversation,
            Err(error) => {
                return Attempt::Failed {
                    error: error.context("Failed to open a TACACS+ server session"),
                    disposition: AttemptDisposition::NotSent,
                };
            }
        };

        let Some(upstream_session_id) = conversation.session_id() else {
            conversation.note_failure().await;
            conversation.complete().await;
            return Attempt::Failed {
                error: anyhow::anyhow!(
                    "The TACACS+ server session completed before the proxy session started"
                ),
                disposition: AttemptDisposition::NotSent,
            };
        };

        let upstream_packet = if attempt_index + 1 >= self.max_attempts {
            self.request
                .take()
                .expect("the proxy request is available for each attempt")
        } else {
            self.request
                .clone()
                .expect("the proxy request is available for each attempt")
        };
        let upstream_packet = rewrite_session_id(upstream_packet, upstream_session_id);
        let attempt_timeout = conversation.timeout().unwrap_or(self.fallback_timeout);
        let round_trip =
            tokio::time::timeout(attempt_timeout, conversation.round_trip(upstream_packet)).await;

        let reply = match round_trip {
            Ok(Ok(reply)) => reply,
            Ok(Err(error)) => {
                conversation.note_failure().await;
                conversation.complete().await;
                return Attempt::Failed {
                    error: error.context("Failed to complete a TACACS+ server round trip"),
                    disposition: AttemptDisposition::OutcomeUnknown,
                };
            }
            Err(_) => {
                conversation.note_failure().await;
                conversation.complete().await;
                return Attempt::Failed {
                    error: anyhow::anyhow!(
                        "The TACACS+ server did not complete a round trip within {attempt_timeout:?}"
                    ),
                    disposition: AttemptDisposition::OutcomeUnknown,
                };
            }
        };

        if is_error_reply(&reply) {
            conversation.note_failure().await;
            Attempt::Rejected((conversation, reply))
        } else {
            conversation.note_success().await;
            Attempt::Accepted((conversation, reply))
        }
    }

    async fn discard(&mut self, value: Self::Value) {
        let (mut conversation, _reply) = value;
        conversation.complete().await;
    }
}

pub(super) async fn run_proxy_session<Provider>(
    downstream_session_id: u32,
    timeout: Duration,
    provider: &Provider,
    routing: Provider::Request,
    reservation: Provider::Reservation,
    packets: mpsc::Receiver<SessionPacket>,
    replies: mpsc::Sender<SessionReply>,
) -> Result<(), ProxyConnectionError>
where
    Provider: ProxyConversationProvider,
{
    provider
        .deadline(&routing)
        .run(run_captured_proxy_session(
            downstream_session_id,
            timeout,
            provider,
            routing,
            reservation,
            packets,
            replies,
        ))
        .await
        .map_err(|error| ProxyConnectionError::Upstream(error.into()))?
}

async fn run_captured_proxy_session<Provider: ProxyConversationProvider>(
    downstream_session_id: u32,
    timeout: Duration,
    provider: &Provider,
    routing: Provider::Request,
    reservation: Provider::Reservation,
    mut packets: mpsc::Receiver<SessionPacket>,
    replies: mpsc::Sender<SessionReply>,
) -> Result<(), ProxyConnectionError> {
    let Some(first_request) = packets.recv().await else {
        return Ok(());
    };
    let operation = OperationKind::try_from(first_request.packet.header().tacacs_type)
        .expect("each TACACS+ packet type maps to an operation");
    let _admission_permit = match provider.admit(&routing, reservation).await {
        Ok(permit) => permit,
        Err(error) => {
            log::warn!(
                "Rejected a local proxy {} request before upstream routing: {error}",
                operation.name()
            );
            let reply = local_error_reply(&first_request.packet, &error.to_string())
                .map_err(ProxyConnectionError::Downstream)?;
            send_proxy_reply(
                &replies,
                first_request.reply_obfuscation,
                first_request.advertise_single_connect,
                reply,
                downstream_session_id,
                false,
                provider.deadline(&routing),
            )
            .await?;
            return Ok(());
        }
    };

    let plan = provider.failover_plan(&routing);
    let max_attempts = plan.max_attempts();
    let SessionPacket {
        packet: first_packet,
        reply_obfuscation,
        advertise_single_connect,
    } = first_request;
    let mut attempt = ProxyAttempt {
        provider,
        routing: &routing,
        operation,
        request: Some(first_packet),
        max_attempts,
        fallback_timeout: timeout,
    };

    let (mut conversation, first_reply) = match run_with_failover(plan, &mut attempt).await {
        FailoverOutcome::Accepted(value) | FailoverOutcome::Rejected(value) => value,
        FailoverOutcome::Failed(error) | FailoverOutcome::Aborted(error) => {
            return Err(ProxyConnectionError::Upstream(error));
        }
        FailoverOutcome::NoAttempt => {
            return Err(ProxyConnectionError::Upstream(anyhow::anyhow!(
                "No TACACS+ server completed the proxy request"
            )));
        }
    };

    let action = reply_action(&first_reply);
    send_proxy_reply(
        &replies,
        reply_obfuscation,
        advertise_single_connect,
        first_reply,
        downstream_session_id,
        true,
        provider.deadline(&routing),
    )
    .await?;

    match action {
        ReplyAction::Complete => {
            conversation.complete().await;
            Ok(())
        }
        ReplyAction::Unsupported(status) => {
            conversation.note_failure().await;
            conversation.complete().await;
            log::warn!(
                "Closing the TACACS+ proxy session because reply status {status} is not supported"
            );
            Ok(())
        }
        ReplyAction::Continue => {
            let result = run_pinned_proxy_session(
                downstream_session_id,
                timeout,
                &routing,
                provider,
                &mut conversation,
                &mut packets,
                &replies,
            )
            .await;
            conversation.complete().await;
            result
        }
    }
}

async fn run_pinned_proxy_session<Conversation, Provider>(
    downstream_session_id: u32,
    timeout: Duration,
    routing: &Provider::Request,
    provider: &Provider,
    conversation: &mut Conversation,
    packets: &mut mpsc::Receiver<SessionPacket>,
    replies: &mpsc::Sender<SessionReply>,
) -> Result<(), ProxyConnectionError>
where
    Conversation: ProxyConversation,
    Provider: ProxyConversationProvider,
{
    let upstream_session_id = conversation.session_id().ok_or_else(|| {
        ProxyConnectionError::Upstream(anyhow::anyhow!(
            "The TACACS+ server session completed before the proxy session continued"
        ))
    })?;
    while let Some(request) = packets.recv().await {
        let SessionPacket {
            packet: request_packet,
            reply_obfuscation,
            advertise_single_connect,
        } = request;
        if let Err(error) = provider.validate_body_length(routing, request_packet.body().len()) {
            let reply = local_error_reply(&request_packet, &error.to_string())
                .map_err(ProxyConnectionError::Downstream)?;
            send_proxy_reply(
                replies,
                reply_obfuscation,
                advertise_single_connect,
                reply,
                downstream_session_id,
                false,
                provider.deadline(routing),
            )
            .await?;
            return Ok(());
        }
        let upstream_packet = rewrite_session_id(request_packet, upstream_session_id);
        let attempt_timeout = conversation.timeout().unwrap_or(timeout);
        let upstream_reply =
            tokio::time::timeout(attempt_timeout, conversation.round_trip(upstream_packet))
                .await
                .map_err(|_| {
                    ProxyConnectionError::Upstream(anyhow::anyhow!(
                "The TACACS+ server did not complete a round trip within {attempt_timeout:?}"
            ))
                })?
                .map_err(|error| {
                    ProxyConnectionError::Upstream(
                        error.context("Failed to complete a TACACS+ server round trip"),
                    )
                })?;
        let action = reply_action(&upstream_reply);
        if is_error_reply(&upstream_reply) {
            conversation.note_failure().await;
        } else {
            conversation.note_success().await;
        }
        send_proxy_reply(
            replies,
            reply_obfuscation,
            advertise_single_connect,
            upstream_reply,
            downstream_session_id,
            true,
            provider.deadline(routing),
        )
        .await?;

        match action {
            ReplyAction::Continue => {}
            ReplyAction::Complete => return Ok(()),
            ReplyAction::Unsupported(status) => {
                conversation.note_failure().await;
                log::warn!(
                    "Closing the TACACS+ proxy session because reply status {status} is not supported"
                );
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn send_proxy_reply(
    replies: &mpsc::Sender<SessionReply>,
    obfuscation: packet_io::DownstreamObfuscation,
    advertise_single_connect: bool,
    reply: Packet,
    downstream_session_id: u32,
    rewrite_id: bool,
    deadline: RequestDeadline,
) -> Result<(), ProxyConnectionError> {
    let mut flags = reply.header().flags;
    flags.set(
        tacacsrs_protocol::enumerations::TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        advertise_single_connect,
    );
    let reply = reply.with_flags(flags);
    let packet = if rewrite_id {
        rewrite_session_id(reply, downstream_session_id)
    } else {
        reply
    };
    let (delivered, delivery) = oneshot::channel();
    replies
        .send(SessionReply {
            packet,
            obfuscation,
            deadline,
            delivered: Some(delivered),
        })
        .await
        .map_err(|_| {
            ProxyConnectionError::Downstream(anyhow::anyhow!(
                "The downstream TACACS+ reply writer stopped"
            ))
        })?;
    delivery.await.map_err(|_| {
        ProxyConnectionError::Downstream(anyhow::anyhow!(
            "The downstream TACACS+ reply was not delivered"
        ))
    })
}
