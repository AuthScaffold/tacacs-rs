//! Per-session admission, routing, retry, and pinning.
//!
//! The proxy retries only its first packet. Once a server returns a valid
//! reply, the session pins that conversation. A multi-packet authentication
//! exchange cannot move to another server without losing protocol state.
//!
//! This module does not read the failover strategy. It builds one
//! [`crate::upstream::FailoverPlan`] and gives one [`ProxyAttempt`] to the
//! shared failover executor.

use std::time::Duration;

use async_trait::async_trait;
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_networking::ClientConversation;
use tokio::sync::mpsc;

use super::error::ProxyConnectionError;
use super::error_reply::local_error_reply;
use super::packet_io;
use super::reply_action::{ReplyAction, is_error_reply, reply_action};
use super::session_mapping::rewrite_session_id;
use crate::upstream::{
    AdmissionError, AdmissionPermit, Attempt, AttemptDisposition, FailoverAttempt, FailoverOutcome,
    FailoverPlan, OperationKind, OperationRouter, run_with_failover,
};
use crate::upstream::manager::BoundServer;

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

    /// Selects a server and opens a conversation for one operation.
    async fn open_conversation(
        &self,
        operation: OperationKind,
    ) -> anyhow::Result<Self::Conversation>;

    /// Waits for shared operation capacity and validates the request size.
    async fn admit(
        &self,
        operation: OperationKind,
        body_length: usize,
    ) -> Result<Option<AdmissionPermit>, AdmissionError>;

    /// Validates one continuing packet without acquiring another permit.
    fn validate_body_length(
        &self,
        operation: OperationKind,
        body_length: usize,
    ) -> Result<(), AdmissionError>;

    /// Builds the retry plan for one proxy request.
    fn failover_plan(&self, operation: OperationKind) -> FailoverPlan;
}

/// Provides proxy conversations through the shared upstream router.
pub(super) struct UpstreamConversationProvider {
    router: OperationRouter,
}

impl UpstreamConversationProvider {
    pub(super) const fn new(router: OperationRouter) -> Self {
        Self { router }
    }
}

/// A proxy conversation bound to one server, operation, and routing generation.
pub(super) struct ManagedProxyConversation {
    router: OperationRouter,
    bound_server: BoundServer,
    conversation: ClientConversation,
}

#[async_trait]
impl ProxyConversationProvider for UpstreamConversationProvider {
    type Conversation = ManagedProxyConversation;

    async fn open_conversation(
        &self,
        operation: OperationKind,
    ) -> anyhow::Result<Self::Conversation> {
        let bound_server = self.router.bind(operation).await?;
        match bound_server.connection.open_conversation().await {
            Ok(conversation) => Ok(ManagedProxyConversation {
                router: self.router.clone(),
                bound_server,
                conversation,
            }),
            Err(error) => {
                self.router.note_failure(&bound_server).await;
                Err(error)
            }
        }
    }

    async fn admit(
        &self,
        operation: OperationKind,
        body_length: usize,
    ) -> Result<Option<AdmissionPermit>, AdmissionError> {
        self.router.admit(operation, body_length).await.map(Some)
    }

    fn validate_body_length(
        &self,
        operation: OperationKind,
        body_length: usize,
    ) -> Result<(), AdmissionError> {
        self.router.validate_body_length(operation, body_length)
    }

    fn failover_plan(&self, operation: OperationKind) -> FailoverPlan {
        self.router.failover_plan(operation)
    }
}

#[async_trait]
impl ProxyConversation for ManagedProxyConversation {
    fn session_id(&self) -> Option<u32> {
        self.conversation.session_id()
    }

    fn timeout(&self) -> Option<Duration> {
        Some(self.bound_server.timeout_duration())
    }

    async fn round_trip(&mut self, packet: Packet) -> anyhow::Result<Packet> {
        self.conversation.round_trip(packet).await
    }

    async fn complete(&mut self) {
        self.conversation.complete().await;
    }

    async fn note_success(&self) {
        self.router.note_success(&self.bound_server).await;
    }

    async fn note_failure(&self) {
        self.router.note_failure(&self.bound_server).await;
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
}

/// The first proxy packet, which is the only packet failover can replay.
struct ProxyAttempt<'session, Provider> {
    provider: &'session Provider,
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
        let mut conversation = match self.provider.open_conversation(self.operation).await {
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
    mut packets: mpsc::Receiver<SessionPacket>,
    replies: mpsc::Sender<SessionReply>,
) -> Result<(), ProxyConnectionError>
where
    Provider: ProxyConversationProvider,
{
    let Some(first_request) = packets.recv().await else {
        return Ok(());
    };
    let operation = OperationKind::try_from(first_request.packet.header().tacacs_type)
        .expect("each TACACS+ packet type maps to an operation");
    let _admission_permit = match provider
        .admit(operation, first_request.packet.body().len())
        .await
    {
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
            )
            .await?;
            return Ok(());
        }
    };

    let plan = provider.failover_plan(operation);
    let max_attempts = plan.max_attempts();
    let SessionPacket {
        packet: first_packet,
        reply_obfuscation,
        advertise_single_connect,
    } = first_request;
    let mut attempt = ProxyAttempt {
        provider,
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
                operation,
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

async fn run_pinned_proxy_session<Conversation>(
    downstream_session_id: u32,
    timeout: Duration,
    operation: OperationKind,
    provider: &impl ProxyConversationProvider,
    conversation: &mut Conversation,
    packets: &mut mpsc::Receiver<SessionPacket>,
    replies: &mpsc::Sender<SessionReply>,
) -> Result<(), ProxyConnectionError>
where
    Conversation: ProxyConversation,
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
        if let Err(error) = provider.validate_body_length(operation, request_packet.body().len()) {
            let reply = local_error_reply(&request_packet, &error.to_string())
                .map_err(ProxyConnectionError::Downstream)?;
            send_proxy_reply(
                replies,
                reply_obfuscation,
                advertise_single_connect,
                reply,
                downstream_session_id,
                false,
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
) -> Result<(), ProxyConnectionError> {
    let mut flags = reply.header().flags;
    flags.set(
        tacacsrs_messages::enumerations::TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG,
        advertise_single_connect,
    );
    let reply = reply.with_flags(flags);
    let packet = if rewrite_id {
        rewrite_session_id(reply, downstream_session_id)
    } else {
        reply
    };
    replies
        .send(SessionReply {
            packet,
            obfuscation,
        })
        .await
        .map_err(|_| {
            ProxyConnectionError::Downstream(anyhow::anyhow!(
                "The downstream TACACS+ reply writer stopped"
            ))
        })
}
