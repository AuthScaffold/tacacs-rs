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
use tacacsrs_protocol::header::Header;
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_networking::RequestDeadline;
use tacacsrs_networking::retry::{
    Attempt, AttemptDisposition, FailoverAttempt, FailoverOutcome, run_with_failover,
};
use tokio::sync::{mpsc, oneshot};

use super::error::ProxyConnectionError;
use super::conversation::{ProxyConversation, ProxyConversationProvider};
use super::error_reply::local_error_reply;
use super::packet_io;
use super::reply_action::{ReplyAction, is_error_reply, reply_action};
use super::session_mapping::rewrite_session_id;
use crate::upstream::OperationKind;

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
            conversation.note_server_failure().await;
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
        let reply = match conversation.round_trip(upstream_packet).await {
            Ok(reply) => reply,
            Err(error) => {
                conversation.complete().await;
                return Attempt::Failed {
                    error: error.context("Failed to complete a TACACS+ server round trip"),
                    disposition: AttemptDisposition::OutcomeUnknown,
                };
            }
        };

        if is_error_reply(&reply) {
            conversation.note_server_failure().await;
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
    let deadline = provider.deadline(&routing);
    let mut channel = SessionChannel {
        packets,
        replies,
        pending: None,
    };
    let result = deadline
        .run(run_captured_proxy_session(
            downstream_session_id,
            provider,
            routing,
            reservation,
            &mut channel,
        ))
        .await;
    let elapsed = match result {
        Err(elapsed) => elapsed,
        Ok(Err(ProxyConnectionError::Upstream(error)))
            if error.is::<tacacsrs_networking::DeadlineElapsed>() =>
        {
            tacacsrs_networking::DeadlineElapsed
        }
        Ok(result) => return result,
    };
    let Some(request) = channel.pending else {
        log::info!(
            "Ended TACACS+ proxy session {downstream_session_id:#x} while it waited for the client: {elapsed}"
        );
        return Ok(());
    };
    log::warn!(
        "TACACS+ proxy session {downstream_session_id:#x} did not complete a request: {elapsed}"
    );
    // The request deadline has expired, so the reply uses the downstream
    // write budget instead.
    let write_deadline =
        RequestDeadline::after(timeout).map_err(ProxyConnectionError::Downstream)?;
    send_local_error(
        &channel.replies,
        &request.header,
        request.obfuscation,
        request.advertise_single_connect,
        write_deadline,
    )
    .await
}

/// The downstream side of one proxy session.
struct SessionChannel {
    packets: mpsc::Receiver<SessionPacket>,
    replies: mpsc::Sender<SessionReply>,
    /// The request that does not have a reply yet.
    pending: Option<PendingRequest>,
}

/// A downstream request that does not have a reply yet.
struct PendingRequest {
    header: Header,
    obfuscation: packet_io::DownstreamObfuscation,
    advertise_single_connect: bool,
}

impl PendingRequest {
    fn new(packet: &SessionPacket) -> Self {
        Self {
            header: packet.packet.header().clone(),
            obfuscation: packet.reply_obfuscation,
            advertise_single_connect: packet.advertise_single_connect,
        }
    }
}

async fn run_captured_proxy_session<Provider: ProxyConversationProvider>(
    downstream_session_id: u32,
    provider: &Provider,
    routing: Provider::Request,
    reservation: Provider::Reservation,
    channel: &mut SessionChannel,
) -> Result<(), ProxyConnectionError> {
    let Some(first_request) = channel.packets.recv().await else {
        return Ok(());
    };
    channel.pending = Some(PendingRequest::new(&first_request));
    let operation = OperationKind::try_from(first_request.packet.header().tacacs_type)
        .expect("each TACACS+ packet type maps to an operation");
    let _admission_permit = match provider.admit(&routing, reservation).await {
        Ok(permit) => permit,
        Err(error) => {
            log::warn!(
                "Rejected a local proxy {} request before upstream routing: {error}",
                operation.name()
            );
            let reply = local_error_reply(first_request.packet.header(), &error.to_string())
                .map_err(ProxyConnectionError::Downstream)?;
            send_proxy_reply(
                &channel.replies,
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
    let first_header = first_request.packet.header().clone();
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
    };

    let failure = match run_with_failover(plan, &mut attempt).await {
        FailoverOutcome::Accepted(value) | FailoverOutcome::Rejected(value) => Ok(value),
        FailoverOutcome::Failed(error) | FailoverOutcome::Aborted(error) => Err(error),
        FailoverOutcome::NoAttempt => Err(anyhow::anyhow!("No TACACS+ server was eligible")),
    };
    let (mut conversation, first_reply) = match failure {
        Ok(value) => value,
        Err(error) => {
            log::warn!(
                "No TACACS+ server completed the proxy {} request: {error:#}",
                operation.name()
            );
            provider
                .deadline(&routing)
                .check()
                .map_err(|error| ProxyConnectionError::Upstream(error.into()))?;
            channel.pending = None;
            return send_local_error(
                &channel.replies,
                &first_header,
                reply_obfuscation,
                advertise_single_connect,
                provider.deadline(&routing),
            )
            .await;
        }
    };

    let action = reply_action(&first_reply);
    channel.pending = None;
    send_proxy_reply(
        &channel.replies,
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
            conversation.note_server_failure().await;
            conversation.complete().await;
            log::warn!(
                "Closing the TACACS+ proxy session because reply status {status} is not supported"
            );
            Ok(())
        }
        ReplyAction::Continue => {
            let result = run_pinned_proxy_session(
                downstream_session_id,
                &routing,
                provider,
                &mut conversation,
                channel,
            )
            .await;
            conversation.complete().await;
            result
        }
    }
}

async fn run_pinned_proxy_session<Conversation, Provider>(
    downstream_session_id: u32,
    routing: &Provider::Request,
    provider: &Provider,
    conversation: &mut Conversation,
    channel: &mut SessionChannel,
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
    while let Some(request) = channel.packets.recv().await {
        channel.pending = Some(PendingRequest::new(&request));
        let SessionPacket {
            packet: request_packet,
            reply_obfuscation,
            advertise_single_connect,
        } = request;
        if let Err(error) = provider.validate_body_length(routing, request_packet.body().len()) {
            channel.pending = None;
            let reply = local_error_reply(request_packet.header(), &error.to_string())
                .map_err(ProxyConnectionError::Downstream)?;
            send_proxy_reply(
                &channel.replies,
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
        let request_header = request_packet.header().clone();
        let upstream_packet = rewrite_session_id(request_packet, upstream_session_id);
        let upstream_reply = match conversation.round_trip(upstream_packet).await {
            Ok(reply) => reply,
            Err(error) => {
                log::warn!(
                    "A continuing TACACS+ proxy round trip failed: {:#}",
                    error.context("Failed to complete a TACACS+ server round trip")
                );
                provider
                    .deadline(routing)
                    .check()
                    .map_err(|error| ProxyConnectionError::Upstream(error.into()))?;
                channel.pending = None;
                return send_local_error(
                    &channel.replies,
                    &request_header,
                    reply_obfuscation,
                    advertise_single_connect,
                    provider.deadline(routing),
                )
                .await;
            }
        };
        let action = reply_action(&upstream_reply);
        channel.pending = None;
        if is_error_reply(&upstream_reply) {
            conversation.note_server_failure().await;
        } else {
            conversation.note_success().await;
        }
        send_proxy_reply(
            &channel.replies,
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
                conversation.note_server_failure().await;
                log::warn!(
                    "Closing the TACACS+ proxy session because reply status {status} is not supported"
                );
                return Ok(());
            }
        }
    }
    Ok(())
}

/// Sends a local `ERROR` reply when no server completed a request.
///
/// RFC 8907 section 4.4 directs the client to treat this reply as if it could
/// not reach the server, and to try its backup servers. The message is generic
/// so that it does not disclose upstream details. The failure is logged.
async fn send_local_error(
    replies: &mpsc::Sender<SessionReply>,
    request: &Header,
    obfuscation: packet_io::DownstreamObfuscation,
    advertise_single_connect: bool,
    deadline: RequestDeadline,
) -> Result<(), ProxyConnectionError> {
    let reply = local_error_reply(request, "No TACACS+ server completed the request")
        .map_err(ProxyConnectionError::Downstream)?;
    send_proxy_reply(
        replies,
        obfuscation,
        advertise_single_connect,
        reply,
        request.session_id,
        false,
        deadline,
    )
    .await
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
