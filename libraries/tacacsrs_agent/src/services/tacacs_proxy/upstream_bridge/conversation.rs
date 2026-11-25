//! Managed upstream conversations for the raw proxy.
//!
//! The provider adapts captured routing and admission to raw conversations.
//! Each conversation owns upstream I/O deadlines and failure observation.
//! Downstream forwarding reports protocol statuses separately.

use async_trait::async_trait;
use tacacsrs_networking::{ClientConversation, RequestDeadline};
use tacacsrs_networking::retry::FailoverPlan;
use tacacsrs_networking::routed::EndpointConnector;
use tacacsrs_protocol::packet::Packet;

use crate::upstream::{AdmissionError, AdmissionPermit, OperationKind, OperationRouter, RequestRouting};
use crate::upstream::manager::BoundServer;
use crate::upstream::UpstreamConnection;

/// One upstream conversation. Implementations bound each round trip.
#[async_trait]
pub(super) trait ProxyConversation: Send + Sync {
    fn session_id(&self) -> Option<u32>;
    async fn round_trip(&mut self, packet: Packet) -> anyhow::Result<Packet>;
    async fn complete(&mut self);
    async fn note_success(&self) {}
    async fn note_server_failure(&self) {}
}

/// Supplies captured routing, admission, and conversations.
#[async_trait]
pub(super) trait ProxyConversationProvider: Send + Sync + 'static {
    type Conversation: ProxyConversation;
    type Request: Send + Sync;
    type Reservation: Send + Sync;

    fn capture_request(&self, operation: OperationKind) -> Self::Request;
    fn deadline(&self, request: &Self::Request) -> RequestDeadline;
    fn reserve(
        &self,
        request: &Self::Request,
        body_length: usize,
    ) -> Result<Self::Reservation, AdmissionError>;
    async fn open_conversation(
        &self,
        request: &Self::Request,
    ) -> anyhow::Result<Self::Conversation>;
    async fn admit(
        &self,
        request: &Self::Request,
        reservation: Self::Reservation,
    ) -> Result<Option<AdmissionPermit>, AdmissionError>;
    async fn admit_continuation(
        &self,
        request: &Self::Request,
        body_length: usize,
    ) -> Result<Option<AdmissionPermit>, AdmissionError>;
    fn failover_plan(&self, request: &Self::Request) -> FailoverPlan;
    fn max_packet_body_length(&self) -> std::num::NonZeroU32;
    fn max_sessions_per_connection(&self) -> usize;
}

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

pub(super) struct ManagedProxyConversation<
    Connector: EndpointConnector = crate::upstream::NetworkUpstreamConnector,
> {
    bound_server: BoundServer<Connector>,
    conversation: ClientConversation,
    deadline: RequestDeadline,
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
        let deadline = request.deadline();
        let conversation = deadline
            .run(async {
                let mut observation = bound_server.observe_failure(deadline);
                let result = bound_server.connection.open_conversation().await;
                if result.is_ok() {
                    observation.disarm();
                } else {
                    observation.fail();
                }
                result
            })
            .await??;
        Ok(ManagedProxyConversation {
            bound_server,
            conversation,
            deadline,
        })
    }

    async fn admit(
        &self,
        request: &Self::Request,
        reservation: Self::Reservation,
    ) -> Result<Option<AdmissionPermit>, AdmissionError> {
        request.admit_reserved(reservation).await.map(Some)
    }

    async fn admit_continuation(
        &self,
        request: &Self::Request,
        body_length: usize,
    ) -> Result<Option<AdmissionPermit>, AdmissionError> {
        request.admit(body_length).await.map(Some)
    }

    fn failover_plan(&self, request: &Self::Request) -> FailoverPlan {
        request.failover_plan()
    }

    fn max_packet_body_length(&self) -> std::num::NonZeroU32 {
        self.router.max_packet_body_length()
    }

    fn max_sessions_per_connection(&self) -> usize {
        self.router.max_proxy_sessions_per_connection()
    }
}

#[async_trait]
impl<Connector: EndpointConnector> ProxyConversation for ManagedProxyConversation<Connector> {
    fn session_id(&self) -> Option<u32> {
        self.conversation.session_id()
    }

    async fn round_trip(&mut self, packet: Packet) -> anyhow::Result<Packet> {
        let deadline = self.deadline.capped(self.bound_server.timeout_duration());
        deadline
            .run(async {
                let mut observation = self.bound_server.observe_failure(deadline);
                let result = self.conversation.round_trip(packet).await;
                if result.is_ok() {
                    observation.disarm();
                } else {
                    observation.fail();
                }
                result
            })
            .await?
    }

    async fn complete(&mut self) {
        self.conversation.complete().await;
    }

    async fn note_success(&self) {
        self.bound_server.note_success().await;
    }

    async fn note_server_failure(&self) {
        self.bound_server.note_server_failure().await;
    }
}
