//! Protobuf conversions for the structured [`ServiceError`] failure contract.
//!
//! The wire error carries explicit failure facts: a cause category, the phase
//! where the failure became known, and the delivery state. The service derives
//! retry advice from these facts and sends it for redundancy. A decoder rejects
//! any message that omits a fact, uses an unknown enum value, or carries retry
//! advice that is inconsistent with its facts. Unknown delivery never permits
//! automatic replay.

use std::num::NonZeroU32;

use anyhow::{Context, anyhow, bail};
use tacacsrs_protocol::failure::{
    DeliveryState, FailureCategory, FailureFacts, FailurePhase, RetryAdvice, ServiceError,
};

use crate::proto;

impl From<ServiceError> for proto::ServiceError {
    fn from(value: ServiceError) -> Self {
        let facts = value.facts;
        Self {
            message: value.message,
            server: value.server.unwrap_or_default(),
            category: encode_category(facts.category()) as i32,
            phase: encode_phase(facts.phase()) as i32,
            delivery: encode_delivery(facts.delivery()) as i32,
            retry_advice: encode_retry_advice(facts.retry_advice()) as i32,
            runtime_generation: value.runtime_generation,
            attempt: value.attempt.map(NonZeroU32::get),
        }
    }
}

impl TryFrom<proto::ServiceError> for ServiceError {
    type Error = anyhow::Error;

    fn try_from(proto: proto::ServiceError) -> Result<Self, Self::Error> {
        let facts = FailureFacts::new(
            decode_category(proto.category)?,
            decode_phase(proto.phase)?,
            decode_delivery(proto.delivery)?,
        );
        if facts.retry_advice() != decode_retry_advice(proto.retry_advice)? {
            bail!("IPC service error retry advice is inconsistent with its failure facts");
        }
        let attempt = proto
            .attempt
            .map(|value| {
                NonZeroU32::new(value)
                    .context("IPC service error attempt must be a one-based non-zero value")
            })
            .transpose()?;
        Ok(Self {
            message: proto.message,
            server: (!proto.server.is_empty()).then_some(proto.server),
            facts,
            runtime_generation: proto.runtime_generation,
            attempt,
        })
    }
}

/// Builds a conservative error for an IPC channel or RPC transport failure.
///
/// The RPC was in flight, so the operation can have reached a server. The
/// delivery state is therefore unknown and the derived advice is never to
/// replay, even when the transport reports a temporary condition.
pub(crate) fn ipc_transport_failure(message: String) -> ServiceError {
    ServiceError::new(
        message,
        FailureFacts::new(
            FailureCategory::Transport,
            FailurePhase::Ipc,
            DeliveryState::OutcomeUnknown,
        ),
    )
}

/// Builds a conservative error for a malformed or invalid IPC reply.
///
/// The reply arrived but violated the contract, so the request can have reached
/// a server. The delivery state is unknown and the derived advice is never to
/// replay.
pub(crate) fn ipc_protocol_failure(message: String) -> ServiceError {
    ServiceError::new(
        message,
        FailureFacts::new(
            FailureCategory::Protocol,
            FailurePhase::Ipc,
            DeliveryState::OutcomeUnknown,
        ),
    )
}

fn encode_category(category: FailureCategory) -> proto::FailureCategory {
    match category {
        FailureCategory::Unclassified => proto::FailureCategory::Unclassified,
        FailureCategory::InvalidRequest => proto::FailureCategory::InvalidRequest,
        FailureCategory::Unavailable => proto::FailureCategory::Unavailable,
        FailureCategory::Overloaded => proto::FailureCategory::Overloaded,
        FailureCategory::Deadline => proto::FailureCategory::Deadline,
        FailureCategory::Transport => proto::FailureCategory::Transport,
        FailureCategory::Protocol => proto::FailureCategory::Protocol,
        FailureCategory::Cancelled => proto::FailureCategory::Cancelled,
        FailureCategory::Internal => proto::FailureCategory::Internal,
    }
}

fn encode_phase(phase: FailurePhase) -> proto::FailurePhase {
    match phase {
        FailurePhase::Unknown => proto::FailurePhase::Unknown,
        FailurePhase::Validation => proto::FailurePhase::Validation,
        FailurePhase::Admission => proto::FailurePhase::Admission,
        FailurePhase::Routing => proto::FailurePhase::Routing,
        FailurePhase::Upstream => proto::FailurePhase::Upstream,
        FailurePhase::Ipc => proto::FailurePhase::Ipc,
    }
}

fn encode_delivery(delivery: DeliveryState) -> proto::DeliveryState {
    match delivery {
        DeliveryState::NotSent => proto::DeliveryState::NotSent,
        DeliveryState::OutcomeUnknown => proto::DeliveryState::OutcomeUnknown,
    }
}

fn encode_retry_advice(advice: RetryAdvice) -> proto::RetryAdvice {
    match advice {
        RetryAdvice::Never => proto::RetryAdvice::Never,
        RetryAdvice::AfterRecovery => proto::RetryAdvice::AfterRecovery,
    }
}

fn decode_category(value: i32) -> anyhow::Result<FailureCategory> {
    match proto::FailureCategory::try_from(value)
        .map_err(|_| anyhow!("IPC service error failure category {value} is not recognized"))?
    {
        proto::FailureCategory::Unspecified => {
            bail!("IPC service error failure category must not be unspecified")
        }
        proto::FailureCategory::Unclassified => Ok(FailureCategory::Unclassified),
        proto::FailureCategory::InvalidRequest => Ok(FailureCategory::InvalidRequest),
        proto::FailureCategory::Unavailable => Ok(FailureCategory::Unavailable),
        proto::FailureCategory::Overloaded => Ok(FailureCategory::Overloaded),
        proto::FailureCategory::Deadline => Ok(FailureCategory::Deadline),
        proto::FailureCategory::Transport => Ok(FailureCategory::Transport),
        proto::FailureCategory::Protocol => Ok(FailureCategory::Protocol),
        proto::FailureCategory::Cancelled => Ok(FailureCategory::Cancelled),
        proto::FailureCategory::Internal => Ok(FailureCategory::Internal),
    }
}

fn decode_phase(value: i32) -> anyhow::Result<FailurePhase> {
    match proto::FailurePhase::try_from(value)
        .map_err(|_| anyhow!("IPC service error failure phase {value} is not recognized"))?
    {
        proto::FailurePhase::Unspecified => {
            bail!("IPC service error failure phase must not be unspecified")
        }
        proto::FailurePhase::Unknown => Ok(FailurePhase::Unknown),
        proto::FailurePhase::Validation => Ok(FailurePhase::Validation),
        proto::FailurePhase::Admission => Ok(FailurePhase::Admission),
        proto::FailurePhase::Routing => Ok(FailurePhase::Routing),
        proto::FailurePhase::Upstream => Ok(FailurePhase::Upstream),
        proto::FailurePhase::Ipc => Ok(FailurePhase::Ipc),
    }
}

fn decode_delivery(value: i32) -> anyhow::Result<DeliveryState> {
    match proto::DeliveryState::try_from(value)
        .map_err(|_| anyhow!("IPC service error delivery state {value} is not recognized"))?
    {
        proto::DeliveryState::Unspecified => {
            bail!("IPC service error delivery state must not be unspecified")
        }
        proto::DeliveryState::NotSent => Ok(DeliveryState::NotSent),
        proto::DeliveryState::OutcomeUnknown => Ok(DeliveryState::OutcomeUnknown),
    }
}

fn decode_retry_advice(value: i32) -> anyhow::Result<RetryAdvice> {
    match proto::RetryAdvice::try_from(value)
        .map_err(|_| anyhow!("IPC service error retry advice {value} is not recognized"))?
    {
        proto::RetryAdvice::Unspecified => {
            bail!("IPC service error retry advice must not be unspecified")
        }
        proto::RetryAdvice::Never => Ok(RetryAdvice::Never),
        proto::RetryAdvice::AfterRecovery => Ok(RetryAdvice::AfterRecovery),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsent_unavailable() -> FailureFacts {
        FailureFacts::new(
            FailureCategory::Unavailable,
            FailurePhase::Routing,
            DeliveryState::NotSent,
        )
    }

    fn uncertain_transport() -> FailureFacts {
        FailureFacts::new(
            FailureCategory::Transport,
            FailurePhase::Upstream,
            DeliveryState::OutcomeUnknown,
        )
    }

    fn valid_wire() -> proto::ServiceError {
        proto::ServiceError::from(ServiceError::new("sample", unsent_unavailable()))
    }

    #[test]
    fn round_trip_preserves_facts_server_generation_and_attempt() {
        let error = ServiceError::new("no responsive servers", unsent_unavailable())
            .with_server("tacacs-a:49")
            .with_runtime_generation(7)
            .with_attempt(NonZeroU32::new(3).unwrap());
        let decoded = ServiceError::try_from(proto::ServiceError::from(error.clone())).unwrap();
        assert_eq!(decoded, error);
    }

    #[test]
    fn round_trip_preserves_absent_optionals_and_empty_server() {
        let error = ServiceError::new(
            "invalid request",
            FailureFacts::new(
                FailureCategory::InvalidRequest,
                FailurePhase::Validation,
                DeliveryState::NotSent,
            ),
        );
        let wire = proto::ServiceError::from(error.clone());
        assert!(wire.server.is_empty());
        assert!(wire.runtime_generation.is_none());
        assert!(wire.attempt.is_none());
        let decoded = ServiceError::try_from(wire).unwrap();
        assert_eq!(decoded, error);
        assert!(decoded.server.is_none());
    }

    #[test]
    fn wire_carries_derived_retry_advice() {
        let unsent = proto::ServiceError::from(ServiceError::new("x", unsent_unavailable()));
        assert_eq!(unsent.retry_advice, proto::RetryAdvice::AfterRecovery as i32);
        let uncertain = proto::ServiceError::from(ServiceError::new("x", uncertain_transport()));
        assert_eq!(uncertain.retry_advice, proto::RetryAdvice::Never as i32);
    }

    #[test]
    fn facts_matrix_round_trips_and_preserves_derived_advice() {
        let categories = [
            FailureCategory::Unclassified,
            FailureCategory::InvalidRequest,
            FailureCategory::Unavailable,
            FailureCategory::Overloaded,
            FailureCategory::Deadline,
            FailureCategory::Transport,
            FailureCategory::Protocol,
            FailureCategory::Cancelled,
            FailureCategory::Internal,
        ];
        let phases = [
            FailurePhase::Unknown,
            FailurePhase::Validation,
            FailurePhase::Admission,
            FailurePhase::Routing,
            FailurePhase::Upstream,
            FailurePhase::Ipc,
        ];
        let deliveries = [DeliveryState::NotSent, DeliveryState::OutcomeUnknown];
        for category in categories {
            for phase in phases {
                for delivery in deliveries {
                    let facts = FailureFacts::new(category, phase, delivery);
                    let error = ServiceError::new("m", facts).with_server("s:49");
                    let decoded =
                        ServiceError::try_from(proto::ServiceError::from(error.clone())).unwrap();
                    assert_eq!(decoded, error);
                    assert_eq!(decoded.facts.retry_advice(), facts.retry_advice());
                }
            }
        }
    }

    #[test]
    fn rejects_unspecified_enum_sentinels() {
        let mutators: [fn(&mut proto::ServiceError); 4] = [
            |wire| wire.category = proto::FailureCategory::Unspecified as i32,
            |wire| wire.phase = proto::FailurePhase::Unspecified as i32,
            |wire| wire.delivery = proto::DeliveryState::Unspecified as i32,
            |wire| wire.retry_advice = proto::RetryAdvice::Unspecified as i32,
        ];
        for mutate in mutators {
            let mut wire = valid_wire();
            mutate(&mut wire);
            assert!(ServiceError::try_from(wire).is_err());
        }
    }

    #[test]
    fn rejects_unknown_enum_values() {
        let mutators: [fn(&mut proto::ServiceError); 4] = [
            |wire| wire.category = 999,
            |wire| wire.phase = 999,
            |wire| wire.delivery = 999,
            |wire| wire.retry_advice = 999,
        ];
        for mutate in mutators {
            let mut wire = valid_wire();
            mutate(&mut wire);
            assert!(ServiceError::try_from(wire).is_err());
        }
    }

    #[test]
    fn rejects_inconsistent_retry_advice() {
        let mut unsent = valid_wire();
        unsent.retry_advice = proto::RetryAdvice::Never as i32;
        assert!(ServiceError::try_from(unsent).is_err());

        let mut uncertain =
            proto::ServiceError::from(ServiceError::new("x", uncertain_transport()));
        uncertain.retry_advice = proto::RetryAdvice::AfterRecovery as i32;
        assert!(ServiceError::try_from(uncertain).is_err());
    }

    #[test]
    fn rejects_zero_attempt() {
        let mut wire = valid_wire();
        wire.attempt = Some(0);
        assert!(ServiceError::try_from(wire).is_err());
    }

    #[test]
    fn rejects_default_message_with_missing_facts() {
        assert!(ServiceError::try_from(proto::ServiceError::default()).is_err());
    }

    #[test]
    fn transport_helper_is_conservative() {
        let error = ipc_transport_failure("ipc channel dropped".to_owned());
        assert_eq!(error.facts.category(), FailureCategory::Transport);
        assert_eq!(error.facts.phase(), FailurePhase::Ipc);
        assert_eq!(error.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_eq!(error.facts.retry_advice(), RetryAdvice::Never);
    }

    #[test]
    fn protocol_helper_is_conservative() {
        let error = ipc_protocol_failure("malformed reply".to_owned());
        assert_eq!(error.facts.category(), FailureCategory::Protocol);
        assert_eq!(error.facts.phase(), FailurePhase::Ipc);
        assert_eq!(error.facts.delivery(), DeliveryState::OutcomeUnknown);
        assert_eq!(error.facts.retry_advice(), RetryAdvice::Never);
    }
}
