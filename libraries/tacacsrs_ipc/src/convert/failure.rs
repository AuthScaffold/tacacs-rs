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
    DeliveryState, FailureCategory, FailureFacts, FailurePhase, RetryAdvice,
};
use tacacsrs_protocol::operations::ServiceError;

use crate::ipc;

impl From<ServiceError> for ipc::ServiceError {
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

impl TryFrom<ipc::ServiceError> for ServiceError {
    type Error = anyhow::Error;

    fn try_from(proto: ipc::ServiceError) -> Result<Self, Self::Error> {
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

fn encode_category(category: FailureCategory) -> ipc::FailureCategory {
    match category {
        FailureCategory::Unclassified => ipc::FailureCategory::Unclassified,
        FailureCategory::InvalidRequest => ipc::FailureCategory::InvalidRequest,
        FailureCategory::Unavailable => ipc::FailureCategory::Unavailable,
        FailureCategory::Overloaded => ipc::FailureCategory::Overloaded,
        FailureCategory::Deadline => ipc::FailureCategory::Deadline,
        FailureCategory::Transport => ipc::FailureCategory::Transport,
        FailureCategory::Protocol => ipc::FailureCategory::Protocol,
        FailureCategory::Cancelled => ipc::FailureCategory::Cancelled,
        FailureCategory::Internal => ipc::FailureCategory::Internal,
    }
}

fn encode_phase(phase: FailurePhase) -> ipc::FailurePhase {
    match phase {
        FailurePhase::Unknown => ipc::FailurePhase::Unknown,
        FailurePhase::Validation => ipc::FailurePhase::Validation,
        FailurePhase::Admission => ipc::FailurePhase::Admission,
        FailurePhase::Routing => ipc::FailurePhase::Routing,
        FailurePhase::Upstream => ipc::FailurePhase::Upstream,
        FailurePhase::Ipc => ipc::FailurePhase::Ipc,
    }
}

fn encode_delivery(delivery: DeliveryState) -> ipc::DeliveryState {
    match delivery {
        DeliveryState::NotSent => ipc::DeliveryState::NotSent,
        DeliveryState::OutcomeUnknown => ipc::DeliveryState::OutcomeUnknown,
    }
}

fn encode_retry_advice(advice: RetryAdvice) -> ipc::RetryAdvice {
    match advice {
        RetryAdvice::Never => ipc::RetryAdvice::Never,
        RetryAdvice::AfterRecovery => ipc::RetryAdvice::AfterRecovery,
    }
}

fn decode_category(value: i32) -> anyhow::Result<FailureCategory> {
    match ipc::FailureCategory::try_from(value)
        .map_err(|_| anyhow!("IPC service error failure category {value} is not recognized"))?
    {
        ipc::FailureCategory::Unspecified => {
            bail!("IPC service error failure category must not be unspecified")
        }
        ipc::FailureCategory::Unclassified => Ok(FailureCategory::Unclassified),
        ipc::FailureCategory::InvalidRequest => Ok(FailureCategory::InvalidRequest),
        ipc::FailureCategory::Unavailable => Ok(FailureCategory::Unavailable),
        ipc::FailureCategory::Overloaded => Ok(FailureCategory::Overloaded),
        ipc::FailureCategory::Deadline => Ok(FailureCategory::Deadline),
        ipc::FailureCategory::Transport => Ok(FailureCategory::Transport),
        ipc::FailureCategory::Protocol => Ok(FailureCategory::Protocol),
        ipc::FailureCategory::Cancelled => Ok(FailureCategory::Cancelled),
        ipc::FailureCategory::Internal => Ok(FailureCategory::Internal),
    }
}

fn decode_phase(value: i32) -> anyhow::Result<FailurePhase> {
    match ipc::FailurePhase::try_from(value)
        .map_err(|_| anyhow!("IPC service error failure phase {value} is not recognized"))?
    {
        ipc::FailurePhase::Unspecified => {
            bail!("IPC service error failure phase must not be unspecified")
        }
        ipc::FailurePhase::Unknown => Ok(FailurePhase::Unknown),
        ipc::FailurePhase::Validation => Ok(FailurePhase::Validation),
        ipc::FailurePhase::Admission => Ok(FailurePhase::Admission),
        ipc::FailurePhase::Routing => Ok(FailurePhase::Routing),
        ipc::FailurePhase::Upstream => Ok(FailurePhase::Upstream),
        ipc::FailurePhase::Ipc => Ok(FailurePhase::Ipc),
    }
}

fn decode_delivery(value: i32) -> anyhow::Result<DeliveryState> {
    match ipc::DeliveryState::try_from(value)
        .map_err(|_| anyhow!("IPC service error delivery state {value} is not recognized"))?
    {
        ipc::DeliveryState::Unspecified => {
            bail!("IPC service error delivery state must not be unspecified")
        }
        ipc::DeliveryState::NotSent => Ok(DeliveryState::NotSent),
        ipc::DeliveryState::OutcomeUnknown => Ok(DeliveryState::OutcomeUnknown),
    }
}

fn decode_retry_advice(value: i32) -> anyhow::Result<RetryAdvice> {
    match ipc::RetryAdvice::try_from(value)
        .map_err(|_| anyhow!("IPC service error retry advice {value} is not recognized"))?
    {
        ipc::RetryAdvice::Unspecified => {
            bail!("IPC service error retry advice must not be unspecified")
        }
        ipc::RetryAdvice::Never => Ok(RetryAdvice::Never),
        ipc::RetryAdvice::AfterRecovery => Ok(RetryAdvice::AfterRecovery),
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

    fn valid_wire() -> ipc::ServiceError {
        ipc::ServiceError::from(ServiceError::new("sample", unsent_unavailable()))
    }

    #[test]
    fn round_trip_preserves_facts_server_generation_and_attempt() {
        let error = ServiceError::new("no responsive servers", unsent_unavailable())
            .with_server("tacacs-a:49")
            .with_runtime_generation(7)
            .with_attempt(NonZeroU32::new(3).unwrap());
        let decoded = ServiceError::try_from(ipc::ServiceError::from(error.clone())).unwrap();
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
        let wire = ipc::ServiceError::from(error.clone());
        assert!(wire.server.is_empty());
        assert!(wire.runtime_generation.is_none());
        assert!(wire.attempt.is_none());
        let decoded = ServiceError::try_from(wire).unwrap();
        assert_eq!(decoded, error);
        assert!(decoded.server.is_none());
    }

    #[test]
    fn wire_carries_derived_retry_advice() {
        let unsent = ipc::ServiceError::from(ServiceError::new("x", unsent_unavailable()));
        assert_eq!(unsent.retry_advice, ipc::RetryAdvice::AfterRecovery as i32);
        let uncertain = ipc::ServiceError::from(ServiceError::new("x", uncertain_transport()));
        assert_eq!(uncertain.retry_advice, ipc::RetryAdvice::Never as i32);
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
                        ServiceError::try_from(ipc::ServiceError::from(error.clone())).unwrap();
                    assert_eq!(decoded, error);
                    assert_eq!(decoded.facts.retry_advice(), facts.retry_advice());
                }
            }
        }
    }

    #[test]
    fn rejects_unspecified_enum_sentinels() {
        let mutators: [fn(&mut ipc::ServiceError); 4] = [
            |wire| wire.category = ipc::FailureCategory::Unspecified as i32,
            |wire| wire.phase = ipc::FailurePhase::Unspecified as i32,
            |wire| wire.delivery = ipc::DeliveryState::Unspecified as i32,
            |wire| wire.retry_advice = ipc::RetryAdvice::Unspecified as i32,
        ];
        for mutate in mutators {
            let mut wire = valid_wire();
            mutate(&mut wire);
            assert!(ServiceError::try_from(wire).is_err());
        }
    }

    #[test]
    fn rejects_unknown_enum_values() {
        let mutators: [fn(&mut ipc::ServiceError); 4] = [
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
        unsent.retry_advice = ipc::RetryAdvice::Never as i32;
        assert!(ServiceError::try_from(unsent).is_err());

        let mut uncertain = ipc::ServiceError::from(ServiceError::new("x", uncertain_transport()));
        uncertain.retry_advice = ipc::RetryAdvice::AfterRecovery as i32;
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
        assert!(ServiceError::try_from(ipc::ServiceError::default()).is_err());
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
