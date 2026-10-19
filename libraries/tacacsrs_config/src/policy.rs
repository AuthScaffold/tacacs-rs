//! Parses the module-qualified YANG runtime-policy resource and validates its ranges.
//!
//! Absent operation containers remain absent in the source value. Consumers
//! apply their generated defaults when deriving runtime policy.

use std::collections::BTreeSet;

use anyhow::{Context, ensure};
use serde::Deserialize;
use tacacsrs_protocol::constants::TACACS_MAX_BODY_LENGTH;

use crate::tacacsrs::RuntimePolicy;

#[derive(Deserialize)]
struct PolicyResource {
    #[serde(rename = "tacacsrs:runtime-policy")]
    policy: RuntimePolicy,
}

/// Parses a canonical RFC 7951 runtime-policy resource.
///
/// # Errors
///
/// Returns an error for unknown fields, malformed JSON, or invalid policy ranges.
pub fn parse_runtime_policy(bytes: &[u8]) -> anyhow::Result<RuntimePolicy> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let mut unknown = BTreeSet::new();
    let resource: PolicyResource = serde_ignored::deserialize(&mut deserializer, |path| {
        unknown.insert(path.to_string());
    })
    .context("decode YANG runtime-policy resource")?;
    deserializer
        .end()
        .context("unexpected data after runtime-policy resource")?;
    ensure!(
        unknown.is_empty(),
        "unknown runtime-policy fields: {}",
        unknown.into_iter().collect::<Vec<_>>().join(", ")
    );
    validate_runtime_policy(&resource.policy)?;
    Ok(resource.policy)
}

/// Validates generated policy values before runtime projection.
///
/// # Errors
///
/// Returns an error for zero intervals or concurrency limits, or body limits
/// outside the supported TACACS+ range.
pub fn validate_runtime_policy(policy: &RuntimePolicy) -> anyhow::Result<()> {
    let candidate = policy.candidate_preparation.clone().unwrap_or_default();
    for (name, value) in [
        ("timeout-seconds", candidate.timeout_seconds),
        ("max-resolution-requests", candidate.max_resolution_requests),
        ("max-retained-material-bytes", candidate.max_retained_material_bytes),
    ] {
        ensure!(value > 0, "runtime-policy/candidate-preparation/{name} must be greater than zero");
    }
    ensure!(
        policy.credential_refresh_interval_seconds > 0,
        "runtime-policy/credential-refresh-interval-seconds must be greater than zero"
    );
    ensure!(
        policy.credential_stale_timeout_seconds > 0,
        "runtime-policy/credential-stale-timeout-seconds must be greater than zero"
    );
    ensure!(
        policy.source_stale_timeout_seconds > 0,
        "runtime-policy/source-stale-timeout-seconds must be greater than zero"
    );
    ensure!(
        policy.shutdown_timeout_seconds > 0,
        "runtime-policy/shutdown-timeout-seconds must be greater than zero"
    );
    ensure!(
        policy.failover_recovery_interval_seconds > 0,
        "runtime-policy/failover-recovery-interval-seconds must be greater than zero"
    );
    let authentication = policy.authentication.clone().unwrap_or_default();
    let authorization = policy.authorization.clone().unwrap_or_default();
    let accounting = policy.accounting.clone().unwrap_or_default();
    for (operation, body, concurrency, timeout) in [
        (
            "authentication",
            authentication.max_body_length,
            authentication.max_concurrent_requests,
            authentication.request_timeout_seconds,
        ),
        (
            "authorization",
            authorization.max_body_length,
            authorization.max_concurrent_requests,
            authorization.request_timeout_seconds,
        ),
        (
            "accounting",
            accounting.max_body_length,
            accounting.max_concurrent_requests,
            accounting.request_timeout_seconds,
        ),
    ] {
        ensure!(
            (1..=TACACS_MAX_BODY_LENGTH).contains(&body),
            "runtime-policy/{operation}/max-body-length must be in 1..={TACACS_MAX_BODY_LENGTH}"
        );
        ensure!(
            concurrency > 0,
            "runtime-policy/{operation}/max-concurrent-requests must be greater than zero"
        );
        ensure!(
            timeout > 0,
            "runtime-policy/{operation}/request-timeout-seconds must be greater than zero"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn candidate_policy_defaults_ranges_and_source_absence() {
        let absent = super::parse_runtime_policy(br#"{"tacacsrs:runtime-policy":{}}"#).unwrap();
        assert!(absent.candidate_preparation.is_none());
        let serialized = serde_json::to_value(&absent).unwrap();
        assert!(serialized.get("candidate-preparation").is_none());
        let empty = super::parse_runtime_policy(
            br#"{"tacacsrs:runtime-policy":{"candidate-preparation":{}}}"#,
        )
        .unwrap();
        let defaults = crate::tacacsrs::CandidatePreparation::default();
        assert_eq!(empty.candidate_preparation, Some(defaults.clone()));
        assert_eq!(
            (
                defaults.timeout_seconds,
                defaults.max_resolution_requests,
                defaults.max_retained_material_bytes
            ),
            (30, 256, 67108864)
        );
        for field in [
            "timeout-seconds",
            "max-resolution-requests",
            "max-retained-material-bytes",
        ] {
            for value in [1_u64, u64::from(u32::MAX)] {
                let input = serde_json::json!({"tacacsrs:runtime-policy":{"candidate-preparation":{field:value}}});
                let parsed =
                    super::parse_runtime_policy(&serde_json::to_vec(&input).unwrap()).unwrap();
                assert!(super::validate_runtime_policy(&parsed).is_ok());
            }
            for value in [0, u64::from(u32::MAX) + 1, u64::MAX] {
                let input = serde_json::json!({"tacacsrs:runtime-policy":{"candidate-preparation":{field:value}}});
                assert!(super::parse_runtime_policy(&serde_json::to_vec(&input).unwrap()).is_err());
            }
        }
        for index in 0..3 {
            let mut candidate = defaults.clone();
            match index {
                0 => candidate.timeout_seconds = 0,
                1 => candidate.max_resolution_requests = 0,
                _ => candidate.max_retained_material_bytes = 0,
            }
            let mut invalid = absent.clone();
            invalid.candidate_preparation = Some(candidate);
            assert!(super::validate_runtime_policy(&invalid).is_err());
        }
    }

    #[test]
    fn zero_credential_refresh_interval_is_rejected() {
        assert!(super::parse_runtime_policy(
            br#"{"tacacsrs:runtime-policy":{"credential-refresh-interval-seconds":0}}"#
        )
        .is_err());
    }

    use super::*;

    #[test]
    fn generated_defaults_preserve_absent_containers() {
        let policy = parse_runtime_policy(br#"{"tacacsrs:runtime-policy":{}}"#).unwrap();
        assert_eq!(policy, RuntimePolicy::default());
        assert_eq!(policy.shutdown_timeout_seconds, 30);
        assert_eq!(policy.source_stale_timeout_seconds, 300);
        assert_eq!(policy.credential_stale_timeout_seconds, 300);
        assert_eq!(policy.credential_refresh_interval_seconds, 60);
        assert!(policy.authentication.is_none());
        assert_eq!(crate::tacacsrs::Authentication::default().max_body_length, 4096);
        assert_eq!(crate::tacacsrs::Authorization::default().max_body_length, 16384);
        assert_eq!(crate::tacacsrs::Authentication::default().request_timeout_seconds, 30);
    }

    #[test]
    fn partial_containers_use_their_own_yang_defaults() {
        let policy = parse_runtime_policy(
            br#"{"tacacsrs:runtime-policy":{
            "authentication":{"max-concurrent-requests":8}, "accounting":{}
        }}"#,
        )
        .unwrap();
        assert_eq!(policy.authentication.unwrap().max_body_length, 4096);
        assert_eq!(policy.accounting.unwrap().max_body_length, 16384);
    }

    #[test]
    fn rejects_legacy_unknown_trailing_and_invalid_policy_data() {
        for input in [
            "{}",
            r#"{"authentication":{"max-body-length":4096}}"#,
            r#"{"tacacsrs:runtime-policy":{"unknown":1}}"#,
            r#"{"tacacsrs:runtime-policy":{"authentication":{"unknown":1}}}"#,
            r#"{"tacacsrs:runtime-policy":{}} {}"#,
            r#"{"tacacsrs:runtime-policy":{"failover-recovery-interval-seconds":0}}"#,
            r#"{"tacacsrs:runtime-policy":{"shutdown-timeout-seconds":0}}"#,
            r#"{"tacacsrs:runtime-policy":{"source-stale-timeout-seconds":0}}"#,
            r#"{"tacacsrs:runtime-policy":{"credential-stale-timeout-seconds":0}}"#,
            r#"{"tacacsrs:runtime-policy":{"accounting":{"max-body-length":65537}}}"#,
            r#"{"tacacsrs:runtime-policy":{"authorization":{"max-concurrent-requests":0}}}"#,
            r#"{"tacacsrs:runtime-policy":{"authentication":{"request-timeout-seconds":0}}}"#,
        ] {
            assert!(parse_runtime_policy(input.as_bytes()).is_err(), "accepted {input}");
        }
    }
}
