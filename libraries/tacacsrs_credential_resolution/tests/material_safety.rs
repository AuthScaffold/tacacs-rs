use std::{fmt::Display, hash::Hash};

use serde::{Serialize, de::DeserializeOwned};
use static_assertions::assert_not_impl_any;
use tacacsrs_credential_resolution::{
    CertificateWithKeyMaterial, CredentialKind, PublicBytes, ResolvedCredential,
    ResolvedCredentialSet, ResolvedResponse, SecretBytes, SymmetricKeyMaterial, ResolutionPlan,
    RequestContext, CredentialReference, PrivateKeyFormat,
};

assert_not_impl_any!(SecretBytes: Display, Hash);
assert_not_impl_any!(CertificateWithKeyMaterial: Clone, Serialize, DeserializeOwned, Display, PartialEq, Eq, Hash);
assert_not_impl_any!(ResolvedCredential: Clone, Serialize, DeserializeOwned, Display, PartialEq, Eq, Hash);
assert_not_impl_any!(ResolvedResponse: Clone, Serialize, DeserializeOwned, Display, PartialEq, Eq, Hash);
assert_not_impl_any!(ResolvedCredentialSet: Clone, Serialize, DeserializeOwned, Display, PartialEq, Eq, Hash);

#[test]
fn secret_bytes_require_explicit_borrow_and_redact_debug() {
    let secret = SecretBytes::new(b"symmetric-secret-value".to_vec());

    assert_eq!(secret.expose_secret(), b"symmetric-secret-value");
    assert_eq!(format!("{secret:?}"), "SecretBytes(<redacted>)");
    assert!(!format!("{secret:?}").contains("symmetric-secret-value"));
}

#[test]
fn revocation_requests_are_closed_and_references_are_redacted() {
    let reference = CredentialReference::CertificateRevocationLists("opaque-crl-object".to_owned());
    assert!(!format!("{reference:?}").contains("opaque-crl-object"));
    let plan = ResolutionPlan::new([(
        RequestContext::new("server", "revocation"),
        CredentialKind::CertificateRevocationLists,
        reference,
    )])
    .unwrap();
    assert_eq!(
        plan.requests()[0]
            .reference()
            .certificate_revocation_lists(),
        Some("opaque-crl-object")
    );
    assert!(!format!("{:?}", plan.requests()[0]).contains("opaque-crl-object"));
    let material = ResolvedCredential::CertificateRevocationLists(
        tacacsrs_credential_resolution::CertificateRevocationListsMaterial {
            validity: tacacsrs_credential_resolution::CredentialValidity::unbounded(),
            lists: vec![PublicBytes::new(b"test-crl-bytes".to_vec())],
        },
    );
    let result = ResolvedCredentialSet::from_responses(
        &plan,
        [ResolvedResponse::new(plan.requests()[0].slot(), material)],
    )
    .unwrap();
    assert_eq!(
        result.credential(plan.requests()[0].slot()).unwrap().kind(),
        CredentialKind::CertificateRevocationLists
    );
    assert!(!format!("{result:?}").contains("test-crl-bytes"));
    assert!(ResolutionPlan::new([(
        RequestContext::new("server", "revocation"),
        CredentialKind::CertificateRevocationLists,
        CredentialReference::SymmetricKey("wrong-kind".to_owned())
    )])
    .is_err());
}

#[test]
fn secret_bearing_aggregate_debug_redacts_all_material() {
    let credential = ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
        intermediates: vec![PublicBytes::new(b"intermediate-certificate-value".to_vec())],
        validity: tacacsrs_credential_resolution::CredentialValidity::unbounded(),
        public_key_format: None,
        public_key: None,
        private_key_format: PrivateKeyFormat::OneAsymmetricKeyFormat,
        certificate: PublicBytes::new(b"public-certificate-value".to_vec()),
        private_key: SecretBytes::new(b"private-key-value".to_vec()),
    });

    let debug = format!("{credential:?}");
    assert!(debug.contains("CertificateWithKey"));
    assert!(debug.contains("length: 24"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("public-certificate-value"));
    assert!(!debug.contains("intermediate-certificate-value"));
    assert!(!debug.contains("private-key-value"));
}

#[test]
fn closed_result_debug_omits_secret_and_reference_values() {
    let plan = ResolutionPlan::new([(
        RequestContext::new("safety-server", "client-identity/tls13-epsk"),
        CredentialKind::SymmetricKey,
        CredentialReference::SymmetricKey("opaque-central-reference".to_owned()),
    )])
    .expect("resolution plan must build");
    let response = ResolvedResponse::new(
        plan.requests()[0].slot(),
        ResolvedCredential::SymmetricKey(SymmetricKeyMaterial {
            validity: tacacsrs_credential_resolution::CredentialValidity::unbounded(),
            key_format: None,
            key: SecretBytes::new(b"resolved-symmetric-secret".to_vec()),
        }),
    );
    let response_debug = format!("{response:?}");
    assert!(response_debug.contains("SymmetricKey"));
    assert!(!response_debug.contains("resolved-symmetric-secret"));

    let result = ResolvedCredentialSet::from_responses(&plan, [response])
        .expect("closed result set must match the plan");
    assert_eq!(
        result
            .credential(plan.requests()[0].slot())
            .expect("resolved credential must exist")
            .kind(),
        CredentialKind::SymmetricKey,
    );
    let result_debug = format!("{result:?}");
    for forbidden in [
        "resolved-symmetric-secret",
        "opaque-central-reference",
        "192.0.2.15",
    ] {
        assert!(!result_debug.contains(forbidden), "debug exposed {forbidden}");
    }
}
