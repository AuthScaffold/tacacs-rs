use std::{fmt::Display, hash::Hash};

use serde::{Serialize, de::DeserializeOwned};
use static_assertions::assert_not_impl_any;
use tacacsrs_credential_resolution::{
    CertificateWithKeyMaterial, CredentialKind, PublicBytes, ResolvedCredential,
    ResolvedCredentialSet, ResolvedResponse, RuntimeServer, SecretBytes, SymmetricKeyMaterial,
};
use tacacsrs_config::parse_yang_json;

assert_not_impl_any!(SecretBytes: Display, Hash);
assert_not_impl_any!(CertificateWithKeyMaterial: Clone, Serialize, DeserializeOwned, Display, PartialEq, Eq, Hash);
assert_not_impl_any!(ResolvedCredential: Clone, Serialize, DeserializeOwned, Display, PartialEq, Eq, Hash);
assert_not_impl_any!(ResolvedResponse: Clone, Serialize, DeserializeOwned, Display, PartialEq, Eq, Hash);
assert_not_impl_any!(ResolvedCredentialSet: Clone, Serialize, DeserializeOwned, Display, PartialEq, Eq, Hash);
assert_not_impl_any!(RuntimeServer: Clone, Serialize, DeserializeOwned, Display, PartialEq, Eq, Hash);

#[test]
fn secret_bytes_require_explicit_borrow_and_redact_debug() {
    let secret = SecretBytes::new(b"symmetric-secret-value".to_vec());

    assert_eq!(secret.expose_secret(), b"symmetric-secret-value");
    assert_eq!(format!("{secret:?}"), "SecretBytes(<redacted>)");
    assert!(!format!("{secret:?}").contains("symmetric-secret-value"));
}

#[test]
fn secret_bearing_aggregate_debug_redacts_all_material() {
    let credential = ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
        public_key_format: None,
        public_key: None,
        private_key_format: tacacsrs_config::crypto_types::PrivateKeyFormat::OneAsymmetricKeyFormat,
        certificate: PublicBytes::new(b"public-certificate-value".to_vec()),
        private_key: SecretBytes::new(b"private-key-value".to_vec()),
    });

    let debug = format!("{credential:?}");
    assert!(debug.contains("CertificateWithKey"));
    assert!(debug.contains("length: 24"));
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("public-certificate-value"));
    assert!(!debug.contains("private-key-value"));
}

#[test]
fn closed_result_debug_omits_secret_and_reference_values() {
    let parsed = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "safety-server",
                    "server-type": "accounting",
                    "address": "192.0.2.15",
                    "port": 49,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "opaque-central-reference",
                            "external-identity": "client"
                        }
                    }
                }]
            }
        }"#,
    )
    .expect("central EPSK config");
    let plan = tacacsrs_credential_resolution::ResolutionPlan::from_server(&parsed.server[0])
        .expect("resolution plan");
    let response = ResolvedResponse::new(
        plan.requests()[0].slot(),
        ResolvedCredential::SymmetricKey(SymmetricKeyMaterial {
            key_format: None,
            key: SecretBytes::new(b"resolved-symmetric-secret".to_vec()),
        }),
    );
    let response_debug = format!("{response:?}");
    assert!(response_debug.contains("SymmetricKey"));
    assert!(!response_debug.contains("resolved-symmetric-secret"));

    let result = ResolvedCredentialSet::from_responses(&plan, [response])
        .expect("closed result set should match the plan");
    assert_eq!(
        result
            .credential(plan.requests()[0].slot())
            .expect("resolved credential")
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
