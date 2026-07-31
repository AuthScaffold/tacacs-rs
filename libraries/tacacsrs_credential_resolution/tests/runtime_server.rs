use tacacsrs_config::parse_yang_json;
use tacacsrs_credential_resolution::{
    FakeCredentialResolver, ResolutionErrorKind, ResolvedCredential, RuntimeServer, SecretBytes,
};

fn central_server() -> tacacsrs_config::TacacsPlusServer {
    parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [{
                    "name": "runtime-test",
                    "server-type": "accounting",
                    "address": "192.0.2.60",
                    "port": 449,
                    "client-identity": {
                        "tls13-epsk": {
                            "central-keystore-reference": "opaque-runtime-reference",
                            "external-identity": "client"
                        }
                    }
                }]
            }
        }"#,
    )
    .expect("central server")
    .server
    .remove(0)
}

#[tokio::test]
async fn resolved_runtime_keeps_reference_and_secret_in_separate_surfaces() {
    let server = central_server();
    let plan = tacacsrs_credential_resolution::ResolutionPlan::from_server(&server)
        .expect("resolution plan");
    let resolver = FakeCredentialResolver::new().with_response(
        plan.requests()[0].slot(),
        ResolvedCredential::SymmetricKey(SecretBytes::new(b"runtime-secret-value".to_vec())),
    );

    let runtime = RuntimeServer::resolve(server, &resolver)
        .await
        .expect("resolved runtime");
    let epsk = runtime
        .config()
        .client_identity
        .as_ref()
        .and_then(|identity| identity.tls13_epsk.as_ref())
        .expect("EPSK config");
    assert!(epsk.inline_definition.is_none());
    assert_eq!(epsk.central_keystore_reference.as_deref(), Some("opaque-runtime-reference"));
    assert_eq!(
        runtime
            .tls13_epsk_secret()
            .expect("resolved secret")
            .expose_secret(),
        b"runtime-secret-value"
    );

    let debug = format!("{runtime:?}");
    assert!(!debug.contains("opaque-runtime-reference"));
    assert!(!debug.contains("runtime-secret-value"));
    let serialized = serde_json::to_string(runtime.config()).expect("generated config serializes");
    assert!(serialized.contains("opaque-runtime-reference"));
    assert!(!serialized.contains("runtime-secret-value"));
}

#[test]
fn inline_runtime_rejects_unresolved_central_requests() {
    let error = RuntimeServer::inline(central_server()).expect_err("resolution is required");
    assert_eq!(error.kind(), ResolutionErrorKind::ResolutionRequired);
    assert!(!error.to_string().contains("opaque-runtime-reference"));
}
