use tacacsrs_config::crypto_types::{PrivateKeyFormat, PublicKeyFormat};
use tacacsrs_config::{enumerate_server, parse_yang_json};
use tacacsrs_credential_resolution::{
    CertificateBagMaterial, CertificateWithKeyMaterial, CredentialKind, FakeCredentialResolver,
    NamedCertificateMaterial, PublicBytes, ResolutionPlan, ResolvedCredential, SecretBytes,
    resolve_plan,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_yang_json(
        r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "client-credentials": [{
                    "id": "central-client",
                    "certificate": {
                        "central-keystore-reference": {
                            "asymmetric-key": "provider-defined-key-reference",
                            "certificate": "provider-defined-certificate-reference"
                        }
                    }
                }],
                "server": [{
                    "name": "primary",
                    "server-type": "accounting",
                    "address": "192.0.2.30",
                    "port": 49,
                    "client-identity": {"credentials-reference": "central-client"},
                    "server-authentication": {
                        "ca-certs": {
                            "central-truststore-reference": "provider-defined-ca-reference"
                        }
                    }
                }]
            }
        }"#,
    )?;
    let server = enumerate_server(&config, "primary")?;
    let plan = ResolutionPlan::from_server(&server)?;

    assert_eq!(plan.requests().len(), 2);
    assert_eq!(plan.requests()[0].kind(), CredentialKind::CertificateWithKey);
    assert_eq!(plan.requests()[1].kind(), CredentialKind::CaCertificateBag);

    let resolver = FakeCredentialResolver::new()
        .with_response(
            plan.requests()[0].slot(),
            ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
                public_key_format: Some(PublicKeyFormat::SubjectPublicKeyInfoFormat),
                public_key: Some(PublicBytes::new(b"example public key bytes".to_vec())),
                private_key_format: PrivateKeyFormat::OneAsymmetricKeyFormat,
                certificate: PublicBytes::new(b"example certificate bytes".to_vec()),
                private_key: SecretBytes::new(b"example private key bytes".to_vec()),
            }),
        )
        .with_response(
            plan.requests()[1].slot(),
            ResolvedCredential::CaCertificateBag(CertificateBagMaterial {
                certificates: vec![NamedCertificateMaterial {
                    name: "example-ca".to_owned(),
                    certificate: PublicBytes::new(b"example CA certificate bytes".to_vec()),
                }],
            }),
        );
    let result_set = resolve_plan(&plan, &resolver).await?;

    let ResolvedCredential::CertificateWithKey(client_identity) = result_set
        .credential(plan.requests()[0].slot())
        .expect("client identity credential must exist")
    else {
        unreachable!("the closed result set already validated the credential variant");
    };
    assert!(!client_identity.private_key.expose_secret().is_empty());
    println!("resolved {} credential slots", result_set.len());

    Ok(())
}
