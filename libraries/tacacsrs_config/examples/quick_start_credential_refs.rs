use tacacsrs_config::{parse_yang_json, resolve_server, validate_credential_references};

fn main() -> anyhow::Result<()> {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "client-bundle-1",
                    "certificate": {
                        "inline-definition": {
                            "cert-data": "dGVzdC1jZXJ0",
                            "cleartext-private-key": "dGVzdC1rZXk="
                        }
                    }
                }
            ],
            "server-credentials": [
                {
                    "id": "server-bundle-1",
                    "ca-certs": {
                        "inline-definition": {
                            "certificate": [
                                { "name": "ca-main", "cert-data": "dGVzdC1jZXJ0" }
                            ]
                        }
                    }
                }
            ],
            "server": [
                {
                    "name": "primary",
                    "server-type": "authentication accounting",
                    "domain-name": "tacacs.example.net",
                    "sni-enabled": true,
                    "address": "192.0.2.10",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "client-bundle-1"
                    },
                    "server-authentication": {
                        "credentials-reference": "server-bundle-1"
                    }
                }
            ]
        }
    }"#;

    // Parse raw config without destructively resolving references
    let config = parse_yang_json(json, None)?;
    println!("📄 Parsed config with reusable client/server credential bundles");

    // Validate all credential references upfront (None = no external resolver needed)
    validate_credential_references(&config, None)?;
    println!("✅ Bundle references are valid\n");

    // Resolve a specific server — bundle references are materialized inline
    let resolved = resolve_server(&config, "primary", None)?;

    let client_identity = resolved
        .client_identity
        .as_ref()
        .expect("resolved server should have client identity");
    let cert = client_identity
        .certificate
        .as_ref()
        .expect("certificate should be materialized from bundle");
    let inline = cert
        .inline_definition
        .as_ref()
        .expect("certificate inline definition should be present");

    assert_eq!(inline.cert_data.as_deref(), Some("dGVzdC1jZXJ0"));
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("dGVzdC1rZXk="));

    println!("🔐 Resolved server '{}'", resolved.name);
    println!("  ├─ endpoint: {}", resolved.socket_address());
    println!("  ├─ is_tls: {}", resolved.is_tls());
    println!("  ├─ bundle reference cleared: {}", client_identity.credentials_reference.is_none());
    println!("  └─ inline certificate + private key are now present on the resolved value");

    Ok(())
}
