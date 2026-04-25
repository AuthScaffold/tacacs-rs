use tacacsrs_config::{enumerate_server, parse_yang_json};

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
    let config = parse_yang_json(json)?;
    println!("📄 Parsed config with reusable client/server credential bundles");

    // Enumerate a specific server — shared bundle references are materialized inline
    let resolved = enumerate_server(&config, "primary")?;
    println!("✅ Bundle references enumerated inline\n");

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

    assert_eq!(inline.cert_data.as_deref(), Some(b"test-cert".as_slice()));
    assert_eq!(inline.cleartext_private_key.as_deref(), Some(b"test-key".as_slice()),);

    println!("🔐 Enumerated server '{}'", resolved.name);
    println!("  ├─ endpoint: {}:{}", resolved.address, resolved.port);
    println!(
        "  ├─ is_tls: {}",
        resolved.client_identity.is_some() || resolved.server_authentication.is_some()
    );
    println!("  ├─ bundle reference cleared: {}", client_identity.credentials_reference.is_none());
    println!("  └─ inline certificate + private key are now present on the enumerated value");

    Ok(())
}
