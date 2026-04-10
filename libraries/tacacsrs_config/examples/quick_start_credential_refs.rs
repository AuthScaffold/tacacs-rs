use tacacsrs_config::{parse_yang_json, resolve_server, validate_credential_references};

fn main() -> anyhow::Result<()> {
    let json = r#"{
        \"ietf-system-tacacs-plus:tacacs-plus\": {
            \"client-credentials\": [
                {
                    \"id\": \"client-bundle-1\",
                    \"certificate\": {
                        \"inline-definition\": {
                            \"cert-data\": \"CLIENT_CERT_PEM\",
                            \"cleartext-private-key\": \"CLIENT_KEY_PEM\"
                        }
                    }
                }
            ],
            \"server-credentials\": [
                {
                    \"id\": \"server-bundle-1\",
                    \"ca-certs\": {
                        \"inline-definition\": {
                            \"certificate\": [
                                { \"name\": \"ca-main\", \"cert-data\": \"CA_CERT_PEM\" }
                            ]
                        }
                    }
                }
            ],
            \"server\": [
                {
                    \"name\": \"primary\",
                    \"server-type\": \"authentication accounting\",
                    \"domain-name\": \"tacacs.example.net\",
                    \"sni-enabled\": true,
                    \"address\": \"192.0.2.10\",
                    \"port\": 49,
                    \"client-identity\": {
                        \"credentials-reference\": \"client-bundle-1\"
                    },
                    \"server-authentication\": {
                        \"credentials-reference\": \"server-bundle-1\"
                    }
                }
            ]
        }
    }"#;

    // Parse raw config without destructively resolving references
    let config = parse_yang_json(json)?;

    // Validate all credential references upfront (None = no external resolver needed)
    validate_credential_references(&config, None)?;

    // Resolve a specific server — bundle references are materialized inline
    let resolved = resolve_server(&config, "primary", None)?;

    println!("Server '{}' resolved successfully", resolved.name);
    println!("  endpoint: {}", resolved.socket_address());
    println!("  is_tls: {}", resolved.is_tls());

    Ok(())
}
