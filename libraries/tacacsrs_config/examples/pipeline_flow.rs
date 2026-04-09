use tacacsrs_config::parse_yang_json;

fn main() -> anyhow::Result<()> {
    let json = r#"{
        \"ietf-system-tacacs-plus:tacacs-plus\": {
            \"server\": [
                {
                    \"name\": \"acct-tls\",
                    \"server-type\": \"accounting\",
                    \"domain-name\": \"tacacs.example.net\",
                    \"sni-enabled\": true,
                    \"address\": \"203.0.113.20\",
                    \"port\": 49,
                    \"client-identity\": {
                        \"certificate\": {
                            \"inline-definition\": {
                                \"cert-data\": \"CLIENT_CERT_PEM\",
                                \"cleartext-private-key\": \"CLIENT_KEY_PEM\"
                            }
                        }
                    },
                    \"server-authentication\": {
                        \"ca-certs\": {
                            \"inline-definition\": {
                                \"certificate\": [
                                    { \"name\": \"ca-main\", \"cert-data\": \"CA_CERT_PEM\" }
                                ]
                            }
                        }
                    }
                }
            ]
        }
    }"#;

    // Step 1: Parse YANG config (non-destructive - preserves original for round-tripping)
    let config = parse_yang_json(json)?;

    // Step 2: Access raw YANG model structure
    let server = &config.server[0];
    println!("Server name: {}", server.name);
    println!("Address: {}:{}", server.address, server.port);
    println!("Has client-identity: {}", server.client_identity.is_some());
    println!("Has server-authentication: {}", server.server_authentication.is_some());

    // Step 3: For production code:
    // 1. Create resolvers implementing CredentialResolver trait
    // 2. Call validate_credential_references(&config, &resolvers)?
    // 3. Call get_resolved_server(&config, server_name, &resolvers)? for on-demand resolution
    // This avoids destructive modifications and supports round-tripping

    Ok(())
}
