use tacacsrs_config::parse_yang_json;

fn main() -> anyhow::Result<()> {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "acct-tls",
                    "server-type": "accounting",
                    "domain-name": "tacacs.example.net",
                    "sni-enabled": true,
                    "address": "203.0.113.20",
                    "port": 49,
                    "client-identity": {
                        "certificate": {
                            "inline-definition": {
                                "cert-data": "dGVzdC1jZXJ0",
                                "cleartext-private-key": "dGVzdC1rZXk="
                            }
                        }
                    },
                    "server-authentication": {
                        "ca-certs": {
                            "inline-definition": {
                                "certificate": [
                                    { "name": "ca-main", "cert-data": "dGVzdC1jZXJ0" }
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
    println!("🧪 Pipeline flow example");
    println!("1. Parsed YANG JSON into the raw model\n");

    // Step 2: Access raw YANG model structure
    let server = &config.server[0];
    println!("2. Inspected the raw server entry:");
    println!("   ├─ name: {}", server.name);
    println!("   ├─ address: {}:{}", server.address, server.port);
    println!("   ├─ has client-identity: {}", server.client_identity.is_some());
    println!("   └─ has server-authentication: {}", server.server_authentication.is_some());

    // Step 3: For production code:
    // 1. Call enumerate_server(s) to inline shared credential bundles.
    // 2. Use tacacsrs-credentials to validate external refs if needed.
    // 3. Use tacacsrs-credentials to resolve one enumerated server when connecting.
    println!("\n3. Production flow: enumerate bundles, then resolve external secrets on demand when connecting");

    Ok(())
}
