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

    // Step 1: Parse the YANG configuration without changing it.
    let config = parse_yang_json(json)?;
    println!("🧪 Pipeline flow example");
    println!("1. Parsed YANG JSON into the raw model\n");

    // Step 2: Read the YANG model structure.
    let server = &config.server[0];
    println!("2. Inspected the raw server entry:");
    println!("   ├─ name: {}", server.name);
    println!("   ├─ address: {}:{}", server.address, server.port);
    println!("   ├─ has client-identity: {}", server.client_identity.is_some());
    println!("   └─ has server-authentication: {}", server.server_authentication.is_some());

    // Step 3: Use this sequence in production:
    // 1. Call enumerate_server(s) to inline shared credential bundles.
    // 2. Materialize the plan, resolving central credential references through
    //    the provider boundary (for example the SONiC or HTTP adapter crates).
    // 3. Prepare the materialized server into a native endpoint, then connect.
    println!("\n3. Production flow: enumerate bundles, resolve central references through the provider boundary, then materialize and prepare the endpoint");

    Ok(())
}
