use tacacsrs_config::{enumerate_servers, parse_yang_json};

fn main() -> anyhow::Result<()> {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "primary",
                    "server-type": "authentication authorization accounting",
                    "address": "192.0.2.10",
                    "port": 49,
                    "shared-secret": "supersecret",
                    "timeout": 10
                }
            ]
        }
    }"#;

    // Parse YANG config
    let config = parse_yang_json(json)?;
    println!("📄 Parsed one TACACS+ server from YANG JSON");

    // Enumerate servers (bundle references are materialized inline when present)
    let servers = enumerate_servers(&config)?;
    println!("✅ Enumerated per-server config entries\n");

    for server in &servers {
        println!("  ┌─ server: '{}'", server.name);
        println!("  │  endpoint: {}:{}", server.address, server.port);
        println!("  │  single_connection: {}", server.single_connection);
        println!("  │  timeout: {}s", server.timeout);
        println!(
            "  │  transport: {}",
            if server.client_identity.is_some()
                || server.server_authentication.is_some()
                || server.hello_params.is_some()
            {
                "TLS"
            } else {
                "obfuscation"
            }
        );
        println!("  └─");
    }

    Ok(())
}
