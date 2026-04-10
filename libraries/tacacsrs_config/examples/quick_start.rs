use tacacsrs_config::{parse_yang_json, resolve_servers};

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
    let config = parse_yang_json(json, None)?;
    println!("📄 Parsed one TACACS+ server from YANG JSON");

    // Resolve servers (None = no external keystore/truststore resolver needed)
    let servers = resolve_servers(&config, None)?;
    println!("✅ Resolved runtime-ready server entries\n");

    for server in &servers {
        println!("  ┌─ server: '{}'", server.name);
        println!("  │  endpoint: {}", server.socket_address());
        println!("  │  single_connection: {}", server.single_connection);
        println!("  │  timeout: {:?}", server.timeout_duration());
        println!("  │  transport: {}", if server.is_tls() { "TLS" } else { "obfuscation" });
        println!("  └─");
    }

    Ok(())
}
