use tacacsrs_config::{model, parse_yang_json};

fn main() -> anyhow::Result<()> {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "authz-obf",
                    "server-type": "authorization",
                    "address": "198.51.100.25",
                    "port": 49,
                    "shared-secret": "obfuscation-secret"
                }
            ]
        }
    }"#;

    // Parse YANG config without credential resolution
    let config = parse_yang_json(json, None)?;
    let server = &config.server[0];

    println!("name={} address={} port={}", server.name, server.address, server.port);

    if server
        .server_type
        .contains(model::TacacsPlusServerType::AUTHORIZATION)
    {
        println!("server-type includes authorization");
    }

    Ok(())
}
