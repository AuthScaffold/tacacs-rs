use tacacsrs_config::{parse_yang_json, runtime};

fn main() -> anyhow::Result<()> {
    let json = r#"{
        \"ietf-system-tacacs-plus:tacacs-plus\": {
            \"server\": [
                {
                    \"name\": \"primary\",
                    \"server-type\": \"authentication authorization accounting\",
                    \"address\": \"192.0.2.10\",
                    \"port\": 49,
                    \"shared-secret\": \"supersecret\",
                    \"timeout\": 10
                }
            ]
        }
    }"#;

    // Parse YANG config
    let config = parse_yang_json(json)?;

    // Map to runtime connection configs
    let servers = runtime::to_connection_configs(&config)?;

    for server in &servers {
        println!(
            "server={} endpoint={} single_connection={} timeout={:?}",
            server.name,
            server.socket_address(),
            server.single_connection,
            server.timeout
        );
    }

    Ok(())
}
