use tacacsrs_config::{
    parse_yang_json, validate_credential_references, get_resolved_server, CredentialResolver,
    CredentialRefType,
};
use anyhow::Result;

/// Example resolver that handles in-config credential bundles.
/// In a real application, this would look up credentials from the config's
/// client-credentials and server-credentials lists.
struct BundleResolver;

impl CredentialResolver for BundleResolver {
    fn resolve(&self, _key: &str, ref_type: CredentialRefType) -> Result<Option<String>> {
        // Only handle bundle references; return None for keystore/truststore refs
        match ref_type {
            CredentialRefType::ClientCredential | CredentialRefType::ServerCredential => {
                // In a real implementation, look up in config.client_credentials or config.server_credentials
                // For now, this is a placeholder
                Ok(None)
            }
            _ => Ok(None), // This resolver doesn't handle keystore/truststore refs
        }
    }
}

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

    // Set up credential resolvers
    let resolvers: Vec<Box<dyn CredentialResolver>> = vec![Box::new(BundleResolver)];

    // Validate all credential references upfront
    validate_credential_references(&config, &resolvers)?;

    // Get a resolved view of a specific server (credentials materialized on-demand)
    let _resolved_server = get_resolved_server(&config, "primary", &resolvers)?;

    println!("Config validated and server resolved successfully");
    println!("Raw config remains unchanged and safe for round-tripping");

    Ok(())
}
