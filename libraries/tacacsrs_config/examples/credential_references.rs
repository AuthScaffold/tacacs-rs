use tacacsrs_config::{
    parse_yang_json, validate_credential_references, CredentialResolver, CredentialRefType,
};

/// Simple reference resolver that copies credentials within the same config
struct LocalReferenceResolver;

impl CredentialResolver for LocalReferenceResolver {
    fn resolve(&self, _key: &str, _ref_type: CredentialRefType) -> anyhow::Result<Option<String>> {
        // In a real implementation, this would look up the credential from the config
        // For this example, we just return None to show validation
        Ok(None)
    }

    fn validate(&self, _key: &str, _ref_type: CredentialRefType) -> anyhow::Result<()> {
        // In a real implementation, this would check if credentials exist
        Ok(())
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
            \"server\": [
                {
                    \"name\": \"tls-by-reference\",
                    \"server-type\": \"authentication\",
                    \"address\": \"192.0.2.44\",
                    \"port\": 49,
                    \"client-identity\": {
                        \"credentials-reference\": \"client-bundle-1\"
                    }
                }
            ]
        }
    }"#;

    // Parse YANG config (preserves credential references)
    let config = parse_yang_json(json)?;

    // Validate all credential references upfront
    validate_credential_references(&config, Some(&LocalReferenceResolver))?;

    // Get resolved server on-demand (would materialize credentials)
    // let resolved = get_resolved_server(&config, "tls-by-reference", &resolvers)?;

    // Raw config remains unchanged - safe for round-tripping
    let server = &config.server[0];
    println!("server: {} has credentials_reference at path client-identity", server.name);

    // Original reference still exists in raw config
    assert!(server
        .client_identity
        .as_ref()
        .and_then(|ci| ci.credentials_reference.as_ref())
        .is_some());

    println!("Raw config preserved for round-tripping");

    Ok(())
}
