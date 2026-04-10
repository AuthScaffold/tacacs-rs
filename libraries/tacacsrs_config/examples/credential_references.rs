use tacacsrs_config::{
    parse_yang_json, resolve_server, resolve_servers, validate_credential_references,
    CredentialResolver, TacacsPlusServerType,
};

/// Simple reference resolver that copies credentials within the same config
struct LocalReferenceResolver;

impl CredentialResolver for LocalReferenceResolver {
    fn resolve_keystore_certificate(
        &self,
        _key: &str,
    ) -> anyhow::Result<Option<tacacsrs_config::X509CertificateMaterial>> {
        Ok(Some(tacacsrs_config::X509CertificateMaterial {
            cert_data: "RESOLVED_CERT_DATA".to_string(),
            key_material: tacacsrs_config::AsymmetricKeyMaterial {
                cleartext_private_key: "RESOLVED_PRIVATE_KEY".to_string(),
                public_key: Some("RESOLVED_PUBLIC_KEY".to_string()),
                private_key_format: Some(
                    tacacsrs_config::crypto_types::PrivateKeyFormat::OneAsymmetricKeyFormat,
                ),
                public_key_format: Some(
                    tacacsrs_config::crypto_types::PublicKeyFormat::SubjectPublicKeyInfoFormat,
                ),
            },
        }))
    }

    fn resolve_certificate_bag(
        &self,
        _key: &str,
    ) -> anyhow::Result<Option<Vec<tacacsrs_config::CertificateEntry>>> {
        Ok(Some(vec![
            tacacsrs_config::CertificateEntry {
                name: "root-ca".to_string(),
                cert_data: "RESOLVED_ROOT_CA".to_string(),
            },
            tacacsrs_config::CertificateEntry {
                name: "intermediate-ca".to_string(),
                cert_data: "RESOLVED_INTERMEDIATE_CA".to_string(),
            },
        ]))
    }

    fn resolve_asymmetric_key(
        &self,
        _key: &str,
    ) -> anyhow::Result<Option<tacacsrs_config::AsymmetricKeyMaterial>> {
        // In a real implementation, this would fetch the full asymmetric key
        // entry (private key, public key, and format identities) from a
        // central keystore.
        Ok(Some(tacacsrs_config::AsymmetricKeyMaterial {
            cleartext_private_key: "RESOLVED_PRIVATE_KEY".to_string(),
            public_key: Some("RESOLVED_PUBLIC_KEY".to_string()),
            private_key_format: Some(
                tacacsrs_config::crypto_types::PrivateKeyFormat::OneAsymmetricKeyFormat,
            ),
            public_key_format: Some(
                tacacsrs_config::crypto_types::PublicKeyFormat::SubjectPublicKeyInfoFormat,
            ),
        }))
    }

    fn resolve_symmetric_key(
        &self,
        _key: &str,
    ) -> anyhow::Result<Option<tacacsrs_config::SymmetricKeyMaterial>> {
        // In a real implementation, this would fetch the symmetric key
        // entry (key material and format identity) from a central keystore.
        Ok(Some(tacacsrs_config::SymmetricKeyMaterial {
            cleartext_symmetric_key: "RESOLVED_SYMMETRIC_KEY".to_string(),
            key_format: Some(
                tacacsrs_config::crypto_types::SymmetricKeyFormat::OctetStringKeyFormat,
            ),
        }))
    }

    fn resolve_public_key_bag(
        &self,
        _key: &str,
    ) -> anyhow::Result<Option<Vec<tacacsrs_config::TruststorePublicKeyMaterial>>> {
        Ok(Some(vec![tacacsrs_config::TruststorePublicKeyMaterial {
            name: "resolved-pk".to_string(),
            public_key: "RESOLVED_PUBLIC_KEY".to_string(),
            public_key_format:
                tacacsrs_config::crypto_types::PublicKeyFormat::SubjectPublicKeyInfoFormat,
        }]))
    }

    fn validate_keystore_certificate(&self, _key: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_asymmetric_key(&self, _key: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_symmetric_key(&self, _key: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_certificate_bag(&self, _key: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn validate_public_key_bag(&self, _key: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

fn main() -> anyhow::Result<()> {
    let json = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "client-credentials": [
                {
                    "id": "bundle-with-external-rpk",
                    "raw-private-key": {
                        "central-keystore-reference": "ks:client-rpk"
                    }
                }
            ],
            "server": [
                {
                    "name": "acct-obf-primary",
                    "server-type": "accounting",
                    "address": "192.0.2.44",
                    "port": 49,
                    "shared-secret": "accounting-shared-secret"
                },
                {
                    "name": "authz-tls-by-reference",
                    "server-type": "authorization",
                    "address": "192.0.2.45",
                    "port": 49,
                    "client-identity": {
                        "credentials-reference": "bundle-with-external-rpk"
                    }
                }
            ]
        }
    }"#;

    // Parse YANG config (preserves credential references in the raw model)
    let config = parse_yang_json(json, Some(&LocalReferenceResolver))?;
    println!("📄 Parsed YANG config — raw model preserved, credential references intact");

    // Validate all credential references upfront
    validate_credential_references(&config, Some(&LocalReferenceResolver))?;
    println!("✅ All credential references validated successfully\n");

    // Named resolution: resolve a specific server by name.
    let named = resolve_server(&config, "authz-tls-by-reference", Some(&LocalReferenceResolver))?;

    let rpk_inline = named
        .client_identity
        .as_ref()
        .and_then(|ci| ci.raw_private_key.as_ref())
        .and_then(|rpk| rpk.inline_definition.as_ref())
        .and_then(|inline| inline.cleartext_private_key.as_deref())
        .expect("resolved server should include inline private key material");

    assert_eq!(rpk_inline, "RESOLVED_MATERIAL");

    // Enumeration approach: resolve all servers, then pick by server-type bitflag.
    let resolved_servers = resolve_servers(&config, Some(&LocalReferenceResolver))?;
    let accounting = resolved_servers
        .iter()
        .find(|s| s.server_type.contains(TacacsPlusServerType::ACCOUNTING))
        .expect("expected an accounting server");

    assert_eq!(accounting.name, "acct-obf-primary");
    assert_eq!(accounting.obfuscation_key(), Some(b"accounting-shared-secret".to_vec()));

    // Raw model serialization keeps full values for round-trip fidelity.
    let raw_json = serde_json::to_string_pretty(&config)?;
    assert!(raw_json.contains("\"credentials-reference\": \"bundle-with-external-rpk\""));
    assert!(raw_json.contains("\"shared-secret\": \"accounting-shared-secret\""));

    // Each raw server entry is untransformed: credential references are still
    // symbolic and secrets appear in plaintext, exactly as parsed from config.
    println!("🗂️  Raw server entries — untransformed, as parsed from config:");
    println!("    (symbolic references and plaintext secrets are both visible here)");
    for server in &config.server {
        println!("\n  ┌─ raw: '{}'", server.name);
        for line in format!("{server:#?}").lines() {
            println!("  │  {line}");
        }
        println!("  └─");
    }

    // ResolvedServer intentionally does not implement Serialize, preventing
    // accidental serialization of resolved key material. The Debug impl
    // redacts secrets so it is safe for logging and diagnostics.
    let named_debug = format!("{named:#?}");
    let accounting_debug = format!("{accounting:#?}");

    assert!(named_debug.contains("<redacted>"));
    assert!(accounting_debug.contains("<redacted>"));
    assert!(!named_debug.contains("RESOLVED_MATERIAL"));
    assert!(!accounting_debug.contains("accounting-shared-secret"));

    // Original reference still exists in raw config — round-trip safe
    let raw = config
        .server
        .iter()
        .find(|s| s.name == "authz-tls-by-reference")
        .expect("server must exist");

    assert!(raw
        .client_identity
        .as_ref()
        .and_then(|ci| ci.credentials_reference.as_ref())
        .is_some());

    println!("\n🔐 Resolved server entries — secrets materialized for use, safe for logging:");
    println!("    (ResolvedServer does not implement Serialize; Debug redacts sensitive fields)");

    println!("\n  ┌─ resolved by name: '{}'", named.name);
    for line in named_debug.lines() {
        println!("  │  {line}");
    }
    println!("  └─");

    println!("\n  ┌─ resolved by server-type (ACCOUNTING): '{}'", accounting.name);
    for line in accounting_debug.lines() {
        println!("  │  {line}");
    }
    println!("  └─");

    println!("\n🔁 Round-trip check: raw config is still unchanged ({} bytes)", raw_json.len());
    println!(
        "    '{}' still carries its symbolic credentials-reference — not mutated by resolution",
        raw.name
    );
    println!(
        "\n✨ Done — resolved variants hold live secret material and are ready for direct use"
    );

    Ok(())
}
