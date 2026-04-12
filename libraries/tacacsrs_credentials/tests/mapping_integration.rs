use std::time::Duration;

use anyhow::Result;

use tacacsrs_config::keystore::{AsymmetricKeyInlineDefinition, EndEntityCertWithKeyInlineDefinition};
use tacacsrs_config::tls_common::{HelloParamsTlsVersions, TlsVersionBase};
use tacacsrs_config::truststore::{CertsCertificate, CertsInlineDefinition};
use tacacsrs_config::{
    ClientCredentials, ClientIdentityCertificate, RawPrivateKey, ServerAuthenticationCaCerts,
    ServerCredentials, TacacsPlus, TacacsPlusServer, TacacsPlusServerType, TlsClientClientIdentity,
    TlsClientHelloParams, TlsClientServerAuthentication,
};
use tacacsrs_credentials::{
    AsymmetricKeyMaterial, CertificateEntry, CredentialResolver, ResolvedServer,
    SymmetricKeyMaterial, TruststorePublicKeyMaterial, X509CertificateMaterial,
};

fn resolve_servers(
    config: &TacacsPlus,
    resolver: Option<&dyn CredentialResolver>,
) -> Result<Vec<ResolvedServer>> {
    let enumerated_servers = tacacsrs_config::enumerate_servers(config)?;
    tacacsrs_credentials::resolve_servers(enumerated_servers, resolver)
}

fn validate_credential_references(
    config: &TacacsPlus,
    resolver: Option<&dyn CredentialResolver>,
) -> Result<()> {
    tacacsrs_config::validate_credential_references(config)?;
    let enumerated_servers = tacacsrs_config::enumerate_servers(config)?;
    tacacsrs_credentials::validate_external_servers_references(&enumerated_servers, resolver)
}

fn config_with_all(
    client_credentials: Vec<ClientCredentials>,
    server_credentials: Vec<ServerCredentials>,
    server: Vec<TacacsPlusServer>,
) -> TacacsPlus {
    TacacsPlus {
        client_credentials,
        server_credentials,
        server,
    }
}

fn config_with_servers(server: Vec<TacacsPlusServer>) -> TacacsPlus {
    config_with_all(vec![], vec![], server)
}

fn bare_server(name: &str, address: &str, port: u16) -> TacacsPlusServer {
    TacacsPlusServer {
        name: name.to_owned(),
        server_type: TacacsPlusServerType::ACCOUNTING,
        address: address.to_owned(),
        port,
        timeout: 5,
        ..default_bare_server()
    }
}

fn obfuscation_server(name: &str, address: &str, port: u16, secret: &str) -> TacacsPlusServer {
    let mut server = bare_server(name, address, port);
    server.shared_secret = Some(secret.to_owned());
    server
}

fn with_timeout(mut server: TacacsPlusServer, timeout: u16) -> TacacsPlusServer {
    server.timeout = timeout;
    server
}

fn with_domain_name(mut server: TacacsPlusServer, domain_name: &str) -> TacacsPlusServer {
    server.domain_name = Some(domain_name.to_owned());
    server
}

fn with_sni_enabled(mut server: TacacsPlusServer, sni_enabled: bool) -> TacacsPlusServer {
    server.sni_enabled = Some(sni_enabled);
    server
}

fn with_client_identity(
    mut server: TacacsPlusServer,
    client_identity: TlsClientClientIdentity,
) -> TacacsPlusServer {
    server.client_identity = Some(client_identity);
    server
}

fn with_server_authentication(
    mut server: TacacsPlusServer,
    server_authentication: TlsClientServerAuthentication,
) -> TacacsPlusServer {
    server.server_authentication = Some(server_authentication);
    server
}

fn with_hello_params(
    mut server: TacacsPlusServer,
    hello_params: TlsClientHelloParams,
) -> TacacsPlusServer {
    server.hello_params = Some(hello_params);
    server
}

fn client_identity_reference(credentials_reference: &str) -> TlsClientClientIdentity {
    TlsClientClientIdentity {
        credentials_reference: Some(credentials_reference.to_owned()),
        certificate: None,
        raw_private_key: None,
        tls13_epsk: None,
    }
}

fn client_identity_certificate_inline(
    cert_data: &str,
    cleartext_private_key: &str,
) -> TlsClientClientIdentity {
    TlsClientClientIdentity {
        credentials_reference: None,
        certificate: Some(ClientIdentityCertificate {
            inline_definition: Some(EndEntityCertWithKeyInlineDefinition {
                public_key_format: None,
                public_key: None,
                private_key_format: None,
                cleartext_private_key: Some(cleartext_private_key.to_owned()),
                hidden_private_key: None,
                encrypted_private_key: None,
                cert_data: Some(cert_data.to_owned()),
            }),
            central_keystore_reference: None,
        }),
        raw_private_key: None,
        tls13_epsk: None,
    }
}

fn server_authentication_reference(credentials_reference: &str) -> TlsClientServerAuthentication {
    TlsClientServerAuthentication {
        credentials_reference: Some(credentials_reference.to_owned()),
        ca_certs: None,
        ee_certs: None,
        raw_public_keys: None,
        tls13_epsks: None,
    }
}

fn certs_inline(certs: &[(&str, &str)]) -> CertsInlineDefinition {
    CertsInlineDefinition {
        certificate: certs
            .iter()
            .map(|(name, cert_data)| CertsCertificate {
                name: (*name).to_owned(),
                cert_data: (*cert_data).to_owned(),
            })
            .collect(),
    }
}

fn server_authentication_ca_inline(certs: &[(&str, &str)]) -> TlsClientServerAuthentication {
    TlsClientServerAuthentication {
        credentials_reference: None,
        ca_certs: Some(ServerAuthenticationCaCerts {
            inline_definition: Some(certs_inline(certs)),
            central_truststore_reference: None,
        }),
        ee_certs: None,
        raw_public_keys: None,
        tls13_epsks: None,
    }
}

fn server_authentication_ca_truststore(reference: &str) -> TlsClientServerAuthentication {
    TlsClientServerAuthentication {
        credentials_reference: None,
        ca_certs: Some(ServerAuthenticationCaCerts {
            inline_definition: None,
            central_truststore_reference: Some(reference.to_owned()),
        }),
        ee_certs: None,
        raw_public_keys: None,
        tls13_epsks: None,
    }
}

fn server_authentication_ee_inline(certs: &[(&str, &str)]) -> TlsClientServerAuthentication {
    TlsClientServerAuthentication {
        credentials_reference: None,
        ca_certs: None,
        ee_certs: Some(ServerAuthenticationCaCerts {
            inline_definition: Some(certs_inline(certs)),
            central_truststore_reference: None,
        }),
        raw_public_keys: None,
        tls13_epsks: None,
    }
}

fn client_credentials_certificate(
    id: &str,
    cert_data: &str,
    cleartext_private_key: &str,
) -> ClientCredentials {
    ClientCredentials {
        id: id.to_owned(),
        certificate: Some(ClientIdentityCertificate {
            inline_definition: Some(EndEntityCertWithKeyInlineDefinition {
                public_key_format: None,
                public_key: None,
                private_key_format: None,
                cleartext_private_key: Some(cleartext_private_key.to_owned()),
                hidden_private_key: None,
                encrypted_private_key: None,
                cert_data: Some(cert_data.to_owned()),
            }),
            central_keystore_reference: None,
        }),
        raw_private_key: None,
        tls13_epsk: None,
    }
}

fn client_credentials_raw_private_key_inline(
    id: &str,
    cleartext_private_key: &str,
) -> ClientCredentials {
    ClientCredentials {
        id: id.to_owned(),
        certificate: None,
        raw_private_key: Some(RawPrivateKey {
            inline_definition: Some(AsymmetricKeyInlineDefinition {
                public_key_format: None,
                public_key: None,
                private_key_format: None,
                cleartext_private_key: Some(cleartext_private_key.to_owned()),
                hidden_private_key: None,
                encrypted_private_key: None,
            }),
            central_keystore_reference: None,
        }),
        tls13_epsk: None,
    }
}

fn server_credentials_ca_inline(id: &str, certs: &[(&str, &str)]) -> ServerCredentials {
    ServerCredentials {
        id: id.to_owned(),
        ca_certs: Some(ServerAuthenticationCaCerts {
            inline_definition: Some(certs_inline(certs)),
            central_truststore_reference: None,
        }),
        ee_certs: None,
        raw_public_keys: None,
        tls13_epsks: None,
    }
}

fn hello_params_min_tls13() -> TlsClientHelloParams {
    TlsClientHelloParams {
        tls_versions: Some(HelloParamsTlsVersions {
            min: Some(TlsVersionBase::Tls13.as_rfc7951_str().to_owned()),
            max: None,
        }),
        cipher_suites: None,
    }
}

#[test]
fn resolve_servers_resolves_credential_references() {
    let config = config_with_all(
        vec![client_credentials_certificate(
            "corp-cert",
            "dGVzdC1jZXJ0",
            "dGVzdC1rZXk=",
        )],
        vec![server_credentials_ca_inline(
            "corp-ca",
            &[("ca1", "dGVzdC1jZXJ0")],
        )],
        vec![with_server_authentication(
            with_client_identity(
                bare_server("tls_server", "10.0.0.1", 4949),
                client_identity_reference("corp-cert"),
            ),
            server_authentication_reference("corp-ca"),
        )],
    );

    let servers =
        resolve_servers(&config, Some(&PanicResolver)).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);

    let server = &servers[0];
    assert_eq!(server.name, "tls_server");
    assert!(server.is_tls());

    let client_identity = server
        .client_identity
        .as_ref()
        .expect("client_identity should be set");
    assert!(client_identity.credentials_reference.is_none());
    let certificate = client_identity
        .certificate
        .as_ref()
        .expect("certificate should be populated from bundle");
    let inline = certificate
        .inline_definition
        .as_ref()
        .expect("inline should be set");
    assert_eq!(inline.cert_data.as_deref(), Some("dGVzdC1jZXJ0"));
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("dGVzdC1rZXk="));

    let server_authentication = server
        .server_authentication
        .as_ref()
        .expect("server_authentication should be set");
    assert!(server_authentication.credentials_reference.is_none());
    let ca_certs = server_authentication
        .ca_certs
        .as_ref()
        .expect("ca_certs should be populated from bundle");
    let ca_inline = ca_certs
        .inline_definition
        .as_ref()
        .expect("ca inline should be set");
    assert_eq!(ca_inline.certificate.len(), 1);
    assert_eq!(ca_inline.certificate[0].cert_data, "dGVzdC1jZXJ0");
}

#[test]
fn resolve_servers_maps_shared_secret_obfuscation() {
    let config = config_with_servers(vec![obfuscation_server(
        "obf_server",
        "10.0.0.20",
        49,
        "corp-shared-secret",
    )]);

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);

    let server = &servers[0];
    assert_eq!(server.name, "obf_server");
    assert!(server.is_obfuscation());
    assert_eq!(server.shared_secret.as_deref(), Some("corp-shared-secret"));
    assert_eq!(server.obfuscation_key(), Some(b"corp-shared-secret".to_vec()));
}

#[test]
fn socket_address_returns_address_and_port() {
    let config =
        config_with_servers(vec![obfuscation_server("sock", "192.0.2.10", 4049, "secret")]);

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers[0].socket_address(), "192.0.2.10:4049");
}

#[test]
fn resolve_servers_maps_tls_hello_only_server() {
    let config = config_with_servers(vec![with_hello_params(
        bare_server("tls_hello_only", "10.0.0.42", 49),
        hello_params_min_tls13(),
    )]);

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);
    assert!(servers[0].is_tls());
    assert!(servers[0].hello_params.is_some());
}

#[test]
fn resolve_servers_maps_tls_server_auth_only() {
    let config = config_with_servers(vec![with_server_authentication(
        bare_server("sa_only", "10.0.0.50", 49),
        server_authentication_ca_inline(&[("ca1", "Y2EtY2VydA==")]),
    )]);

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);
    assert!(servers[0].is_tls());

    let server_authentication = servers[0]
        .server_authentication
        .as_ref()
        .expect("server_authentication");
    let ca_certs = server_authentication.ca_certs.as_ref().expect("ca_certs");
    let inline = ca_certs.inline_definition.as_ref().expect("inline");
    assert_eq!(inline.certificate.len(), 1);
    assert_eq!(inline.certificate[0].cert_data, "Y2EtY2VydA==");
}

#[test]
fn resolve_servers_maps_none_obfuscation_for_unvalidated_bare_server() {
    let config = config_with_servers(vec![bare_server("bare", "10.0.0.30", 49)]);

    let servers = resolve_servers(&config, None).expect("resolution should succeed");
    assert_eq!(servers.len(), 1);
    assert!(servers[0].is_obfuscation());
    assert!(servers[0].shared_secret.is_none());
}

#[test]
fn resolve_server_wraps_inlined_server_without_external_resolution() {
    let server = TacacsPlusServer {
        name: "raw".to_owned(),
        server_type: TacacsPlusServerType::ACCOUNTING,
        address: "10.0.0.99".to_owned(),
        port: 4949,
        timeout: 30,
        ..default_bare_server()
    };

    let resolved = tacacsrs_credentials::resolve_server(server, None).unwrap();
    assert_eq!(resolved.name, "raw");
    assert_eq!(resolved.port, 4949);
}

#[test]
fn resolved_server_into_inner_returns_original() {
    let server = TacacsPlusServer {
        name: "inner".to_owned(),
        server_type: TacacsPlusServerType::ACCOUNTING,
        address: "10.0.0.98".to_owned(),
        port: 49,
        timeout: 5,
        ..default_bare_server()
    };

    let resolved = tacacsrs_credentials::resolve_server(server, None).unwrap();
    let inner = resolved.into_inner();
    assert_eq!(inner.name, "inner");
    assert_eq!(inner.address, "10.0.0.98");
}

#[test]
fn resolve_server_rejects_client_credentials_reference() {
    let server = with_client_identity(
        bare_server("raw-client-ref", "10.0.0.101", 49),
        client_identity_reference("shared-client-bundle"),
    );

    let error = tacacsrs_credentials::resolve_server(server, None).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("raw-client-ref"), "error: {message}");
    assert!(message.contains("client-identity credentials-reference"), "error: {message}");
}

#[test]
fn resolve_server_rejects_server_credentials_reference() {
    let server = with_server_authentication(
        bare_server("raw-server-ref", "10.0.0.102", 49),
        server_authentication_reference("shared-server-bundle"),
    );

    let error = tacacsrs_credentials::resolve_server(server, None).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("raw-server-ref"), "error: {message}");
    assert!(message.contains("server-authentication credentials-reference"), "error: {message}");
}

#[test]
fn resolved_server_timeout_duration() {
    let config = config_with_servers(vec![with_timeout(
        obfuscation_server("td", "10.0.0.70", 49, "secret"),
        42,
    )]);

    let servers = resolve_servers(&config, None).unwrap();
    assert_eq!(servers[0].timeout_duration(), Duration::from_secs(42));
}

#[test]
fn resolved_server_obfuscation_key_returns_none_without_shared_secret() {
    let config = config_with_servers(vec![bare_server("nokey", "10.0.0.71", 49)]);

    let servers = resolve_servers(&config, None).unwrap();
    assert!(servers[0].obfuscation_key().is_none());
}

#[test]
fn resolved_server_sni_enabled_defaults_to_false() {
    let config = config_with_servers(vec![obfuscation_server("nosni", "10.0.0.72", 49, "secret")]);

    let servers = resolve_servers(&config, None).unwrap();
    assert!(!servers[0].sni_enabled());
}

#[test]
fn resolved_server_sni_enabled_returns_true_when_set() {
    let config = config_with_servers(vec![with_client_identity(
        with_sni_enabled(
            with_domain_name(bare_server("sni", "10.0.0.73", 49), "tacacs.example.com"),
            true,
        ),
        client_identity_certificate_inline("Y2VydA==", "a2V5"),
    )]);

    let servers = resolve_servers(&config, None).unwrap();
    assert!(servers[0].sni_enabled());
}

#[test]
fn resolved_server_debug_redacts_secrets() {
    let config = config_with_servers(vec![with_server_authentication(
        with_client_identity(
            bare_server("debug_test", "10.0.0.74", 49),
            client_identity_certificate_inline("cHJpdmF0ZS1jZXJ0", "cHJpdmF0ZS1rZXk="),
        ),
        server_authentication_ca_inline(&[("ca1", "Y2E=")]),
    )]);

    let servers = resolve_servers(&config, None).unwrap();
    let debug_output = format!("{:?}", servers[0]);
    assert!(debug_output.contains("debug_test"));
    assert!(debug_output.contains("<redacted>"));
    assert!(!debug_output.contains("cHJpdmF0ZS1rZXk="));
    assert!(!debug_output.contains("cHJpdmF0ZS1jZXJ0"));
}

#[test]
fn resolved_server_debug_redacts_shared_secret() {
    let config = config_with_servers(vec![obfuscation_server(
        "debug_obf",
        "10.0.0.75",
        49,
        "SUPER_SECRET_VALUE",
    )]);

    let servers = resolve_servers(&config, None).unwrap();
    let debug_output = format!("{:?}", servers[0]);
    assert!(debug_output.contains("debug_obf"));
    assert!(debug_output.contains("<redacted>"));
    assert!(!debug_output.contains("SUPER_SECRET_VALUE"));
}

struct PanicResolver;

impl CredentialResolver for PanicResolver {
    fn resolve_keystore_certificate(&self, key: &str) -> Result<Option<X509CertificateMaterial>> {
        panic!("resolver should not be called for inline definitions: {key}");
    }

    fn resolve_certificate_bag(&self, key: &str) -> Result<Option<Vec<CertificateEntry>>> {
        panic!("resolver should not be called for inline definitions: {key}");
    }

    fn resolve_asymmetric_key(&self, key: &str) -> Result<Option<AsymmetricKeyMaterial>> {
        panic!("resolver should not be called for inline definitions: {key}");
    }

    fn resolve_symmetric_key(&self, key: &str) -> Result<Option<SymmetricKeyMaterial>> {
        panic!("resolver should not be called for inline definitions: {key}");
    }

    fn resolve_public_key_bag(
        &self,
        key: &str,
    ) -> Result<Option<Vec<TruststorePublicKeyMaterial>>> {
        panic!("resolver should not be called for inline definitions: {key}");
    }

    fn validate_keystore_certificate(&self, key: &str) -> Result<()> {
        panic!("resolver should not be called for inline definitions: {key}");
    }

    fn validate_asymmetric_key(&self, key: &str) -> Result<()> {
        panic!("resolver should not be called for inline definitions: {key}");
    }

    fn validate_symmetric_key(&self, key: &str) -> Result<()> {
        panic!("resolver should not be called for inline definitions: {key}");
    }

    fn validate_certificate_bag(&self, key: &str) -> Result<()> {
        panic!("resolver should not be called for inline definitions: {key}");
    }

    fn validate_public_key_bag(&self, key: &str) -> Result<()> {
        panic!("resolver should not be called for inline definitions: {key}");
    }
}

struct FailingResolver;

impl CredentialResolver for FailingResolver {
    fn resolve_keystore_certificate(&self, key: &str) -> Result<Option<X509CertificateMaterial>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn resolve_certificate_bag(&self, key: &str) -> Result<Option<Vec<CertificateEntry>>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn resolve_asymmetric_key(&self, key: &str) -> Result<Option<AsymmetricKeyMaterial>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn resolve_symmetric_key(&self, key: &str) -> Result<Option<SymmetricKeyMaterial>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn resolve_public_key_bag(
        &self,
        key: &str,
    ) -> Result<Option<Vec<TruststorePublicKeyMaterial>>> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_keystore_certificate(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_asymmetric_key(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_symmetric_key(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_certificate_bag(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }

    fn validate_public_key_bag(&self, key: &str) -> Result<()> {
        Err(anyhow::anyhow!("resolution failed for '{key}'"))
    }
}

#[test]
fn resolve_ee_certs_inline_definition_without_calling_resolver() {
    let config = config_with_servers(vec![with_server_authentication(
        bare_server("inline-ee", "10.0.1.5", 49),
        server_authentication_ee_inline(&[("ee-ref", "EE_CERT_PEM")]),
    )]);

    let servers = resolve_servers(&config, Some(&PanicResolver)).unwrap();
    let server_authentication = servers[0].server_authentication.as_ref().unwrap();
    let ee_certs = server_authentication.ee_certs.as_ref().unwrap();
    assert!(ee_certs.central_truststore_reference.is_none());
    let inline = ee_certs.inline_definition.as_ref().unwrap();
    assert_eq!(inline.certificate.len(), 1);
    assert_eq!(inline.certificate[0].name, "ee-ref");
    assert_eq!(inline.certificate[0].cert_data, "EE_CERT_PEM");
}

#[test]
fn resolve_server_errors_on_failing_truststore_resolver() {
    let config = config_with_servers(vec![with_server_authentication(
        bare_server("fail-ts", "10.0.1.8", 49),
        server_authentication_ca_truststore("bad-ts-ref"),
    )]);

    let error = resolve_servers(&config, Some(&FailingResolver)).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("fail-ts"), "error should name the server: {message}");
    assert!(
        message.contains("resolution failed"),
        "error should include resolver failure: {message}",
    );
}

#[test]
fn resolve_servers_rejects_unenumerated_client_credentials_reference() {
    let server = with_client_identity(
        bare_server("unevaluated-client-ref", "10.0.2.10", 49),
        client_identity_reference("shared-client-bundle"),
    );

    let error = tacacsrs_credentials::resolve_servers(vec![server], None).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("unevaluated-client-ref"), "error: {message}");
    assert!(message.contains("client-identity credentials-reference"), "error: {message}");
}

#[test]
fn resolve_servers_rejects_unenumerated_server_credentials_reference() {
    let server = with_server_authentication(
        bare_server("unevaluated-server-ref", "10.0.2.11", 49),
        server_authentication_reference("shared-server-bundle"),
    );

    let error = tacacsrs_credentials::resolve_servers(vec![server], None).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("unevaluated-server-ref"), "error: {message}");
    assert!(message.contains("server-authentication credentials-reference"), "error: {message}");
}

#[test]
fn validate_credential_references_collects_missing_client_bundle_ref() {
    let config = config_with_servers(vec![with_client_identity(
        bare_server("vcr-client", "10.0.2.1", 49),
        client_identity_reference("nonexistent-client"),
    )]);

    let error = validate_credential_references(&config, None).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("nonexistent-client"), "error: {message}");
    assert!(message.contains("client-identity credentials-reference"), "error: {message}",);
}

#[test]
fn validate_credential_references_collects_missing_server_bundle_ref() {
    let config = config_with_servers(vec![with_server_authentication(
        bare_server("vcr-server", "10.0.2.2", 49),
        server_authentication_reference("nonexistent-server"),
    )]);

    let error = validate_credential_references(&config, None).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("nonexistent-server"), "error: {message}");
    assert!(message.contains("server-authentication credentials-reference"), "error: {message}",);
}

#[test]
fn validate_credential_references_collects_multiple_errors() {
    let config = config_with_servers(vec![
        with_client_identity(
            bare_server("s1", "10.0.2.3", 49),
            client_identity_reference("missing-ci"),
        ),
        with_server_authentication(
            bare_server("s2", "10.0.2.4", 50),
            server_authentication_reference("missing-sa"),
        ),
    ]);

    let error = validate_credential_references(&config, None).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("missing-ci"), "error should mention first ref: {message}",);
    assert!(message.contains("missing-sa"), "error should mention second ref: {message}",);
}

#[test]
fn resolve_bundle_ref_then_inline_raw_private_key() {
    let config = config_with_all(
        vec![client_credentials_raw_private_key_inline(
            "bundle-inline-rpk",
            "FULLY_RESOLVED",
        )],
        vec![],
        vec![with_client_identity(
            bare_server("combo", "10.0.3.1", 49),
            client_identity_reference("bundle-inline-rpk"),
        )],
    );

    let servers = resolve_servers(&config, Some(&PanicResolver)).unwrap();
    let client_identity = servers[0].client_identity.as_ref().unwrap();
    assert!(client_identity.credentials_reference.is_none());
    let raw_private_key = client_identity.raw_private_key.as_ref().unwrap();
    assert!(raw_private_key.central_keystore_reference.is_none());
    let inline = raw_private_key.inline_definition.as_ref().unwrap();
    assert_eq!(inline.cleartext_private_key.as_deref(), Some("FULLY_RESOLVED"));
}

#[test]
fn socket_address_wraps_ipv6_in_brackets() {
    let server = TacacsPlusServer {
        name: "ipv6".to_owned(),
        server_type: TacacsPlusServerType::ACCOUNTING,
        address: "2001:db8::1".to_owned(),
        port: 49,
        timeout: 5,
        ..default_bare_server()
    };

    let resolved = tacacsrs_credentials::resolve_server(server, None).unwrap();
    assert_eq!(resolved.socket_address(), "[2001:db8::1]:49");
}

fn default_bare_server() -> TacacsPlusServer {
    TacacsPlusServer {
        name: String::new(),
        server_type: TacacsPlusServerType::ACCOUNTING,
        address: String::new(),
        port: 49,
        domain_name: None,
        sni_enabled: None,
        single_connection: false,
        timeout: 5,
        source_ip: None,
        source_interface: None,
        shared_secret: None,
        client_identity: None,
        server_authentication: None,
        hello_params: None,
        vrf_instance: None,
    }
}
