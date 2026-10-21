//! Opt-in interoperability checks against the independent tac_plus-ng fixture.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use openssl::x509::X509;

use tacacsrs_config::input::{load_client_certificate, load_client_private_key};
use tacacsrs_config::prepare::{prepare_endpoint, validate_materialized_servers};
use tacacsrs_config::{
    EpskSupportedHash, ServerAuthenticationCaCerts, TacacsPlusServer, TacacsPlusServerBuilder,
    TacacsPlusServerType, TlsClientServerAuthentication, ValidationOptions, ValidationRelaxation,
};
use tacacsrs_config::prepare::PrepareOptions;
use tacacsrs_networking::{TacacsClient};
use tacacsrs_protocol::enumerations::{
    TacacsAccountingStatus, TacacsAuthenticationStatus, TacacsAuthorizationStatus,
};
use tacacsrs_protocol::operations::{
    AccountingOperation, AuthorizationAuthenticationContext, AuthorizationOperation,
    PapAuthenticationOperation,
};
use tacacsrs_protocol::privilege::PrivilegeLevel;
use tacacsrs_secrets::SecretBytes;

/// Public test key from the Compose fixture, not a deployment credential.
const FIXTURE_PSK: &[u8] = &[
    0x1b, 0xa7, 0x99, 0x72, 0x9c, 0x83, 0x01, 0x52, 0xc9, 0x1d, 0x4f, 0xbc, 0xa5, 0x14, 0x99, 0x72,
];

fn certificates() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../lde/containers/config/certificates")
}

fn server(variable: &str, default_port: u16) -> Result<TacacsPlusServerBuilder> {
    let address: SocketAddr = std::env::var(variable)
        .unwrap_or_else(|_| format!("127.0.0.1:{default_port}"))
        .parse()
        .context("invalid interoperability server address")?;
    Ok(TacacsPlusServerBuilder::new(
        "independent-server",
        TacacsPlusServerType::all(),
        address.ip().to_string(),
        address.port(),
    )
    .with_single_connection(true)
    .with_timeout(3))
}

fn trust_store() -> Result<TlsClientServerAuthentication> {
    let ca = X509::from_pem(&std::fs::read(certificates().join("ca.crt"))?)?.to_der()?;
    Ok(TlsClientServerAuthentication {
        require_crls: None,
        require_ocsp: None,
        require_stapled_ocsp: None,
        credentials_reference: None,
        ca_certs: Some(ServerAuthenticationCaCerts {
            inline_definition: Some(tacacsrs_config::truststore::CertsInlineDefinition {
                certificate: vec![tacacsrs_config::truststore::CertsCertificate {
                    name: "fixture-ca".to_owned(),
                    cert_data: ca,
                }],
            }),
            central_truststore_reference: None,
        }),
        ee_certs: None,
        tls13_epsks: None,
    })
}

async fn operations(server: TacacsPlusServer) -> Result<()> {
    operations_with_policy(server, &ValidationOptions::default()).await
}

async fn operations_with_policy(
    server: TacacsPlusServer,
    policy: &ValidationOptions,
) -> Result<()> {
    validate_materialized_servers([&server], policy)?;
    let endpoint = prepare_endpoint(&server, PrepareOptions::default())?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let client = TacacsClient::connect_prepared(endpoint).await?;
        let authentication = PapAuthenticationOperation {
            user: "testuser".to_owned(),
            password: SecretBytes::new(b"test-password".to_vec()),
            port: "pts/1".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            privilege_level: PrivilegeLevel::MAX,
        };
        let reply = client.execute(&authentication.exchange()?).await?;
        assert_eq!(reply.status, TacacsAuthenticationStatus::TacPlusAuthenStatusPass);
        let authorization = AuthorizationOperation::builder(
            "testuser",
            15,
            AuthorizationAuthenticationContext::TacacsPap,
        )
        .port("pts/1")
        .remote_address("127.0.0.1")
        .service("shell")
        .command("show")
        .command_arg("version")
        .build()?;
        let reply = client.execute(&authorization.exchange()?).await?;
        assert!(matches!(
            reply.status,
            TacacsAuthorizationStatus::TacPlusPassAdd | TacacsAuthorizationStatus::TacPlusPassRepl
        ));
        for _ in 0..3 {
            let operation = AccountingOperation {
                user: "testuser".to_owned(),
                port: "pts/1".to_owned(),
                remote_address: "127.0.0.1".to_owned(),
                command: "show".to_owned(),
                command_arguments: vec!["version".to_owned()],
            };
            let reply = client.execute(&operation.exchange()?).await?;
            assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        }
        client.stop_accepting_new_sessions().await;
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
#[ignore = "requires the independent tac_plus-ng server; see docs/tacplus-interop.md"]
async fn tcp_operations() -> Result<()> {
    operations(
        server("TACPLUS_TCP_ADDR", 4949)?
            .with_shared_secret("tac_plus_key")
            .build(),
    )
    .await
}

#[tokio::test]
#[ignore = "requires an un-obfuscated TCP compatibility peer; see docs/tacplus-interop.md"]
async fn plain_tcp_operations() -> Result<()> {
    let policy = ValidationOptions::new()
        .with_relaxation(ValidationRelaxation::AllowPlainTcpWithoutSharedSecret);
    operations_with_policy(server("TACPLUS_TCP_ADDR", 4949)?.build(), &policy).await
}

#[tokio::test]
#[ignore = "requires the independent tac_plus-ng server; see docs/tacplus-interop.md"]
async fn certificate_tls_operations() -> Result<()> {
    let mut server = server("TACPLUS_TLS_ADDR", 4449)?
        .with_tls_server_authentication()
        .build();
    server.server_authentication = Some(trust_store()?);
    operations(server).await
}

#[tokio::test]
#[ignore = "requires the independent tac_plus-ng server; see docs/tacplus-interop.md"]
async fn client_certificate_tls_operations() -> Result<()> {
    let (key, format) = load_client_private_key(&certificates().join("client.key"))?;
    let cert = load_client_certificate(&certificates().join("client.crt"))?;
    let mut server = server("TACPLUS_TLS_ADDR", 4449)?
        .with_tls_client_certificate_chain(
            Some(cert.leaf),
            cert.intermediates,
            Some(key),
            Some(format),
        )
        .build();
    server.server_authentication = Some(trust_store()?);
    operations(server).await
}

#[tokio::test]
#[ignore = "requires a peer that enforces client certificates; see docs/tacplus-interop.md"]
async fn missing_client_certificate_is_rejected() -> Result<()> {
    let mut server = server("TACPLUS_TLS_ADDR", 4449)?
        .with_tls_server_authentication()
        .build();
    server.server_authentication = Some(trust_store()?);
    assert!(operations(server).await.is_err(), "mutual TLS must require a client certificate");
    Ok(())
}

#[tokio::test]
#[ignore = "requires the independent tac_plus-ng server; see docs/tacplus-interop.md"]
async fn psk_dhe_operations() -> Result<()> {
    operations(
        server("TACPLUS_PSK_ADDR", 4450)?
            .with_tls13_epsk("psk-demo", FIXTURE_PSK.to_vec())
            .build(),
    )
    .await
}

#[tokio::test]
#[ignore = "requires a no-DHE peer configuration; see docs/tacplus-interop.md"]
async fn psk_only_operations() -> Result<()> {
    operations(
        server("TACPLUS_PSK_ADDR", 4450)?
            .with_tls13_epsk_psk_only("psk-demo", FIXTURE_PSK.to_vec())
            .build(),
    )
    .await
}

#[tokio::test]
#[ignore = "requires a SHA-384 PSK peer configuration; see docs/tacplus-interop.md"]
async fn psk_sha384_operations() -> Result<()> {
    let mut server = server("TACPLUS_PSK_ADDR", 4450)?
        .with_tls13_epsk("psk-demo", FIXTURE_PSK.to_vec())
        .build();
    server
        .client_identity
        .as_mut()
        .unwrap()
        .tls13_epsk
        .as_mut()
        .unwrap()
        .hash = EpskSupportedHash::Sha384;
    operations(server).await
}
