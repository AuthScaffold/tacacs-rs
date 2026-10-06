use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{bail, Result};
use openssl::nid::Nid;
use openssl::ssl::{NameType, Ssl, SslContext, SslMethod, SslOptions, SslVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

use tacacsrs_config::input::{
    tacacs_plus_from_cli_input, CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityInputs,
    CliServerInput, CliPskInputs, PskKeyExchangeMode, PskKeyMaterial,
};
use tacacsrs_config::prepare::{
    enumerate_materialized_servers, prepare_endpoint, validate_materialized_servers,
};
use tacacsrs_config::{
    PskDheKeSupportedGroup, TacacsPlus, TacacsPlusServer, ValidationOptions, ValidationRelaxation,
};
use tacacsrs_credential_resolution::{
    FakeCredentialResolver, ProviderErrorKind, RequestSlot, ResolvedCredential, SecretBytes,
    SymmetricKeyMaterial,
};
use tacacsrs_networking::{
    ConnectOptions, PacketReadResult, PacketReader, PacketWriteResult, PacketWriter,
    PreparedEndpoint, TacacsClient,
};
use tacacsrs_protocol::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_protocol::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType, TacacsFlags,
};
use tacacsrs_protocol::exchange::accounting::AccountingExchange;
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_protocol::traits::TacacsBodyTrait;
use tacacsrs_sonic::{map_sonic_tables_to_tacacs_plus, SonicTacacsTables};

/// OpenSSL option bit 10 permits TLS 1.3 PSK exchange without DHE.
const ALLOW_NO_DHE_KEX: SslOptions = SslOptions::from_bits_retain(1 << 10);
/// A peer group absent from the client's default list forces the no-DHE path.
const NO_SHARED_GROUP: &str = "P-224";
const PSK_IDENTITY: &str = "prepared-client";
const PSK_REFERENCE: &str = "prepared-key-reference";
const SERVER_NAME: &str = "tacacs.example.test";
const ORIGINAL_KEY: &[u8] = b"original-psk-material-for-preparation";
const ROTATED_KEY: &[u8] = b"rotated-psk-material-for-preparation";

fn plain_options() -> ValidationOptions {
    ValidationOptions::new().with_relaxation(ValidationRelaxation::AllowPlainTcpWithoutSharedSecret)
}

fn plain_sources(
    address: SocketAddr,
    secret: Option<&str>,
    single_connection: bool,
) -> Result<[TacacsPlus; 3]> {
    let host = address.ip().to_string();
    let name = format!("sonic-server-{host}");
    let cli = tacacs_plus_from_cli_input(
        &CliDatastoreInput::new(
            CliConfigSource::Inline {
                servers: vec![CliServerInput::new(&name, address.to_string())
                    .with_timeout_seconds(7)
                    .with_single_connection(single_connection)],
                security: CliSecurity::from_cli_inputs(CliSecurityInputs {
                    shared_secret: secret.map(str::to_owned),
                    ..Default::default()
                }),
            },
            "cli",
        )
        .with_validation_options(plain_options()),
    )?;
    let mut fields = BTreeMap::from([
        ("tcp_port".to_owned(), address.port().to_string()),
        ("timeout".to_owned(), "7".to_owned()),
        ("single_connection".to_owned(), single_connection.to_string()),
    ]);
    if let Some(secret) = secret {
        fields.insert("passkey".to_owned(), secret.to_owned());
    }
    let sonic = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(
        BTreeMap::new(),
        BTreeMap::from([(host.clone(), fields)]),
    ))?;
    let mut server = serde_json::json!({
        "name": name, "address": host, "port": address.port(),
        "server-type": "authentication authorization accounting", "timeout": 7,
        "single-connection": single_connection,
    });
    if let Some(secret) = secret {
        server["shared-secret"] = serde_json::json!(secret);
    }
    let yang = tacacsrs_config::parse_yang_json_with_options(
        &serde_json::json!({"ietf-system-tacacs-plus:tacacs-plus": {"server": [server]}})
            .to_string(),
        &plain_options(),
    )?;
    assert_eq!(cli, yang);
    assert_eq!(sonic, yang);
    Ok([cli, sonic, yang])
}

fn accounting_request() -> AccountingRequest {
    AccountingRequest {
        flags: TacacsAccountingFlags::STOP,
        authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
        priv_lvl: 0,
        authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
        authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
        user: "test-user".to_owned(),
        port: "pts/1".to_owned(),
        rem_address: "192.0.2.7".to_owned(),
        args: vec![
            "service=shell".to_owned(),
            "cmd=show".to_owned(),
            "cmd-arg=version".to_owned(),
        ],
    }
}

fn psk_sources(address: SocketAddr, key: &[u8], dhe: bool) -> Result<[TacacsPlus; 3]> {
    let host = address.ip().to_string();
    let name = format!("sonic-server-{host}");
    let groups = if dhe {
        vec![
            PskDheKeSupportedGroup::X25519,
            PskDheKeSupportedGroup::Secp384r1,
        ]
    } else {
        Vec::new()
    };
    let cli = tacacs_plus_from_cli_input(&CliDatastoreInput::new(
        CliConfigSource::Inline {
            servers: vec![CliServerInput::new(&name, address.to_string())
                .with_timeout_seconds(7)
                .with_single_connection(false)
                .with_tls_server_name(SERVER_NAME)],
            security: CliSecurity::from_cli_inputs(CliSecurityInputs {
                use_tls: true,
                psk: Some(CliPskInputs {
                    identity: PSK_IDENTITY.to_owned(),
                    key: PskKeyMaterial::Raw(key.to_vec()),
                    exchange: if dhe {
                        PskKeyExchangeMode::PskDhe
                    } else {
                        PskKeyExchangeMode::PskOnly
                    },
                    groups,
                }),
                ..Default::default()
            }),
        },
        "cli",
    ))?;
    let mut fields = BTreeMap::from([
        ("tcp_port".to_owned(), address.port().to_string()),
        ("timeout".to_owned(), "7".to_owned()),
        ("single_connection".to_owned(), "false".to_owned()),
        ("domain_name".to_owned(), SERVER_NAME.to_owned()),
        ("sni_enabled".to_owned(), "true".to_owned()),
        ("psk_identity".to_owned(), PSK_IDENTITY.to_owned()),
        ("psk_secret_ref".to_owned(), PSK_REFERENCE.to_owned()),
        (
            "psk_key_exchange".to_owned(),
            if dhe {
                "psk-dhe"
            } else {
                "psk-only"
            }
            .to_owned(),
        ),
    ]);
    if dhe {
        fields.insert("psk_key_exchange_groups".to_owned(), "x25519:secp384r1".to_owned());
    }
    let sonic = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::with_extended_tables(
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::from([(host.clone(), fields)]),
        BTreeMap::new(),
    ))?;
    let group_names = if dhe {
        vec!["x25519", "secp384r1"]
    } else {
        Vec::new()
    };
    let yang = tacacsrs_config::parse_yang_json(
        &serde_json::json!({
            "ietf-system-tacacs-plus:tacacs-plus": {"server": [{
                "name": name, "server-type": "authentication authorization accounting",
                "address": host, "port": address.port(), "timeout": 7, "single-connection": false,
                "domain-name": SERVER_NAME, "sni-enabled": true,
                "client-identity": {"tls13-epsk": {
                    "central-keystore-reference": PSK_REFERENCE, "external-identity": PSK_IDENTITY,
                    "tacacsrs:psk-dhe-ke-groups": group_names,
                }},
            }]}
        })
        .to_string(),
    )?;
    assert_eq!(sonic, yang);
    Ok([cli, sonic, yang])
}

async fn materialized_endpoint(
    source: &TacacsPlus,
    key: &[u8],
) -> Result<(PreparedEndpoint, TacacsPlusServer)> {
    let resolver = FakeCredentialResolver::new().with_response(
        RequestSlot::from_index(0),
        ResolvedCredential::SymmetricKey(SymmetricKeyMaterial {
            key_format: None,
            key: SecretBytes::new(key.to_vec()),
        }),
    );
    let materialized =
        enumerate_materialized_servers(source, &resolver, &ValidationOptions::default()).await?;
    validate_materialized_servers(materialized.iter(), &ValidationOptions::default())?;
    let endpoint = prepare_endpoint(&materialized[0], ConnectOptions::default())?;
    Ok((endpoint, materialized[0].clone()))
}

fn psk_peer_context(key: &[u8], dhe: bool) -> Result<SslContext> {
    let mut builder = SslContext::builder(SslMethod::tls_server())?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_ciphersuites("TLS_AES_128_GCM_SHA256")?;
    if dhe {
        builder.set_groups_list("P-384")?;
    } else {
        builder.set_options(ALLOW_NO_DHE_KEX);
        builder.set_groups_list(NO_SHARED_GROUP)?;
    }
    let key = SecretBytes::new(key.to_vec());
    builder.set_psk_server_callback(move |_, identity, output| {
        let key = key.expose_secret();
        if identity != Some(PSK_IDENTITY.as_bytes()) || output.len() < key.len() {
            return Ok(0);
        }
        output[..key.len()].copy_from_slice(key);
        Ok(key.len())
    });
    Ok(builder.build())
}

async fn psk_exchange(
    listener: &TcpListener,
    endpoint: PreparedEndpoint,
    key: &[u8],
    dhe: bool,
    accepted: bool,
) -> Result<()> {
    let context = psk_peer_context(key, dhe)?;
    let peer = async {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
        Pin::new(&mut stream).accept().await?;
        assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_3));
        assert_eq!(stream.ssl().servername(NameType::HOST_NAME), Some(SERVER_NAME));
        assert_eq!(stream.ssl().current_cipher().unwrap().name(), "TLS_AES_128_GCM_SHA256");
        if dhe {
            assert_eq!(
                stream.ssl().peer_tmp_key()?.ec_key()?.group().curve_name(),
                Some(Nid::SECP384R1)
            );
        } else {
            assert!(stream.ssl().peer_tmp_key().is_err());
        }
        reply_to_accounting(&mut stream, None, false).await
    };
    let (peer, client) = tokio::join!(peer, execute(endpoint));
    assert_eq!(peer.is_ok(), accepted, "unexpected PSK peer result: {peer:?}");
    assert_eq!(client.is_ok(), accepted, "unexpected PSK client result: {client:?}");
    Ok(())
}

async fn reply_to_accounting(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    key: Option<&[u8]>,
    single_connection: bool,
) -> Result<Vec<u8>> {
    let PacketReadResult::Success(raw) = PacketReader::new(None).read_packet(stream).await else {
        bail!("peer expected a complete TACACS+ request");
    };
    assert_eq!(
        raw.header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG),
        key.is_none()
    );
    assert_eq!(
        raw.header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_SINGLE_CONNECT_FLAG),
        single_connection
    );
    assert_eq!(raw.header().seq_no, 1);
    let request = match key {
        Some(key) => raw.to_deobfuscated(key),
        None => raw,
    };
    assert_eq!(request.body(), accounting_request().to_bytes()?);
    let body = AccountingReply {
        status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
        server_msg: "accepted".to_owned(),
        data: String::new(),
    }
    .to_bytes()?;
    let mut header = request.header().clone();
    header.seq_no = 2;
    header.length = body.len().try_into()?;
    let reply = Packet::new(header, body)?;
    let writer = PacketWriter::new(key.map(<[u8]>::to_vec));
    if let PacketWriteResult::WriteError(error) = writer.write_packet(stream, reply).await {
        return Err(error.into());
    }
    Ok(request.body().to_vec())
}

async fn execute(endpoint: PreparedEndpoint) -> Result<()> {
    let client = TacacsClient::connect_prepared(endpoint).await?;
    let reply = client
        .execute(AccountingExchange::new(accounting_request()))
        .await?;
    assert_eq!(reply.status, TacacsAccountingStatus::TacPlusAcctStatusSuccess);
    assert_eq!(reply.server_msg, "accepted");
    client.stop_accepting_new_sessions().await;
    Ok(())
}

#[tokio::test]
async fn equivalent_plain_sources_produce_the_same_wire_behavior() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(10), async {
        for secret in [None, Some("shared-test-secret")] {
            for single_connection in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                let sources = plain_sources(listener.local_addr()?, secret, single_connection)?;
                for source in sources {
                    let original = source.clone();
                    validate_materialized_servers(source.server.iter(), &plain_options())?;
                    let endpoint = prepare_endpoint(&source.server[0], ConnectOptions::default())?;
                    let peer = async {
                        let (mut stream, _) = listener.accept().await?;
                        reply_to_accounting(
                            &mut stream,
                            secret.map(str::as_bytes),
                            single_connection,
                        )
                        .await
                    };
                    let (body, ()) = tokio::try_join!(peer, execute(endpoint))?;
                    assert_eq!(body, accounting_request().to_bytes()?);
                    assert_eq!(source, original);
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn equivalent_psk_sources_keep_prepared_generations_independent() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        for dhe in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let initial = psk_sources(listener.local_addr()?, ORIGINAL_KEY, dhe)?;
            let rotated = psk_sources(listener.local_addr()?, ROTATED_KEY, dhe)?;
            assert_eq!(initial[1..], rotated[1..]);
            for index in 0..initial.len() {
                let original = initial[index].clone();
                let rotated_original = rotated[index].clone();
                let (old_endpoint, old_materialized) =
                    materialized_endpoint(&initial[index], ORIGINAL_KEY).await?;
                let (new_endpoint, new_materialized) =
                    materialized_endpoint(&rotated[index], ROTATED_KEY).await?;
                assert_eq!(old_materialized, initial[0].server[0]);
                assert_eq!(new_materialized, rotated[0].server[0]);
                if index != 0 {
                    let failing = FakeCredentialResolver::new()
                        .with_error(RequestSlot::from_index(0), ProviderErrorKind::Unavailable);
                    assert!(enumerate_materialized_servers(
                        &initial[index],
                        &failing,
                        &ValidationOptions::default()
                    )
                    .await
                    .is_err());
                    assert!(materialized_endpoint(&initial[index], b"short")
                        .await
                        .is_err());
                }
                if dhe {
                    psk_exchange(&listener, old_endpoint.clone(), ORIGINAL_KEY, false, false)
                        .await?;
                } else {
                    psk_exchange(&listener, old_endpoint.clone(), ORIGINAL_KEY, true, false)
                        .await?;
                }
                psk_exchange(&listener, old_endpoint.clone(), ORIGINAL_KEY, dhe, true).await?;
                psk_exchange(&listener, new_endpoint.clone(), ROTATED_KEY, dhe, true).await?;
                psk_exchange(&listener, old_endpoint.clone(), ROTATED_KEY, dhe, false).await?;
                psk_exchange(&listener, new_endpoint, ORIGINAL_KEY, dhe, false).await?;
                psk_exchange(&listener, old_endpoint, ORIGINAL_KEY, dhe, true).await?;
                assert_eq!(initial[index], original);
                assert_eq!(rotated[index], rotated_original);
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn psk_only_rejects_dhe_before_sending_application_data() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let sources = psk_sources(listener.local_addr()?, ORIGINAL_KEY, false)?;
        let (endpoint, _) = materialized_endpoint(&sources[0], ORIGINAL_KEY).await?;
        let context = psk_peer_context(ORIGINAL_KEY, true)?;
        let peer = async {
            let (tcp, _) = listener.accept().await?;
            let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
            Pin::new(&mut stream).accept().await?;
            assert!(stream.ssl().peer_tmp_key().is_ok());
            let mut byte = [0];
            Ok::<_, anyhow::Error>(stream.read(&mut byte).await.unwrap_or(0))
        };
        let (received, client) = tokio::join!(peer, execute(endpoint));
        assert_eq!(received?, 0, "a mismatched PSK mode must not carry application data");
        let error = client.expect_err("PSK-only must reject a DHE connection");
        assert!(format!("{error:#}").contains("expected PSK-only, negotiated PSK-DHE"));
        Ok::<_, anyhow::Error>(())
    })
    .await?
}

#[tokio::test]
async fn psk_rejects_certificate_fallback_before_sending_application_data() -> Result<()> {
    use openssl::pkey::PKey;
    use openssl::x509::X509;

    let samples = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../lde/containers/config/certificates");
    let certificate = X509::from_pem(&std::fs::read(samples.join("server.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(samples.join("server.key"))?)?;
    let mut context = SslContext::builder(SslMethod::tls_server())?;
    context.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    context.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    context.set_ciphersuites("TLS_AES_128_GCM_SHA256")?;
    context.set_certificate(&certificate)?;
    context.set_private_key(&key)?;
    let context = context.build();
    tokio::time::timeout(Duration::from_secs(10), async {
        for dhe in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let sources = psk_sources(listener.local_addr()?, ORIGINAL_KEY, dhe)?;
            let (endpoint, _) = materialized_endpoint(&sources[0], ORIGINAL_KEY).await?;
            let peer = async {
                let (tcp, _) = listener.accept().await?;
                let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
                Pin::new(&mut stream).accept().await?;
                assert!(!stream.ssl().session_reused());
                let mut byte = [0];
                Ok::<_, anyhow::Error>(stream.read(&mut byte).await.unwrap_or(0))
            };
            let (received, client) = tokio::join!(peer, execute(endpoint));
            assert_eq!(received?, 0, "certificate fallback must not carry application data");
            let error = client.expect_err("PSK transport must reject certificate authentication");
            assert!(format!("{error:#}").contains("did not authenticate with the configured PSK"));
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
}
