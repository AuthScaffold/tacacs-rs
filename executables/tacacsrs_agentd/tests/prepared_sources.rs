use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use openssl::nid::Nid;
use openssl::ssl::{NameType, Ssl, SslContext, SslContextBuilder, SslMethod, SslOptions, SslVersion};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpListener;
use tokio_openssl::SslStream;

use tacacsrs_config::input::{
    tacacs_plus_from_cli_input, CliConfigSource, CliDatastoreInput, CliSecurity, CliSecurityInputs,
    CliServerInput, CliPskInputs, PskKeyExchangeMode, PskKeyMaterial,
};
use tacacsrs_config::prepare::{
    enumerate_materialized_servers, prepare_endpoint, validate_materialized_servers, PrepareOptions,
};
use tacacsrs_config::{
    EpskSupportedHash, PskDheKeSupportedGroup, TacacsPlus, TacacsPlusServer, ValidationOptions,
    ValidationRelaxation,
};
use tacacsrs_credential_resolution::{
    CertificateWithKeyMaterial, CredentialRequest, CredentialResolver, CredentialValidity,
    FakeCredentialResolver, PrivateKeyFormat, ProviderErrorKind, PublicBytes, RequestSlot,
    ResolvedCredential, ResolutionError, SecretBytes, SymmetricKeyMaterial,
};
use tacacsrs_networking::{
    PacketReadResult, PacketReader, PacketWriteResult, PacketWriter, PreparedEndpoint, TacacsClient,
};
use tacacsrs_protocol::accounting::{reply::AccountingReply, request::AccountingRequest};
use tacacsrs_protocol::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationType, TacacsFlags,
};
use tacacsrs_protocol::exchange::accounting::AccountingExchange;
use tacacsrs_protocol::packet::{Packet, PacketTrait};
use tacacsrs_protocol::body::TacacsBodyTrait;
use tacacsrs_sonic::{map_sonic_tables_to_tacacs_plus, SonicTacacsTables};

#[path = "prepared_sources/psk_peer.rs"]
mod psk_peer;

#[path = "prepared_sources/ocsp_peer.rs"]
mod ocsp_peer;

#[path = "prepared_sources/crl_peer.rs"]
mod crl_peer;

#[path = "prepared_sources/http_provider.rs"]
mod http_provider;

/// Composes the IPC client API listener with the agent runtime for tests.
///
/// Integration tests of the daemon binary cannot reach the daemon's internal
/// composition module, so this mirrors it over the public agent and IPC APIs.
mod client_api {
    use std::path::PathBuf;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::sync::watch;
    use tokio::task::JoinHandle;

    use tacacsrs_agent::{
        ClientApiHandle, ListenerRegistration, ListenerState, RuntimeHealthPublisher,
        RuntimeHealthSnapshot, RuntimeListenerService, RuntimeService, ShutdownReceiver,
        TacacsClientService,
    };
    use tacacsrs_ipc::server::{self, HealthStatus, ListenerOptions};
    use tacacsrs_protocol::operations::{
        AccountingOperation, AccountingOperationResponse, AuthorizationOperation,
        AuthorizationOperationResponse, PapAuthenticationOperation,
        PapAuthenticationOperationResponse,
    };
    use tacacsrs_protocol::failure::ServiceError;

    pub(crate) fn client_api_listeners(
        service: &TacacsClientService,
    ) -> Vec<Box<dyn RuntimeListenerService>> {
        match service.client_api_socket_path() {
            Some(path) => {
                let settings = service.client_api_listener_settings();
                vec![Box::new(ClientApiListener {
                    handler: Arc::new(AgentHandler {
                        handle: service.client_api_handle(),
                    }),
                    path,
                    options: ListenerOptions {
                        socket_mode: settings.socket_mode,
                        max_connections: settings.max_connections,
                        max_client_api_streams: settings.max_client_api_streams,
                        connection_lifetime: settings.connection_lifetime,
                    },
                })]
            }
            None => Vec::new(),
        }
    }

    struct AgentHandler {
        handle: ClientApiHandle,
    }

    #[async_trait]
    impl server::Handler for AgentHandler {
        async fn authenticate_pap(
            &self,
            request: PapAuthenticationOperation,
        ) -> Result<PapAuthenticationOperationResponse, ServiceError> {
            self.handle.authenticate_pap(request).await
        }

        async fn accounting(
            &self,
            request: AccountingOperation,
        ) -> Result<AccountingOperationResponse, ServiceError> {
            self.handle.accounting(request).await
        }

        async fn authorization(
            &self,
            request: AuthorizationOperation,
        ) -> Result<AuthorizationOperationResponse, ServiceError> {
            self.handle.authorization(request).await
        }
    }

    struct ClientApiListener {
        handler: Arc<AgentHandler>,
        path: PathBuf,
        options: ListenerOptions,
    }

    #[async_trait]
    impl RuntimeListenerService for ClientApiListener {
        async fn serve(
            self: Box<Self>,
            shutdown: ShutdownReceiver,
            health: RuntimeHealthPublisher,
        ) -> anyhow::Result<()> {
            let Self {
                handler,
                path,
                options,
            } = *self;
            let registration = ListenerRegistration::new(health.clone(), RuntimeService::ClientApi);
            let mut snapshot = health.subscribe();
            let (sender, receiver) = watch::channel(status(&snapshot.borrow()));
            let forwarder = Forwarder(tokio::spawn(async move {
                while snapshot.changed().await.is_ok() {
                    if sender.send(status(&snapshot.borrow())).is_err() {
                        break;
                    }
                }
            }));
            let bound = health.clone();
            let on_bound = move || {
                let _ = bound.set_listener(RuntimeService::ClientApi, ListenerState::Bound);
            };
            let result =
                server::serve_unix(&path, options, handler, receiver, shutdown.flag(), on_bound)
                    .await;
            drop(forwarder);
            drop(registration);
            result
        }
    }

    struct Forwarder(JoinHandle<()>);

    impl Drop for Forwarder {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    fn status(snapshot: &RuntimeHealthSnapshot) -> HealthStatus {
        HealthStatus {
            startup_serving: snapshot.is_startup_serving(),
            liveness_serving: snapshot.is_liveness_serving(),
            readiness_serving: snapshot.is_readiness_serving(),
        }
    }
}

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
    let [sonic, yang] = referenced_psk_sources(address, dhe, EpskSupportedHash::Sha256)?;
    Ok([cli, sonic, yang])
}

fn referenced_psk_sources(
    address: SocketAddr,
    dhe: bool,
    hash: EpskSupportedHash,
) -> Result<[TacacsPlus; 2]> {
    let host = address.ip().to_string();
    let name = format!("sonic-server-{host}");
    let mut fields = BTreeMap::from([
        ("tcp_port".to_owned(), address.port().to_string()),
        ("timeout".to_owned(), "7".to_owned()),
        ("single_connection".to_owned(), "false".to_owned()),
        ("domain_name".to_owned(), SERVER_NAME.to_owned()),
        ("sni_enabled".to_owned(), "true".to_owned()),
        ("psk_identity".to_owned(), PSK_IDENTITY.to_owned()),
        ("psk_secret_ref".to_owned(), PSK_REFERENCE.to_owned()),
        (
            "psk_hash".to_owned(),
            match hash {
                EpskSupportedHash::Sha256 => "sha-256",
                EpskSupportedHash::Sha384 => "sha-384",
            }
            .to_owned(),
        ),
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
                    "hash": hash,
                    "tacacsrs:psk-dhe-ke-groups": group_names,
                }},
            }]}
        })
        .to_string(),
    )?;
    assert_eq!(sonic, yang);
    Ok([sonic, yang])
}

async fn materialized_endpoint(
    source: &TacacsPlus,
    key: &[u8],
) -> Result<(PreparedEndpoint, TacacsPlusServer)> {
    let resolver = FakeCredentialResolver::new().with_response(
        RequestSlot::from_index(0),
        ResolvedCredential::SymmetricKey(SymmetricKeyMaterial {
            validity: tacacsrs_credential_resolution::CredentialValidity::unbounded(),
            key_format: None,
            key: SecretBytes::new(key.to_vec()),
        }),
    );
    let materialized =
        enumerate_materialized_servers(source, &resolver, &ValidationOptions::default()).await?;
    validate_materialized_servers(
        materialized
            .iter()
            .map(tacacsrs_config::prepare::MaterializedServer::server),
        &ValidationOptions::default(),
    )?;
    assert_eq!(
        materialized[0].validity(),
        tacacsrs_credential_resolution::CredentialValidity::unbounded()
    );
    let endpoint = prepare_endpoint(&materialized[0], PrepareOptions::default())?;
    assert_eq!(
        endpoint.connection_timeout(),
        Some(Duration::from_secs(u64::from(source.server[0].timeout)))
    );
    Ok((endpoint, materialized[0].server().clone()))
}

fn psk_peer_builder(dhe: bool) -> Result<SslContextBuilder> {
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
    Ok(builder)
}

fn psk_peer_context(key: &[u8], dhe: bool) -> Result<SslContext> {
    let mut builder = psk_peer_builder(dhe)?;
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

fn hash_bound_peer_context(key: &[u8], dhe: bool, hash: EpskSupportedHash) -> Result<SslContext> {
    let mut builder = psk_peer_builder(dhe)?;
    builder.set_ciphersuites("TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384")?;
    psk_peer::install(&mut builder, PSK_IDENTITY, key, hash)?;
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
    exchange_with_peer(listener, endpoint, &context, EpskSupportedHash::Sha256, dhe, accepted).await
}

async fn exchange_with_peer(
    listener: &TcpListener,
    endpoint: PreparedEndpoint,
    context: &SslContext,
    hash: EpskSupportedHash,
    dhe: bool,
    accepted: bool,
) -> Result<()> {
    let peer = async {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(context)?, tcp)?;
        Pin::new(&mut stream).accept().await?;
        assert_eq!(stream.ssl().version2(), Some(SslVersion::TLS1_3));
        assert_eq!(stream.ssl().servername(NameType::HOST_NAME), Some(SERVER_NAME));
        assert!(stream.ssl().session_reused());
        assert_eq!(stream.ssl().current_cipher().unwrap().name(), psk_peer::cipher_suite(hash));
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
    reply_to_expected_accounting(stream, key, single_connection, &accounting_request()).await
}

async fn reply_to_expected_accounting(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    key: Option<&[u8]>,
    single_connection: bool,
    expected: &AccountingRequest,
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
    assert_eq!(request.body(), expected.to_bytes()?);
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

struct CertificateFixture {
    source: TacacsPlus,
    context: SslContext,
    certificate: Vec<u8>,
    private_key: Vec<u8>,
    expires_at: std::time::SystemTime,
}

struct RefreshingIdentityResolver {
    certificate: Vec<u8>,
    private_key: Vec<u8>,
    initial_validity: CredentialValidity,
    refreshed_validity: CredentialValidity,
    calls: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl CredentialResolver for RefreshingIdentityResolver {
    async fn resolve(&self, _: &CredentialRequest) -> Result<ResolvedCredential, ResolutionError> {
        let call = self.calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Ok(ResolvedCredential::CertificateWithKey(CertificateWithKeyMaterial {
            validity: if call == 0 {
                self.initial_validity
            } else {
                self.refreshed_validity
            },
            public_key_format: None,
            public_key: None,
            private_key_format: PrivateKeyFormat::OneAsymmetricKeyFormat,
            certificate: PublicBytes::new(self.certificate.clone()),
            intermediates: Vec::new(),
            private_key: SecretBytes::new(self.private_key.clone()),
        }))
    }
}

struct DelayConnected(Duration);

impl tacacsrs_networking::ConnectionGuard for DelayConnected {
    fn check_destination(&self, _: SocketAddr) -> Result<()> {
        Ok(())
    }

    fn check_connected(&self, _: SocketAddr, _: SocketAddr) -> Result<()> {
        std::thread::sleep(self.0);
        Ok(())
    }
}

fn certificate_source(address: SocketAddr, valid_for: Duration) -> Result<CertificateFixture> {
    use openssl::asn1::Asn1Time;
    use openssl::pkey::PKey;
    use openssl::x509::X509;
    use tacacsrs_config::{TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType};
    let samples = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../lde/containers/config/certificates");
    let template = X509::from_pem(&std::fs::read(samples.join("client.crt"))?)?;
    let key = PKey::private_key_from_pem(&std::fs::read(samples.join("client.key"))?)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let mut certificate = X509::builder()?;
    certificate.set_version(2)?;
    certificate.set_serial_number(template.serial_number())?;
    certificate.set_subject_name(template.subject_name())?;
    certificate.set_issuer_name(template.subject_name())?;
    certificate.set_pubkey(&key)?;
    certificate.set_not_before(Asn1Time::from_unix((now - 60).try_into()?)?.as_ref())?;
    let expires_at = std::time::UNIX_EPOCH + Duration::from_secs(now) + valid_for;
    certificate
        .set_not_after(Asn1Time::from_unix((now + valid_for.as_secs()).try_into()?)?.as_ref())?;
    let names = openssl::x509::extension::SubjectAlternativeName::new()
        .dns("localhost")
        .build(&certificate.x509v3_context(None, None))?;
    certificate.append_extension(names)?;
    certificate.sign(&key, openssl::hash::MessageDigest::sha256())?;
    let certificate = certificate.build();
    let certificate_der = certificate.to_der()?;
    let private_key = key.private_key_to_pkcs8()?;
    let source = TacacsPlusBuilder::new()
        .with_server_builder(
            TacacsPlusServerBuilder::new(
                "certificate",
                TacacsPlusServerType::all(),
                address.ip().to_string(),
                address.port(),
            )
            .with_single_connection(true)
            .with_tls_client_certificate(Some(certificate_der.clone()), Some(private_key.clone())),
        )
        .build()?;
    let mut context = SslContext::builder(SslMethod::tls_server())?;
    context.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    context.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    context.set_certificate(&certificate)?;
    context.set_private_key(&key)?;
    context.cert_store_mut().add_cert(certificate)?;
    context.set_verify(
        openssl::ssl::SslVerifyMode::PEER | openssl::ssl::SslVerifyMode::FAIL_IF_NO_PEER_CERT,
    );
    Ok(CertificateFixture {
        source,
        context: context.build(),
        certificate: certificate_der,
        private_key,
        expires_at,
    })
}

#[tokio::test]
async fn established_mtls_pin_survives_authentication_certificate_expiry() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fixture = certificate_source(listener.local_addr()?, Duration::from_secs(4))?;
    let certificate = fixture.certificate.as_slice();
    let endpoint = PreparedEndpoint::tcp(
        listener.local_addr()?.to_string(),
        true,
        None,
        tacacsrs_networking::ConnectOptions::default(),
    )
    .with_certificate_tls(
        "localhost",
        None,
        tacacsrs_networking::CertificateTrust::Certificates {
            authorities: &[],
            end_entities: &[certificate],
        },
        Some(tacacsrs_networking::CertificateIdentity {
            certificate,
            intermediates: &[],
            public_key_info: None,
            private_key: &fixture.private_key,
            private_key_encoding: tacacsrs_networking::PrivateKeyEncoding::Pkcs8,
        }),
    )?;
    let counters = endpoint.counters();
    let (handshake_complete, handshake_observed) = tokio::sync::oneshot::channel();
    let (delayed_received, request_observed) = tokio::sync::oneshot::channel();
    let (release_reply, reply_release) = tokio::sync::oneshot::channel();
    let context = fixture.context;
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
        Pin::new(&mut stream).accept().await?;
        assert!(stream.ssl().peer_certificate().is_some());
        let _ = handshake_complete.send(());
        reply_to_accounting(&mut stream, None, true).await?;
        let raw = match PacketReader::new(None).read_packet(&mut stream).await {
            PacketReadResult::Success(packet) => packet,
            result => bail!("failed to read delayed request: {result:?}"),
        };
        let _ = delayed_received.send(());
        reply_release.await?;
        let mut header = raw.header().clone();
        header.seq_no = header.seq_no.checked_add(1).expect("test sequence number");
        let body = AccountingReply {
            status: TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            server_msg: "accepted".to_owned(),
            data: String::new(),
        }
        .to_bytes()?;
        header.length = body.len().try_into()?;
        if let PacketWriteResult::WriteError(error) = PacketWriter::new(None)
            .write_packet(&mut stream, Packet::new(header, body)?)
            .await
        {
            return Err(error.into());
        }
        reply_to_accounting(&mut stream, None, false).await?;
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await?, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(300), listener.accept())
                .await
                .is_err(),
            "an expired reused identity must fail before TCP"
        );
        Ok::<(), anyhow::Error>(())
    });
    let client = TacacsClient::connect_prepared(endpoint.clone()).await?;
    let first = client.execute(AccountingExchange::new(accounting_request()));
    tokio::pin!(first);
    tokio::time::timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = &mut first => panic!("exchange ended before the server handshake barrier: {result:?}"),
            result = handshake_observed => result.unwrap(),
        }
    })
    .await?;
    tokio::time::timeout(Duration::from_secs(3), &mut first).await??;
    let mut retained = client.open_conversation().await?;
    let session_id = retained.session_id().expect("active retained conversation");
    let body = accounting_request().to_bytes()?;
    let delayed_packet = Packet::new(
        tacacsrs_protocol::header::Header {
            major_version: tacacsrs_protocol::enumerations::TacacsMajorVersion::TacacsPlusMajor1,
            minor_version:
                tacacsrs_protocol::enumerations::TacacsMinorVersion::TacacsPlusMinorVerDefault,
            tacacs_type: tacacsrs_protocol::enumerations::TacacsType::TacPlusAccounting,
            seq_no: 1,
            flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
            session_id,
            length: body.len().try_into()?,
        },
        body,
    )?;
    let delayed = tokio::spawn(async move {
        let reply = retained.round_trip(delayed_packet).await?;
        Ok::<_, anyhow::Error>((retained, reply))
    });
    tokio::time::timeout(Duration::from_secs(3), request_observed).await??;
    let remaining = fixture
        .expires_at
        .duration_since(std::time::SystemTime::now())
        .unwrap_or_default();
    tokio::time::timeout(
        remaining + Duration::from_secs(3),
        tokio::time::sleep(remaining + Duration::from_secs(1)),
    )
    .await?;
    let _ = release_reply.send(());
    let (mut retained, reply) = tokio::time::timeout(Duration::from_secs(3), delayed).await???;
    assert_eq!(reply.header().seq_no, 2);
    tokio::time::timeout(
        Duration::from_secs(3),
        client.execute(AccountingExchange::new(accounting_request())),
    )
    .await??;
    assert_eq!(counters.snapshot().connection_opens, 1);
    retained.complete().await;
    client
        .close_and_join(tacacsrs_networking::RequestDeadline::after(Duration::from_secs(2))?)
        .await?;
    let expired_client = TacacsClient::connect_prepared(endpoint).await?;
    let error = tokio::time::timeout(
        Duration::from_secs(3),
        expired_client.execute_classified(AccountingExchange::new(accounting_request())),
    )
    .await?
    .unwrap_err();
    assert_eq!(error.transmission_state(), tacacsrs_networking::TransmissionState::NotSent);
    tokio::time::timeout(Duration::from_secs(3), peer).await???;
    Ok(())
}

#[tokio::test]
async fn inline_client_certificate_expiry_preserves_supervised_catalog() -> Result<()> {
    use std::sync::Arc;
    use tacacsrs_agent::{EnabledServices, RuntimeHealthPublisher, ServiceConfig, TacacsClientService};
    use tacacsrs_agent::runtime::{ConfigSupervisor, NoopTacacsPlusFilter};
    use tacacsrs_config::source::{ConfigDatastore, StaticDatastore};
    let fixture = certificate_source("127.0.0.1:449".parse()?, Duration::from_secs(2))?;
    let source = fixture.source;
    let original = source.clone();
    let datastore = Arc::new(StaticDatastore::new(source));
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let service = Arc::new(TacacsClientService::waiting_for_configuration(
        ServiceConfig {
            local_services: tacacsrs_config::tacacsrs::LocalServices::default(),
            tacacs_plus: TacacsPlus::empty(),
            validation_options: ValidationOptions::default(),
            runtime_policy: tacacsrs_agent::RuntimePolicy::default(),
            disable_certificate_verification: true,
        },
        health.clone(),
    )?);
    let mut supervisor = ConfigSupervisor::new(
        datastore.clone(),
        service.clone(),
        health.clone(),
        Arc::new(NoopTacacsPlusFilter::default()),
    );
    supervisor.initialize_until(std::future::pending()).await?;
    assert_eq!(
        health
            .snapshot()
            .credential_validity()
            .and_then(tacacsrs_credential_resolution::CredentialValidity::valid_until),
        None
    );
    assert_eq!(service.server_count(), 1);
    let counter_epoch = service.statistics().servers[0].counter_epoch;
    let cancellation = tokio_util::sync::CancellationToken::new();
    let monitor = supervisor.run_until(cancellation.cancelled());
    tokio::pin!(monitor);
    assert!(futures_util::poll!(&mut monitor).is_pending());
    let remaining = fixture
        .expires_at
        .duration_since(std::time::SystemTime::now())
        .unwrap_or_default();
    tokio::time::sleep(remaining + Duration::from_secs(1)).await;
    assert!(futures_util::poll!(&mut monitor).is_pending());
    service
        .reload_runtime_policy(tacacsrs_agent::RuntimePolicy::default())
        .await?;
    assert_eq!(service.server_count(), 1);
    assert_eq!(service.statistics().servers[0].counter_epoch, counter_epoch);
    assert_eq!(
        health
            .snapshot()
            .credential_validity()
            .and_then(tacacsrs_credential_resolution::CredentialValidity::valid_until),
        None
    );
    assert_eq!(datastore.load().await?, original);
    cancellation.cancel();
    monitor.await?;
    Ok(())
}

#[tokio::test]
async fn unchanged_provider_refresh_after_certificate_expiry_reuses_catalog_and_connection(
) -> Result<()> {
    use std::sync::Arc;
    use tacacsrs_agent::{EnabledServices, RuntimeHealthPublisher, ServiceConfig, TacacsClientService};
    use tacacsrs_agent::runtime::{ConfigSupervisor, NoopTacacsPlusFilter};
    use tacacsrs_config::source::{ConfigDatastore, StaticDatastore};
    use tacacsrs_protocol::operations::AccountingOperation;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fixture = certificate_source(listener.local_addr()?, Duration::from_secs(2))?;
    let mut source = fixture.source;
    source.server[0]
        .client_identity
        .as_mut()
        .context("test client identity")?
        .certificate = Some(tacacsrs_config::ClientIdentityCertificate {
        inline_definition: None,
        central_keystore_reference: Some(
            tacacsrs_config::keystore::EndEntityCertWithKeyCentralKeystoreReference {
                asymmetric_key: Some("test-provider-key".to_owned()),
                certificate: Some("test-provider-certificate".to_owned()),
            },
        ),
    });
    let original = source.clone();
    let now = std::time::SystemTime::now();
    let initial_validity = CredentialValidity::new(None, Some(now + Duration::from_secs(8)))?;
    let refreshed_valid_until = now + Duration::from_secs(30);
    let refreshed_validity = CredentialValidity::new(None, Some(refreshed_valid_until))?;
    let resolver = Arc::new(RefreshingIdentityResolver {
        certificate: fixture.certificate,
        private_key: fixture.private_key,
        initial_validity,
        refreshed_validity,
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    let datastore = Arc::new(StaticDatastore::new(source));
    let health = RuntimeHealthPublisher::new(EnabledServices::CLIENT_API);
    let service = Arc::new(TacacsClientService::waiting_for_configuration(
        ServiceConfig {
            local_services: tacacsrs_config::tacacsrs::LocalServices::default(),
            tacacs_plus: TacacsPlus::empty(),
            validation_options: ValidationOptions::default(),
            runtime_policy: tacacsrs_agent::RuntimePolicy::default(),
            disable_certificate_verification: true,
        },
        health.clone(),
    )?);
    let mut supervisor = ConfigSupervisor::new(
        datastore.clone(),
        service.clone(),
        health.clone(),
        Arc::new(NoopTacacsPlusFilter::default()),
    )
    .with_credential_resolver(resolver.clone());
    supervisor.initialize_until(std::future::pending()).await?;
    let initial_statistics = service.statistics();
    let counter_epoch = initial_statistics.servers[0].counter_epoch;
    let initial_materialization = health
        .snapshot()
        .materialization_revision()
        .context("initial materialization revision")?;
    let context = fixture.context;
    let operation = AccountingOperation {
        user: "provider-refresh".to_owned(),
        port: "test".to_owned(),
        remote_address: "127.0.0.1".to_owned(),
        command: "show".to_owned(),
        command_arguments: Vec::new(),
    };
    let expected = operation.to_request();
    let peer = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = SslStream::new(Ssl::new(&context)?, tcp)?;
        Pin::new(&mut stream).accept().await?;
        reply_to_expected_accounting(&mut stream, None, true, &expected).await?;
        reply_to_expected_accounting(&mut stream, None, false, &expected).await?;
        assert_eq!(stream.read(&mut [0_u8; 1]).await?, 0);
        Ok::<_, anyhow::Error>(())
    });
    tokio::time::timeout(
        Duration::from_secs(3),
        service.client_api_handle().accounting(operation.clone()),
    )
    .await??;
    let cancellation = tokio_util::sync::CancellationToken::new();
    let stop = cancellation.clone();
    let monitor = tokio::spawn(async move { supervisor.run_until(stop.cancelled()).await });
    tokio::time::timeout(Duration::from_secs(8), async {
        while resolver.calls.load(std::sync::atomic::Ordering::Acquire) < 2 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    assert!(std::time::SystemTime::now() >= fixture.expires_at);
    tokio::time::timeout(Duration::from_secs(3), service.client_api_handle().accounting(operation))
        .await??;
    let statistics = service.statistics();
    let refreshed_health = health.snapshot();
    let refreshed_materialization = refreshed_health
        .materialization_revision()
        .context("refreshed materialization revision")?;
    assert!(statistics.runtime_generation > initial_statistics.runtime_generation);
    assert!(
        refreshed_materialization.credentials().value()
            > initial_materialization.credentials().value()
    );
    assert_eq!(statistics.servers[0].counter_epoch, counter_epoch);
    assert_eq!(statistics.servers[0].statistics.connection_opens, 1);
    assert_eq!(
        refreshed_health
            .credential_validity()
            .and_then(CredentialValidity::valid_until),
        Some(refreshed_valid_until)
    );
    assert_eq!(datastore.load().await?, original);
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(2), monitor).await???;
    service
        .close_and_join(tacacsrs_networking::RequestDeadline::after(Duration::from_secs(2))?)
        .await?;
    tokio::time::timeout(Duration::from_secs(2), peer).await???;
    Ok(())
}

#[tokio::test]
async fn caller_deadline_controls_stalled_tls_after_client_certificate_expiry() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fixture = certificate_source(listener.local_addr()?, Duration::from_secs(2))?;
    let endpoint = prepare_endpoint(
        &fixture.source.server[0],
        PrepareOptions::default().with_certificate_verification_disabled(true),
    )?;
    let client = TacacsClient::connect_prepared(endpoint).await?;
    let (connected, accepted) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let _ = connected.send(());
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await?;
        Ok::<(), anyhow::Error>(())
    });
    let started = tokio::time::Instant::now();
    let request = client.execute_classified_until(
        AccountingExchange::new(accounting_request()),
        tacacsrs_networking::RequestDeadline::after(Duration::from_secs(4))?,
    );
    tokio::pin!(request);
    tokio::select! {
        result = &mut request => panic!("request ended before the stalled peer accepted: {result:?}"),
        result = accepted => result?,
    }
    let error = tokio::time::timeout(Duration::from_secs(6), request)
        .await?
        .unwrap_err();
    assert_eq!(error.transmission_state(), tacacsrs_networking::TransmissionState::NotSent);
    assert!(started.elapsed() >= Duration::from_secs(3));
    client
        .close_and_join(tacacsrs_networking::RequestDeadline::after(Duration::ZERO)?)
        .await?;
    tokio::time::timeout(Duration::from_secs(5), peer).await???;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_certificate_expiry_between_tcp_and_handshake_sends_no_tls_bytes() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let fixture = certificate_source(listener.local_addr()?, Duration::from_secs(2))?;
    let certificate = fixture.certificate.as_slice();
    let endpoint = PreparedEndpoint::tcp(
        listener.local_addr()?.to_string(),
        false,
        None,
        tacacsrs_networking::ConnectOptions::default(),
    )
    .with_certificate_tls(
        "localhost",
        None,
        tacacsrs_networking::CertificateTrust::Certificates {
            authorities: &[],
            end_entities: &[certificate],
        },
        Some(tacacsrs_networking::CertificateIdentity {
            certificate,
            intermediates: &[],
            public_key_info: None,
            private_key: &fixture.private_key,
            private_key_encoding: tacacsrs_networking::PrivateKeyEncoding::Pkcs8,
        }),
    )?
    .with_connection_guard(DelayConnected(Duration::from_secs(3)));
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let mut byte = [0_u8; 1];
        assert_eq!(stream.read(&mut byte).await?, 0);
        Ok::<_, anyhow::Error>(())
    });
    let client = TacacsClient::connect_prepared(endpoint).await?;
    let error = tokio::time::timeout(
        Duration::from_secs(6),
        client.execute_classified(AccountingExchange::new(accounting_request())),
    )
    .await?
    .unwrap_err();
    assert_eq!(error.transmission_state(), tacacsrs_networking::TransmissionState::NotSent);
    assert!(format!("{error:#}").contains("Client certificate validity excludes"));
    tokio::time::timeout(Duration::from_secs(2), peer).await???;
    Ok(())
}

#[tokio::test]
async fn hash_bound_psk_sources_preserve_rotated_handshake_behavior() -> Result<()> {
    tokio::time::timeout(Duration::from_secs(20), async {
        for hash in EpskSupportedHash::ALL {
            let other_hash = match hash {
                EpskSupportedHash::Sha256 => EpskSupportedHash::Sha384,
                EpskSupportedHash::Sha384 => EpskSupportedHash::Sha256,
            };
            for dhe in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").await?;
                for source in referenced_psk_sources(listener.local_addr()?, dhe, *hash)? {
                    let original = source.clone();
                    let (old, _) = materialized_endpoint(&source, ORIGINAL_KEY).await?;
                    let (new, _) = materialized_endpoint(&source, ROTATED_KEY).await?;
                    let old_peer = hash_bound_peer_context(ORIGINAL_KEY, dhe, *hash)?;
                    let new_peer = hash_bound_peer_context(ROTATED_KEY, dhe, *hash)?;
                    let wrong_hash_peer = hash_bound_peer_context(ORIGINAL_KEY, dhe, other_hash)?;
                    exchange_with_peer(&listener, old.clone(), &old_peer, *hash, dhe, true).await?;
                    exchange_with_peer(&listener, new.clone(), &new_peer, *hash, dhe, true).await?;
                    exchange_with_peer(&listener, old.clone(), &new_peer, *hash, dhe, false)
                        .await?;
                    exchange_with_peer(&listener, new, &old_peer, *hash, dhe, false).await?;
                    exchange_with_peer(&listener, old.clone(), &wrong_hash_peer, *hash, dhe, false)
                        .await?;
                    exchange_with_peer(&listener, old, &old_peer, *hash, dhe, true).await?;
                    assert_eq!(source, original);
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await?
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
                    let endpoint = prepare_endpoint(&source.server[0], PrepareOptions::default())?;
                    assert_eq!(endpoint.connection_timeout(), Some(Duration::from_secs(7)));
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
