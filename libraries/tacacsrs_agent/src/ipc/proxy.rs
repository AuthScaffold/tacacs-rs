//! Raw TACACS+ proxy listener.
//!
//! The proxy accepts one downstream TACACS+ session per local connection,
//! rewrites only the TACACS+ session id, and forwards packet bodies unchanged
//! through the routed upstream session selected by [`crate::routing`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_config::TacacsPlusServer;
use tacacsrs_flow_abstractions::client_session_flow_io::ClientSessionFlowIoTrait;
use tacacsrs_messages::accounting::reply::AccountingReply;
use tacacsrs_messages::authentication::reply::AuthenticationReply;
use tacacsrs_messages::authorization::reply::AuthorizationReply;
use tacacsrs_messages::enumerations::{
    TacacsAccountingStatus, TacacsAuthenticationStatus, TacacsAuthorizationStatus, TacacsFlags,
    TacacsType,
};
use tacacsrs_messages::packet::{Packet, PacketTrait};
use tacacsrs_networking::{
    PacketReadResult, PacketReader, PacketReaderTrait, PacketWriteResult, PacketWriter,
    PacketWriterTrait,
};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::routing::{BoundServer, ClientGuard, RoutingState};
use crate::runtime::shutdown_signal;

#[cfg(unix)]
use super::listener;

/// Serves the configured TACACS+ proxy endpoint until process shutdown is signalled.
#[cfg(unix)]
pub(crate) async fn serve(
    endpoint: &IpcEndpoint,
    state: Arc<RoutingState>,
    socket_mode: u32,
) -> anyhow::Result<()> {
    match endpoint {
        IpcEndpoint::Unix(path) => serve_unix(path, state, socket_mode).await,
        IpcEndpoint::Tcp(address) => serve_tcp(*address, state).await,
    }
}

/// Serves the configured TACACS+ proxy endpoint until process shutdown is signalled.
#[cfg(not(unix))]
pub(crate) async fn serve(endpoint: &IpcEndpoint, state: Arc<RoutingState>) -> anyhow::Result<()> {
    match endpoint {
        IpcEndpoint::Tcp(address) => serve_tcp(*address, state).await,
    }
}

async fn serve_tcp(address: SocketAddr, state: Arc<RoutingState>) -> anyhow::Result<()> {
    if !address.ip().is_loopback() {
        log::error!("Refusing non-loopback TCP TACACS+ proxy endpoint: {address}");
        bail!("TCP TACACS+ proxy endpoint must be loopback-only: {address}");
    }

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("Failed to bind TCP TACACS+ proxy endpoint {address}"))?;
    let local_address = listener
        .local_addr()
        .with_context(|| format!("Failed to inspect TCP TACACS+ proxy endpoint {address}"))?;

    log::info!("Listening for TACACS+ proxy clients on TCP {local_address}");
    accept_loop(listener, state, format!("TCP {local_address}")).await
}

#[cfg(unix)]
async fn serve_unix(
    path: &std::path::Path,
    state: Arc<RoutingState>,
    socket_mode: u32,
) -> anyhow::Result<()> {
    let listener = listener::prepare_unix_listener(path, socket_mode).await?;
    let socket_guard = listener::UnixSocketCleanupGuard::new(path);

    log::info!("Listening for TACACS+ proxy clients on Unix socket {}", path.display());
    let result = accept_loop(listener, state, format!("Unix socket {}", path.display())).await;
    socket_guard.cleanup("TACACS+ proxy Unix socket").await?;
    result
}

async fn accept_loop<Listener, Stream>(
    listener: Listener,
    state: Arc<RoutingState>,
    endpoint_label: String,
) -> anyhow::Result<()>
where
    Listener: ProxyListener<Stream>,
    Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut shutdown = Box::pin(shutdown_signal());

    loop {
        tokio::select! {
            () = &mut shutdown => {
                log::info!("Shutdown signal received; stopping TACACS+ proxy listener on {endpoint_label}");
                break;
            }
            accepted = listener.accept_proxy_stream() => {
                let (stream, peer_label) = accepted?;
                let client_guard = state.start_client_request();
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(stream, state, peer_label.clone(), client_guard).await {
                        log::warn!("TACACS+ proxy connection {peer_label} closed with error: {error:#}");
                    }
                });
            }
        }
    }

    state.wait_for_active_clients().await;
    Ok(())
}

#[async_trait::async_trait]
trait ProxyListener<Stream>: Send + Sync {
    async fn accept_proxy_stream(&self) -> anyhow::Result<(Stream, String)>;
}

#[async_trait::async_trait]
impl ProxyListener<tokio::net::TcpStream> for tokio::net::TcpListener {
    async fn accept_proxy_stream(&self) -> anyhow::Result<(tokio::net::TcpStream, String)> {
        let (stream, address) = self
            .accept()
            .await
            .context("Failed to accept TCP TACACS+ proxy connection")?;
        Ok((stream, address.to_string()))
    }
}

#[cfg(unix)]
#[async_trait::async_trait]
impl ProxyListener<tokio::net::UnixStream> for tokio::net::UnixListener {
    async fn accept_proxy_stream(&self) -> anyhow::Result<(tokio::net::UnixStream, String)> {
        let (stream, address) = self
            .accept()
            .await
            .context("Failed to accept Unix TACACS+ proxy connection")?;
        let peer_label = address
            .as_pathname()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "anonymous-unix-peer".to_owned());
        Ok((stream, peer_label))
    }
}

async fn handle_connection<Stream>(
    stream: Stream,
    state: Arc<RoutingState>,
    peer_label: String,
    _client_guard: ClientGuard,
) -> anyhow::Result<()>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send,
{
    let bound_server = state.bind_server_for_new_session().await.with_context(|| {
        format!("Failed to bind TACACS+ proxy client {peer_label} to an upstream server")
    })?;

    log::debug!(
        "Proxying TACACS+ client {peer_label} via {} (server index {})",
        bound_server.connection.server_address(),
        bound_server.index,
    );

    match proxy_bound_connection(stream, &bound_server).await {
        Ok(()) => Ok(()),
        Err(ProxyConnectionError::Upstream(error)) => {
            state.note_bound_server_failure(&bound_server).await;
            Err(error)
        }
        Err(ProxyConnectionError::Downstream(error)) => Err(error),
    }
}

async fn proxy_bound_connection<Stream>(
    stream: Stream,
    bound_server: &BoundServer,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send,
{
    let server = bound_server.server();
    let timeout = bound_server.timeout_duration();
    let obfuscation_key = server
        .shared_secret
        .as_ref()
        .map(|secret| secret.as_bytes().to_vec());
    let upstream_session = bound_server
        .connection
        .create_raw_session()
        .await
        .map_err(|error| {
            ProxyConnectionError::Upstream(error.context("Failed to create upstream proxy session"))
        })?;

    proxy_connection_with_session(stream, server, timeout, obfuscation_key, &upstream_session).await
}

async fn proxy_connection_with_session<Stream, Session>(
    mut stream: Stream,
    server: &TacacsPlusServer,
    timeout: Duration,
    obfuscation_key: Option<Vec<u8>>,
    upstream_session: &Session,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send,
    Session: ClientSessionFlowIoTrait + Sync + ?Sized,
{
    let reader = PacketReader::new(obfuscation_key.clone());
    let writer = PacketWriter::new(obfuscation_key);
    let result =
        proxy_connection_loop(&mut stream, server, timeout, &reader, &writer, upstream_session)
            .await;

    upstream_session.complete().await;
    result
}

async fn proxy_connection_loop<Stream, Session>(
    stream: &mut Stream,
    server: &TacacsPlusServer,
    timeout: Duration,
    reader: &PacketReader,
    writer: &PacketWriter,
    upstream_session: &Session,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncRead + AsyncWrite + Unpin + Send,
    Session: ClientSessionFlowIoTrait + Sync + ?Sized,
{
    let mut downstream_session_id = None;
    let upstream_session_id = upstream_session.session_id();

    loop {
        let downstream_packet = read_downstream_packet(reader, stream, timeout).await?;
        validate_downstream_obfuscation(&downstream_packet, server)?;

        let packet_session_id = downstream_packet.header().session_id;
        match downstream_session_id {
            Some(expected) if expected != packet_session_id => {
                return Err(ProxyConnectionError::Downstream(anyhow::anyhow!(
                    "TACACS+ proxy connection attempted session id {packet_session_id:#x} after starting session {expected:#x}"
                )));
            }
            Some(_) => {}
            None => {
                downstream_session_id = Some(packet_session_id);
            }
        }

        let downstream_session_id = downstream_session_id.expect("session id was just set");
        let upstream_packet = rewrite_session_id(&downstream_packet, upstream_session_id)
            .map_err(ProxyConnectionError::Downstream)?;
        upstream_session
            .send_packet(upstream_packet)
            .await
            .map_err(|error| {
                ProxyConnectionError::Upstream(
                    error.context("Failed to send proxied packet upstream"),
                )
            })?;

        let upstream_reply = read_upstream_packet(upstream_session, timeout).await?;
        let action = reply_action(&upstream_reply);
        let downstream_reply = rewrite_session_id(&upstream_reply, downstream_session_id)
            .map_err(ProxyConnectionError::Upstream)?;
        write_downstream_packet(writer, stream, downstream_reply).await?;

        match action {
            ReplyAction::Continue => {}
            ReplyAction::Complete => {
                return Ok(());
            }
            ReplyAction::Unsupported(status) => {
                log::warn!("Closing TACACS+ proxy session after unsupported reply status {status}");
                return Ok(());
            }
        }
    }
}

async fn read_downstream_packet<Stream>(
    reader: &PacketReader,
    stream: &mut Stream,
    timeout: Duration,
) -> Result<Packet, ProxyConnectionError>
where
    Stream: AsyncRead + Unpin + Send,
{
    let result = tokio::time::timeout(timeout, reader.read_packet(stream))
        .await
        .map_err(|_| {
            ProxyConnectionError::Downstream(anyhow::anyhow!(
                "Timed out waiting for downstream TACACS+ packet after {timeout:?}"
            ))
        })?;

    packet_read_result_to_result(result).map_err(ProxyConnectionError::Downstream)
}

async fn read_upstream_packet<Session>(
    upstream_session: &Session,
    timeout: Duration,
) -> Result<Packet, ProxyConnectionError>
where
    Session: ClientSessionFlowIoTrait + Sync + ?Sized,
{
    tokio::time::timeout(timeout, upstream_session.receive_packet())
        .await
        .map_err(|_| {
            ProxyConnectionError::Upstream(anyhow::anyhow!(
                "Timed out waiting for upstream TACACS+ reply after {timeout:?}"
            ))
        })?
        .map_err(|error| {
            ProxyConnectionError::Upstream(
                error.context("Failed to receive upstream TACACS+ reply"),
            )
        })
}

async fn write_downstream_packet<Stream>(
    writer: &PacketWriter,
    stream: &mut Stream,
    packet: Packet,
) -> Result<(), ProxyConnectionError>
where
    Stream: AsyncWrite + Unpin + Send,
{
    match writer.write_packet(stream, packet).await {
        PacketWriteResult::Success => Ok(()),
        PacketWriteResult::WriteError(error) => Err(ProxyConnectionError::Downstream(
            anyhow::Error::new(error).context("Failed to write TACACS+ proxy reply downstream"),
        )),
    }
}

fn packet_read_result_to_result(result: PacketReadResult) -> anyhow::Result<Packet> {
    match result {
        PacketReadResult::Success(packet) => Ok(packet),
        PacketReadResult::HeaderReadError(error) => {
            Err(anyhow::Error::new(error).context("Failed to read TACACS+ proxy header"))
        }
        PacketReadResult::HeaderParseError(error) => {
            Err(error.context("Failed to parse TACACS+ proxy header"))
        }
        PacketReadResult::BodyLengthExceeded {
            session_id,
            body_length,
            max_length,
        } => bail!(
            "TACACS+ proxy packet for session {session_id:#x} declared body length {body_length}, exceeding maximum {max_length}"
        ),
        PacketReadResult::BodyReadError { session_id, error } => Err(anyhow::Error::new(error)
            .context(format!("Failed to read TACACS+ proxy body for session {session_id:#x}"))),
        PacketReadResult::PacketCreateError { session_id, error } => Err(error.context(format!(
            "Failed to create TACACS+ proxy packet for session {session_id:#x}"
        ))),
    }
}

fn validate_downstream_obfuscation(
    packet: &Packet,
    server: &TacacsPlusServer,
) -> Result<(), ProxyConnectionError> {
    if server.shared_secret.is_some()
        || packet
            .header()
            .flags
            .contains(TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG)
    {
        return Ok(());
    }

    Err(ProxyConnectionError::Downstream(anyhow::anyhow!(
        "Downstream TACACS+ packet for session {:#x} is obfuscated, but selected upstream server {} has no shared secret",
        packet.header().session_id,
        server.name,
    )))
}

fn rewrite_session_id(packet: &Packet, session_id: u32) -> anyhow::Result<Packet> {
    let mut header = packet.header().clone();
    header.session_id = session_id;
    Packet::new(header, packet.body().clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplyAction {
    Continue,
    Complete,
    Unsupported(u8),
}

fn reply_action(packet: &Packet) -> ReplyAction {
    match packet.header().tacacs_type {
        TacacsType::TacPlusAccounting => accounting_reply_action(packet),
        TacacsType::TacPlusAuthorisation => authorization_reply_action(packet),
        TacacsType::TacPlusAuthentication => authentication_reply_action(packet),
    }
}

fn accounting_reply_action(packet: &Packet) -> ReplyAction {
    let status = AccountingReply::status_from_packet(packet).unwrap_or_default();
    match TacacsAccountingStatus::try_from(status) {
        Ok(
            TacacsAccountingStatus::TacPlusAcctStatusSuccess
            | TacacsAccountingStatus::TacPlusAcctStatusError
            | TacacsAccountingStatus::TacPlusAcctStatusFollow,
        ) => ReplyAction::Complete,
        Err(_) => ReplyAction::Unsupported(status),
    }
}

fn authorization_reply_action(packet: &Packet) -> ReplyAction {
    let status = AuthorizationReply::status_from_packet(packet).unwrap_or_default();
    match TacacsAuthorizationStatus::try_from(status) {
        Ok(
            TacacsAuthorizationStatus::TacPlusPassAdd
            | TacacsAuthorizationStatus::TacPlusPassRepl
            | TacacsAuthorizationStatus::TacPlusFail
            | TacacsAuthorizationStatus::TacPlusError
            | TacacsAuthorizationStatus::TacPlusFollow,
        ) => ReplyAction::Complete,
        Err(_) => ReplyAction::Unsupported(status),
    }
}

fn authentication_reply_action(packet: &Packet) -> ReplyAction {
    let status = AuthenticationReply::status_from_packet(packet).unwrap_or_default();
    match TacacsAuthenticationStatus::try_from(status) {
        Ok(
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetdata
            | TacacsAuthenticationStatus::TacPlusAuthenStatusGetuser
            | TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
        ) => ReplyAction::Continue,
        Ok(
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass
            | TacacsAuthenticationStatus::TacPlusAuthenStatusFail
            | TacacsAuthenticationStatus::TacPlusAuthenStatusRestart
            | TacacsAuthenticationStatus::TacPlusAuthenStatusError
            | TacacsAuthenticationStatus::TacPlusAuthenStatusFollow,
        ) => ReplyAction::Complete,
        Err(_) => ReplyAction::Unsupported(status),
    }
}

#[derive(Debug)]
enum ProxyConnectionError {
    Downstream(anyhow::Error),
    Upstream(anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use tacacsrs_messages::accounting::reply::ACCOUNTING_REPLY_STATUS_OFFSET;
    use tacacsrs_messages::authentication::reply::AUTHENTICATION_REPLY_STATUS_OFFSET;
    use tacacsrs_messages::authorization::reply::AUTHORIZATION_REPLY_STATUS_OFFSET;
    use tacacsrs_messages::enumerations::{
        TacacsAuthenticationReplyFlags, TacacsMajorVersion, TacacsMinorVersion,
    };
    use tacacsrs_messages::header::Header;
    use tacacsrs_messages::traits::TacacsBodyTrait;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;

    fn test_packet(tacacs_type: TacacsType, session_id: u32, body: Vec<u8>) -> Packet {
        Packet::new(
            Header {
                major_version: TacacsMajorVersion::TacacsPlusMajor1,
                minor_version: TacacsMinorVersion::TacacsPlusMinorVerDefault,
                tacacs_type,
                seq_no: 2,
                flags: TacacsFlags::TAC_PLUS_UNENCRYPTED_FLAG,
                session_id,
                length: u32::try_from(body.len()).unwrap(),
            },
            body,
        )
        .unwrap()
    }

    fn accounting_reply_body(status: TacacsAccountingStatus) -> Vec<u8> {
        AccountingReply {
            status,
            server_msg: "ok".to_owned(),
            data: "display".to_owned(),
        }
        .to_bytes()
        .unwrap()
    }

    fn authorization_reply_body(status: TacacsAuthorizationStatus) -> Vec<u8> {
        AuthorizationReply {
            status,
            server_msg: "ok".to_owned(),
            data: "display".to_owned(),
            args: vec!["priv-lvl=15".to_owned()],
        }
        .to_bytes()
        .unwrap()
    }

    fn authentication_reply_body(status: TacacsAuthenticationStatus) -> Vec<u8> {
        AuthenticationReply {
            status,
            flags: TacacsAuthenticationReplyFlags::empty(),
            server_msg: "ok".to_owned(),
            data: vec![1, 2, 3],
        }
        .to_bytes()
        .unwrap()
    }

    fn test_server() -> TacacsPlusServer {
        TacacsPlusServer {
            name: "server".to_owned(),
            server_type: tacacsrs_config::TacacsPlusServerType::AUTHENTICATION
                | tacacsrs_config::TacacsPlusServerType::AUTHORIZATION
                | tacacsrs_config::TacacsPlusServerType::ACCOUNTING,
            address: "127.0.0.1".to_owned(),
            port: 49,
            shared_secret: None,
            timeout: 5,
            single_connection: false,
            domain_name: None,
            sni_enabled: None,
            client_identity: None,
            server_authentication: None,
            source_ip: None,
            source_interface: None,
            vrf_instance: None,
        }
    }

    #[derive(Default)]
    struct FakeProxySession {
        complete: AtomicBool,
        next_sequence_number: AtomicU8,
        received_packets: Mutex<Vec<Packet>>,
        replies: Mutex<VecDeque<Packet>>,
        session_id: u32,
    }

    impl FakeProxySession {
        fn new(session_id: u32, replies: Vec<Packet>) -> Self {
            Self {
                complete: AtomicBool::new(false),
                next_sequence_number: AtomicU8::new(1),
                received_packets: Mutex::default(),
                replies: Mutex::new(replies.into()),
                session_id,
            }
        }
    }

    #[async_trait::async_trait]
    impl ClientSessionFlowIoTrait for FakeProxySession {
        async fn is_complete(&self) -> bool {
            self.complete.load(Ordering::Acquire)
        }

        async fn next_sequence_number(&self) -> u8 {
            self.next_sequence_number.fetch_add(2, Ordering::AcqRel)
        }

        fn session_id(&self) -> u32 {
            self.session_id
        }

        async fn send_packet(&self, packet: Packet) -> anyhow::Result<()> {
            self.received_packets.lock().await.push(packet);
            Ok(())
        }

        async fn receive_packet(&self) -> anyhow::Result<Packet> {
            self.replies
                .lock()
                .await
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("missing fake proxy reply"))
        }

        async fn complete(&self) {
            self.complete.store(true, Ordering::Release);
        }
    }

    async fn write_packet(stream: &mut tokio::io::DuplexStream, packet: &Packet) {
        stream
            .write_all(&packet.to_bytes())
            .await
            .expect("packet should write");
    }

    async fn read_packet(stream: &mut tokio::io::DuplexStream) -> Packet {
        let reader = PacketReader::new(None);
        match reader.read_packet(stream).await {
            PacketReadResult::Success(packet) => packet,
            _ => panic!("packet should read"),
        }
    }

    #[test]
    fn rewrite_session_id_preserves_body_and_header_fields() {
        let packet = test_packet(TacacsType::TacPlusAccounting, 0x1111_2222, b"body".to_vec());

        let rewritten = rewrite_session_id(&packet, 0x3333_4444).unwrap();

        assert_eq!(rewritten.header().session_id, 0x3333_4444);
        assert_eq!(rewritten.header().tacacs_type, packet.header().tacacs_type);
        assert_eq!(rewritten.header().seq_no, packet.header().seq_no);
        assert_eq!(rewritten.header().flags, packet.header().flags);
        assert_eq!(rewritten.body(), packet.body());
    }

    #[test]
    fn reply_action_classifies_accounting_statuses() {
        for status in [
            TacacsAccountingStatus::TacPlusAcctStatusSuccess,
            TacacsAccountingStatus::TacPlusAcctStatusError,
            TacacsAccountingStatus::TacPlusAcctStatusFollow,
        ] {
            assert_eq!(
                reply_action(&test_packet(
                    TacacsType::TacPlusAccounting,
                    1,
                    accounting_reply_body(status),
                )),
                ReplyAction::Complete,
            );
        }
    }

    #[test]
    fn reply_action_classifies_authorization_statuses() {
        for status in [
            TacacsAuthorizationStatus::TacPlusPassAdd,
            TacacsAuthorizationStatus::TacPlusPassRepl,
            TacacsAuthorizationStatus::TacPlusFail,
            TacacsAuthorizationStatus::TacPlusError,
            TacacsAuthorizationStatus::TacPlusFollow,
        ] {
            assert_eq!(
                reply_action(&test_packet(
                    TacacsType::TacPlusAuthorisation,
                    1,
                    authorization_reply_body(status),
                )),
                ReplyAction::Complete,
            );
        }
    }

    #[test]
    fn reply_action_classifies_unknown_statuses_as_unsupported() {
        let mut accounting_body =
            accounting_reply_body(TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        accounting_body[ACCOUNTING_REPLY_STATUS_OFFSET] = 0xff;
        assert_eq!(
            reply_action(&test_packet(TacacsType::TacPlusAccounting, 1, accounting_body)),
            ReplyAction::Unsupported(0xff),
        );

        let mut authorization_body =
            authorization_reply_body(TacacsAuthorizationStatus::TacPlusPassAdd);
        authorization_body[AUTHORIZATION_REPLY_STATUS_OFFSET] = 0xff;
        assert_eq!(
            reply_action(&test_packet(TacacsType::TacPlusAuthorisation, 1, authorization_body)),
            ReplyAction::Unsupported(0xff),
        );

        let mut authentication_body =
            authentication_reply_body(TacacsAuthenticationStatus::TacPlusAuthenStatusPass);
        authentication_body[AUTHENTICATION_REPLY_STATUS_OFFSET] = 0xff;
        assert_eq!(
            reply_action(&test_packet(TacacsType::TacPlusAuthentication, 1, authentication_body)),
            ReplyAction::Unsupported(0xff),
        );
    }

    #[test]
    fn reply_action_classifies_authentication_statuses() {
        for status in [
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetdata,
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetuser,
            TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass,
        ] {
            assert_eq!(
                reply_action(&test_packet(
                    TacacsType::TacPlusAuthentication,
                    1,
                    authentication_reply_body(status),
                )),
                ReplyAction::Continue,
            );
        }

        for status in [
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass,
            TacacsAuthenticationStatus::TacPlusAuthenStatusFail,
            TacacsAuthenticationStatus::TacPlusAuthenStatusRestart,
            TacacsAuthenticationStatus::TacPlusAuthenStatusError,
            TacacsAuthenticationStatus::TacPlusAuthenStatusFollow,
        ] {
            assert_eq!(
                reply_action(&test_packet(
                    TacacsType::TacPlusAuthentication,
                    1,
                    authentication_reply_body(status),
                )),
                ReplyAction::Complete,
            );
        }
    }

    #[tokio::test]
    async fn proxy_connection_maps_session_id_and_preserves_body() {
        let downstream_session_id = 0x1111_2222;
        let upstream_session_id = 0x3333_4444;
        let request = test_packet(
            TacacsType::TacPlusAccounting,
            downstream_session_id,
            b"request-body".to_vec(),
        );
        let reply_body = accounting_reply_body(TacacsAccountingStatus::TacPlusAcctStatusSuccess);
        let upstream_reply =
            test_packet(TacacsType::TacPlusAccounting, upstream_session_id, reply_body.clone());
        let fake_session = FakeProxySession::new(upstream_session_id, vec![upstream_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &request).await;

        proxy_connection_with_session(
            proxy_stream,
            &test_server(),
            Duration::from_secs(1),
            None,
            &fake_session,
        )
        .await
        .expect("proxy connection should complete");

        let received_packets = fake_session.received_packets.lock().await;
        assert_eq!(received_packets.len(), 1);
        assert_eq!(received_packets[0].header().session_id, upstream_session_id);
        assert_eq!(received_packets[0].body(), request.body());
        assert!(fake_session.is_complete().await);
        drop(received_packets);

        let downstream_reply = read_packet(&mut client_stream).await;
        assert_eq!(downstream_reply.header().session_id, downstream_session_id);
        assert_eq!(downstream_reply.body(), &reply_body);
    }

    #[tokio::test]
    async fn proxy_connection_rejects_second_downstream_session_id() {
        let downstream_session_id = 0x1111_2222;
        let upstream_session_id = 0x3333_4444;
        let first_request = test_packet(
            TacacsType::TacPlusAuthentication,
            downstream_session_id,
            b"first".to_vec(),
        );
        let second_request =
            test_packet(TacacsType::TacPlusAuthentication, 0x5555_6666, b"second".to_vec());
        let continue_reply = test_packet(
            TacacsType::TacPlusAuthentication,
            upstream_session_id,
            authentication_reply_body(TacacsAuthenticationStatus::TacPlusAuthenStatusGetpass),
        );
        let fake_session = FakeProxySession::new(upstream_session_id, vec![continue_reply]);
        let (proxy_stream, mut client_stream) = tokio::io::duplex(4096);

        write_packet(&mut client_stream, &first_request).await;
        write_packet(&mut client_stream, &second_request).await;

        let result = proxy_connection_with_session(
            proxy_stream,
            &test_server(),
            Duration::from_secs(1),
            None,
            &fake_session,
        )
        .await;

        match result {
            Err(ProxyConnectionError::Downstream(error)) => {
                assert!(error.to_string().contains("attempted session id"));
            }
            _ => panic!("expected downstream session-id rejection"),
        }

        let received_packets = fake_session.received_packets.lock().await;
        assert_eq!(received_packets.len(), 1);
        assert_eq!(received_packets[0].header().session_id, upstream_session_id);
        assert!(fake_session.is_complete().await);
    }
}
