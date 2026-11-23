use std::sync::Arc;

use tokio::sync::watch;

use tacacsrs_config::TacacsPlusServer;
use tacacsrs_config::prepare::PrepareOptions;
use tacacsrs_networking::{
    CertificateVerification, RevocationSettings, RevocationVerifier, TacacsClient,
};
use tacacsrs_protocol::exchange::FixedExchange;
use tacacsrs_revocation::CrlVerifier;

/// Connection settings that every direct-mode connection of one run shares.
///
/// When the configuration enables certificate revocation, the options hold one
/// [`CrlVerifier`]. Certificate TLS connections can reuse its cached CRLs. The
/// verifier does not run a background refresh. A configured `cache-directory`
/// keeps CRLs between runs.
#[derive(Clone)]
pub(crate) struct DirectOptions {
    prepare: PrepareOptions,
    revocation: Option<Arc<dyn RevocationVerifier>>,
}

impl DirectOptions {
    /// Builds the options for one run from the CLI verification flag and the
    /// validated revocation policy.
    pub(crate) fn new(
        verification: CertificateVerification,
        revocation: RevocationSettings,
    ) -> Self {
        let revocation = revocation.enforcement.requires_verifier().then(|| {
            let (_sender, receiver) = watch::channel(revocation);
            Arc::new(CrlVerifier::new(receiver)) as Arc<dyn RevocationVerifier>
        });
        Self {
            prepare: PrepareOptions::default().with_certificate_verification(verification),
            revocation,
        }
    }

    fn prepare_endpoint(
        &self,
        server: &TacacsPlusServer,
    ) -> anyhow::Result<tacacsrs_networking::PreparedEndpoint> {
        let endpoint = tacacsrs_config::prepare::prepare_endpoint(server, self.prepare.clone())?;
        Ok(match &self.revocation {
            Some(verifier) => endpoint.with_revocation_verifier(Arc::clone(verifier)),
            None => endpoint,
        })
    }
}

/// Represents an active TACACS+ connection (either plain TCP or TLS)
#[derive(Clone)]
pub(crate) struct Connection {
    inner: Arc<TacacsClient>,
    server_name: String,
}

impl Connection {
    pub(crate) const fn from_inner(inner: Arc<TacacsClient>, server_name: String) -> Self {
        Self { inner, server_name }
    }

    pub(crate) fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Executes one fixed TACACS+ request/reply exchange.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying exchange fails.
    pub(crate) async fn execute<Exchange>(
        &self,
        exchange: &Exchange,
    ) -> anyhow::Result<Exchange::Reply>
    where
        Exchange: FixedExchange,
    {
        self.inner.execute(exchange).await
    }
}

/// Establishes a multiplexed TACACS+ connection using the given server configuration.
///
/// # Errors
///
/// Returns an error if:
/// - TCP connection cannot be established
/// - TLS is requested but certificate/key are missing or invalid
/// - TLS handshake fails
pub(crate) async fn establish_connection(
    server: &TacacsPlusServer,
    options: &DirectOptions,
) -> anyhow::Result<Connection> {
    let endpoint = options.prepare_endpoint(server)?;
    let connection = TacacsClient::connect_prepared(endpoint).await?;
    Ok(Connection::from_inner(Arc::new(connection), server.name.clone()))
}

/// Establishes a connection with TACACS+ single-connection mode disabled in
/// the effective server configuration.
///
/// Networking follows [`TacacsPlusServer::single_connection`] exactly, so the
/// CLI forces dedicated behavior by modifying a cloned server configuration before
/// handing it to [`TacacsClient`].
///
/// # Errors
///
/// Returns an error if the underlying connection cannot be established.
pub(crate) async fn establish_dedicated_connection(
    server: &TacacsPlusServer,
    options: &DirectOptions,
) -> anyhow::Result<Connection> {
    let mut dedicated_server = server.clone();
    dedicated_server.single_connection = false;
    establish_connection(&dedicated_server, options).await
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use clap::Parser;

    use tacacsrs_config::TacacsPlusServer;
    use tacacsrs_networking::{
        CertificateVerification, DistributionPointPattern, RevocationEnforcement,
        RevocationSettings,
    };

    use super::DirectOptions;
    use crate::cli::Cli;
    use crate::config::tacacs_plus_from_cli;

    fn mtls_server() -> TacacsPlusServer {
        let sample = |name: &str| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../lde/containers/config/certificates")
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        let cli = Cli::parse_from([
            "tacon",
            "--server-addr",
            "192.0.2.10:300",
            "--use-tls",
            "--client-certificate",
            &sample("client.crt"),
            "--client-key",
            &sample("client.key"),
            "accounting",
            "--user",
            "alice",
            "--port",
            "tty0",
            "--rem-addr",
            "192.0.2.50",
            "show",
        ]);
        let root = tacacs_plus_from_cli(&cli).expect("mTLS configuration");
        tacacsrs_config::enumerate_servers(&root)
            .expect("servers")
            .remove(0)
    }

    fn hard_fail() -> RevocationSettings {
        let mut settings = RevocationSettings::default();
        settings.enforcement = RevocationEnforcement::HardFail;
        settings.allowed_distribution_points =
            vec![DistributionPointPattern::parse("http://crl.example/**").expect("pattern")];
        settings
    }

    #[test]
    fn enabled_revocation_attaches_one_shared_verifier_to_mtls_endpoints() {
        let options = DirectOptions::new(CertificateVerification::Required, hard_fail());
        let server = mtls_server();
        assert!(options
            .prepare_endpoint(&server)
            .expect("endpoint")
            .has_revocation_verifier());

        let clone = options.clone();
        let (Some(first), Some(second)) = (&options.revocation, &clone.revocation) else {
            panic!("both options must hold the verifier");
        };
        assert!(Arc::ptr_eq(first, second), "a run must share one CRL cache");
    }

    #[test]
    fn disabled_revocation_attaches_no_verifier() {
        let options =
            DirectOptions::new(CertificateVerification::Required, RevocationSettings::default());
        assert!(!options
            .prepare_endpoint(&mtls_server())
            .expect("endpoint")
            .has_revocation_verifier());
    }
}
