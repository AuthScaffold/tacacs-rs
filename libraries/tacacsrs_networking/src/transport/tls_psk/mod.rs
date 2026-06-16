//! TLS 1.3 Pre-Shared Key (PSK) transport for TACACS+ connections.
//!
//! Connections are constructed exclusively through
//! [`establish_from_server`], which interprets a [`TacacsPlusServer`]
//! configuration (specifically, the `client-identity.tls13-epsk` container)
//! and performs the TLS-PSK handshake. The internal `PskIdentity` and
//! `PskClientConfig` helpers are not part of the public API; callers should
//! drive the dispatcher in [`crate::establish`] instead.
//!
//! [`TacacsPlusServer`]: tacacsrs_config::TacacsPlusServer

mod config_builder;
mod from_server;
mod psk_identity;
mod tls13_psk_session;
#[allow(clippy::module_inception)]
mod tls_psk;

pub(crate) use config_builder::PskClientConfig;
pub(crate) use from_server::{PskDheKeGroups, PskHandshakeHash, establish_from_server, server_has_psk};
pub(crate) use psk_identity::PskIdentity;

use anyhow::Context;
use openssl::ssl::{SslContext, SslMethod, SslVerifyMode, SslVersion};

use self::tls13_psk_session::set_tls13_psk_use_session_callback;

/// Creates an OpenSSL `SslContext` configured for TLS 1.3 PSK.
///
/// This is used internally by [`PskClientConfig`].
///
/// # Arguments
///
/// * `psk` - The pre-shared key identity and secret
/// * `handshake_hash` - The configured externally established PSK handshake hash.
fn create_psk_ssl_context(
    psk: &PskIdentity,
    handshake_hash: PskHandshakeHash,
    psk_dhe_ke_groups: Option<&PskDheKeGroups>,
) -> anyhow::Result<SslContext> {
    let mut ctx_builder = SslContext::builder(SslMethod::tls_client())
        .context("OpenSSL failed to create a TLS 1.3 PSK client context builder")?;

    ctx_builder
        .set_min_proto_version(Some(SslVersion::TLS1_3))
        .context("OpenSSL failed to enforce TLS 1.3 as the minimum PSK protocol version")?;
    ctx_builder
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .context("OpenSSL failed to enforce TLS 1.3 as the maximum PSK protocol version")?;

    ctx_builder.set_verify(SslVerifyMode::NONE);

    set_tls13_psk_use_session_callback(&mut ctx_builder, psk, handshake_hash)
        .context("OpenSSL failed to register TLS 1.3 PSK session callback")?;

    ctx_builder
        .set_ciphersuites(handshake_hash.tls13_ciphersuites())
        .with_context(|| {
            format!(
                "OpenSSL failed to apply TLS 1.3 PSK ciphersuite {}",
                handshake_hash.tls13_ciphersuites()
            )
        })?;

    if let Some(groups) = psk_dhe_ke_groups {
        ctx_builder
            .set_groups_list(groups.as_openssl_list())
            .map_err(|error| groups.unsupported_error(&error))?;
    }

    Ok(ctx_builder.build())
}
