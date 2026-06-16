//! TLS 1.3 Pre-Shared Key (PSK) transport for TACACS+ connections.
//!
//! Connections are constructed exclusively through
//! [`establish_from_server`], which interprets a [`TacacsPlusServer`]
//! configuration (specifically, the `client-identity.tls13-epsk` container)
//! and performs the TLS-PSK handshake. The internal `PskIdentity` and
//! `PskConfigurationBuilder` helpers are no longer part of the public API;
//! callers should drive the dispatcher in [`crate::establish`] instead.
//!
//! [`TacacsPlusServer`]: tacacsrs_config::TacacsPlusServer

mod config_builder;
mod from_server;
mod psk_identity;
mod tls13_psk_session;
#[allow(clippy::module_inception)]
mod tls_psk;

pub(crate) use config_builder::PskConfigurationBuilder;
pub(crate) use from_server::{PskDheKeGroups, PskHandshakeHash, establish_from_server, server_has_psk};
pub(crate) use psk_identity::PskIdentity;

use openssl::ssl::{SslContext, SslMethod, SslVerifyMode, SslVersion};

use self::tls13_psk_session::set_tls13_psk_use_session_callback;

/// Creates an OpenSSL `SslContext` configured for TLS 1.3 PSK.
///
/// This is used internally by [`PskConfigurationBuilder`].
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
    let mut ctx_builder = SslContext::builder(SslMethod::tls_client())?;

    // Restrict to TLS 1.3 only
    ctx_builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // For PSK-only mode, we don't verify server certificates
    ctx_builder.set_verify(SslVerifyMode::NONE);

    set_tls13_psk_use_session_callback(&mut ctx_builder, psk, handshake_hash)?;

    ctx_builder.set_ciphersuites(handshake_hash.tls13_ciphersuites())?;

    if let Some(groups) = psk_dhe_ke_groups {
        ctx_builder
            .set_groups_list(groups.as_openssl_list())
            .map_err(|error| groups.unsupported_error(&error))?;
    }

    Ok(ctx_builder.build())
}
