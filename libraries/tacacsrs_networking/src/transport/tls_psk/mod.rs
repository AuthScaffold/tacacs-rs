//! TLS 1.3 Pre-Shared Key (PSK) transport for TACACS+ connections.
//!
//! Connections are constructed exclusively through
//! [`establish_from_server`], which interprets a [`TacacsPlusServer`]
//! configuration (specifically, the `client-identity.tls13-epsk` container)
//! and performs the TLS-PSK handshake. The internal `PskIdentity` and
//! `PskConfigurationBuilder` helpers are no longer part of the public API;
//! callers should drive the dispatcher in [`crate::config_connect`] instead.
//!
//! [`TacacsPlusServer`]: tacacsrs_config::TacacsPlusServer

mod config_builder;
mod from_server;
mod psk_identity;
#[allow(clippy::module_inception)]
mod tls_psk;

pub(crate) use config_builder::PskConfigurationBuilder;
pub(crate) use from_server::{PskDheKeGroups, establish_from_server, server_has_psk};
pub(crate) use psk_identity::PskIdentity;

use openssl::ssl::{SslContext, SslMethod, SslVerifyMode, SslVersion};

/// Creates an OpenSSL `SslContext` configured for TLS 1.3 PSK.
///
/// This is used internally by [`PskConfigurationBuilder`].
///
/// # Arguments
///
/// * `psk` - The pre-shared key identity and secret
/// * `ciphersuites` - Optional TLS 1.3 ciphersuites override. If `None`, defaults
///   to `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`.
fn create_psk_ssl_context(
    psk: &PskIdentity,
    ciphersuites: Option<&str>,
    psk_dhe_ke_groups: Option<&PskDheKeGroups>,
) -> anyhow::Result<SslContext> {
    let mut ctx_builder = SslContext::builder(SslMethod::tls_client())?;

    // Restrict to TLS 1.3 only
    ctx_builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    ctx_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // For PSK-only mode, we don't verify server certificates
    ctx_builder.set_verify(SslVerifyMode::NONE);

    // Set the PSK client callback
    let psk_identity = psk.identity().to_owned();
    let psk_key = psk.key().to_vec();

    ctx_builder.set_psk_client_callback(move |_ssl, _hint, identity_out, psk_out| {
        // Write the PSK identity (null-terminated C string)
        let identity_bytes = psk_identity.as_bytes();
        if identity_bytes.len() + 1 > identity_out.len() {
            log::error!(
                target: module_path!(),
                "PSK identity buffer too small: need {} bytes, have {}",
                identity_bytes.len() + 1,
                identity_out.len()
            );
            return Err(openssl::error::ErrorStack::get());
        }

        identity_out[..identity_bytes.len()].copy_from_slice(identity_bytes);
        identity_out[identity_bytes.len()] = 0; // null terminator

        // Write the PSK key
        if psk_key.len() > psk_out.len() {
            log::error!(
                target: module_path!(),
                "PSK key buffer too small: need {} bytes, have {}",
                psk_key.len(),
                psk_out.len()
            );
            return Err(openssl::error::ErrorStack::get());
        }

        psk_out[..psk_key.len()].copy_from_slice(&psk_key);

        log::debug!(
            target: module_path!(),
            "Provided PSK for TLS 1.3 handshake (identity: {})",
            std::str::from_utf8(identity_bytes).unwrap_or("<invalid utf8>")
        );

        Ok(psk_key.len())
    });

    // Set TLS 1.3 ciphersuites compatible with PSK
    let ciphersuites = ciphersuites.unwrap_or("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256");
    ctx_builder.set_ciphersuites(ciphersuites)?;

    if let Some(groups) = psk_dhe_ke_groups {
        ctx_builder
            .set_groups_list(groups.as_openssl_list())
            .map_err(|error| groups.unsupported_error(&error))?;
    }

    Ok(ctx_builder.build())
}
