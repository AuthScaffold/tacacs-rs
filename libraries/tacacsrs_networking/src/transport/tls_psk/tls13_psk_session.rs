#![allow(unsafe_code)]

use std::os::raw::{c_int, c_uchar};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use foreign_types::ForeignTypeRef;
use openssl::ex_data::Index;
use openssl::ssl::{SslContext, SslContextBuilder, SslContextRef};
use openssl_sys::{
    EVP_MD, EVP_MD_get_type, EVP_sha256, EVP_sha384, SSL, SSL_CIPHER, SSL_CTX, SSL_SESSION,
    SSL_SESSION_free, SSL_get_SSL_CTX, TLS1_3_VERSION,
};
use tacacsrs_config::generated::tacacs_plus::Tls13Epsk;

use super::{tls13_epsk, PskHandshakeHash};

const TLS_AES_128_GCM_SHA256_WIRE_ID: [c_uchar; 2] = [0x13, 0x01];
const TLS_AES_256_GCM_SHA384_WIRE_ID: [c_uchar; 2] = [0x13, 0x02];

type PskUseSessionCallback = unsafe extern "C" fn(
    ssl: *mut SSL,
    digest: *const EVP_MD,
    identity: *mut *const c_uchar,
    identity_len: *mut usize,
    session: *mut *mut SSL_SESSION,
) -> c_int;

#[derive(Debug)]
struct OpenSslTls13EpskConfig {
    epsk: Tls13Epsk,
}

extern "C" {
    fn SSL_CTX_set_psk_use_session_callback(
        context: *mut SSL_CTX,
        callback: Option<PskUseSessionCallback>,
    );

    fn SSL_SESSION_new() -> *mut SSL_SESSION;

    fn SSL_SESSION_set1_master_key(
        session: *mut SSL_SESSION,
        key: *const c_uchar,
        key_len: usize,
    ) -> c_int;

    fn SSL_SESSION_set_cipher(session: *mut SSL_SESSION, cipher: *const SSL_CIPHER) -> c_int;

    fn SSL_SESSION_set_protocol_version(session: *mut SSL_SESSION, version: c_int) -> c_int;

    fn SSL_CIPHER_find(ssl: *mut SSL, cipher_suite: *const c_uchar) -> *const SSL_CIPHER;
}

/// Configures a TLS 1.3 PSK use-session callback on an OpenSSL context.
///
/// The high-level `openssl` crate currently exposes only the legacy PSK client
/// callback. That callback cannot describe the digest associated with an
/// externally established TLS 1.3 PSK, so OpenSSL treats the PSK as SHA-256.
/// This bridge uses OpenSSL's TLS 1.3 callback directly and keeps the configured
/// EPSK hash bound to the synthetic `SSL_SESSION`.
pub(crate) fn set_tls13_psk_use_session_callback(
    builder: &mut SslContextBuilder,
    epsk: &Tls13Epsk,
) -> Result<()> {
    let index = psk_config_index().context("failed to allocate OpenSSL PSK ex-data index")?;
    let config = OpenSslTls13EpskConfig { epsk: epsk.clone() };

    builder.set_ex_data(index, config);

    // SAFETY: `builder.as_ptr()` is a live `SSL_CTX` owned by the builder, and
    // `psk_use_session_callback` has the exact C ABI required by OpenSSL. The
    // callback state is stored in `SSL_CTX` ex-data above and is dropped with
    // the context by the `openssl` crate.
    unsafe {
        SSL_CTX_set_psk_use_session_callback(builder.as_ptr(), Some(psk_use_session_callback));
    }

    Ok(())
}

pub(super) fn configured_tls13_epsk(context: &SslContext) -> Option<&Tls13Epsk> {
    let index = psk_config_index().ok()?;

    context.ex_data(index).map(|config| &config.epsk)
}

fn psk_config_index(
) -> Result<Index<SslContext, OpenSslTls13EpskConfig>, openssl::error::ErrorStack> {
    static INDEX: OnceLock<Index<SslContext, OpenSslTls13EpskConfig>> = OnceLock::new();

    if let Some(index) = INDEX.get() {
        return Ok(*index);
    }

    let index = SslContext::new_ex_index::<OpenSslTls13EpskConfig>()?;
    Ok(*INDEX.get_or_init(|| index))
}

unsafe extern "C" fn psk_use_session_callback(
    ssl: *mut SSL,
    digest: *const EVP_MD,
    identity: *mut *const c_uchar,
    identity_len: *mut usize,
    session: *mut *mut SSL_SESSION,
) -> c_int {
    if ssl.is_null() || identity.is_null() || identity_len.is_null() || session.is_null() {
        log::error!(target: module_path!(), "OpenSSL invoked TLS 1.3 PSK callback with null argument");
        return 0;
    }

    match build_callback_session(ssl, digest) {
        Some((config, callback_session)) => {
            let identity_bytes = config.epsk.external_identity.as_bytes();
            // SAFETY: OpenSSL consumes these out-parameters before the callback
            // returns. The identity bytes live in the context ex-data for the
            // lifetime of the `SSL_CTX`, and `callback_session` transfers
            // ownership of a newly allocated `SSL_SESSION` to OpenSSL.
            unsafe {
                *identity = identity_bytes.as_ptr();
                *identity_len = identity_bytes.len();
                *session = callback_session;
            }

            log::debug!(
                target: module_path!(),
                "Provided TLS 1.3 PSK session (identity: {}, hash: {})",
                config.epsk.external_identity,
                PskHandshakeHash::from_config(config.epsk.hash).as_name()
            );

            1
        }
        None => 0,
    }
}

unsafe fn build_callback_session(
    ssl: *mut SSL,
    digest: *const EVP_MD,
) -> Option<(&'static OpenSslTls13EpskConfig, *mut SSL_SESSION)> {
    let config = callback_config(ssl)?;
    let handshake_hash = PskHandshakeHash::from_config(config.epsk.hash);

    if !digest.is_null() && !handshake_hash.matches_digest(digest) {
        log::warn!(
            target: module_path!(),
            "OpenSSL requested TLS 1.3 PSK hash that does not match configured hash {}",
            handshake_hash.as_name()
        );
        return None;
    }

    let cipher = handshake_hash.find_cipher(ssl);
    if cipher.is_null() {
        log::error!(
            target: module_path!(),
            "OpenSSL could not find TLS 1.3 cipher suite {}",
            handshake_hash.tls13_ciphersuites()
        );
        return None;
    }

    let callback_session = create_session(config, cipher)?;
    Some((config, callback_session))
}

unsafe fn callback_config(ssl: *mut SSL) -> Option<&'static OpenSslTls13EpskConfig> {
    // SAFETY: `ssl` is the non-null `SSL*` OpenSSL passed to the callback.
    let context = unsafe { SSL_get_SSL_CTX(ssl) };
    if context.is_null() {
        log::error!(target: module_path!(), "OpenSSL TLS 1.3 PSK callback had no SSL context");
        return None;
    }

    let index = match psk_config_index() {
        Ok(index) => index,
        Err(error) => {
            log::error!(target: module_path!(), "Failed to retrieve OpenSSL PSK ex-data index: {error}");
            return None;
        }
    };

    // SAFETY: `context` is the `SSL_CTX*` associated with the callback's `SSL*`.
    // It is owned by OpenSSL and remains valid for the duration of the callback.
    let context = unsafe { SslContextRef::from_ptr(context) };
    context.ex_data(index)
}

unsafe fn create_session(
    config: &OpenSslTls13EpskConfig,
    cipher: *const SSL_CIPHER,
) -> Option<*mut SSL_SESSION> {
    let key = match tls13_epsk::symmetric_key(&config.epsk) {
        Ok(key) => key,
        Err(error) => {
            log::error!(target: module_path!(), "TLS 1.3 EPSK callback has no symmetric key: {error}");
            return None;
        }
    };

    // SAFETY: `SSL_SESSION_new` returns either null or a freshly allocated
    // session owned by the caller until transferred to OpenSSL.
    let session = unsafe { SSL_SESSION_new() };
    if session.is_null() {
        log::error!(target: module_path!(), "OpenSSL failed to allocate TLS 1.3 PSK session");
        return None;
    }

    let configured = unsafe {
        // SAFETY: `session` is newly allocated, `cipher` came from
        // `SSL_CIPHER_find` for the same `SSL*`, and the key slice is valid for
        // the duration of the call. Each OpenSSL setter copies the supplied
        // data into the session.
        SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION) == 1
            && SSL_SESSION_set_cipher(session, cipher) == 1
            && SSL_SESSION_set1_master_key(session, key.as_ptr(), key.len()) == 1
    };

    if configured {
        Some(session)
    } else {
        // SAFETY: The session has not been handed to OpenSSL on this failure
        // path, so this callback remains responsible for releasing it.
        unsafe {
            SSL_SESSION_free(session);
        }
        log::error!(target: module_path!(), "OpenSSL failed to configure TLS 1.3 PSK session");
        None
    }
}

impl PskHandshakeHash {
    unsafe fn find_cipher(self, ssl: *mut SSL) -> *const SSL_CIPHER {
        // SAFETY: `ssl` is the non-null `SSL*` OpenSSL passed to the callback,
        // and the cipher suite ID is the two-byte TLS wire identifier from
        // RFC 8446 Appendix B.4 expected by `SSL_CIPHER_find`.
        unsafe { SSL_CIPHER_find(ssl, self.tls13_cipher_suite_id().as_ptr()) }
    }

    fn matches_digest(self, digest: *const EVP_MD) -> bool {
        let expected = match self {
            Self::Sha256 => unsafe {
                // SAFETY: `EVP_sha256` returns OpenSSL's process-global SHA-256
                // digest descriptor.
                EVP_sha256()
            },
            Self::Sha384 => unsafe {
                // SAFETY: `EVP_sha384` returns OpenSSL's process-global SHA-384
                // digest descriptor.
                EVP_sha384()
            },
        };

        if expected.is_null() {
            return false;
        }

        unsafe {
            // SAFETY: `digest` is the non-null digest pointer OpenSSL supplied
            // to the callback, and `expected` is one of OpenSSL's digest
            // descriptors. Comparing NIDs avoids relying on pointer identity.
            EVP_MD_get_type(digest) == EVP_MD_get_type(expected)
        }
    }

    const fn tls13_cipher_suite_id(self) -> [c_uchar; 2] {
        match self {
            Self::Sha256 => TLS_AES_128_GCM_SHA256_WIRE_ID,
            Self::Sha384 => TLS_AES_256_GCM_SHA384_WIRE_ID,
        }
    }
}
