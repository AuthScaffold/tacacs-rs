#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_void};
use std::os::raw::{c_int, c_uchar};
use std::ptr;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use foreign_types::ForeignTypeRef;
use openssl::ex_data::Index;
use openssl::ssl::{SslContext, SslContextBuilder, SslContextRef};
use openssl_sys::{
    stack_st_SSL_CIPHER, EVP_MD, EVP_MD_get_type, EVP_sha256, EVP_sha384, OPENSSL_STACK,
    OPENSSL_sk_num, OPENSSL_sk_value, SSL, SSL_CIPHER, SSL_CIPHER_standard_name, SSL_CTX,
    SSL_CTX_set_options, SSL_SESSION, SSL_SESSION_free, SSL_get_SSL_CTX, TLS1_3_VERSION,
};
use tacacsrs_config::{EpskSupportedHash, TacacsPlusServer};

use super::{tls13_epsk, EpskSupportedHashExt};

type PskUseSessionCallback = unsafe extern "C" fn(
    ssl: *mut SSL,
    digest: *const EVP_MD,
    identity: *mut *const c_uchar,
    identity_len: *mut usize,
    session: *mut *mut SSL_SESSION,
) -> c_int;

struct OpenSslPskCallbackState {
    server: Arc<TacacsPlusServer>,
}

const SSL_OP_ALLOW_NO_DHE_KEX_BIT: u32 = 10;
const SSL_OP_PREFER_NO_DHE_KEX_BIT: u32 = 35;

extern "C" {
    fn EVP_KDF_fetch(
        library_context: *mut c_void,
        algorithm: *const c_char,
        properties: *const c_char,
    ) -> *mut c_void;

    fn EVP_KDF_free(kdf: *mut c_void);

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

    fn SSL_get_ciphers(ssl: *const SSL) -> *mut stack_st_SSL_CIPHER;
}

/// Returns whether the active OpenSSL provider policy supplies `TLS13-KDF`.
pub(super) fn has_tls13_kdf() -> bool {
    const TLS13_KDF: &[u8] = b"TLS13-KDF\0";

    // SAFETY: The name is a static NUL-terminated C string. Null library and
    // property pointers select the active process OpenSSL provider policy.
    let kdf =
        unsafe { EVP_KDF_fetch(ptr::null_mut(), TLS13_KDF.as_ptr().cast::<c_char>(), ptr::null()) };
    if kdf.is_null() {
        let _ = openssl::error::ErrorStack::get();
        return false;
    }

    // SAFETY: EVP_KDF_fetch returned this non-null owned pointer.
    unsafe { EVP_KDF_free(kdf) };
    true
}

/// Configures a TLS 1.3 PSK use-session callback on an OpenSSL context.
///
/// The high-level `openssl` crate exposes only the legacy PSK client
/// callback. That callback cannot describe the digest associated with an
/// externally established TLS 1.3 PSK, so OpenSSL treats the PSK as SHA-256.
/// This bridge calls OpenSSL's TLS 1.3 callback directly and keeps the configured
/// EPSK hash bound to the synthetic `SSL_SESSION`.
pub(crate) fn set_tls13_psk_use_session_callback(
    builder: &mut SslContextBuilder,
    server: Arc<TacacsPlusServer>,
) -> Result<()> {
    let index = psk_config_index().context("failed to allocate OpenSSL PSK ex-data index")?;
    let state = OpenSslPskCallbackState { server };

    builder.set_ex_data(index, state);

    // SAFETY: The builder owns the live `SSL_CTX` from `builder.as_ptr()`.
    // `psk_use_session_callback` has the exact C ABI that OpenSSL requires. The
    // callback state is stored in `SSL_CTX` ex-data above and is dropped with
    // the context by the `openssl` crate.
    unsafe {
        SSL_CTX_set_psk_use_session_callback(builder.as_ptr(), Some(psk_use_session_callback));
    }

    Ok(())
}

/// Configures OpenSSL to offer and prefer TLS 1.3 PSK-only key exchange.
pub(crate) fn prefer_tls13_psk_only_key_exchange(builder: &mut SslContextBuilder) {
    let options = (1 << SSL_OP_ALLOW_NO_DHE_KEX_BIT) | (1 << SSL_OP_PREFER_NO_DHE_KEX_BIT);

    // SAFETY: The builder owns the live `SSL_CTX` from `builder.as_ptr()`. The
    // option bit values are OpenSSL public ABI constants for allowing and
    // preferring TLS 1.3 PSK key exchange without DHE.
    unsafe {
        SSL_CTX_set_options(builder.as_ptr(), options);
    }
}

fn psk_config_index(
) -> Result<Index<SslContext, OpenSslPskCallbackState>, openssl::error::ErrorStack> {
    static INDEX: OnceLock<Index<SslContext, OpenSslPskCallbackState>> = OnceLock::new();

    if let Some(index) = INDEX.get() {
        return Ok(*index);
    }

    let index = SslContext::new_ex_index::<OpenSslPskCallbackState>()?;
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
        log::error!(target: module_path!(), "OpenSSL called the TLS 1.3 PSK callback with a null argument");
        return 0;
    }

    let Some(state) = callback_state(ssl) else {
        return 0;
    };

    let Some(callback_session) = build_callback_session(ssl, digest, state) else {
        return 0;
    };

    let Ok(epsk) = tls13_epsk::config(&state.server) else {
        log::error!(target: module_path!(), "TLS 1.3 PSK callback has no EPSK configuration");
        return 0;
    };
    let identity_bytes = epsk.external_identity.as_bytes();
    // SAFETY: OpenSSL provides valid storage for these output values. It uses
    // the identity bytes after the callback returns. The bytes live in the
    // context ex-data for the lifetime of the `SSL_CTX`. `callback_session`
    // transfers ownership of a new `SSL_SESSION` to OpenSSL.
    unsafe {
        *identity = identity_bytes.as_ptr();
        *identity_len = identity_bytes.len();
        *session = callback_session;
    }

    log::debug!(
        target: module_path!(),
        "Provided a TLS 1.3 PSK session (hash: {})",
        epsk.hash.as_rfc7951_str()
    );

    1
}

unsafe fn build_callback_session(
    ssl: *mut SSL,
    digest: *const EVP_MD,
    state: &OpenSslPskCallbackState,
) -> Option<*mut SSL_SESSION> {
    let handshake_hash = match tls13_epsk::config(&state.server) {
        Ok(epsk) => epsk.hash,
        Err(error) => {
            log::error!(target: module_path!(), "Failed to read TLS 1.3 EPSK callback configuration: {error}");
            return None;
        }
    };

    if !digest.is_null() && !handshake_hash.matches_digest(digest) {
        log::warn!(
            target: module_path!(),
            "OpenSSL requested a TLS 1.3 PSK hash that does not match configured hash {}",
            handshake_hash.as_rfc7951_str()
        );
        return None;
    }

    let cipher = handshake_hash.find_cipher(ssl);
    if cipher.is_null() {
        log::error!(
            target: module_path!(),
            "OpenSSL did not find TLS 1.3 cipher suite {}",
            handshake_hash.tls13_ciphersuites()
        );
        return None;
    }

    create_session(state, cipher)
}

unsafe fn callback_state(ssl: *mut SSL) -> Option<&'static OpenSslPskCallbackState> {
    // SAFETY: `ssl` is the non-null `SSL*` that OpenSSL passed to the callback.
    let context = unsafe { SSL_get_SSL_CTX(ssl) };
    if context.is_null() {
        log::error!(target: module_path!(), "OpenSSL TLS 1.3 PSK callback has no SSL context");
        return None;
    }

    let index = match psk_config_index() {
        Ok(index) => index,
        Err(error) => {
            log::error!(target: module_path!(), "Failed to retrieve OpenSSL PSK ex-data index: {error}");
            return None;
        }
    };

    // SAFETY: `context` is the `SSL_CTX*` for the callback's `SSL*`.
    // It is owned by OpenSSL and remains valid for the duration of the callback.
    let context = unsafe { SslContextRef::from_ptr(context) };
    context.ex_data(index)
}

unsafe fn create_session(
    state: &OpenSslPskCallbackState,
    cipher: *const SSL_CIPHER,
) -> Option<*mut SSL_SESSION> {
    let key = match tls13_epsk::symmetric_key(&state.server) {
        Ok(key) => key,
        Err(error) => {
            log::error!(target: module_path!(), "TLS 1.3 EPSK callback has no symmetric key: {error}");
            return None;
        }
    };

    // SAFETY: `SSL_SESSION_new` returns null or a newly allocated
    // session owned by the caller until transferred to OpenSSL.
    let session = unsafe { SSL_SESSION_new() };
    if session.is_null() {
        log::error!(target: module_path!(), "OpenSSL failed to allocate TLS 1.3 PSK session");
        return None;
    }

    let configured = unsafe {
        // SAFETY: `session` is newly allocated. `cipher` came from OpenSSL's
        // configured cipher stack for the same `SSL*`, and the key slice is
        // valid for the duration of the call. Each OpenSSL setter copies the
        // supplied data into the session.
        SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION) == 1
            && SSL_SESSION_set_cipher(session, cipher) == 1
            && SSL_SESSION_set1_master_key(session, key.as_ptr(), key.len()) == 1
    };

    if configured {
        Some(session)
    } else {
        // SAFETY: This failure path has not given the session to OpenSSL.
        // Therefore, this callback must release it.
        unsafe {
            SSL_SESSION_free(session);
        }
        log::error!(target: module_path!(), "OpenSSL failed to configure TLS 1.3 PSK session");
        None
    }
}

trait OpenSslEpskSupportedHashExt {
    unsafe fn find_cipher(self, ssl: *mut SSL) -> *const SSL_CIPHER;

    fn matches_digest(self, digest: *const EVP_MD) -> bool;
}

impl OpenSslEpskSupportedHashExt for EpskSupportedHash {
    unsafe fn find_cipher(self, ssl: *mut SSL) -> *const SSL_CIPHER {
        let expected_name = self.tls13_ciphersuites();

        // SAFETY: `ssl` is the non-null `SSL*` that OpenSSL passed to the callback.
        // `SSL_get_ciphers` returns OpenSSL's configured cipher stack owned by
        // the `SSL`; this code only inspects it during the callback.
        let ciphers = unsafe { SSL_get_ciphers(ssl) };
        if ciphers.is_null() {
            return ptr::null();
        }

        // SAFETY: OpenSSL safe-stack macros use `OPENSSL_sk_num` for the stack
        // length. Casting the typed stack to `OPENSSL_STACK` matches those
        // macros for `STACK_OF(SSL_CIPHER)`.
        let cipher_count = unsafe { OPENSSL_sk_num(ciphers.cast::<OPENSSL_STACK>()) };
        if cipher_count <= 0 {
            return ptr::null();
        }

        for index in 0..cipher_count {
            // SAFETY: `index` is within the stack length returned above.
            let cipher = unsafe { OPENSSL_sk_value(ciphers.cast::<OPENSSL_STACK>(), index) }
                .cast::<SSL_CIPHER>();
            if cipher.is_null() {
                continue;
            }

            // SAFETY: `cipher` is an `SSL_CIPHER*` from the OpenSSL cipher stack.
            let standard_name = unsafe { SSL_CIPHER_standard_name(cipher) };
            if standard_name.is_null() {
                continue;
            }

            // SAFETY: OpenSSL returns a valid, NUL-terminated static cipher name.
            let Ok(standard_name) = unsafe { CStr::from_ptr(standard_name) }.to_str() else {
                continue;
            };

            if standard_name == expected_name {
                return cipher;
            }
        }

        ptr::null()
    }

    fn matches_digest(self, digest: *const EVP_MD) -> bool {
        let expected = match self {
            Self::Sha256 => unsafe {
                // SAFETY: `EVP_sha256` returns the OpenSSL process-global SHA-256
                // digest descriptor.
                EVP_sha256()
            },
            Self::Sha384 => unsafe {
                // SAFETY: `EVP_sha384` returns the OpenSSL process-global SHA-384
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
}
