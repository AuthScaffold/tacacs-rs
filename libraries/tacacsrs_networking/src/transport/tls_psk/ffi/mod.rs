#![allow(unsafe_code)]

use std::ffi::CStr;
use std::os::raw::{c_int, c_uchar};
use std::ptr;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use foreign_types::ForeignTypeRef;
use openssl::ex_data::Index;
use openssl::hash::MessageDigest;
use openssl::ssl::{SslContext, SslContextBuilder, SslRef};
use openssl_sys::{
    stack_st_SSL_CIPHER, EVP_MD, EVP_MD_get_type, OPENSSL_STACK, OPENSSL_sk_num, OPENSSL_sk_value,
    SSL, SSL_CIPHER, SSL_CIPHER_standard_name, SSL_CTX, SSL_ctrl, SSL_SESSION, SSL_SESSION_free,
    TLS1_3_VERSION,
};
use tacacsrs_secrets::SecretBytes;

type PskUseSessionCallback = unsafe extern "C" fn(
    ssl: *mut SSL,
    digest: *const EVP_MD,
    identity: *mut *const c_uchar,
    identity_len: *mut usize,
    session: *mut *mut SSL_SESSION,
) -> c_int;

pub(super) struct OpenSslPskCallbackState {
    pub(super) identity: Box<[u8]>,
    pub(super) key: SecretBytes,
    pub(super) digest: MessageDigest,
    pub(super) cipher_suite: &'static str,
}

/// OpenSSL 3.0 control used by the public `SSL_get_negotiated_group` macro.
const SSL_CTRL_GET_NEGOTIATED_GROUP: c_int = 134;

/// Reads the negotiated group after a completed TLS 1.3 handshake.
pub(super) fn negotiated_key_exchange_uses_dhe(ssl: &SslRef) -> Result<bool> {
    // SAFETY: The borrowed SSL object is live. This read-only OpenSSL 3.0 control
    // takes no pointer argument and returns zero for no group or a group NID.
    let group =
        unsafe { SSL_ctrl(ssl.as_ptr(), SSL_CTRL_GET_NEGOTIATED_GROUP, 0, ptr::null_mut()) };
    anyhow::ensure!(group >= 0, "OpenSSL could not report the negotiated key-exchange group");
    Ok(group != 0)
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

    fn SSL_get_ciphers(ssl: *const SSL) -> *mut stack_st_SSL_CIPHER;
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
    state: OpenSslPskCallbackState,
) -> Result<()> {
    let index = psk_config_index().context("failed to allocate OpenSSL PSK ex-data index")?;

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

    // SAFETY: OpenSSL supplies a live SSL object for the duration of this callback.
    let ssl_ref = unsafe { SslRef::from_ptr(ssl) };
    let Some(state) = callback_state(ssl_ref) else {
        return 0;
    };

    let Some(callback_session) = build_callback_session(ssl, digest, state) else {
        return 0;
    };

    let identity_bytes = &state.identity;
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
        "Provided a TLS 1.3 PSK session (cipher: {})",
        state.cipher_suite
    );

    1
}

unsafe fn build_callback_session(
    ssl: *mut SSL,
    digest: *const EVP_MD,
    state: &OpenSslPskCallbackState,
) -> Option<*mut SSL_SESSION> {
    // SAFETY: A non-null digest is an OpenSSL descriptor supplied to the callback.
    if !digest.is_null() && unsafe { EVP_MD_get_type(digest) } != state.digest.type_().as_raw() {
        log::warn!(
            target: module_path!(),
            "OpenSSL requested a TLS 1.3 PSK hash that does not match prepared cipher {}",
            state.cipher_suite
        );
        return None;
    }

    let cipher = find_cipher(ssl, state.cipher_suite);
    if cipher.is_null() {
        log::error!(
            target: module_path!(),
            "OpenSSL did not find TLS 1.3 cipher suite {}",
            state.cipher_suite
        );
        return None;
    }

    create_session(state, cipher)
}

fn callback_state(ssl: &SslRef) -> Option<&OpenSslPskCallbackState> {
    let index = match psk_config_index() {
        Ok(index) => index,
        Err(error) => {
            log::error!(target: module_path!(), "Failed to retrieve OpenSSL PSK ex-data index: {error}");
            return None;
        }
    };

    ssl.ssl_context().ex_data(index)
}

unsafe fn create_session(
    state: &OpenSslPskCallbackState,
    cipher: *const SSL_CIPHER,
) -> Option<*mut SSL_SESSION> {
    let key = state.key.expose_secret();

    // SAFETY: `SSL_SESSION_new` returns null or a newly allocated
    // session owned by the caller until transferred to OpenSSL.
    let session = unsafe { SSL_SESSION_new() };
    if session.is_null() {
        log::error!(target: module_path!(), "OpenSSL failed to allocate TLS 1.3 PSK session");
        return None;
    }

    // SAFETY: `session` is newly allocated. `cipher` came from OpenSSL's
    // configured cipher stack for the same `SSL*`, and the key slice is
    // valid for the duration of the call. Each OpenSSL setter copies the
    // supplied data into the session.
    let configured = unsafe {
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

unsafe fn find_cipher(ssl: *mut SSL, expected_name: &str) -> *const SSL_CIPHER {
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

#[cfg(test)]
mod tests {
    use foreign_types::ForeignType;
    use openssl::ssl::{Ssl, SslMethod, SslSession};

    use super::*;

    const KEY: &[u8] = b"prepared-psk-material-for-native-tests";

    fn context(digest: MessageDigest, cipher_suite: &'static str) -> SslContext {
        let mut builder = SslContext::builder(SslMethod::tls_client()).unwrap();
        builder.set_ciphersuites(cipher_suite).unwrap();
        set_tls13_psk_use_session_callback(
            &mut builder,
            OpenSslPskCallbackState {
                identity: b"prepared-client".to_vec().into_boxed_slice(),
                key: SecretBytes::new(KEY.to_vec()),
                digest,
                cipher_suite,
            },
        )
        .unwrap();
        builder.build()
    }

    fn offer(context: &SslContext, digest: Option<MessageDigest>) -> Option<SslSession> {
        let ssl = Ssl::new(context).unwrap();
        let mut identity = ptr::null();
        let mut identity_len = 0;
        let mut session = ptr::null_mut();
        // SAFETY: The SSL object and digest remain live. Each output points to
        // initialized storage that remains valid throughout the callback.
        let result = unsafe {
            psk_use_session_callback(
                ssl.as_ptr(),
                digest.map_or(ptr::null(), |digest| digest.as_ptr()),
                &raw mut identity,
                &raw mut identity_len,
                &raw mut session,
            )
        };
        if result == 0 {
            assert!(session.is_null());
            assert!(identity.is_null());
            assert_eq!(identity_len, 0);
            return None;
        }
        assert_eq!(result, 1);
        assert!(!identity.is_null());
        assert!(!session.is_null());
        // SAFETY: Successful callbacks return context-owned identity bytes and
        // transfer one allocated session. The context is still live here.
        unsafe {
            assert_eq!(std::slice::from_raw_parts(identity, identity_len), b"prepared-client");
            Some(SslSession::from_ptr(session))
        }
    }

    #[test]
    fn repeated_callbacks_use_prepared_identity_key_and_hash() {
        for (digest, cipher_suite) in [
            (MessageDigest::sha256(), "TLS_AES_128_GCM_SHA256"),
            (MessageDigest::sha384(), "TLS_AES_256_GCM_SHA384"),
        ] {
            let context = context(digest, cipher_suite);
            for requested_digest in [None, Some(digest), None, Some(digest)] {
                let session = offer(&context, requested_digest).unwrap();
                let mut key = vec![0; session.master_key_len()];
                assert_eq!(session.master_key(&mut key), KEY.len());
                assert_eq!(key, KEY);
            }
        }
    }

    #[test]
    fn callback_rejects_a_different_handshake_hash() {
        let context = context(MessageDigest::sha256(), "TLS_AES_128_GCM_SHA256");
        assert!(offer(&context, Some(MessageDigest::sha384())).is_none());
        assert!(offer(&context, Some(MessageDigest::sha256())).is_some());
    }

    #[test]
    fn callback_rejects_null_outputs() {
        let context = context(MessageDigest::sha256(), "TLS_AES_128_GCM_SHA256");
        let ssl = Ssl::new(&context).unwrap();
        // SAFETY: The SSL is live. Null outputs must be rejected before access.
        let result = unsafe {
            psk_use_session_callback(
                ssl.as_ptr(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(result, 0);
    }
}
