//! Test-only OpenSSL server callback for hash-bound TLS 1.3 external PSKs.
#![allow(unsafe_code)]

use std::os::raw::{c_int, c_uchar};
use std::ptr;
use std::sync::OnceLock;

use anyhow::{Context, Result};
use foreign_types::ForeignTypeRef;
use openssl::ex_data::Index;
use openssl::ssl::{SslContext, SslContextBuilder, SslRef};
use openssl_sys::{SSL, SSL_CIPHER, SSL_CTX, SSL_SESSION, SSL_SESSION_free, TLS1_3_VERSION};

use tacacsrs_config::EpskSupportedHash;
use tacacsrs_secrets::SecretBytes;

struct ServerPsk {
    identity: Box<[u8]>,
    key: SecretBytes,
    cipher_id: [u8; 2],
}

static STATE_INDEX: OnceLock<Index<SslContext, ServerPsk>> = OnceLock::new();

type FindSessionCallback =
    unsafe extern "C" fn(*mut SSL, *const c_uchar, usize, *mut *mut SSL_SESSION) -> c_int;

extern "C" {
    fn SSL_CTX_set_psk_find_session_callback(
        context: *mut SSL_CTX,
        callback: Option<FindSessionCallback>,
    );
    fn SSL_CIPHER_find(ssl: *mut SSL, id: *const c_uchar) -> *const SSL_CIPHER;
    fn SSL_SESSION_new() -> *mut SSL_SESSION;
    fn SSL_SESSION_set_protocol_version(session: *mut SSL_SESSION, version: c_int) -> c_int;
    fn SSL_SESSION_set_cipher(session: *mut SSL_SESSION, cipher: *const SSL_CIPHER) -> c_int;
    fn SSL_SESSION_set1_master_key(
        session: *mut SSL_SESSION,
        key: *const c_uchar,
        length: usize,
    ) -> c_int;
}

pub(super) fn cipher_suite(hash: EpskSupportedHash) -> &'static str {
    match hash {
        EpskSupportedHash::Sha256 => "TLS_AES_128_GCM_SHA256",
        EpskSupportedHash::Sha384 => "TLS_AES_256_GCM_SHA384",
    }
}

pub(super) fn install(
    builder: &mut SslContextBuilder,
    identity: &str,
    key: &[u8],
    hash: EpskSupportedHash,
) -> Result<()> {
    let index = if let Some(index) = STATE_INDEX.get() {
        *index
    } else {
        let index = SslContext::new_ex_index::<ServerPsk>()
            .context("allocate test peer PSK state index")?;
        *STATE_INDEX.get_or_init(|| index)
    };
    builder.set_ex_data(
        index,
        ServerPsk {
            identity: identity.as_bytes().into(),
            key: SecretBytes::new(key.to_vec()),
            cipher_id: match hash {
                EpskSupportedHash::Sha256 => [0x13, 0x01],
                EpskSupportedHash::Sha384 => [0x13, 0x02],
            },
        },
    );
    // SAFETY: The builder owns a live SSL_CTX. OpenSSL invokes this exact callback
    // ABI while the context and its Rust-owned ex-data remain alive.
    unsafe {
        SSL_CTX_set_psk_find_session_callback(builder.as_ptr(), Some(find_session));
    }
    Ok(())
}

unsafe extern "C" fn find_session(
    ssl: *mut SSL,
    identity: *const c_uchar,
    identity_len: usize,
    output: *mut *mut SSL_SESSION,
) -> c_int {
    if ssl.is_null() || identity.is_null() || output.is_null() {
        return 0;
    }
    // SAFETY: OpenSSL supplies a live SSL, a readable identity of identity_len
    // bytes, and writable session output for the duration of this callback.
    let (ssl_ref, offered_identity) = unsafe {
        *output = ptr::null_mut();
        (SslRef::from_ptr(ssl), std::slice::from_raw_parts(identity, identity_len))
    };
    let Some(index) = STATE_INDEX.get() else {
        return 0;
    };
    let Some(state) = ssl_ref.ssl_context().ex_data(*index) else {
        return 0;
    };
    if offered_identity != state.identity.as_ref() {
        return 1;
    }
    // SAFETY: SSL_CIPHER_find reads the two-byte TLS cipher ID and returns a
    // native cipher descriptor. The live SSL and context outlive these calls.
    let cipher = unsafe { SSL_CIPHER_find(ssl, state.cipher_id.as_ptr()) };
    if cipher.is_null() {
        return 0;
    }
    // SAFETY: The constructor returns null or a new session owned by this callback.
    let session = unsafe { SSL_SESSION_new() };
    if session.is_null() {
        return 0;
    }
    let key = state.key.expose_secret();
    // SAFETY: Each setter receives a live session and copies or retains its
    // native input. The key slice remains valid for the complete setter call.
    let configured = unsafe {
        SSL_SESSION_set_protocol_version(session, TLS1_3_VERSION) == 1
            && SSL_SESSION_set_cipher(session, cipher) == 1
            && SSL_SESSION_set1_master_key(session, key.as_ptr(), key.len()) == 1
    };
    // SAFETY: Success transfers the new session to OpenSSL. Failure frees it
    // here because ownership has not crossed the callback boundary.
    unsafe {
        if configured {
            *output = session;
        } else {
            SSL_SESSION_free(session);
        }
    }
    c_int::from(configured)
}

#[cfg(test)]
mod tests {
    use foreign_types::ForeignType;
    use openssl::ssl::{Ssl, SslMethod};

    use super::*;

    #[test]
    fn callback_rejects_null_arguments() {
        // SAFETY: Null arguments exercise the callback guards and must never be dereferenced.
        let result = unsafe { find_session(ptr::null_mut(), ptr::null(), 0, ptr::null_mut()) };
        assert_eq!(result, 0);
    }

    #[test]
    fn unrecognized_identity_returns_no_session() -> Result<()> {
        let mut builder = SslContext::builder(SslMethod::tls_server())?;
        install(
            &mut builder,
            "expected-client",
            b"protected-test-key-material",
            EpskSupportedHash::Sha384,
        )?;
        let context = builder.build();
        let ssl = Ssl::new(&context)?;
        let identity = b"different-client";
        let mut session = ptr::null_mut();
        // SAFETY: The SSL, identity buffer, and output storage remain live throughout the callback.
        let result = unsafe {
            find_session(ssl.as_ptr(), identity.as_ptr(), identity.len(), &raw mut session)
        };
        assert_eq!(result, 1);
        assert!(session.is_null());
        Ok(())
    }
}
