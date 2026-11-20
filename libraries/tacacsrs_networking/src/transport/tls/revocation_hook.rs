//! Calls an injected revocation verifier from the OpenSSL verify callback.
//!
//! The hook runs at depth 0, after OpenSSL and the trust callback accept the
//! server path. It reads per-connection state from SSL ex_data, so a context
//! without a verifier does no revocation work. When the verifier needs evidence,
//! the hook calls `SSL_set_retry_verify`. OpenSSL then returns
//! `SSL_ERROR_WANT_RETRY_VERIFY` before the client sends its certificate, and
//! [`connect_tls`](super::connect_tls) waits for the evidence and resumes.

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use anyhow::{Context, Result};
use foreign_types::ForeignTypeRef;
use openssl::ex_data::Index;
use openssl::ssl::{Ssl, SslRef};
use openssl::x509::{X509, X509VerifyResult};

use crate::revocation::{
    RevocationDecision, RevocationNetwork, RevocationRejection, RevocationVerifier, VerifiedPath,
};
use crate::statistics::RevocationEvent;

/// OpenSSL 3 `SSL_ERROR_WANT_RETRY_VERIFY`.
pub(super) const SSL_ERROR_WANT_RETRY_VERIFY: i32 = 12;

/// OpenSSL 3 `SSL_CTRL_SET_RETRY_VERIFY`. The `SSL_set_retry_verify` macro
/// expands to `SSL_ctrl` with this command, and `openssl-sys` does not bind it.
const SSL_CTRL_SET_RETRY_VERIFY: std::ffi::c_int = 136;

/// The revocation inputs for one connection attempt.
#[derive(Clone)]
pub(crate) struct RevocationCheck {
    pub(crate) verifier: Arc<dyn RevocationVerifier>,
    pub(crate) network: RevocationNetwork,
    pub(crate) deadline: Option<tokio::time::Instant>,
    pub(crate) counters: crate::ServerCounters,
}

/// Per-SSL hook state, stored in SSL ex_data.
pub(super) struct HandshakeRevocation {
    verifier: Arc<dyn RevocationVerifier>,
    counters: crate::ServerCounters,
    peer_identity: String,
    state: Mutex<HookState>,
}

#[derive(Default)]
struct HookState {
    pending: Option<VerifiedPath>,
    resumed: bool,
    rejection: Option<RevocationRejection>,
}

/// The hook's instruction to the verify callback.
pub(super) enum Verdict {
    Continue,
    Reject(X509VerifyResult),
}

fn index() -> Result<Index<Ssl, Arc<HandshakeRevocation>>> {
    static INDEX: OnceLock<Index<Ssl, Arc<HandshakeRevocation>>> = OnceLock::new();
    if let Some(index) = INDEX.get() {
        return Ok(*index);
    }
    let index = Ssl::new_ex_index().context("OpenSSL failed to allocate a revocation index")?;
    Ok(*INDEX.get_or_init(|| index))
}

impl HandshakeRevocation {
    /// Attaches hook state to `ssl` and returns a handle for the retry loop.
    pub(super) fn attach(
        ssl: &mut Ssl,
        check: &RevocationCheck,
        peer_identity: &str,
    ) -> Result<Arc<Self>> {
        let hook = Arc::new(Self {
            verifier: Arc::clone(&check.verifier),
            counters: check.counters.clone(),
            peer_identity: peer_identity.to_owned(),
            state: Mutex::new(HookState::default()),
        });
        ssl.set_ex_data(index()?, Arc::clone(&hook));
        Ok(hook)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, HookState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes the path that paused the handshake and marks the next verify as a resume.
    pub(super) fn take_pending(&self) -> Option<VerifiedPath> {
        let mut state = self.state();
        let path = state.pending.take();
        state.resumed |= path.is_some();
        path
    }

    /// Returns the verifier.
    pub(super) fn verifier(&self) -> &dyn RevocationVerifier {
        self.verifier.as_ref()
    }

    /// Records a handshake pause.
    pub(super) fn record_wait(&self) {
        self.counters
            .revocation_event(RevocationEvent::EvidenceWait);
    }

    /// Returns the rejection that failed the handshake, if any.
    pub(super) fn rejection(&self) -> Option<RevocationRejection> {
        self.state().rejection.clone()
    }

    fn reject(&self, rejection: RevocationRejection) -> Verdict {
        log::warn!(
            target: "tacacsrs_networking::revocation",
            "Rejected TLS server {} during revocation check: {}",
            self.peer_identity,
            rejection.reason()
        );
        let code = if rejection.is_revoked() {
            // SAFETY: `X509_V_ERR_CERT_REVOKED` is a defined OpenSSL verify result.
            #[allow(unsafe_code)]
            unsafe {
                X509VerifyResult::from_raw(openssl_sys::X509_V_ERR_CERT_REVOKED)
            }
        } else {
            X509VerifyResult::APPLICATION_VERIFICATION
        };
        self.state().rejection = Some(rejection);
        Verdict::Reject(code)
    }

    fn decide(&self, ssl: &SslRef, path: Option<Vec<X509>>) -> Verdict {
        let Some(certificates) = path else {
            self.counters.revocation_event(RevocationEvent::PinnedSkip);
            log::debug!(
                target: "tacacsrs_networking::revocation",
                "Skipped revocation check for pinned TLS server {}",
                self.peer_identity
            );
            return Verdict::Continue;
        };
        let path = match VerifiedPath::new(certificates, &self.peer_identity) {
            Ok(path) => path,
            Err(error) => {
                return self.reject(RevocationRejection::unverified(error.to_string()));
            }
        };
        match self.verifier.decide(&path) {
            RevocationDecision::Verified => Verdict::Continue,
            RevocationDecision::Accept(reason) => {
                self.counters
                    .revocation_event(RevocationEvent::UnverifiedAccept);
                log::warn!(
                    target: "tacacsrs_networking::revocation",
                    "Accepted TLS server {} without fresh revocation evidence: {reason}",
                    self.peer_identity
                );
                Verdict::Continue
            }
            RevocationDecision::Reject(rejection) => self.reject(rejection),
            RevocationDecision::NeedEvidence if self.state().resumed => {
                self.reject(RevocationRejection::unverified("revocation evidence is unavailable"))
            }
            RevocationDecision::NeedEvidence => {
                self.state().pending = Some(path);
                // SAFETY: `ssl` is the live SSL object whose verify callback is
                // running. OpenSSL documents `SSL_set_retry_verify` for use from
                // that callback. The command takes no argument or pointer.
                #[allow(unsafe_code)]
                let paused = unsafe {
                    openssl_sys::SSL_ctrl(
                        ssl.as_ptr(),
                        SSL_CTRL_SET_RETRY_VERIFY,
                        0,
                        std::ptr::null_mut(),
                    )
                } > 0;
                if paused {
                    Verdict::Continue
                } else {
                    self.state().pending = None;
                    self.reject(RevocationRejection::unverified(
                        "OpenSSL could not pause the handshake for revocation evidence",
                    ))
                }
            }
        }
    }
}

/// Returns whether `ssl` has a revocation hook.
pub(super) fn attached(ssl: &SslRef) -> bool {
    index().is_ok_and(|index| ssl.ex_data(index).is_some())
}

/// Checks an accepted path. `None` means that an exact pinned certificate
/// authenticated the server without a CA path.
pub(super) fn check(ssl: &SslRef, path: Option<Vec<X509>>) -> Verdict {
    let Some(hook) = index().ok().and_then(|index| ssl.ex_data(index)) else {
        return Verdict::Continue;
    };
    hook.decide(ssl, path)
}

/// Copies an OpenSSL chain into owned certificates.
pub(super) fn owned_chain(chain: Option<&openssl::stack::StackRef<X509>>) -> Option<Vec<X509>> {
    chain.map(|chain| chain.iter().map(ToOwned::to_owned).collect())
}
