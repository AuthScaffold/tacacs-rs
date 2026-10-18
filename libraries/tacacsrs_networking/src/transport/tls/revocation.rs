//! Certificate revocation requirements for native TLS connections.

mod responder;
mod crl_scope;
mod crl_delta;
pub(in crate::transport::tls) mod crls;

use std::num::NonZeroU32;
use std::time::{Duration, SystemTime};
use std::sync::{Mutex, OnceLock};
use std::sync::Arc;

use foreign_types::ForeignTypeRef;

use anyhow::{Context, ensure};
use openssl::hash::MessageDigest;
use openssl::ocsp::{OcspCertId, OcspCertStatus, OcspResponse, OcspResponseStatus};
use openssl::ssl::{Ssl, SslRef, SslContextBuilder};
use openssl::x509::{X509, X509VerifyResult};

use super::validity::{RevocationEvidenceValidity, generalized_system_time};

/// Bounds untrusted OCSP parsing work during the TLS handshake.
const MAXIMUM_STAPLE_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub(super) struct VerificationFailure {
    message: String,
    code: Option<i32>,
}

impl VerificationFailure {
    pub(super) fn capture(error: &anyhow::Error) -> Self {
        Self {
            message: format!("{error:#}"),
            code: error
                .downcast_ref::<crate::statistics::CertificateVerificationCode>()
                .map(|code| code.0),
        }
    }

    pub(super) fn error(&self) -> anyhow::Error {
        let error = anyhow::anyhow!(self.message.clone());
        match self.code {
            Some(code) => error.context(crate::statistics::CertificateVerificationCode(code)),
            None => error,
        }
    }
}

pub(super) struct ConnectionRevocation {
    policy: CertificateRevocationPolicy,
    issuers: Vec<X509>,
    local_authentication_certificates: Vec<Vec<u8>>,
    provided: Option<ProvidedResponse>,
    result: Mutex<Option<Result<RevocationEvidenceValidity, VerificationFailure>>>,
}

impl ConnectionRevocation {
    pub(super) fn new(
        policy: CertificateRevocationPolicy,
        issuers: &[X509],
        local_authentication_certificates: Vec<Vec<u8>>,
        provided: Option<ProvidedResponse>,
    ) -> Option<Self> {
        (policy.maximum_response_age().is_some() || provided.is_some()).then(|| Self {
            policy,
            issuers: issuers.to_vec(),
            local_authentication_certificates,
            provided,
            result: Mutex::new(None),
        })
    }
}

type RevocationIndex = openssl::ex_data::Index<Ssl, ConnectionRevocation>;

fn index() -> Result<RevocationIndex, openssl::error::ErrorStack> {
    static INDEX: OnceLock<Result<RevocationIndex, openssl::error::ErrorStack>> = OnceLock::new();
    INDEX
        .get_or_init(Ssl::new_ex_index)
        .as_ref()
        .copied()
        .map_err(Clone::clone)
}

pub(super) fn configure_verifier(builder: &mut SslContextBuilder) -> anyhow::Result<()> {
    let index = index()?;
    builder.set_status_callback(move |ssl| {
        let Some(connection) = ssl.ex_data(index) else {
            return Ok(true);
        };
        let verified = connection
            .policy
            .verify(ssl, &connection.issuers, &connection.local_authentication_certificates)
            .and_then(|current| {
                let extra = connection
                    .provided
                    .as_ref()
                    .map(|provided| {
                        provided.policy.verify_encoded(
                            ssl,
                            &connection.issuers,
                            &connection.local_authentication_certificates,
                            &provided.encoded,
                        )
                    })
                    .transpose()?
                    .flatten();
                match (current, extra) {
                    (Some(first), Some(second)) => Ok(Some(first.intersect(second)?)),
                    (first, second) => Ok(first.or(second)),
                }
            })
            .and_then(|validity| validity.context("Required OCSP evidence was not verified"))
            .map_err(|error| VerificationFailure::capture(&error));
        let accepted = verified.is_ok();
        *connection
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(verified);
        Ok(accepted)
    })?;
    Ok(())
}

pub(super) fn request(
    ssl: &mut SslRef,
    connection: Option<ConnectionRevocation>,
) -> anyhow::Result<()> {
    if let Some(connection) = connection {
        ssl.set_ex_data(index()?, connection);
        ssl.set_status_type(openssl::ssl::StatusType::OCSP)?;
    }
    Ok(())
}

pub(super) fn verified_validity(
    ssl: &SslRef,
) -> anyhow::Result<Option<RevocationEvidenceValidity>> {
    let Some(connection) = ssl.ex_data(index()?) else {
        return Ok(None);
    };
    let result = connection
        .result
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match result.as_ref() {
        Some(Ok(validity)) => Ok(Some(*validity)),
        Some(Err(error)) => Err(error.error().context("OCSP verification failed")),
        None => anyhow::bail!("Required stapled OCSP response was not verified"),
    }
}

pub(super) fn verification_failed(ssl: &SslRef) -> bool {
    index()
        .ok()
        .and_then(|index| ssl.ex_data(index))
        .is_some_and(|connection| {
            connection
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .is_some_and(Result::is_err)
        })
}

/// Controls mandatory, fresh stapled OCSP evidence for a TLS peer leaf.
///
/// The default disables OCSP requirements, not configured CRL checks. Required evidence fails closed.
/// Responses can be signed by the issuer or its authorized delegated responder.
/// Delegated responders require OCSP signing usage and either valid No Check or verified configured CRLs.
/// SHA-1 and SHA-256 certificate IDs are supported. OCSP covers the peer leaf; CRLs can also cover its CA path.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CertificateRevocationPolicy {
    maximum_age_seconds: Option<NonZeroU32>,
}

impl CertificateRevocationPolicy {
    /// Disables OCSP requirements without disabling certificate verification.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            maximum_age_seconds: None,
        }
    }

    /// Requires a verified OCSP staple no older than the supplied maximum age.
    /// The effective expiry is the earlier of `nextUpdate` and `thisUpdate` plus this age.
    ///
    /// # Errors
    /// Returns an error unless the age is a positive whole number of seconds that fits a `u32`.
    pub fn require_stapled_ocsp(maximum_age: Duration) -> anyhow::Result<Self> {
        anyhow::ensure!(maximum_age.subsec_nanos() == 0, "OCSP maximum age must use whole seconds");
        let seconds = u32::try_from(maximum_age.as_secs())?;
        let seconds = NonZeroU32::new(seconds)
            .ok_or_else(|| anyhow::anyhow!("OCSP maximum age must be positive"))?;
        Ok(Self {
            maximum_age_seconds: Some(seconds),
        })
    }

    /// Returns the maximum response age, or `None` when revocation checks are disabled.
    #[must_use]
    pub fn maximum_response_age(self) -> Option<Duration> {
        self.maximum_age_seconds
            .map(|seconds| Duration::from_secs(u64::from(seconds.get())))
    }

    pub(super) fn verify(
        self,
        ssl: &SslRef,
        configured_issuers: &[X509],
        local_authentication_certificates: &[Vec<u8>],
    ) -> anyhow::Result<Option<RevocationEvidenceValidity>> {
        if self.maximum_age_seconds.is_none() {
            return Ok(None);
        }
        let encoded = ssl
            .ocsp_status()
            .context("Required stapled OCSP response is missing")?;
        self.verify_encoded(ssl, configured_issuers, local_authentication_certificates, encoded)
    }

    fn verify_encoded(
        self,
        ssl: &SslRef,
        configured_issuers: &[X509],
        local_authentication_certificates: &[Vec<u8>],
        encoded: &[u8],
    ) -> anyhow::Result<Option<RevocationEvidenceValidity>> {
        let Some(maximum_age) = self.maximum_age_seconds else {
            return Ok(None);
        };
        ensure!(
            encoded.len() <= MAXIMUM_STAPLE_BYTES,
            "Stapled OCSP response exceeds the size limit"
        );
        let response = OcspResponse::from_der(encoded).context("Invalid stapled OCSP response")?;
        ensure!(
            response.to_der()?.as_slice() == encoded,
            "OCSP input must contain exactly one DER response"
        );
        ensure!(
            response.status() == OcspResponseStatus::SUCCESSFUL,
            "OCSP responder did not return successful evidence"
        );
        let basic = response.basic().context("OCSP basic response is missing")?;
        let peer = ssl
            .peer_certificate()
            .context("TLS peer certificate is missing")?;
        let issuer = ssl
            .verified_chain()
            .into_iter()
            .flat_map(|chain| chain.iter())
            .chain(
                ssl.peer_cert_chain()
                    .into_iter()
                    .flat_map(|chain| chain.iter()),
            )
            .chain(configured_issuers.iter().map(std::ops::Deref::deref))
            .find(|issuer| {
                issuer.issued(&peer) == X509VerifyResult::OK
                    && issuer.to_der().ok() != peer.to_der().ok()
                    && issuer
                        .public_key()
                        .is_ok_and(|key| peer.verify(&key).unwrap_or(false))
            })
            .context("OCSP requires the authenticated peer's issuer certificate")?;
        let signer_validity =
            responder::verify(&basic, issuer, ssl, local_authentication_certificates)?;
        let mut status = None;
        for digest in [MessageDigest::sha1(), MessageDigest::sha256()] {
            let identifier = OcspCertId::from_cert(digest, &peer, issuer)?;
            if let Some(found) = basic.find_status(&identifier) {
                status = Some(found);
                break;
            }
        }
        let status = status.context("OCSP response does not cover the TLS peer certificate")?;
        if status.status == OcspCertStatus::REVOKED {
            return Err(anyhow::anyhow!("TLS peer certificate is revoked").context(
                crate::statistics::CertificateVerificationCode(
                    openssl_sys::X509_V_ERR_CERT_REVOKED,
                ),
            ));
        }
        ensure!(status.status == OcspCertStatus::GOOD, "OCSP peer certificate status is unknown");
        status
            .check_validity(0, Some(maximum_age.get()))
            .context("OCSP response is stale or not yet valid")?;
        let start = generalized_system_time(status.this_update)?;
        let next = status
            .next_update()
            .map(generalized_system_time)
            .transpose()?;
        let freshness = freshness_interval(start, next, maximum_age, SystemTime::now())?;
        let validity =
            signer_validity.map_or(Ok(freshness), |signer| freshness.intersect(signer))?;
        ensure!(
            validity.is_valid_at(SystemTime::now()),
            "OCSP responder or evidence validity expired"
        );
        Ok(Some(validity))
    }
}

#[derive(Clone)]
pub(super) struct ProvidedResponse {
    encoded: Arc<[u8]>,
    policy: CertificateRevocationPolicy,
    pub(super) lifetime: super::RevocationEvidenceLifetime,
}

#[allow(unsafe_code)]
unsafe extern "C" {
    fn OCSP_resp_count(response: *mut openssl_sys::OCSP_BASICRESP) -> std::ffi::c_int;
    fn OCSP_resp_get0(
        response: *mut openssl_sys::OCSP_BASICRESP,
        index: std::ffi::c_int,
    ) -> *mut std::ffi::c_void;
    fn OCSP_single_get0_status(
        single: *mut std::ffi::c_void,
        reason: *mut std::ffi::c_int,
        revoked: *mut *mut openssl_sys::ASN1_GENERALIZEDTIME,
        this_update: *mut *mut openssl_sys::ASN1_GENERALIZEDTIME,
        next_update: *mut *mut openssl_sys::ASN1_GENERALIZEDTIME,
    ) -> std::ffi::c_int;
}

impl ProvidedResponse {
    #[allow(unsafe_code)]
    pub(super) fn prepare(encoded: &[u8], maximum_age: Duration) -> anyhow::Result<Self> {
        let policy = CertificateRevocationPolicy::require_stapled_ocsp(maximum_age)?;
        ensure!(
            encoded.len() <= MAXIMUM_STAPLE_BYTES,
            "Fetched OCSP response exceeds the size limit"
        );
        let response = OcspResponse::from_der(encoded)?;
        ensure!(
            response.to_der()?.as_slice() == encoded,
            "Fetched OCSP response must contain one DER object"
        );
        ensure!(
            response.status() == OcspResponseStatus::SUCCESSFUL,
            "Fetched OCSP response is not successful"
        );
        let basic = response.basic()?;
        let mut start = std::ptr::null_mut();
        let mut next = std::ptr::null_mut();
        // SAFETY: The decoded basic response owns all borrowed values. Count and
        // pointers are checked before reading; only owned clock values escape.
        let validity = unsafe {
            ensure!(
                OCSP_resp_count(basic.as_ptr()) == 1,
                "Fetched OCSP response must cover exactly one certificate"
            );
            let single = OCSP_resp_get0(basic.as_ptr(), 0);
            ensure!(!single.is_null(), "Fetched OCSP status is missing");
            let status = OCSP_single_get0_status(
                single,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut start,
                &raw mut next,
            );
            ensure!(
                [
                    OcspCertStatus::GOOD.as_raw(),
                    OcspCertStatus::REVOKED.as_raw(),
                    OcspCertStatus::UNKNOWN.as_raw()
                ]
                .contains(&status),
                "Invalid fetched OCSP status"
            );
            ensure!(!start.is_null(), "Fetched OCSP thisUpdate is missing");
            let start =
                generalized_system_time(openssl::asn1::Asn1GeneralizedTimeRef::from_ptr(start))?;
            let next = if next.is_null() {
                None
            } else {
                Some(generalized_system_time(openssl::asn1::Asn1GeneralizedTimeRef::from_ptr(
                    next,
                ))?)
            };
            freshness_interval(
                start,
                next,
                NonZeroU32::new(u32::try_from(maximum_age.as_secs())?)
                    .context("OCSP maximum age is zero")?,
                SystemTime::now(),
            )?
        };
        Ok(Self {
            encoded: Arc::from(encoded),
            policy,
            lifetime: super::RevocationEvidenceLifetime::new(validity)?,
        })
    }
}

fn freshness_interval(
    start: SystemTime,
    next: Option<SystemTime>,
    maximum_age: NonZeroU32,
    now: SystemTime,
) -> anyhow::Result<RevocationEvidenceValidity> {
    let age_limit = start
        .checked_add(Duration::from_secs(u64::from(maximum_age.get())))
        .context("OCSP freshness exceeds the system clock range")?;
    let validity = RevocationEvidenceValidity::from_bounds(
        start,
        next.map_or(age_limit, |next| next.min(age_limit)),
    )?;
    ensure!(validity.is_valid_at(now), "OCSP response is stale or not yet valid");
    Ok(validity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_freshness_never_renews_signed_times() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let maximum = NonZeroU32::new(300).unwrap();
        let next = start + Duration::from_secs(60);
        assert_eq!(
            freshness_interval(start, Some(next), maximum, start)
                .unwrap()
                .valid_until(),
            next
        );
        assert_eq!(
            freshness_interval(start, None, maximum, next)
                .unwrap()
                .valid_until(),
            start + Duration::from_secs(300)
        );
        for (next, now) in [
            (Some(next), next),
            (None, start + Duration::from_secs(300)),
            (None, start - Duration::from_secs(1)),
            (Some(start), start),
        ] {
            assert!(freshness_interval(start, next, maximum, now).is_err());
        }
    }

    #[test]
    fn required_ocsp_policy_has_a_bounded_positive_age() {
        assert_eq!(CertificateRevocationPolicy::default().maximum_response_age(), None);
        for invalid in [
            Duration::ZERO,
            Duration::from_millis(1500),
            Duration::from_secs(u64::from(u32::MAX) + 1),
        ] {
            assert!(CertificateRevocationPolicy::require_stapled_ocsp(invalid).is_err());
        }
        assert_eq!(
            CertificateRevocationPolicy::require_stapled_ocsp(Duration::from_secs(300))
                .unwrap()
                .maximum_response_age(),
            Some(Duration::from_secs(300))
        );
    }
}
