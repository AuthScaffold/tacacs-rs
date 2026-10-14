//! Prepared full CRLs and native verified-path revocation checks.
//! Preparation validates scope encoding because native path verification can ignore malformed scope.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, ensure};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::nid::Nid;
use openssl::ssl::{Ssl, SslRef};
use openssl::stack::{Stack, StackRef};
use openssl::x509::{
    X509, X509Ref, X509Crl, X509Extension, X509ExtensionRef, X509StoreContext, X509PurposeId,
};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;

use super::super::{CertificateLifetime, CertificateValidity};
use super::super::validity::system_time;

/// Bounds parsing work and retained evidence for one prepared endpoint.
const MAXIMUM_CRL_BYTES: usize = 4 * 1024 * 1024;

#[allow(unsafe_code)]
unsafe extern "C" {
    fn ISSUING_DIST_POINT_free(scope: *mut std::ffi::c_void);
    fn X509_STORE_add_crl(
        store: *mut openssl_sys::X509_STORE,
        crl: *mut openssl_sys::X509_CRL,
    ) -> std::os::raw::c_int;
}

pub(in crate::transport::tls) struct CrlEvidence {
    lists: Vec<X509Crl>,
    pub(in crate::transport::tls) lifetime: CertificateLifetime,
}

impl CrlEvidence {
    pub(in crate::transport::tls) fn prepare(
        encoded: &[&[u8]],
        maximum_age: Duration,
    ) -> anyhow::Result<Self> {
        ensure!(!encoded.is_empty(), "Required CRL set is empty");
        ensure!(
            maximum_age.subsec_nanos() == 0
                && maximum_age.as_secs() > 0
                && u32::try_from(maximum_age.as_secs()).is_ok(),
            "CRL maximum age must be positive whole u32 seconds"
        );
        ensure!(
            encoded
                .iter()
                .try_fold(0usize, |total, data| total.checked_add(data.len()))
                .is_some_and(|total| total <= MAXIMUM_CRL_BYTES),
            "CRL set exceeds the size limit"
        );
        let mut lists = Vec::with_capacity(encoded.len());
        let mut validity: Option<CertificateValidity> = None;
        let mut issuers = std::collections::BTreeSet::new();
        for data in encoded {
            let crl = X509Crl::from_der(data).context("Invalid DER CRL")?;
            ensure!(
                crl.to_der()?.as_slice() == *data,
                "CRL input must contain exactly one DER object"
            );
            reject_delta_crl(&crl)?;
            validate_scope(&crl)?;
            ensure!(
                issuers.insert(crl.issuer_name().to_der()?),
                "CRL set contains multiple lists for one issuer"
            );
            let start = system_time(crl.last_update())?;
            let next = system_time(
                crl.next_update()
                    .context("Required CRL has no nextUpdate")?,
            )?;
            let limit = start
                .checked_add(maximum_age)
                .context("CRL age exceeds the clock range")?;
            let current = CertificateValidity::from_bounds(start, next.min(limit))?;
            ensure!(current.is_valid_at(SystemTime::now()), "CRL is stale or not yet valid");
            validity = Some(match validity {
                Some(previous) => previous.intersect(current)?,
                None => current,
            });
            lists.push(crl);
        }
        Ok(Self {
            lists,
            lifetime: CertificateLifetime::new(
                validity.context("Required CRL validity is missing")?,
            )?,
        })
    }

    fn verify(&self, chain: &StackRef<X509>) -> anyhow::Result<()> {
        self.verify_with_purpose(chain, X509PurposeId::SSL_SERVER, true)
    }

    #[allow(unsafe_code)]
    fn verify_with_purpose(
        &self,
        chain: &StackRef<X509>,
        purpose: X509PurposeId,
        entire_chain: bool,
    ) -> anyhow::Result<()> {
        self.lifetime.check()?;
        let leaf = chain.get(0).context("Verified peer chain is empty")?;
        let anchor = chain
            .iter()
            .next_back()
            .context("Verified peer anchor is missing")?;
        let mut store = X509StoreBuilder::new()?;
        let mut flags = X509VerifyFlags::PARTIAL_CHAIN | X509VerifyFlags::CRL_CHECK;
        if entire_chain {
            flags |= X509VerifyFlags::CRL_CHECK_ALL;
        }
        store.set_flags(flags)?;
        store.set_purpose(purpose)?;
        store.add_cert(anchor.to_owned())?;
        for crl in &self.lists {
            // SAFETY: Both native objects remain alive. OpenSSL takes its own
            // reference to each CRL; this call transfers no Rust ownership.
            ensure!(
                unsafe { X509_STORE_add_crl(store.as_ptr(), crl.as_ptr()) } == 1,
                "OpenSSL rejected CRL evidence"
            );
        }
        let store = store.build();
        let mut untrusted = Stack::new()?;
        for certificate in chain.iter().skip(1) {
            untrusted.push(certificate.to_owned())?;
        }
        let mut verification = X509StoreContext::new()?;
        let accepted = verification.init(
            &store,
            leaf,
            &untrusted,
            openssl::x509::X509StoreContextRef::verify_cert,
        )?;
        ensure!(accepted, "Peer CRL validation failed: {}", verification.error());
        Ok(())
    }
}

#[allow(unsafe_code)]
fn validate_scope(crl: &X509Crl) -> anyhow::Result<()> {
    let nid = Nid::ISSUING_DISTRIBUTION_POINT.as_raw();
    // SAFETY: The extension borrows the live CRL. Indices and pointers are
    // checked before use. Native decoding owns a separate scope allocation.
    unsafe {
        let position = openssl_sys::X509_CRL_get_ext_by_NID(crl.as_ptr(), nid, -1);
        if position < 0 {
            return Ok(());
        }
        ensure!(
            openssl_sys::X509_CRL_get_ext_by_NID(crl.as_ptr(), nid, position) < 0,
            "CRL has duplicate issuing distribution points"
        );
        let extension = openssl_sys::X509_CRL_get_ext(crl.as_ptr(), position);
        ensure!(!extension.is_null(), "CRL scope extension is missing");
        ensure!(
            openssl_sys::X509_EXTENSION_get_critical(extension) == 1,
            "CRL scope must be critical"
        );
        let scope = std::ptr::NonNull::new(openssl_sys::X509V3_EXT_d2i(extension))
            .ok_or_else(openssl::error::ErrorStack::get)
            .context("CRL scope is malformed")?;
        let encoded = openssl_sys::X509V3_EXT_i2d(nid, 1, scope.as_ptr());
        // SAFETY: The verified NID selects ISSUING_DIST_POINT decoding. The
        // encoder finishes all reads before this free; no Rust reference exists.
        ISSUING_DIST_POINT_free(scope.as_ptr());
        let encoded = std::ptr::NonNull::new(encoded)
            .ok_or_else(openssl::error::ErrorStack::get)
            .context("Could not encode CRL scope")?;
        let encoded = X509Extension::from_ptr(encoded.as_ptr());
        ensure!(
            encoded.to_der()? == X509ExtensionRef::from_ptr(extension).to_der()?,
            "CRL scope must round-trip as one DER value"
        );
    }
    Ok(())
}

#[allow(unsafe_code)]
fn reject_delta_crl(crl: &X509Crl) -> anyhow::Result<()> {
    for nid in [Nid::DELTA_CRL, Nid::FRESHEST_CRL] {
        // SAFETY: This read-only lookup borrows the live native CRL and returns an index.
        ensure!(
            unsafe { openssl_sys::X509_CRL_get_ext_by_NID(crl.as_ptr(), nid.as_raw(), -1) } < 0,
            "Delta CRLs and freshest-CRL references are not supported"
        );
    }
    Ok(())
}

struct ConnectionEvidence {
    evidence: Arc<CrlEvidence>,
    result: Mutex<Option<Result<(), String>>>,
}

type EvidenceIndex = openssl::ex_data::Index<Ssl, ConnectionEvidence>;

fn index() -> Result<EvidenceIndex, openssl::error::ErrorStack> {
    static INDEX: OnceLock<Result<EvidenceIndex, openssl::error::ErrorStack>> = OnceLock::new();
    INDEX
        .get_or_init(Ssl::new_ex_index)
        .as_ref()
        .copied()
        .map_err(Clone::clone)
}

pub(in crate::transport::tls) fn attach(
    ssl: &mut SslRef,
    evidence: Option<Arc<CrlEvidence>>,
) -> anyhow::Result<()> {
    if let Some(evidence) = evidence {
        ssl.set_ex_data(
            index()?,
            ConnectionEvidence {
                evidence,
                result: Mutex::new(None),
            },
        );
    }
    Ok(())
}

pub(in crate::transport::tls) fn verify(
    ssl: &SslRef,
    chain: Option<&StackRef<X509>>,
) -> anyhow::Result<()> {
    if let Some(connection) = ssl.ex_data(index()?) {
        let result = chain
            .context("Verified CRL certificate path is missing")
            .and_then(|chain| connection.evidence.verify(chain));
        *connection
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(
            result
                .as_ref()
                .copied()
                .map_err(|error| format!("{error:#}")),
        );
        result?;
    }
    Ok(())
}

pub(in crate::transport::tls) fn require_verified(ssl: &SslRef) -> anyhow::Result<()> {
    let Some(connection) = ssl.ex_data(index()?) else {
        return Ok(());
    };
    match connection
        .result
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
    {
        Some(Ok(())) => Ok(()),
        Some(Err(error)) => anyhow::bail!("CRL verification failed: {error}"),
        None => anyhow::bail!("Required CRL evidence was not verified"),
    }
}

pub(super) fn verify_responder(
    ssl: &SslRef,
    signer: &X509Ref,
    issuer: &X509Ref,
) -> anyhow::Result<()> {
    let connection = ssl
        .ex_data(index()?)
        .context("Delegated OCSP responder requires No Check or configured CRL evidence")?;
    require_verified(ssl)?;
    let mut chain = Stack::new()?;
    chain.push(signer.to_owned())?;
    chain.push(issuer.to_owned())?;
    connection
        .evidence
        .verify_with_purpose(&chain, X509PurposeId::OCSP_HELPER, false)
        .context("OCSP responder CRL validation failed")
}
