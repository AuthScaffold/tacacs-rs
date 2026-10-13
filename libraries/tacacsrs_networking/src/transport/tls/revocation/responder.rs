//! Native OCSP signer authorization and responder lifetime constraints.

use std::ptr;

use anyhow::{Context, ensure};
use foreign_types::ForeignTypeRef;
use openssl::asn1::Asn1OctetStringRef;
use openssl::nid::Nid;
use openssl::ocsp::{OcspBasicResponseRef, OcspFlag};
use openssl::stack::Stack;
use openssl::x509::{X509Ref, X509VerifyResult};
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyFlags;

use super::super::CertificateValidity;

/// The No Check extension has the DER encoding of ASN.1 NULL.
const DER_NULL: &[u8] = &[0x05, 0x00];

#[allow(unsafe_code)]
unsafe extern "C" {
    fn OCSP_resp_get0_signer(
        response: *mut openssl_sys::OCSP_BASICRESP,
        signer: *mut *mut openssl_sys::X509,
        certificates: *mut openssl_sys::stack_st_X509,
    ) -> std::os::raw::c_int;
}

#[allow(unsafe_code)]
pub(super) fn verify(
    response: &OcspBasicResponseRef,
    issuer: &X509Ref,
) -> anyhow::Result<CertificateValidity> {
    let mut certificates = Stack::new()?;
    certificates.push(issuer.to_owned())?;
    let mut store = X509StoreBuilder::new()?;
    store.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;
    store.add_cert(issuer.to_owned())?;
    let store = store.build();
    response
        .verify(&certificates, &store, OcspFlag::NO_EXPLICIT)
        .context("OCSP response signer is not authorized by the peer certificate issuer")?;
    let mut signer = ptr::null_mut();
    // SAFETY: The response and certificate stack remain alive. OpenSSL writes a
    // borrowed signer pointer owned by one of them; it is never freed here.
    let found =
        unsafe { OCSP_resp_get0_signer(response.as_ptr(), &raw mut signer, certificates.as_ptr()) };
    ensure!(found == 1 && !signer.is_null(), "Verified OCSP response signer is missing");
    // SAFETY: The pointer was checked above, and both possible owners remain
    // alive until all signer reads finish. No borrowed reference escapes.
    let signer = unsafe { X509Ref::from_ptr(signer) };
    if signer.to_der()? != issuer.to_der()? {
        ensure!(
            issuer.issued(signer) == X509VerifyResult::OK,
            "OCSP responder must be issued directly by the peer issuer"
        );
        let key = issuer.public_key()?;
        ensure!(signer.verify(&key)?, "OCSP responder certificate signature is invalid");
        // SAFETY: The verified signer remains alive. OpenSSL reads its cached
        // key-usage mask and returns all usage bits when the extension is absent.
        let key_usage = unsafe { openssl_sys::X509_get_key_usage(signer.as_ptr()) };
        ensure!(
            key_usage & openssl_sys::X509v3_KU_DIGITAL_SIGNATURE != 0,
            "OCSP responder key usage must permit digital signatures"
        );
        require_no_check(signer)?;
    }
    CertificateValidity::from_certificate(signer)?
        .intersect(CertificateValidity::from_certificate(issuer)?)
}

#[allow(unsafe_code)]
fn require_no_check(certificate: &X509Ref) -> anyhow::Result<()> {
    let nid = Nid::ID_PKIX_OCSP_NOCHECK.as_raw();
    // SAFETY: All native reads borrow the live certificate. Indices and returned
    // pointers are checked before use; no extension data outlives the certificate.
    unsafe {
        let position = openssl_sys::X509_get_ext_by_NID(certificate.as_ptr(), nid, -1);
        ensure!(position >= 0, "Delegated OCSP responder requires the No Check extension");
        ensure!(
            openssl_sys::X509_get_ext_by_NID(certificate.as_ptr(), nid, position) < 0,
            "Delegated OCSP responder has duplicate No Check extensions"
        );
        let extension = openssl_sys::X509_get_ext(certificate.as_ptr(), position);
        ensure!(!extension.is_null(), "OCSP responder No Check extension is missing");
        ensure!(
            openssl_sys::X509_EXTENSION_get_critical(extension) == 0,
            "OCSP responder No Check must be noncritical"
        );
        let data = openssl_sys::X509_EXTENSION_get_data(extension);
        ensure!(!data.is_null(), "OCSP responder No Check data is missing");
        ensure!(
            Asn1OctetStringRef::from_ptr(data).as_slice() == DER_NULL,
            "OCSP responder No Check must contain DER NULL"
        );
    }
    Ok(())
}
