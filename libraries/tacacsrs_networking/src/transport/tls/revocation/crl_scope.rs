//! Strict native CRL scope decoding and unambiguous reason-partition admission.

use std::cmp::Ordering;
use std::ffi::{c_int, c_void};
use std::ptr::{self, NonNull};

use anyhow::{Context, ensure};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::asn1::Asn1BitStringRef;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::x509::{X509Crl, X509Extension, X509ExtensionRef, X509Name, X509NameRef};

/// RFC 5280 `ReasonFlags` bits 1 through 8; bit zero is unused.
const ALL_REASONS: u16 = 0x01fe;

/// Matches the public `ISSUING_DIST_POINT` layout in OpenSSL's x509v3.h.
#[repr(C)]
#[derive(Clone, Copy)]
struct NativeScope {
    distribution_point: *mut c_void,
    only_user: c_int,
    only_ca: c_int,
    reasons: *mut openssl_sys::ASN1_BIT_STRING,
    indirect: c_int,
    only_attribute: c_int,
}

#[allow(unsafe_code)]
unsafe extern "C" {
    fn ISSUING_DIST_POINT_free(scope: *mut NativeScope);
    fn ASN1_BIT_STRING_get_bit(bits: *const openssl_sys::ASN1_BIT_STRING, index: c_int) -> c_int;
}

struct OwnedScope(NonNull<NativeScope>);

impl Drop for OwnedScope {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: This allocation comes only from the IDP decoder and has one owner.
        unsafe {
            ISSUING_DIST_POINT_free(self.0.as_ptr());
        }
    }
}

pub(super) struct CrlScope {
    identity: Option<Vec<u8>>,
    reasons: u16,
    certificates: CertificateScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CertificateScope {
    All,
    EndEntity,
    Authority,
}

impl CertificateScope {
    fn from_flags(user: c_int, ca: c_int, attribute: c_int) -> anyhow::Result<Self> {
        match (user != 0, ca != 0, attribute != 0) {
            (false, false, false) => Ok(Self::All),
            (true, false, false) => Ok(Self::EndEntity),
            (false, true, false) => Ok(Self::Authority),
            (false, false, true) => anyhow::bail!("Attribute-certificate CRLs are not supported"),
            _ => anyhow::bail!("CRL scope has contradictory certificate types"),
        }
    }

    fn is_disjoint(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::EndEntity, Self::Authority) | (Self::Authority, Self::EndEntity)
        )
    }
}

impl CrlScope {
    fn merge(&mut self, other: &Self) -> anyhow::Result<()> {
        ensure!(self.identity == other.identity, "CRLs for one issuer must use the same scope");
        ensure!(self.reasons & other.reasons == 0, "CRL reason partitions overlap or repeat");
        self.reasons |= other.reasons;
        Ok(())
    }

    #[allow(unsafe_code)]
    pub(super) fn read(crl: &X509Crl) -> anyhow::Result<Self> {
        let nid = Nid::ISSUING_DISTRIBUTION_POINT.as_raw();
        // SAFETY: Extension pointers borrow the live CRL. The checked NID selects
        // NativeScope decoding. OwnedScope retains all decoded fields through encoding.
        unsafe {
            let position = openssl_sys::X509_CRL_get_ext_by_NID(crl.as_ptr(), nid, -1);
            if position < 0 {
                return Ok(Self {
                    identity: None,
                    reasons: ALL_REASONS,
                    certificates: CertificateScope::All,
                });
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
            let decoded = NonNull::new(openssl_sys::X509V3_EXT_d2i(extension))
                .ok_or_else(ErrorStack::get)
                .context("CRL scope is malformed")?;
            let scope = OwnedScope(decoded.cast());
            let encoded = NonNull::new(openssl_sys::X509V3_EXT_i2d(nid, 1, decoded.as_ptr()))
                .ok_or_else(ErrorStack::get)
                .context("Could not encode CRL scope")?;
            let encoded = X509Extension::from_ptr(encoded.as_ptr());
            ensure!(
                encoded.to_der()? == X509ExtensionRef::from_ptr(extension).to_der()?,
                "CRL scope must round-trip as one DER value"
            );
            let mut matching_scope = scope.0.as_ptr().read();
            ensure!(matching_scope.indirect == 0, "Indirect CRLs are not supported");
            let certificates = CertificateScope::from_flags(
                matching_scope.only_user,
                matching_scope.only_ca,
                matching_scope.only_attribute,
            )?;
            let reasons = if matching_scope.reasons.is_null() {
                ALL_REASONS
            } else {
                ensure!(
                    Asn1BitStringRef::from_ptr(matching_scope.reasons)
                        .as_slice()
                        .len()
                        <= 2,
                    "CRL reason flags exceed the supported range"
                );
                let mut reasons = 0u16;
                for index in 0..16 {
                    if ASN1_BIT_STRING_get_bit(matching_scope.reasons, index) != 0 {
                        reasons |= 1 << index;
                    }
                }
                ensure!(
                    reasons != 0 && reasons & !ALL_REASONS == 0,
                    "CRL reason flags are empty or unsupported"
                );
                reasons
            };
            matching_scope.reasons = ptr::null_mut();
            // SAFETY: This shallow copy borrows OwnedScope's fields. The encoder
            // takes no ownership. Only the original decoded object is freed.
            let identity = NonNull::new(openssl_sys::X509V3_EXT_i2d(
                nid,
                1,
                ptr::from_mut(&mut matching_scope).cast(),
            ))
            .ok_or_else(ErrorStack::get)
            .context("Could not encode CRL scope identity")?;
            let identity = X509Extension::from_ptr(identity.as_ptr()).to_der()?;
            Ok(Self {
                identity: Some(identity),
                reasons,
                certificates,
            })
        }
    }
}

#[derive(Default)]
pub(super) struct ScopeSet(Vec<(X509Name, CrlScope)>);

impl ScopeSet {
    pub(super) fn insert(&mut self, issuer: &X509NameRef, scope: CrlScope) -> anyhow::Result<()> {
        for (existing_issuer, existing) in &mut self.0 {
            if existing_issuer.try_cmp(issuer)? == Ordering::Equal {
                if existing.identity == scope.identity {
                    return existing.merge(&scope);
                }
                ensure!(
                    existing.certificates.is_disjoint(scope.certificates),
                    "CRLs for one issuer must use the same scope or disjoint certificate types"
                );
            }
        }
        self.0.push((issuer.to_owned()?, scope));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn partition(reasons: u16) -> CrlScope {
        CrlScope {
            identity: Some(vec![1]),
            reasons,
            certificates: CertificateScope::All,
        }
    }

    #[test]
    fn certificate_scope_flags_and_disjointness_are_explicit() {
        for (flags, expected) in [
            ((0, 0, 0), CertificateScope::All),
            ((255, 0, 0), CertificateScope::EndEntity),
            ((0, -1, 0), CertificateScope::Authority),
        ] {
            assert_eq!(CertificateScope::from_flags(flags.0, flags.1, flags.2).unwrap(), expected);
        }
        for flags in [
            (0, 0, 255),
            (255, 255, 0),
            (255, 0, 255),
            (0, 255, 255),
            (255, 255, 255),
        ] {
            assert!(CertificateScope::from_flags(flags.0, flags.1, flags.2).is_err());
        }
        for first in [
            CertificateScope::All,
            CertificateScope::EndEntity,
            CertificateScope::Authority,
        ] {
            for second in [
                CertificateScope::All,
                CertificateScope::EndEntity,
                CertificateScope::Authority,
            ] {
                assert_eq!(
                    first.is_disjoint(second),
                    first != CertificateScope::All
                        && second != CertificateScope::All
                        && first != second
                );
            }
        }
    }

    #[test]
    fn reason_partition_admission_rejects_overlap_without_changing_coverage() {
        let mut scope = partition(2);
        assert!(scope.merge(&partition(2)).is_err());
        assert!(scope.merge(&partition(6)).is_err());
        assert!(scope
            .merge(&CrlScope {
                identity: Some(vec![2]),
                reasons: 4,
                certificates: CertificateScope::All,
            })
            .is_err());
        assert!(scope
            .merge(&CrlScope {
                identity: None,
                reasons: ALL_REASONS,
                certificates: CertificateScope::All,
            })
            .is_err());
        assert_eq!(scope.reasons, 2);
        scope.merge(&partition(ALL_REASONS & !2)).unwrap();
        assert_eq!(scope.reasons, ALL_REASONS);
        assert!(scope.merge(&partition(4)).is_err());
    }

    #[test]
    fn issuer_comparison_uses_native_name_semantics() {
        let mut first = openssl::x509::X509NameBuilder::new().unwrap();
        first.append_entry_by_text("CN", "issuer").unwrap();
        let first = first.build();
        let mut equivalent = openssl::x509::X509NameBuilder::new().unwrap();
        equivalent.append_entry_by_text("CN", "  ISSUER  ").unwrap();
        let equivalent = equivalent.build();
        assert_ne!(first.to_der().unwrap(), equivalent.to_der().unwrap());
        assert_eq!(first.try_cmp(&equivalent).unwrap(), Ordering::Equal);
        let mut scopes = ScopeSet::default();
        scopes.insert(&first, partition(2)).unwrap();
        assert!(scopes.insert(&equivalent, partition(2)).is_err());
        scopes.insert(&equivalent, partition(4)).unwrap();
        assert!(scopes.insert(&first, partition(4)).is_err());
    }
}
