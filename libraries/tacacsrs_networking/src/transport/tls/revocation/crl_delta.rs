//! Strict delta metadata decoding and complete, unambiguous base/delta pairing.

use std::cmp::Ordering;
use std::ffi::c_void;
use std::ptr::NonNull;

use anyhow::{Context, ensure};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::asn1::Asn1Integer;
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::x509::{X509Crl, X509Extension, X509ExtensionRef};

use super::super::validity::system_time;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CrlNumber([u8; 20]);

pub(super) struct CrlMetadata {
    number: Option<CrlNumber>,
    base_number: Option<CrlNumber>,
    scope: Option<crate::preparation_payload::PayloadBytes>,
    authority: Option<crate::preparation_payload::PayloadBytes>,
    freshest: bool,
}

impl CrlMetadata {
    pub(super) fn read(
        crl: &X509Crl,
        payload: &crate::PreparationPayload,
        encoded_bound: usize,
    ) -> anyhow::Result<Self> {
        let number = read_number(crl, Nid::CRL_NUMBER, false, payload, encoded_bound)?;
        let base_number = read_number(crl, Nid::DELTA_CRL, true, payload, encoded_bound)?;
        let scope = extension(crl, Nid::ISSUING_DISTRIBUTION_POINT)?
            .map(|extension| payload.native_bytes(encoded_bound, || extension.to_der()))
            .transpose()?;
        let authority = checked_extension(crl, ExtensionKind::Authority, payload, encoded_bound)?;
        let freshest =
            checked_extension(crl, ExtensionKind::Freshest, payload, encoded_bound)?.is_some();
        ensure!(
            base_number.is_none() || !freshest,
            "Delta CRLs cannot contain freshest-CRL references"
        );
        ensure!(base_number.is_none() || number.is_some(), "Delta CRL has no CRL number");
        validate_entries(crl, base_number.is_some(), payload, encoded_bound)?;
        Ok(Self {
            number,
            base_number,
            scope,
            authority,
            freshest,
        })
    }

    pub(super) fn is_delta(&self) -> bool {
        self.base_number.is_some()
    }

    pub(super) fn uses_delta(&self) -> bool {
        self.is_delta() || self.freshest
    }

    fn matches_base(&self, base: &Self) -> bool {
        match (self.base_number, base.number, self.number) {
            (Some(minimum), Some(base_number), Some(delta_number)) => {
                !base.is_delta()
                    && base.freshest
                    && self.scope == base.scope
                    && self.authority == base.authority
                    && minimum <= base_number
                    && base_number < delta_number
            }
            _ => false,
        }
    }
}

pub(super) fn validate_pairs(lists: &[X509Crl], metadata: &[CrlMetadata]) -> anyhow::Result<()> {
    let mut paired = vec![false; lists.len()];
    for (delta_index, delta) in metadata
        .iter()
        .enumerate()
        .filter(|(_, entry)| entry.is_delta())
    {
        let mut selected = None;
        for (base_index, base) in metadata.iter().enumerate() {
            if delta.matches_base(base)
                && lists[base_index]
                    .issuer_name()
                    .try_cmp(lists[delta_index].issuer_name())?
                    == Ordering::Equal
            {
                ensure!(selected.is_none(), "Delta CRL has multiple compatible bases");
                selected = Some(base_index);
            }
        }
        let base_index = selected.context("Delta CRL has no compatible advertised base")?;
        ensure!(!paired[base_index], "A CRL base cannot have multiple deltas");
        ensure!(
            system_time(lists[delta_index].last_update())?
                >= system_time(lists[base_index].last_update())?,
            "Delta CRL predates its base"
        );
        paired[base_index] = true;
    }
    for (index, base) in metadata.iter().enumerate() {
        ensure!(
            base.is_delta() || !base.freshest || paired[index],
            "Advertised delta CRL is missing"
        );
    }
    Ok(())
}

#[allow(unsafe_code)]
fn extension(crl: &X509Crl, nid: Nid) -> anyhow::Result<Option<&X509ExtensionRef>> {
    // SAFETY: The returned extension borrows the immutable, live CRL. Native
    // indices and pointers are checked, and the Rust lifetime is tied to crl.
    unsafe {
        let index = openssl_sys::X509_CRL_get_ext_by_NID(crl.as_ptr(), nid.as_raw(), -1);
        if index < 0 {
            return Ok(None);
        }
        ensure!(
            openssl_sys::X509_CRL_get_ext_by_NID(crl.as_ptr(), nid.as_raw(), index) < 0,
            "Duplicate CRL metadata extension"
        );
        let value = openssl_sys::X509_CRL_get_ext(crl.as_ptr(), index);
        ensure!(!value.is_null(), "CRL metadata extension is missing");
        Ok(Some(X509ExtensionRef::from_ptr(value)))
    }
}

#[allow(unsafe_code)]
fn read_number(
    crl: &X509Crl,
    nid: Nid,
    critical: bool,
    payload: &crate::PreparationPayload,
    encoded_bound: usize,
) -> anyhow::Result<Option<CrlNumber>> {
    let Some(extension) = extension(crl, nid)? else {
        return Ok(None);
    };
    // SAFETY: Callers select only ASN.1 integer extensions. The owned integer
    // and re-encoded extension use their native Rust destructors on every exit.
    unsafe {
        ensure!(
            (openssl_sys::X509_EXTENSION_get_critical(extension.as_ptr()) != 0) == critical,
            "Invalid CRL number extension criticality"
        );
        let decoded = NonNull::new(openssl_sys::X509V3_EXT_d2i(extension.as_ptr()))
            .ok_or_else(ErrorStack::get)
            .context("Malformed CRL number extension")?;
        let integer = Asn1Integer::from_ptr(decoded.as_ptr().cast());
        let encoded = NonNull::new(openssl_sys::X509V3_EXT_i2d(
            nid.as_raw(),
            i32::from(critical),
            integer.as_ptr().cast(),
        ))
        .ok_or_else(ErrorStack::get)
        .context("Could not encode CRL number")?;
        let encoded = X509Extension::from_ptr(encoded.as_ptr());
        ensure!(
            payload.native_bytes(encoded_bound, || encoded.to_der())?
                == payload.native_bytes(encoded_bound, || extension.to_der())?,
            "CRL number must round-trip as one DER value"
        );
        let value = integer.to_bn()?;
        ensure!(
            !value.is_negative() && value.num_bits() <= 159,
            "CRL number must be nonnegative and fit 20 DER octets"
        );
        let _bytes = payload.temporary(usize::try_from(value.num_bytes())?)?;
        let bytes = value.to_vec();
        let mut result = [0; 20];
        result[20 - bytes.len()..].copy_from_slice(&bytes);
        Ok(Some(CrlNumber(result)))
    }
}

#[derive(Clone, Copy)]
enum ExtensionKind {
    Authority,
    Freshest,
}

#[allow(unsafe_code)]
fn validate_entries(
    crl: &X509Crl,
    delta: bool,
    payload: &crate::PreparationPayload,
    encoded_bound: usize,
) -> anyhow::Result<()> {
    for entry in crl.get_revoked().into_iter().flatten() {
        // SAFETY: Each extension borrows an entry owned by the live CRL. The
        // typed reason owns its decoded value; re-encoding returns an owned extension.
        unsafe {
            let nid = Nid::CRL_REASON.as_raw();
            let index = openssl_sys::X509_REVOKED_get_ext_by_NID(entry.as_ptr(), nid, -1);
            if index < 0 {
                continue;
            }
            ensure!(
                openssl_sys::X509_REVOKED_get_ext_by_NID(entry.as_ptr(), nid, index) < 0,
                "Duplicate CRL entry reason"
            );
            let original = openssl_sys::X509_REVOKED_get_ext(entry.as_ptr(), index);
            ensure!(!original.is_null(), "CRL entry reason is missing");
            let (critical, reason) = entry
                .extension::<openssl::x509::ReasonCode>()?
                .context("Malformed CRL entry reason")?;
            ensure!(!critical, "CRL entry reason must be noncritical");
            let encoded = NonNull::new(openssl_sys::X509V3_EXT_i2d(nid, 0, reason.as_ptr().cast()))
                .ok_or_else(ErrorStack::get)
                .context("Could not encode CRL entry reason")?;
            let encoded = X509Extension::from_ptr(encoded.as_ptr());
            ensure!(
                payload.native_bytes(encoded_bound, || encoded.to_der())?
                    == payload
                        .native_bytes(encoded_bound, || X509ExtensionRef::from_ptr(original)
                            .to_der())?,
                "CRL entry reason must round-trip as one DER value"
            );
            let reason = reason.get_i64()?;
            ensure!(matches!(reason, 0..=6 | 8..=10), "Unsupported CRL entry reason");
            ensure!(
                delta || reason != i64::from(openssl::x509::CrlReason::REMOVE_FROM_CRL.as_raw()),
                "removeFromCRL requires a delta CRL"
            );
        }
    }
    Ok(())
}

impl ExtensionKind {
    fn nid(self) -> Nid {
        match self {
            Self::Authority => Nid::AUTHORITY_KEY_IDENTIFIER,
            Self::Freshest => Nid::FRESHEST_CRL,
        }
    }
}

#[allow(unsafe_code)]
unsafe extern "C" {
    fn CRL_DIST_POINTS_free(points: *mut c_void);
}

struct DecodedExtension {
    pointer: NonNull<c_void>,
    kind: ExtensionKind,
}

impl Drop for DecodedExtension {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: The closed kind selects the same type used by the decoder.
        // This object uniquely owns the native allocation.
        unsafe {
            match self.kind {
                ExtensionKind::Authority => {
                    openssl_sys::AUTHORITY_KEYID_free(self.pointer.as_ptr().cast());
                }
                ExtensionKind::Freshest => CRL_DIST_POINTS_free(self.pointer.as_ptr()),
            }
        }
    }
}

#[allow(unsafe_code)]
fn checked_extension(
    crl: &X509Crl,
    kind: ExtensionKind,
    payload: &crate::PreparationPayload,
    encoded_bound: usize,
) -> anyhow::Result<Option<crate::preparation_payload::PayloadBytes>> {
    let Some(extension) = extension(crl, kind.nid())? else {
        return Ok(None);
    };
    // SAFETY: The enum fixes the decoder/free pair. All pointers borrow the CRL
    // or the owned decoder allocation; only copied DER bytes leave this block.
    unsafe {
        ensure!(
            openssl_sys::X509_EXTENSION_get_critical(extension.as_ptr()) == 0,
            "CRL authority and freshest extensions must be noncritical"
        );
        let decoded = DecodedExtension {
            pointer: NonNull::new(openssl_sys::X509V3_EXT_d2i(extension.as_ptr()))
                .ok_or_else(ErrorStack::get)
                .context("Malformed CRL authority or freshest extension")?,
            kind,
        };
        if matches!(kind, ExtensionKind::Freshest) {
            ensure!(
                openssl_sys::OPENSSL_sk_num(decoded.pointer.as_ptr().cast()) > 0,
                "Freshest CRL extension is empty"
            );
        }
        let encoded = NonNull::new(openssl_sys::X509V3_EXT_i2d(
            kind.nid().as_raw(),
            0,
            decoded.pointer.as_ptr(),
        ))
        .ok_or_else(ErrorStack::get)
        .context("Could not encode CRL metadata")?;
        let encoded = X509Extension::from_ptr(encoded.as_ptr());
        let encoded = payload.native_bytes(encoded_bound, || encoded.to_der())?;
        ensure!(
            encoded == payload.native_bytes(encoded_bound, || extension.to_der())?,
            "CRL metadata must round-trip as one DER value"
        );
        Ok(Some(encoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn number(value: u8) -> CrlNumber {
        let mut bytes = [0; 20];
        bytes[19] = value;
        CrlNumber(bytes)
    }

    fn metadata(value: u8, minimum: Option<u8>) -> CrlMetadata {
        CrlMetadata {
            number: Some(number(value)),
            base_number: minimum.map(number),
            scope: None,
            authority: None,
            freshest: minimum.is_none(),
        }
    }

    #[test]
    fn delta_pairing_number_interval_and_metadata_are_strict() {
        for minimum in 0..4 {
            for base in 0..4 {
                for delta in 0..4 {
                    assert_eq!(
                        metadata(delta, Some(minimum)).matches_base(&metadata(base, None)),
                        minimum <= base && base < delta
                    );
                }
            }
        }
        let mut base = metadata(2, None);
        let mut delta = metadata(3, Some(1));
        base.freshest = false;
        assert!(!delta.matches_base(&base));
        base.freshest = true;
        delta.scope = Some(vec![1].into());
        assert!(!delta.matches_base(&base));
        base.scope = Some(vec![1].into());
        assert!(delta.matches_base(&base));
        delta.authority = Some(vec![2].into());
        assert!(!delta.matches_base(&base));
        base.authority = Some(vec![2].into());
        assert!(delta.matches_base(&base));
        base.base_number = Some(number(1));
        assert!(!delta.matches_base(&base));
        base.base_number = None;
        delta.number = None;
        assert!(!delta.matches_base(&base));
    }
}
