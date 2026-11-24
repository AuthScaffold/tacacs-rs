//! Parsed CRLs with the metadata that selection, pairing, and refresh use.

use std::cmp::Ordering;
use std::time::SystemTime;

use anyhow::{Context, Result, bail, ensure};
use der::asn1::{BitString, Uint};
use der::oid::ObjectIdentifier;
use der::{Decode, Sequence};
use openssl::bn::BigNum;
use openssl::hash::{MessageDigest, hash};
use openssl::x509::X509Crl;
use x509_cert::Version;
use x509_cert::crl::RevokedCert;
use x509_cert::ext::{Extension, Extensions};
use x509_cert::ext::pkix::crl::dp::IssuingDistributionPoint;
use x509_cert::ext::pkix::name::DistributionPointName;
use x509_cert::ext::pkix::{BaseCrlNumber, CrlNumber, FreshestCrl};
use x509_cert::name::Name;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::time::Time;

use crate::certificate::{
    CertificateInfo, OID_FRESHEST_CRL, distribution_point_uris, general_name_uris,
    reject_duplicate_extensions,
};

/// RFC 5280 limits CRL numbers to 20 octets.
const MAXIMUM_CRL_NUMBER_OCTETS: usize = 20;

const OID_CRL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.20");
const OID_DELTA_CRL_INDICATOR: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.27");
const OID_ISSUING_DISTRIBUTION_POINT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.28");
const OID_CERTIFICATE_ISSUER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.29");
/// AD CS "Next CRL Publish" extension OID.
const OID_NEXT_CRL_PUBLISH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.21.4");

/// Nonnegative CRL sequence number ordered by numeric value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CrlSequenceNumber(Vec<u8>);

impl CrlSequenceNumber {
    fn from_uint(value: &Uint) -> Result<Self> {
        let magnitude = value.as_bytes();
        ensure!(magnitude.len() <= MAXIMUM_CRL_NUMBER_OCTETS, "CRL number exceeds 20 octets");
        let start = magnitude
            .iter()
            .position(|octet| *octet != 0)
            .unwrap_or(magnitude.len());
        Ok(Self(magnitude[start..].to_vec()))
    }
}

impl PartialOrd for CrlSequenceNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CrlSequenceNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

/// RFC 5280 `CertificateList` with optional `version` per Section 5.1.2.1.
#[derive(Sequence)]
struct DecodedCertificateList {
    tbs_cert_list: DecodedTbsCertList,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

#[derive(Sequence)]
struct DecodedTbsCertList {
    version: Option<Version>,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    this_update: Time,
    next_update: Option<Time>,
    revoked_certificates: Option<Vec<RevokedCert>>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    crl_extensions: Option<Extensions>,
}

/// A parsed CRL. The signature is not verified at this stage.
pub(crate) struct Crl {
    pub(crate) crl: X509Crl,
    pub(crate) der: Vec<u8>,
    pub(crate) digest: [u8; 32],
    pub(crate) this_update: SystemTime,
    pub(crate) next_update: Option<SystemTime>,
    pub(crate) next_publish: Option<SystemTime>,
    pub(crate) number: Option<CrlSequenceNumber>,
    pub(crate) delta_base: Option<CrlSequenceNumber>,
    pub(crate) scope: CrlScope,
    pub(crate) freshest: Vec<String>,
}

/// The issuing distribution point of a CRL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CrlScope {
    /// The DER extension value. Base and delta CRLs must have the same value.
    pub(crate) identity: Option<Vec<u8>>,
    pub(crate) only_user: bool,
    pub(crate) only_ca: bool,
    pub(crate) names: Vec<String>,
}

impl CrlScope {
    /// Returns whether a CRL with this scope can cover the certificate.
    pub(crate) fn applies_to(&self, certificate: &CertificateInfo) -> bool {
        if (self.only_user && certificate.is_ca) || (self.only_ca && !certificate.is_ca) {
            return false;
        }
        self.names.is_empty()
            || certificate
                .distribution_points
                .iter()
                .any(|name| self.names.contains(name))
    }

    fn read(value: &[u8]) -> Result<Self> {
        let decoded =
            IssuingDistributionPoint::from_der(value).context("Invalid CRL scope extension")?;
        let names = match &decoded.distribution_point {
            None => Vec::new(),
            Some(DistributionPointName::FullName(general_names)) => {
                let uris = general_name_uris(general_names);
                ensure!(!uris.is_empty(), "CRL scopes without URI names are not supported");
                uris
            }
            Some(DistributionPointName::NameRelativeToCRLIssuer(_)) => {
                bail!("CRL scopes relative to the CRL issuer are not supported")
            }
        };
        ensure!(decoded.only_some_reasons.is_none(), "CRL reason partitions are not supported");
        ensure!(!decoded.indirect_crl, "Indirect CRLs are not supported");
        ensure!(
            !decoded.only_contains_attribute_certs,
            "Attribute certificate CRLs are not supported"
        );
        ensure!(
            !(decoded.only_contains_user_certs && decoded.only_contains_ca_certs),
            "CRL scope has contradictory certificate types"
        );
        Ok(Self {
            identity: Some(value.to_vec()),
            only_user: decoded.only_contains_user_certs,
            only_ca: decoded.only_contains_ca_certs,
            names,
        })
    }
}

impl Crl {
    /// Parses one DER or PEM CRL.
    pub(crate) fn parse(body: &[u8]) -> Result<Self> {
        let trimmed = body.trim_ascii_start();
        let der = if trimmed.starts_with(b"-----BEGIN") {
            X509Crl::from_pem(trimmed)
                .context("Invalid PEM CRL")?
                .to_der()
                .context("Could not encode a PEM CRL")?
        } else {
            body.to_vec()
        };
        let crl = X509Crl::from_der(&der).context("Invalid DER CRL")?;
        let decoded = DecodedCertificateList::from_der(&der).context("Invalid RFC 5280 CRL")?;
        let _ = (&decoded.signature_algorithm, &decoded.signature);
        let tbs = decoded.tbs_cert_list;
        let _ = (tbs.version, &tbs.signature, &tbs.issuer);
        if let Some(revoked) = &tbs.revoked_certificates {
            for entry in revoked {
                if let Some(extensions) = &entry.crl_entry_extensions {
                    reject_duplicate_extensions(extensions)?;
                    for extension in extensions {
                        ensure!(
                            extension.extn_id != OID_CERTIFICATE_ISSUER,
                            "Indirect CRL entries are not supported"
                        );
                        ensure!(
                            !extension.critical,
                            "CRL entry has an unsupported critical extension"
                        );
                    }
                }
            }
        }
        let mut parsed = Self {
            digest: digest(&der)?,
            crl,
            der: Vec::new(),
            this_update: tbs.this_update.to_system_time(),
            next_update: tbs.next_update.map(|time| time.to_system_time()),
            next_publish: None,
            number: None,
            delta_base: None,
            scope: CrlScope::default(),
            freshest: Vec::new(),
        };
        if let Some(extensions) = &tbs.crl_extensions {
            reject_duplicate_extensions(extensions)?;
            for extension in extensions {
                parsed.read_extension(extension)?;
            }
        }
        if parsed.delta_base.is_some() {
            ensure!(parsed.number.is_some(), "Delta CRL has no CRL number");
            ensure!(
                parsed.freshest.is_empty(),
                "Delta CRLs cannot contain freshest CRL references"
            );
        }
        // OpenSSL sorts the revoked list on the first lookup. Sort it here, on
        // the blocking pool, so that the lookup in the verify callback is cheap.
        let zero = BigNum::new()?.to_asn1_integer()?;
        let _ = parsed.crl.get_by_serial(&zero);
        parsed.der = der;
        Ok(parsed)
    }

    fn read_extension(&mut self, extension: &Extension) -> Result<()> {
        let value = extension.extn_value.as_bytes();
        if extension.extn_id == OID_CRL_NUMBER {
            let number = CrlNumber::from_der(value).context("Invalid CRL number")?;
            self.number = Some(CrlSequenceNumber::from_uint(&number.0)?);
        } else if extension.extn_id == OID_DELTA_CRL_INDICATOR {
            ensure!(extension.critical, "The delta CRL indicator must be critical");
            let base = BaseCrlNumber::from_der(value).context("Invalid delta CRL indicator")?;
            self.delta_base = Some(CrlSequenceNumber::from_uint(&base.0)?);
        } else if extension.extn_id == OID_ISSUING_DISTRIBUTION_POINT {
            ensure!(extension.critical, "The CRL scope must be critical");
            self.scope = CrlScope::read(value)?;
        } else if extension.extn_id == OID_FRESHEST_CRL {
            let points = FreshestCrl::from_der(value).context("Invalid freshest CRL extension")?;
            self.freshest = distribution_point_uris(&points.0);
        } else if extension.extn_id == OID_NEXT_CRL_PUBLISH {
            // The value is only a refresh hint. Ignore a malformed hint.
            self.next_publish = Time::from_der(value).ok().map(|time| time.to_system_time());
        } else if extension.critical {
            bail!("CRL has an unsupported critical extension");
        }
        Ok(())
    }

    /// Returns whether this CRL is a delta CRL.
    pub(crate) fn is_delta(&self) -> bool {
        self.delta_base.is_some()
    }

    /// Orders two CRLs from the same issuer by CRL number, then by `thisUpdate`.
    pub(crate) fn recency(&self, other: &Self) -> Ordering {
        match (&self.number, &other.number) {
            (Some(left), Some(right)) => left.cmp(right),
            _ => Ordering::Equal,
        }
        .then_with(|| self.this_update.cmp(&other.this_update))
    }

    /// Returns whether this delta CRL can update `base`.
    pub(crate) fn is_delta_for(&self, base: &Self) -> bool {
        match (&self.delta_base, &base.number, &self.number) {
            (Some(minimum), Some(base_number), Some(delta_number)) => {
                !base.is_delta()
                    && self.scope.identity == base.scope.identity
                    && minimum <= base_number
                    && base_number < delta_number
                    && self.this_update >= base.this_update
                    && self
                        .crl
                        .issuer_name()
                        .try_cmp(base.crl.issuer_name())
                        .is_ok_and(Ordering::is_eq)
            }
            _ => false,
        }
    }
}

/// Returns the SHA-256 digest of `data`.
pub(crate) fn digest(data: &[u8]) -> Result<[u8; 32]> {
    let value = hash(MessageDigest::sha256(), data)?;
    let mut result = [0; 32];
    result.copy_from_slice(&value);
    Ok(result)
}

/// Returns lowercase hexadecimal text for `data`.
pub(crate) fn hex(data: &[u8]) -> String {
    use std::fmt::Write;
    data.iter()
        .fold(String::with_capacity(data.len() * 2), |mut text, octet| {
            let _ = write!(text, "{octet:02x}");
            text
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crl_sequence_numbers_order_numerically() {
        let small = CrlSequenceNumber::from_uint(&Uint::new(&[0xff]).unwrap()).unwrap();
        let large = CrlSequenceNumber::from_uint(&Uint::new(&[0x01, 0x00]).unwrap()).unwrap();
        assert!(small < large);
        assert_eq!(
            CrlSequenceNumber::from_uint(&Uint::new(&[0x00]).unwrap()).unwrap(),
            CrlSequenceNumber::from_uint(&Uint::new(&[]).unwrap()).unwrap()
        );
    }
}
