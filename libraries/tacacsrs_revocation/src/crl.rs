//! Parsed CRLs with the metadata that selection, pairing, and refresh use.

use std::cmp::Ordering;
use std::time::SystemTime;

use anyhow::{Context, Result, bail, ensure};
use openssl::bn::BigNum;
use openssl::hash::{MessageDigest, hash};
use openssl::x509::X509Crl;

use crate::certificate::CertificateInfo;
use crate::der::{self, Reader, Unsigned};

/// RFC 5280 limits CRL numbers to 20 octets.
const MAXIMUM_CRL_NUMBER_OCTETS: usize = 20;

/// A parsed CRL. The signature is not verified at this stage.
pub(crate) struct Crl {
    pub(crate) crl: X509Crl,
    pub(crate) der: Vec<u8>,
    pub(crate) digest: [u8; 32],
    pub(crate) this_update: SystemTime,
    pub(crate) next_update: Option<SystemTime>,
    pub(crate) next_publish: Option<SystemTime>,
    pub(crate) number: Option<Unsigned>,
    pub(crate) delta_base: Option<Unsigned>,
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
        let sequence = der::single(value, der::SEQUENCE)?;
        let mut fields = Reader::new(sequence.value);
        let mut scope = Self {
            identity: Some(value.to_vec()),
            ..Self::default()
        };
        if let Some(point) = fields.optional(der::constructed(0))? {
            let choice = der::single_any(point.value)?;
            ensure!(
                choice.tag == der::constructed(0),
                "CRL scopes relative to the CRL issuer are not supported"
            );
            scope.names = der::general_name_uris(choice.value)?;
        }
        if let Some(value) = fields.optional(der::primitive(1))? {
            scope.only_user = der::boolean(value)?;
        }
        if let Some(value) = fields.optional(der::primitive(2))? {
            scope.only_ca = der::boolean(value)?;
        }
        ensure!(
            fields.optional(der::primitive(3))?.is_none(),
            "CRL reason partitions are not supported"
        );
        if let Some(value) = fields.optional(der::primitive(4))? {
            ensure!(!der::boolean(value)?, "Indirect CRLs are not supported");
        }
        if let Some(value) = fields.optional(der::primitive(5))? {
            ensure!(!der::boolean(value)?, "Attribute certificate CRLs are not supported");
        }
        ensure!(fields.is_empty(), "CRL scope has unknown fields");
        ensure!(
            !(scope.only_user && scope.only_ca),
            "CRL scope has contradictory certificate types"
        );
        Ok(scope)
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
        let outer = der::single(&der, der::SEQUENCE).context("CRL must be one DER object")?;
        let mut outer = Reader::new(outer.value);
        let tbs = outer.expect(der::SEQUENCE)?;
        let mut tbs = Reader::new(tbs.value);
        tbs.optional(der::INTEGER)?;
        tbs.expect(der::SEQUENCE)?;
        tbs.expect(der::SEQUENCE)?;
        let this_update = der::time(tbs.read()?).context("Invalid CRL thisUpdate")?;
        let next_update = match tbs.peek_tag() {
            Some(der::UTC_TIME | der::GENERALIZED_TIME) => {
                Some(der::time(tbs.read()?).context("Invalid CRL nextUpdate")?)
            }
            _ => None,
        };
        tbs.optional(der::SEQUENCE)?;
        let mut parsed = Self {
            digest: digest(&der)?,
            crl,
            der: Vec::new(),
            this_update,
            next_update,
            next_publish: None,
            number: None,
            delta_base: None,
            scope: CrlScope::default(),
            freshest: Vec::new(),
        };
        if let Some(wrapper) = tbs.optional(der::constructed(0))? {
            let sequence = der::single(wrapper.value, der::SEQUENCE)?;
            for extension in der::extensions(sequence.value)? {
                parsed.read_extension(extension)?;
            }
        }
        ensure!(tbs.is_empty(), "CRL has unknown fields");
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

    fn read_extension(&mut self, extension: der::Extension<'_>) -> Result<()> {
        match extension.oid {
            der::OID_CRL_NUMBER => {
                let value = der::single(extension.value, der::INTEGER)?;
                self.number = Some(Unsigned::read(value.value, MAXIMUM_CRL_NUMBER_OCTETS)?);
            }
            der::OID_DELTA_CRL_INDICATOR => {
                ensure!(extension.critical, "The delta CRL indicator must be critical");
                let value = der::single(extension.value, der::INTEGER)?;
                self.delta_base = Some(Unsigned::read(value.value, MAXIMUM_CRL_NUMBER_OCTETS)?);
            }
            der::OID_ISSUING_DISTRIBUTION_POINT => {
                ensure!(extension.critical, "The CRL scope must be critical");
                self.scope = CrlScope::read(extension.value)?;
            }
            der::OID_FRESHEST_CRL => {
                self.freshest = crate::certificate::distribution_point_uris(extension.value)
                    .context("Invalid freshest CRL extension")?;
            }
            der::OID_NEXT_CRL_PUBLISH => {
                // The value is only a refresh hint. Ignore a malformed hint.
                self.next_publish = der::single_any(extension.value)
                    .ok()
                    .and_then(|value| der::time(value).ok());
            }
            _ if extension.critical => bail!("CRL has an unsupported critical extension"),
            _ => {}
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
