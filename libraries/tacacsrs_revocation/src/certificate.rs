//! Revocation fields of a certificate in a verified path.

use anyhow::{Context, Result};
use openssl::x509::X509Ref;

use crate::der::{self, Reader};

/// The certificate fields that select and scope a CRL.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CertificateInfo {
    /// All URIs from the CRL distribution points, in certificate order.
    pub(crate) distribution_points: Vec<String>,
    /// All URIs from the freshest CRL extension, in certificate order.
    pub(crate) freshest: Vec<String>,
    /// Whether the basic constraints mark the certificate as a CA.
    pub(crate) is_ca: bool,
}

impl CertificateInfo {
    /// Reads the revocation fields of `certificate`.
    pub(crate) fn read(certificate: &X509Ref) -> Result<Self> {
        let encoded = certificate
            .to_der()
            .context("Could not encode a certificate")?;
        let certificate = der::single(&encoded, der::SEQUENCE)?;
        let mut fields = Reader::new(certificate.value);
        let tbs = fields.expect(der::SEQUENCE)?;
        let mut tbs = Reader::new(tbs.value);
        tbs.optional(der::constructed(0))?;
        tbs.expect(der::INTEGER)?;
        for _ in 0..5 {
            // signature, issuer, validity, subject, subjectPublicKeyInfo
            tbs.expect(der::SEQUENCE)?;
        }
        tbs.optional(der::primitive(1))?;
        tbs.optional(der::primitive(2))?;
        let mut info = Self::default();
        let Some(wrapper) = tbs.optional(der::constructed(3))? else {
            return Ok(info);
        };
        let sequence = der::single(wrapper.value, der::SEQUENCE)?;
        for extension in der::extensions(sequence.value)? {
            match extension.oid {
                der::OID_CRL_DISTRIBUTION_POINTS => {
                    info.distribution_points = distribution_point_uris(extension.value)
                        .context("Invalid CRL distribution points")?;
                }
                der::OID_FRESHEST_CRL => {
                    info.freshest = distribution_point_uris(extension.value)
                        .context("Invalid freshest CRL extension")?;
                }
                der::OID_BASIC_CONSTRAINTS => {
                    let constraints = der::single(extension.value, der::SEQUENCE)?;
                    let mut constraints = Reader::new(constraints.value);
                    info.is_ca = match constraints.optional(der::BOOLEAN)? {
                        Some(value) => der::boolean(value)?,
                        None => false,
                    };
                }
                _ => {}
            }
        }
        Ok(info)
    }
}

/// Reads the full-name URIs of a `CRLDistributionPoints` value.
///
/// Distribution points with a `reasons` or `cRLIssuer` field are skipped. They
/// name partitioned or indirect CRLs, which this crate does not support.
pub(crate) fn distribution_point_uris(value: &[u8]) -> Result<Vec<String>> {
    let points = der::single(value, der::SEQUENCE)?;
    let mut points = Reader::new(points.value);
    let mut uris = Vec::new();
    while !points.is_empty() {
        let point = points.expect(der::SEQUENCE)?;
        let mut fields = Reader::new(point.value);
        let name = fields.optional(der::constructed(0))?;
        let reasons = fields.optional(der::primitive(1))?;
        let issuer = fields.optional(der::constructed(2))?;
        anyhow::ensure!(fields.is_empty(), "Distribution point has unknown fields");
        if reasons.is_some() || issuer.is_some() {
            log::debug!("Skipped a CRL distribution point with reasons or a CRL issuer");
            continue;
        }
        let Some(name) = name else {
            continue;
        };
        let choice = der::single_any(name.value)?;
        if choice.tag == der::constructed(0) {
            uris.extend(der::general_name_uris(choice.value)?);
        }
    }
    Ok(uris)
}
