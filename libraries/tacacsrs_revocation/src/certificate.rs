//! Revocation fields of a certificate in a verified path.

use std::collections::HashSet;

use anyhow::{Context, Result, ensure};
use der::{Decode, oid::ObjectIdentifier};
use openssl::x509::X509Ref;
use x509_cert::Certificate;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::constraints::BasicConstraints;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName};
use x509_cert::ext::pkix::{CrlDistributionPoints, FreshestCrl};

pub(crate) const OID_BASIC_CONSTRAINTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.19");
pub(crate) const OID_CRL_DISTRIBUTION_POINTS: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.31");
pub(crate) const OID_FRESHEST_CRL: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.46");

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
        let parsed = Certificate::from_der(&encoded).context("Could not decode a certificate")?;
        let mut info = Self::default();
        let Some(extensions) = parsed.tbs_certificate().extensions() else {
            return Ok(info);
        };
        reject_duplicate_extensions(extensions)?;
        for extension in extensions {
            let value = extension.extn_value.as_bytes();
            if extension.extn_id == OID_CRL_DISTRIBUTION_POINTS {
                let points = CrlDistributionPoints::from_der(value)
                    .context("Invalid CRL distribution points")?;
                info.distribution_points = distribution_point_uris(&points.0);
            } else if extension.extn_id == OID_FRESHEST_CRL {
                let points =
                    FreshestCrl::from_der(value).context("Invalid freshest CRL extension")?;
                info.freshest = distribution_point_uris(&points.0);
            } else if extension.extn_id == OID_BASIC_CONSTRAINTS {
                let constraints =
                    BasicConstraints::from_der(value).context("Invalid basic constraints")?;
                info.is_ca = constraints.ca;
            }
        }
        Ok(info)
    }
}

/// Rejects duplicate extension OIDs in one `Extensions` sequence.
pub(crate) fn reject_duplicate_extensions(extensions: &[Extension]) -> Result<()> {
    let mut seen = HashSet::with_capacity(extensions.len());
    for extension in extensions {
        ensure!(seen.insert(extension.extn_id), "Duplicate extension");
    }
    Ok(())
}

/// Collects full-name ASCII URIs from a `CRLDistributionPoints` list.
///
/// Distribution points with a `reasons` or `cRLIssuer` field are skipped. They
/// name partitioned or indirect CRLs, which this crate does not support.
pub(crate) fn distribution_point_uris(points: &[DistributionPoint]) -> Vec<String> {
    let mut uris = Vec::new();
    for point in points {
        if point.reasons.is_some() || point.crl_issuer.is_some() {
            log::debug!("Skipped a CRL distribution point with reasons or a CRL issuer");
            continue;
        }
        if let Some(DistributionPointName::FullName(names)) = &point.distribution_point {
            uris.extend(general_name_uris(names));
        }
    }
    uris
}

/// Extracts ASCII URIs from a `GeneralNames` sequence and skips other name forms.
pub(crate) fn general_name_uris(names: &[GeneralName]) -> Vec<String> {
    names
        .iter()
        .filter_map(|name| match name {
            GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str().to_owned()),
            _ => None,
        })
        .collect()
}
