//! Test PKI: certificates with CRL extensions and hand-built CRLs.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;
use openssl::x509::extension::{BasicConstraints, SubjectAlternativeName};
use openssl::x509::{X509, X509Builder, X509Extension, X509Name, X509NameBuilder};

const OID_CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
const OID_FRESHEST_CRL: &str = "2.5.29.46";
const OID_CRL_NUMBER: &str = "2.5.29.20";
const OID_DELTA_CRL_INDICATOR: &str = "2.5.29.27";
const ECDSA_WITH_SHA256: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(u8::try_from(length).unwrap());
    } else {
        let bytes: Vec<u8> = length
            .to_be_bytes()
            .into_iter()
            .skip_while(|byte| *byte == 0)
            .collect();
        out.push(0x80 | u8::try_from(bytes.len()).unwrap());
        out.extend(bytes);
    }
    out.extend_from_slice(content);
    out
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn oid(text: &str) -> Vec<u8> {
    let arcs: Vec<u64> = text.split('.').map(|arc| arc.parse().unwrap()).collect();
    let mut content = vec![u8::try_from(arcs[0] * 40 + arcs[1]).unwrap()];
    for arc in &arcs[2..] {
        let mut groups = vec![u8::try_from(arc & 0x7f).unwrap()];
        let mut rest = arc >> 7;
        while rest > 0 {
            groups.push(u8::try_from(rest & 0x7f).unwrap() | 0x80);
            rest >>= 7;
        }
        groups.reverse();
        content.extend(groups);
    }
    tlv(0x06, &content)
}

fn integer(value: &[u8]) -> Vec<u8> {
    let mut content: Vec<u8> = value
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0)
        .collect();
    if content.first().is_none_or(|byte| byte & 0x80 != 0) {
        content.insert(0, 0);
    }
    tlv(0x02, &content)
}

fn small_integer(value: u64) -> Vec<u8> {
    integer(&value.to_be_bytes())
}

fn utc_time(time: SystemTime) -> Vec<u8> {
    let seconds = time.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days = i64::try_from(seconds / 86_400).unwrap();
    let rest = seconds % 86_400;
    // Civil-from-days by Howard Hinnant.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 {
        mp + 3
    } else {
        mp - 9
    };
    let year = yoe + era * 400 + i64::from(month <= 2);
    let text = format!(
        "{:02}{month:02}{day:02}{:02}{:02}{:02}Z",
        year % 100,
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    );
    tlv(0x17, text.as_bytes())
}

/// Encodes a CRL distribution points value with one point and these mirrors.
pub(crate) fn distribution_points(uris: &[&str]) -> Vec<u8> {
    let names: Vec<u8> = uris
        .iter()
        .flat_map(|uri| tlv(0x86, uri.as_bytes()))
        .collect();
    sequence(&[sequence(&[tlv(0xa0, &tlv(0xa0, &names))])])
}

fn extension(oid_text: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![oid(oid_text)];
    if critical {
        parts.push(vec![0x01, 0x01, 0xff]);
    }
    parts.push(tlv(0x04, value));
    sequence(&parts)
}

fn der_extension(oid_text: &str, value: &[u8]) -> X509Extension {
    let object = Asn1Object::from_str(oid_text).unwrap();
    let octets = Asn1OctetString::new_from_bytes(value).unwrap();
    X509Extension::new_from_der(&object, false, &octets).unwrap()
}

/// A certificate and its private key.
pub(crate) struct Issued {
    pub(crate) certificate: X509,
    pub(crate) key: PKey<Private>,
}

/// Options for one test certificate.
#[derive(Default)]
pub(crate) struct CertificateOptions<'a> {
    pub(crate) ca: bool,
    pub(crate) serial: u32,
    pub(crate) distribution_points: &'a [&'a str],
    pub(crate) freshest: &'a [&'a str],
    pub(crate) dns_names: &'a [&'a str],
}

fn name(common_name: &str) -> X509Name {
    let mut builder = X509NameBuilder::new().unwrap();
    builder
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .unwrap();
    builder.build()
}

pub(crate) fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

/// Issues a certificate for `subject`. Without `issuer`, the certificate is self-signed.
pub(crate) fn issue(
    subject: &str,
    key: PKey<Private>,
    issuer: Option<&Issued>,
    options: &CertificateOptions<'_>,
) -> Issued {
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    let serial = BigNum::from_u32(options.serial)
        .unwrap()
        .to_asn1_integer()
        .unwrap();
    builder.set_serial_number(&serial).unwrap();
    let subject_name = name(subject);
    builder.set_subject_name(&subject_name).unwrap();
    match issuer {
        Some(issuer) => builder
            .set_issuer_name(issuer.certificate.subject_name())
            .unwrap(),
        None => builder.set_issuer_name(&subject_name).unwrap(),
    }
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(30).unwrap())
        .unwrap();
    if options.ca {
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
    }
    if !options.dns_names.is_empty() {
        let mut names = SubjectAlternativeName::new();
        for dns_name in options.dns_names {
            names.dns(dns_name);
        }
        let extension = names.build(&builder.x509v3_context(None, None)).unwrap();
        builder.append_extension(extension).unwrap();
    }
    if !options.distribution_points.is_empty() {
        builder
            .append_extension(der_extension(
                OID_CRL_DISTRIBUTION_POINTS,
                &distribution_points(options.distribution_points),
            ))
            .unwrap();
    }
    if !options.freshest.is_empty() {
        builder
            .append_extension(der_extension(
                OID_FRESHEST_CRL,
                &distribution_points(options.freshest),
            ))
            .unwrap();
    }
    let signing_key = issuer.map_or(&key, |issuer| &issuer.key);
    builder.sign(signing_key, MessageDigest::sha256()).unwrap();
    Issued {
        certificate: builder.build(),
        key,
    }
}

/// Options for one test CRL.
pub(crate) struct CrlOptions<'a> {
    pub(crate) this_update: SystemTime,
    pub(crate) next_update: SystemTime,
    pub(crate) revoked: &'a [&'a X509],
    pub(crate) number: u64,
    pub(crate) delta_base: Option<u64>,
    pub(crate) freshest: &'a [&'a str],
}

impl Default for CrlOptions<'_> {
    fn default() -> Self {
        let now = SystemTime::now();
        Self {
            this_update: now - Duration::from_secs(3600),
            next_update: now + Duration::from_secs(86_400),
            revoked: &[],
            number: 1,
            delta_base: None,
            freshest: &[],
        }
    }
}

/// Builds a DER CRL issued and signed by `issuer`.
pub(crate) fn crl(issuer: &Issued, options: &CrlOptions<'_>) -> Vec<u8> {
    let mut tbs = vec![
        small_integer(1),
        ECDSA_WITH_SHA256.to_vec(),
        issuer.certificate.subject_name().to_der().unwrap(),
        utc_time(options.this_update),
        utc_time(options.next_update),
    ];
    if !options.revoked.is_empty() {
        let entries: Vec<Vec<u8>> = options
            .revoked
            .iter()
            .map(|certificate| {
                let serial = certificate.serial_number().to_bn().unwrap().to_vec();
                sequence(&[integer(&serial), utc_time(options.this_update)])
            })
            .collect();
        tbs.push(sequence(&entries));
    }
    let mut extensions = vec![extension(
        OID_CRL_NUMBER,
        false,
        &small_integer(options.number),
    )];
    if let Some(base) = options.delta_base {
        extensions.push(extension(OID_DELTA_CRL_INDICATOR, true, &small_integer(base)));
    }
    if !options.freshest.is_empty() {
        extensions.push(extension(OID_FRESHEST_CRL, false, &distribution_points(options.freshest)));
    }
    tbs.push(tlv(0xa0, &sequence(&extensions)));
    let tbs = sequence(&tbs);
    let mut signer = Signer::new(MessageDigest::sha256(), &issuer.key).unwrap();
    signer.update(&tbs).unwrap();
    let signature = signer.sign_to_vec().unwrap();
    let mut bits = vec![0];
    bits.extend(signature);
    sequence(&[tbs, ECDSA_WITH_SHA256.to_vec(), tlv(0x03, &bits)])
}
