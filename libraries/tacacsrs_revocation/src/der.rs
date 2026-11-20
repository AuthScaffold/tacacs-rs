//! Minimal DER reader for certificate and CRL fields.
//!
//! The `openssl` crate does not expose the issuing distribution point, the
//! freshest CRL, the delta CRL indicator, or the CRL number in a safe form. This
//! module reads these fields from the DER encoding. It supports only the
//! single-byte tags and definite lengths that DER allows for these structures.

use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail, ensure};

pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const OBJECT_IDENTIFIER: u8 = 0x06;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
pub(crate) const SEQUENCE: u8 = 0x30;

/// Context-specific constructed tag `[n]`.
pub(crate) const fn constructed(number: u8) -> u8 {
    0xa0 | number
}

/// Context-specific primitive tag `[n]`.
pub(crate) const fn primitive(number: u8) -> u8 {
    0x80 | number
}

/// Content bytes of the CRL distribution points OID 2.5.29.31.
pub(crate) const OID_CRL_DISTRIBUTION_POINTS: &[u8] = &[0x55, 0x1d, 0x1f];
/// Content bytes of the freshest CRL OID 2.5.29.46.
pub(crate) const OID_FRESHEST_CRL: &[u8] = &[0x55, 0x1d, 0x2e];
/// Content bytes of the basic constraints OID 2.5.29.19.
pub(crate) const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
/// Content bytes of the issuing distribution point OID 2.5.29.28.
pub(crate) const OID_ISSUING_DISTRIBUTION_POINT: &[u8] = &[0x55, 0x1d, 0x1c];
/// Content bytes of the delta CRL indicator OID 2.5.29.27.
pub(crate) const OID_DELTA_CRL_INDICATOR: &[u8] = &[0x55, 0x1d, 0x1b];
/// Content bytes of the CRL number OID 2.5.29.20.
pub(crate) const OID_CRL_NUMBER: &[u8] = &[0x55, 0x1d, 0x14];
/// Content bytes of the AD CS "Next CRL Publish" OID 1.3.6.1.4.1.311.21.4.
pub(crate) const OID_NEXT_CRL_PUBLISH: &[u8] =
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x15, 0x04];

/// Largest DER length that this reader accepts.
const MAXIMUM_LENGTH_OCTETS: usize = 4;

/// One tag-length-value element.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
}

/// Reads consecutive DER elements from a byte slice.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    pub(crate) fn read(&mut self) -> Result<Tlv<'a>> {
        let (&tag, rest) = self
            .data
            .split_first()
            .context("DER element is truncated")?;
        ensure!(tag & 0x1f != 0x1f, "DER high tag numbers are not supported");
        let (&first, mut rest) = rest.split_first().context("DER length is truncated")?;
        let length = if first < 0x80 {
            usize::from(first)
        } else {
            let count = usize::from(first & 0x7f);
            ensure!(
                (1..=MAXIMUM_LENGTH_OCTETS).contains(&count),
                "DER length form is not supported"
            );
            ensure!(rest.len() >= count, "DER length is truncated");
            let (octets, tail) = rest.split_at(count);
            rest = tail;
            octets
                .iter()
                .fold(0usize, |total, octet| (total << 8) | usize::from(*octet))
        };
        ensure!(rest.len() >= length, "DER value is truncated");
        let (value, tail) = rest.split_at(length);
        self.data = tail;
        Ok(Tlv { tag, value })
    }

    pub(crate) fn expect(&mut self, tag: u8) -> Result<Tlv<'a>> {
        let element = self.read()?;
        ensure!(element.tag == tag, "Expected DER tag {tag:#04x}, found {:#04x}", element.tag);
        Ok(element)
    }

    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>> {
        if self.peek_tag() == Some(tag) {
            self.read().map(Some)
        } else {
            Ok(None)
        }
    }
}

/// Reads `data` as exactly one DER element with `tag`.
pub(crate) fn single(data: &[u8], tag: u8) -> Result<Tlv<'_>> {
    let mut reader = Reader::new(data);
    let element = reader.expect(tag)?;
    ensure!(reader.is_empty(), "DER data has trailing bytes");
    Ok(element)
}

/// Reads `data` as exactly one DER element with any tag.
pub(crate) fn single_any(data: &[u8]) -> Result<Tlv<'_>> {
    let mut reader = Reader::new(data);
    let element = reader.read()?;
    ensure!(reader.is_empty(), "DER data has trailing bytes");
    Ok(element)
}

/// One X.509 extension.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Extension<'a> {
    pub(crate) oid: &'a [u8],
    pub(crate) critical: bool,
    pub(crate) value: &'a [u8],
}

/// Reads the content of an `Extensions` sequence and rejects duplicate OIDs.
pub(crate) fn extensions(sequence: &[u8]) -> Result<Vec<Extension<'_>>> {
    let mut reader = Reader::new(sequence);
    let mut result: Vec<Extension<'_>> = Vec::new();
    while !reader.is_empty() {
        let extension = reader.expect(SEQUENCE)?;
        let mut fields = Reader::new(extension.value);
        let oid = fields.expect(OBJECT_IDENTIFIER)?.value;
        let critical = match fields.optional(BOOLEAN)? {
            Some(value) => boolean(value)?,
            None => false,
        };
        let value = fields.expect(OCTET_STRING)?.value;
        ensure!(fields.is_empty(), "Extension has trailing fields");
        ensure!(result.iter().all(|existing| existing.oid != oid), "Duplicate extension");
        result.push(Extension {
            oid,
            critical,
            value,
        });
    }
    Ok(result)
}

/// Reads a DER boolean, or an implicitly tagged boolean value.
pub(crate) fn boolean(element: Tlv<'_>) -> Result<bool> {
    match element.value {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => bail!("Invalid DER boolean"),
    }
}

/// Reads the URIs from the content of a `GeneralNames` sequence.
///
/// Other name forms are skipped.
pub(crate) fn general_name_uris(names: &[u8]) -> Result<Vec<String>> {
    let mut reader = Reader::new(names);
    let mut uris = Vec::new();
    while !reader.is_empty() {
        let name = reader.read()?;
        if name.tag == primitive(6) {
            let uri =
                std::str::from_utf8(name.value).context("Distribution point URI is not text")?;
            ensure!(uri.is_ascii(), "Distribution point URI is not ASCII");
            uris.push(uri.to_owned());
        }
    }
    Ok(uris)
}

/// A nonnegative integer as big-endian magnitude without leading zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unsigned(Vec<u8>);

impl Unsigned {
    /// Reads the content of a DER integer that has at most `limit` magnitude octets.
    pub(crate) fn read(value: &[u8], limit: usize) -> Result<Self> {
        let (&first, _) = value.split_first().context("DER integer is empty")?;
        ensure!(first & 0x80 == 0, "Integer is negative");
        let start = value
            .iter()
            .position(|octet| *octet != 0)
            .unwrap_or(value.len());
        let magnitude = &value[start..];
        ensure!(magnitude.len() <= limit, "Integer is too large");
        Ok(Self(magnitude.to_vec()))
    }
}

impl PartialOrd for Unsigned {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Unsigned {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

/// Reads a `UTCTime` or `GeneralizedTime` in the DER form `...Z` with seconds.
pub(crate) fn time(element: Tlv<'_>) -> Result<SystemTime> {
    let text = std::str::from_utf8(element.value).context("Time is not text")?;
    let (year, rest) = match element.tag {
        UTC_TIME => {
            ensure!(text.len() == 13, "Invalid UTCTime");
            let short = digits(&text[0..2])?;
            (
                if short >= 50 {
                    1900 + short
                } else {
                    2000 + short
                },
                &text[2..],
            )
        }
        GENERALIZED_TIME => {
            ensure!(text.len() == 15, "Invalid GeneralizedTime");
            (digits(&text[0..4])?, &text[4..])
        }
        _ => bail!("Expected a DER time"),
    };
    ensure!(rest.ends_with('Z'), "Time must use UTC");
    let month = digits(&rest[0..2])?;
    let day = digits(&rest[2..4])?;
    let hour = digits(&rest[4..6])?;
    let minute = digits(&rest[6..8])?;
    let second = digits(&rest[8..10])?;
    ensure!(
        (1..=12).contains(&month)
            && (1..=31).contains(&day)
            && hour < 24
            && minute < 60
            && second < 60,
        "Time is out of range"
    );
    let days = days_from_civil(i64::from(year), month, day);
    let seconds = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second);
    let seconds = u64::try_from(seconds).context("Time is before 1970")?;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
}

fn digits(text: &str) -> Result<u32> {
    ensure!(text.bytes().all(|byte| byte.is_ascii_digit()), "Time contains a non-digit");
    text.parse().context("Invalid time digits")
}

/// Returns the number of days from 1970-01-01 to a proleptic Gregorian date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 {
        year - 1
    } else {
        year
    };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year = (153
        * (month
            + if month > 2 {
                -3
            } else {
                9
            })
        + 2)
        / 5
        + i64::from(day)
        - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_utc_and_generalized_times() {
        let utc = time(Tlv {
            tag: UTC_TIME,
            value: b"700101000000Z",
        })
        .unwrap();
        assert_eq!(utc, SystemTime::UNIX_EPOCH);
        let generalized = time(Tlv {
            tag: GENERALIZED_TIME,
            value: b"20240229123456Z",
        })
        .unwrap();
        assert_eq!(
            generalized
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1_709_210_096
        );
        assert!(time(Tlv {
            tag: UTC_TIME,
            value: b"700101000000+0100",
        })
        .is_err());
    }

    #[test]
    fn rejects_truncated_and_trailing_data() {
        assert!(single(&[SEQUENCE, 0x03, 0x01], SEQUENCE).is_err());
        assert!(single(&[SEQUENCE, 0x00, 0x00], SEQUENCE).is_err());
        assert!(single(&[SEQUENCE, 0x80, 0x00, 0x00], SEQUENCE).is_err());
        single(&[SEQUENCE, 0x81, 0x01, 0x05], SEQUENCE).unwrap();
    }

    #[test]
    fn compares_unsigned_integers_numerically() {
        let small = Unsigned::read(&[0x00, 0xff], 20).unwrap();
        let large = Unsigned::read(&[0x01, 0x00], 20).unwrap();
        assert!(small < large);
        assert!(Unsigned::read(&[0x80], 20).is_err());
        assert_eq!(
            Unsigned::read(&[0x00], 20).unwrap(),
            Unsigned::read(&[0x00, 0x00], 20).unwrap()
        );
    }
}
