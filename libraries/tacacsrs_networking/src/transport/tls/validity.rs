//! Conversion of ASN.1 certificate times to system time.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use openssl::asn1::{Asn1Time, Asn1TimeRef};

/// ASN.1 time differences express whole days separately from seconds.
const SECONDS_PER_DAY: i64 = 86_400;

/// Converts an ASN.1 `UTCTime` or `GeneralizedTime` to system time.
///
/// # Errors
///
/// Returns an error when OpenSSL cannot compare the time or the result is
/// outside the system clock range.
pub fn asn1_system_time(time: &Asn1TimeRef) -> Result<SystemTime> {
    let epoch = Asn1Time::from_unix(0)?;
    let difference = epoch
        .diff(time)
        .context("Invalid certificate validity timestamp")?;
    let seconds = i64::from(difference.days) * SECONDS_PER_DAY + i64::from(difference.secs);
    let duration = Duration::from_secs(seconds.unsigned_abs());
    if seconds < 0 {
        UNIX_EPOCH.checked_sub(duration)
    } else {
        UNIX_EPOCH.checked_add(duration)
    }
    .context("Certificate validity exceeds the system clock range")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn1_dates_preserve_seconds_before_and_after_the_epoch() {
        for (date, seconds) in [
            ("691230235959Z", -86_401_i64),
            ("691231235959Z", -1),
            ("700101000000Z", 0),
            ("700101000001Z", 1),
            ("700102000001Z", 86_401),
            ("20500101000000Z", 2_524_608_000),
        ] {
            let date = Asn1Time::from_str_x509(date).unwrap();
            let duration = Duration::from_secs(seconds.unsigned_abs());
            let expected = if seconds < 0 {
                UNIX_EPOCH - duration
            } else {
                UNIX_EPOCH + duration
            };
            assert_eq!(asn1_system_time(&date).unwrap(), expected);
        }
    }
}
