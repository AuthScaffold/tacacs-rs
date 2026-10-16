//! Intrinsic validity dates decoded from native X.509 objects.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::x509::X509Ref;

/// ASN.1 time differences express whole days separately from seconds.
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Clone, Copy)]
pub(crate) struct CertificateLifetime {
    pub(crate) validity: CertificateValidity,
    pub(crate) deadline: crate::RequestDeadline,
}

impl CertificateLifetime {
    pub(crate) fn intersect(self, other: Self) -> Result<Self> {
        Ok(Self {
            validity: self.validity.intersect(other.validity)?,
            deadline: crate::RequestDeadline::at(
                self.deadline.expires_at().min(other.deadline.expires_at()),
            ),
        })
    }

    pub(crate) fn new(validity: CertificateValidity) -> Result<Self> {
        let monotonic = tokio::time::Instant::now();
        let now = SystemTime::now();
        ensure!(validity.is_valid_at(now), "Certificate validity excludes the current time");
        let deadline = monotonic
            .checked_add(validity.valid_until.duration_since(now)?)
            .context("Certificate validity exceeds the runtime clock range")?;
        Ok(Self {
            validity,
            deadline: crate::RequestDeadline::at(deadline),
        })
    }

    pub(crate) fn check(self) -> Result<()> {
        ensure!(
            self.validity.is_valid_at(SystemTime::now()),
            "Certificate validity excludes the current time"
        );
        self.deadline.check()?;
        Ok(())
    }

    pub(crate) async fn run<Output>(
        self,
        operation: impl std::future::Future<Output = Result<Output>>,
    ) -> Result<Output> {
        self.check()?;
        let result = self.deadline.run(operation).await??;
        self.check()?;
        Ok(result)
    }
}

/// Absolute validity of a certificate or selected certificate chain.
///
/// Runtime use includes the lower bound and excludes the upper bound.
/// Alternative trust paths must be evaluated separately, not intersected together.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CertificateValidity {
    valid_from: SystemTime,
    valid_until: SystemTime,
}

impl CertificateValidity {
    pub(crate) fn from_chain(
        chain: &openssl::stack::StackRef<openssl::x509::X509>,
    ) -> Result<Self> {
        let first = chain
            .get(0)
            .context("Verified certificate chain is empty")?;
        chain
            .iter()
            .skip(1)
            .try_fold(Self::from_certificate(first)?, |validity, certificate| {
                validity.intersect(Self::from_certificate(certificate)?)
            })
    }

    pub(crate) fn from_certificate(certificate: &X509Ref) -> Result<Self> {
        let validity = Self {
            valid_from: system_time(certificate.not_before())?,
            valid_until: system_time(certificate.not_after())?,
        };
        ensure!(
            validity.valid_from < validity.valid_until,
            "Certificate validity interval is empty"
        );
        Ok(validity)
    }

    pub(crate) fn intersect(self, other: Self) -> Result<Self> {
        let validity = Self {
            valid_from: self.valid_from.max(other.valid_from),
            valid_until: self.valid_until.min(other.valid_until),
        };
        ensure!(
            validity.valid_from < validity.valid_until,
            "Certificate validity intervals do not overlap"
        );
        Ok(validity)
    }

    /// Returns the inclusive start of the certificate interval.
    #[must_use]
    pub const fn valid_from(self) -> SystemTime {
        self.valid_from
    }

    /// Returns the exclusive end of the certificate interval.
    #[must_use]
    pub const fn valid_until(self) -> SystemTime {
        self.valid_until
    }

    /// Reports whether the supplied wall-clock time is within the interval.
    #[must_use]
    pub fn is_valid_at(self, now: SystemTime) -> bool {
        self.valid_from <= now && now < self.valid_until
    }
}

fn system_time(time: &Asn1TimeRef) -> Result<SystemTime> {
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
            assert_eq!(system_time(&date).unwrap(), expected);
        }
    }
}
