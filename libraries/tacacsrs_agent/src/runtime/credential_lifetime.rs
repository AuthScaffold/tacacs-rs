//! Provider and revocation-evidence validity checked against wall and monotonic clocks.

use std::time::SystemTime;

use tokio::time::Instant;

use tacacsrs_credential_resolution::CredentialValidity;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct CredentialLifetime {
    pub(crate) validity: CredentialValidity,
    pub(crate) deadline: Option<Instant>,
}

impl CredentialLifetime {
    pub(crate) const fn unbounded() -> Self {
        Self {
            validity: CredentialValidity::unbounded(),
            deadline: None,
        }
    }

    pub(crate) fn new(validity: CredentialValidity) -> anyhow::Result<Self> {
        let monotonic = Instant::now();
        let now = SystemTime::now();
        anyhow::ensure!(validity.is_valid_at(now), "Credential validity excludes the current time");
        let deadline = validity
            .valid_until()
            .map(|end| {
                monotonic
                    .checked_add(end.duration_since(now).unwrap_or_default())
                    .ok_or_else(|| {
                        anyhow::anyhow!("Credential validity exceeds the runtime clock range")
                    })
            })
            .transpose()?;
        Ok(Self { validity, deadline })
    }

    pub(crate) fn intersect(self, other: Self) -> anyhow::Result<Self> {
        Ok(Self {
            validity: self.validity.intersect(other.validity)?,
            deadline: match (self.deadline, other.deadline) {
                (Some(left), Some(right)) => Some(left.min(right)),
                (left, right) => left.or(right),
            },
        })
    }

    pub(crate) fn is_valid(self) -> bool {
        self.is_valid_at(SystemTime::now(), Instant::now())
    }

    fn is_valid_at(self, wall_clock: SystemTime, monotonic: Instant) -> bool {
        self.validity.is_valid_at(wall_clock)
            && self.deadline.is_none_or(|deadline| monotonic < deadline)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn validity_requires_both_clocks_and_intersection_keeps_the_earliest_deadline() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let end = start + Duration::from_secs(10);
        let monotonic = Instant::now();
        let deadline = monotonic + Duration::from_secs(10);
        let lifetime = CredentialLifetime {
            validity: CredentialValidity::new(Some(start), Some(end)).unwrap(),
            deadline: Some(deadline),
        };
        assert!(lifetime.is_valid_at(start, monotonic));
        assert!(!lifetime.is_valid_at(end, monotonic));
        assert!(!lifetime.is_valid_at(start - Duration::from_secs(1), monotonic));
        assert!(!lifetime.is_valid_at(start, deadline));
        let later = CredentialLifetime {
            deadline: Some(deadline + Duration::from_secs(10)),
            ..lifetime
        };
        assert_eq!(lifetime.intersect(later).unwrap(), lifetime);
        assert_eq!(later.intersect(lifetime).unwrap(), lifetime);
        assert_eq!(lifetime.intersect(CredentialLifetime::unbounded()).unwrap(), lifetime);
    }
}
