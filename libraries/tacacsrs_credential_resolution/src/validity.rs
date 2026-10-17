//! Provider-supplied absolute validity limits for resolved credential material.

use std::fmt;
use std::time::SystemTime;

/// Absolute validity interval. The start is inclusive and the end is exclusive.
/// Missing bounds are unbounded. Consumers must not extend these limits with grace periods.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CredentialValidity {
    valid_from: Option<SystemTime>,
    valid_until: Option<SystemTime>,
}

/// The supplied validity bounds have no usable interval.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InvalidCredentialValidity;

impl fmt::Display for InvalidCredentialValidity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("credential validity interval is empty")
    }
}

impl std::error::Error for InvalidCredentialValidity {}

impl CredentialValidity {
    /// Creates an unbounded validity interval.
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            valid_from: None,
            valid_until: None,
        }
    }

    /// Creates absolute validity bounds supplied by a provider.
    ///
    /// # Errors
    /// Returns an error if the end is at or before the start.
    pub fn new(
        valid_from: Option<SystemTime>,
        valid_until: Option<SystemTime>,
    ) -> Result<Self, InvalidCredentialValidity> {
        if matches!((valid_from, valid_until), (Some(start), Some(end)) if start >= end) {
            return Err(InvalidCredentialValidity);
        }
        Ok(Self {
            valid_from,
            valid_until,
        })
    }

    /// Returns the inclusive lower bound.
    #[must_use]
    pub const fn valid_from(self) -> Option<SystemTime> {
        self.valid_from
    }

    /// Returns the exclusive upper bound.
    #[must_use]
    pub const fn valid_until(self) -> Option<SystemTime> {
        self.valid_until
    }

    /// Reports whether the supplied wall-clock time is within the interval.
    #[must_use]
    pub fn is_valid_at(self, now: SystemTime) -> bool {
        self.valid_from.is_none_or(|start| now >= start)
            && self.valid_until.is_none_or(|end| now < end)
    }

    /// Intersects validity constraints without extending either interval.
    ///
    /// # Errors
    /// Returns an error if the intervals do not overlap.
    pub fn intersect(self, other: Self) -> Result<Self, InvalidCredentialValidity> {
        let start = self.valid_from.max(other.valid_from);
        let end = match (self.valid_until, other.valid_until) {
            (Some(first), Some(second)) => Some(first.min(second)),
            (first, second) => first.or(second),
        };
        Self::new(start, end)
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};
    use super::*;

    #[test]
    fn validity_is_half_open_and_intersection_never_extends_it() {
        let start = UNIX_EPOCH + Duration::from_secs(10);
        let middle = UNIX_EPOCH + Duration::from_secs(15);
        let end = UNIX_EPOCH + Duration::from_secs(20);
        let validity = CredentialValidity::new(Some(start), Some(end)).unwrap();
        assert!(!validity.is_valid_at(UNIX_EPOCH));
        assert!(validity.is_valid_at(start));
        assert!(validity.is_valid_at(middle));
        assert!(!validity.is_valid_at(end));
        assert_eq!(validity.intersect(CredentialValidity::unbounded()).unwrap(), validity);
        let shorter = validity
            .intersect(CredentialValidity::new(Some(middle), None).unwrap())
            .unwrap();
        assert_eq!(shorter.valid_from(), Some(middle));
        assert_eq!(shorter.valid_until(), Some(end));
        assert!(CredentialValidity::new(Some(end), Some(start)).is_err());
        assert!(CredentialValidity::new(Some(start), Some(start)).is_err());
        assert!(validity
            .intersect(CredentialValidity::new(Some(end), None).unwrap())
            .is_err());
    }
}
