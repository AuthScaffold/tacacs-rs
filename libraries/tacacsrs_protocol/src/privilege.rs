//! The bounded TACACS+ privilege-level field.

/// A TACACS+ privilege level in the inclusive range 0 through 15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PrivilegeLevel(u8);

impl PrivilegeLevel {
    /// The lowest protocol privilege level.
    pub const MIN: Self = Self(0);
    /// The highest protocol privilege level.
    pub const MAX: Self = Self(15);

    /// Returns the validated wire value.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u32> for PrivilegeLevel {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        if value > 15 {
            anyhow::bail!("privilege level {value} is outside the TACACS+ range 0-15");
        }
        Ok(Self(u8::try_from(value)?))
    }
}

impl TryFrom<u8> for PrivilegeLevel {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_from(u32::from(value))
    }
}

impl From<PrivilegeLevel> for u32 {
    fn from(value: PrivilegeLevel) -> Self {
        Self::from(value.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exactly_the_protocol_range() {
        for value in 0..=15_u32 {
            assert_eq!(u32::from(PrivilegeLevel::try_from(value).unwrap()), value);
        }
        for value in [16, 255, u32::MAX] {
            assert!(PrivilegeLevel::try_from(value).is_err());
        }
    }
}
