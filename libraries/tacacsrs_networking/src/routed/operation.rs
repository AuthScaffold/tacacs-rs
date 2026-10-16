//! TACACS+ operation identity for routing and connection isolation.

use tacacsrs_protocol::enumerations::TacacsType;

/// A TACACS+ service operation.
#[derive(Debug, Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum OperationKind {
    /// User authentication exchanges.
    Authentication,
    /// Command and service authorization exchanges.
    Authorization,
    /// Activity accounting exchanges.
    Accounting,
}

impl OperationKind {
    /// All operations in stable order.
    pub const ALL: [Self; 3] = [Self::Authentication, Self::Authorization, Self::Accounting];

    /// Returns the operation's stable position in an operation-indexed array.
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Self::Authentication => 0,
            Self::Authorization => 1,
            Self::Accounting => 2,
        }
    }

    /// Returns the stable operation name for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Authorization => "authorization",
            Self::Accounting => "accounting",
        }
    }
}

impl TryFrom<TacacsType> for OperationKind {
    type Error = anyhow::Error;

    fn try_from(value: TacacsType) -> Result<Self, Self::Error> {
        Ok(match value {
            TacacsType::TacPlusAuthentication => Self::Authentication,
            TacacsType::TacPlusAuthorisation => Self::Authorization,
            TacacsType::TacPlusAccounting => Self::Accounting,
        })
    }
}
