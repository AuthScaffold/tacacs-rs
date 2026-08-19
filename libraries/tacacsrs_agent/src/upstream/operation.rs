//! TACACS+ operation identity used by routing and connection ownership.

use tacacsrs_config::TacacsPlusServerType;
use tacacsrs_messages::enumerations::TacacsType;

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
    /// All supported operation kinds in stable order.
    pub const ALL: [Self; 3] = [Self::Authentication, Self::Authorization, Self::Accounting];

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Authentication => 0,
            Self::Authorization => 1,
            Self::Accounting => 2,
        }
    }

    /// Returns the server capability required for this operation.
    #[must_use]
    pub const fn server_type(self) -> TacacsPlusServerType {
        match self {
            Self::Authentication => TacacsPlusServerType::AUTHENTICATION,
            Self::Authorization => TacacsPlusServerType::AUTHORIZATION,
            Self::Accounting => TacacsPlusServerType::ACCOUNTING,
        }
    }

    /// Returns the stable operation name used in logs and configuration errors.
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
        match value {
            TacacsType::TacPlusAuthentication => Ok(Self::Authentication),
            TacacsType::TacPlusAuthorisation => Ok(Self::Authorization),
            TacacsType::TacPlusAccounting => Ok(Self::Accounting),
        }
    }
}
