//! PAP authentication operation inputs, responses, and reply status.

use tacacsrs_secrets::SecretBytes;

use crate::privilege::PrivilegeLevel;

/// Client-supplied inputs for one fixed PAP authentication operation.
#[derive(Debug, Clone)]
pub struct PapAuthenticationOperation {
    pub user: String,
    pub password: SecretBytes,
    pub port: String,
    pub remote_address: String,
    pub privilege_level: PrivilegeLevel,
}

/// Successful PAP authentication response from an upstream TACACS+ server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PapAuthenticationOperationResponse {
    pub server: String,
    pub status: AuthenticationResponseStatus,
    pub server_message: String,
    pub data: Vec<u8>,
}

/// Terminal statuses valid for an RFC 8907 PAP exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationResponseStatus {
    Pass,
    Fail,
    Error,
}

impl AuthenticationResponseStatus {
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Pass => 0x01,
            Self::Fail => 0x02,
            Self::Error => 0x07,
        }
    }
}
