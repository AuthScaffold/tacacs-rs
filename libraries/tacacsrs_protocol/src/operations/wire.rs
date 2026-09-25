//! Conversion between logical operations and TACACS+ wire bodies.

use crate::accounting::{reply::AccountingReply, request::AccountingRequest};
use crate::authentication::reply::AuthenticationReply;
use crate::authorization::{reply::AuthorizationReply, request::AuthorizationRequest};
use crate::enumerations::{
    TacacsAccountingFlags, TacacsAccountingStatus, TacacsAuthenticationMethod,
    TacacsAuthenticationService, TacacsAuthenticationStatus, TacacsAuthenticationType,
    TacacsAuthorizationStatus,
};
use crate::exchange::accounting::AccountingExchange;
use crate::exchange::authentication::PapAuthenticationExchange;
use crate::exchange::authorization::AuthorizationExchange;

use super::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus,
    AuthenticationResponseStatus, AuthorizationArg, AuthorizationAuthenticationContext,
    AuthorizationOperation, AuthorizationOperationResponse, AuthorizationResponseStatus,
    PapAuthenticationOperation, PapAuthenticationOperationResponse,
};

impl AccountingOperation {
    /// Builds the shell accounting body with combined START and STOP flags.
    #[must_use]
    pub fn to_request(&self) -> AccountingRequest {
        let mut args = vec!["service=shell".to_owned(), format!("cmd={}", self.command)];
        args.extend(
            self.command_arguments
                .iter()
                .map(|argument| format!("cmd-arg={argument}")),
        );
        AccountingRequest {
            flags: TacacsAccountingFlags::START | TacacsAccountingFlags::STOP,
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
            priv_lvl: 0,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcNone,
            user: self.user.clone(),
            port: self.port.clone(),
            rem_address: self.remote_address.clone(),
            args,
        }
    }

    /// Describes this accounting exchange without opening a connection.
    #[must_use]
    pub fn exchange(&self) -> AccountingExchange {
        AccountingExchange::new(self.to_request())
    }
}

impl AuthorizationAuthenticationContext {
    pub(crate) const fn protocol_fields(
        self,
    ) -> (TacacsAuthenticationMethod, TacacsAuthenticationType, TacacsAuthenticationService) {
        match self {
            Self::TacacsAscii => (
                TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus,
                TacacsAuthenticationType::TacPlusAuthenTypeAscii,
                TacacsAuthenticationService::TacPlusAuthenSvcLogin,
            ),
            Self::TacacsPap => (
                TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus,
                TacacsAuthenticationType::TacPlusAuthenTypePap,
                TacacsAuthenticationService::TacPlusAuthenSvcLogin,
            ),
            Self::Unauthenticated => (
                TacacsAuthenticationMethod::TacPlusAuthenMethodNone,
                TacacsAuthenticationType::TacPlusAuthenTypeNotSet,
                TacacsAuthenticationService::TacPlusAuthenSvcNone,
            ),
        }
    }
}

impl AuthorizationArg {
    /// Encodes the mandatory or optional separator without changing the value.
    #[must_use]
    pub fn to_wire(&self) -> String {
        let separator = if self.mandatory {
            '='
        } else {
            '*'
        };
        format!("{}{separator}{}", self.name, self.value)
    }
}

impl AuthorizationOperation {
    /// Builds the validated authorization body and preserves argument order.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation contains invalid authorization arguments.
    pub fn to_request(&self) -> anyhow::Result<AuthorizationRequest> {
        self.validate()?;
        let (authen_method, authen_type, authen_service) =
            self.authentication_context.protocol_fields();
        Ok(AuthorizationRequest {
            authen_method,
            priv_lvl: self.privilege_level.get(),
            authen_type,
            authen_service,
            user: self.user.clone(),
            port: self.port.clone(),
            rem_address: self.remote_address.clone(),
            args: self.args.iter().map(AuthorizationArg::to_wire).collect(),
        })
    }

    /// Describes this authorization exchange without opening a connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation cannot form a valid authorization request.
    pub fn exchange(&self) -> anyhow::Result<AuthorizationExchange> {
        Ok(AuthorizationExchange::new(self.to_request()?))
    }
}

impl PapAuthenticationOperation {
    /// Validates the logical PAP request independently of its transport.
    ///
    /// # Errors
    ///
    /// Returns an error if the user name is empty.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.user.is_empty() {
            anyhow::bail!("PAP authentication requires a user name");
        }
        Ok(())
    }

    /// Describes a validated PAP exchange without opening a connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the logical request is invalid.
    pub fn exchange(&self) -> anyhow::Result<PapAuthenticationExchange> {
        self.validate()?;
        Ok(PapAuthenticationExchange::new(
            self.user.clone(),
            self.password.clone(),
            self.port.clone(),
            self.remote_address.clone(),
            self.privilege_level.get(),
        ))
    }
}

impl AccountingOperationResponse {
    /// Attaches server identity to a valid wire accounting response.
    #[must_use]
    pub fn from_reply(server: impl Into<String>, reply: AccountingReply) -> Self {
        let status = match reply.status {
            TacacsAccountingStatus::TacPlusAcctStatusSuccess => AccountingResponseStatus::Success,
            TacacsAccountingStatus::TacPlusAcctStatusError => AccountingResponseStatus::Error,
            TacacsAccountingStatus::TacPlusAcctStatusFollow => AccountingResponseStatus::Follow,
        };
        Self {
            server: server.into(),
            status,
            server_message: reply.server_msg,
            data: reply.data,
        }
    }
}

impl AuthorizationOperationResponse {
    /// Decodes ordered arguments and attaches server identity to an authorization response.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed authorization arguments.
    pub fn from_reply(
        server: impl Into<String>,
        reply: AuthorizationReply,
    ) -> anyhow::Result<Self> {
        let status = match reply.status {
            TacacsAuthorizationStatus::TacPlusPassAdd => AuthorizationResponseStatus::PassAdd,
            TacacsAuthorizationStatus::TacPlusPassRepl => AuthorizationResponseStatus::PassRepl,
            TacacsAuthorizationStatus::TacPlusFail => AuthorizationResponseStatus::Fail,
            TacacsAuthorizationStatus::TacPlusError => AuthorizationResponseStatus::Error,
            TacacsAuthorizationStatus::TacPlusFollow => AuthorizationResponseStatus::Follow,
        };
        Ok(Self {
            server: server.into(),
            status,
            server_message: reply.server_msg,
            data: reply.data,
            args: reply
                .args
                .iter()
                .map(|argument| AuthorizationArg::parse(argument))
                .collect::<anyhow::Result<_>>()?,
        })
    }
}

impl PapAuthenticationOperationResponse {
    /// Attaches server identity to a terminal PAP response.
    ///
    /// # Errors
    ///
    /// Returns an error if the reply requests a continuation or uses an unsupported status.
    pub fn from_reply(
        server: impl Into<String>,
        reply: AuthenticationReply,
    ) -> anyhow::Result<Self> {
        let status = match reply.status {
            TacacsAuthenticationStatus::TacPlusAuthenStatusPass => {
                AuthenticationResponseStatus::Pass
            }
            TacacsAuthenticationStatus::TacPlusAuthenStatusFail => {
                AuthenticationResponseStatus::Fail
            }
            TacacsAuthenticationStatus::TacPlusAuthenStatusError => {
                AuthenticationResponseStatus::Error
            }
            _ => anyhow::bail!("PAP authentication returned a nonterminal reply"),
        };
        Ok(Self {
            server: server.into(),
            status,
            server_message: reply.server_msg,
            data: reply.data,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::exchange::FixedExchange;
    use crate::traits::TacacsBodyTrait;

    use super::*;

    #[test]
    fn logical_authorization_has_one_wire_encoding() -> anyhow::Result<()> {
        for context in [
            AuthorizationAuthenticationContext::TacacsAscii,
            AuthorizationAuthenticationContext::TacacsPap,
            AuthorizationAuthenticationContext::Unauthenticated,
        ] {
            let operation = AuthorizationOperation::builder("admin", 15, context)
                .service("shell")
                .command("show")
                .command_args(["interfaces", "brief"])
                .arg(AuthorizationArg::optional("protocol", "ssh"))
                .build()?;
            let wire = operation.to_request()?;
            let decoded =
                AuthorizationRequest::from_bytes(&operation.exchange()?.encode_request()?)?;
            assert_eq!(wire.to_bytes()?, decoded.to_bytes()?);
            assert_eq!(
                wire.args,
                [
                    "service=shell",
                    "cmd=show",
                    "cmd-arg=interfaces",
                    "cmd-arg=brief",
                    "protocol*ssh"
                ]
            );
            assert_eq!(wire.priv_lvl, 15);
        }
        Ok(())
    }

    #[test]
    fn logical_accounting_preserves_command_arguments() {
        let request = AccountingOperation {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "192.0.2.1".to_owned(),
            command: "show".to_owned(),
            command_arguments: vec!["users".to_owned(), "brief".to_owned()],
        }
        .to_request();
        assert_eq!(
            request.args,
            [
                "service=shell",
                "cmd=show",
                "cmd-arg=users",
                "cmd-arg=brief"
            ]
        );
        assert_eq!(request.flags, TacacsAccountingFlags::START | TacacsAccountingFlags::STOP);
    }
}
