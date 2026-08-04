//! Fixed authorization exchanges.

use tacacsrs_messages::authorization::{reply::AuthorizationReply, request::AuthorizationRequest};
use tacacsrs_messages::enumerations::{
    TacacsAuthenticationMethod, TacacsAuthenticationService, TacacsAuthenticationType,
    TacacsMinorVersion, TacacsType,
};
use tacacsrs_messages::traits::TacacsBodyTrait;
use tacacsrs_networking::FixedExchange;

/// One TACACS+ authorization request followed by one authorization reply.
#[derive(Debug)]
pub struct AuthorizationExchange {
    request: AuthorizationRequest,
}

/// Authentication metadata included in an authorization request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationContext {
    /// The user authenticated using a TACACS+ ASCII login.
    TacacsAscii,
    /// The user authenticated using a TACACS+ PAP login.
    TacacsPap,
    /// No authenticated identity is asserted.
    Unauthenticated,
}

impl AuthenticationContext {
    const fn protocol_fields(
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

impl AuthorizationExchange {
    /// Creates an authorization exchange from its protocol request body.
    #[must_use]
    pub const fn new(request: AuthorizationRequest) -> Self {
        Self { request }
    }

    /// Creates session-based shell authorization using RFC 8907 `cmd=`.
    #[must_use]
    pub fn shell_session(
        context: AuthenticationContext,
        user: impl Into<String>,
        port: impl Into<String>,
        remote_address: impl Into<String>,
        privilege_level: u8,
    ) -> Self {
        Self::shell(context, user, port, remote_address, privilege_level, "", Vec::new())
    }

    /// Creates command-based shell authorization with ordered `cmd-arg` values.
    #[must_use]
    pub fn shell_command<I, S>(
        context: AuthenticationContext,
        user: impl Into<String>,
        port: impl Into<String>,
        remote_address: impl Into<String>,
        privilege_level: u8,
        command: impl Into<String>,
        arguments: I,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let command = command.into();
        Self::shell(
            context,
            user,
            port,
            remote_address,
            privilege_level,
            &command,
            arguments.into_iter().map(Into::into).collect(),
        )
    }

    fn shell(
        context: AuthenticationContext,
        user: impl Into<String>,
        port: impl Into<String>,
        remote_address: impl Into<String>,
        privilege_level: u8,
        command: &str,
        arguments: Vec<String>,
    ) -> Self {
        let (authen_method, authen_type, authen_service) = context.protocol_fields();
        let mut args = Vec::with_capacity(arguments.len() + 2);
        args.push("service=shell".to_owned());
        args.push(format!("cmd={command}"));
        args.extend(
            arguments
                .into_iter()
                .map(|argument| format!("cmd-arg={argument}")),
        );

        Self::new(AuthorizationRequest {
            authen_method,
            priv_lvl: privilege_level,
            authen_type,
            authen_service,
            user: user.into(),
            port: port.into(),
            rem_address: remote_address.into(),
            args,
        })
    }
}


impl FixedExchange for AuthorizationExchange {
    type Reply = AuthorizationReply;

    fn packet_type(&self) -> TacacsType {
        TacacsType::TacPlusAuthorisation
    }

    fn minor_version(&self) -> TacacsMinorVersion {
        TacacsMinorVersion::TacacsPlusMinorVerDefault
    }

    fn encode_request(&self) -> anyhow::Result<Vec<u8>> {
        self.request.to_bytes()
    }

    fn decode_reply(self, body: &[u8]) -> anyhow::Result<Self::Reply> {
        AuthorizationReply::from_bytes(body)
    }
}

#[cfg(test)]
mod tests {
    use tacacsrs_messages::enumerations::{
        TacacsAuthenticationMethod, TacacsAuthenticationService, TacacsAuthenticationType,
        TacacsAuthorizationStatus,
    };

    use super::*;

    #[test]
    fn exchange_encodes_request_and_decodes_reply() -> anyhow::Result<()> {
        let exchange = AuthorizationExchange::new(AuthorizationRequest {
            authen_method: TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus,
            priv_lvl: 15,
            authen_type: TacacsAuthenticationType::TacPlusAuthenTypePap,
            authen_service: TacacsAuthenticationService::TacPlusAuthenSvcLogin,
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            rem_address: "192.0.2.1".to_owned(),
            args: vec!["service=shell".to_owned(), "cmd=".to_owned()],
        });
        let request = AuthorizationRequest::from_bytes(&exchange.encode_request()?)?;
        assert_eq!(request.args, vec!["service=shell", "cmd="]);

        let body = AuthorizationReply {
            status: TacacsAuthorizationStatus::TacPlusPassAdd,
            server_msg: "authorized".to_owned(),
            data: String::new(),
            args: vec!["priv-lvl=15".to_owned()],
        }
        .to_bytes()?;
        let reply = exchange.decode_reply(&body)?;
        assert_eq!(reply.status, TacacsAuthorizationStatus::TacPlusPassAdd);
        Ok(())
    }

    #[test]
    fn shell_session_encodes_empty_command_and_pap_context() -> anyhow::Result<()> {
        let exchange = AuthorizationExchange::shell_session(
            AuthenticationContext::TacacsPap,
            "admin",
            "tty0",
            "192.0.2.1",
            15,
        );
        let request = AuthorizationRequest::from_bytes(&exchange.encode_request()?)?;

        assert_eq!(
            request.authen_method,
            TacacsAuthenticationMethod::TacPlusAuthenMethodTacacsplus
        );
        assert_eq!(request.authen_type, TacacsAuthenticationType::TacPlusAuthenTypePap);
        assert_eq!(request.authen_service, TacacsAuthenticationService::TacPlusAuthenSvcLogin);
        assert_eq!(request.args, vec!["service=shell", "cmd="]);
        Ok(())
    }

    #[test]
    fn shell_command_preserves_argument_order() -> anyhow::Result<()> {
        let exchange = AuthorizationExchange::shell_command(
            AuthenticationContext::TacacsAscii,
            "admin",
            "tty0",
            "192.0.2.1",
            15,
            "show",
            ["users", "brief"],
        );
        let request = AuthorizationRequest::from_bytes(&exchange.encode_request()?)?;

        assert_eq!(
            request.args,
            vec![
                "service=shell",
                "cmd=show",
                "cmd-arg=users",
                "cmd-arg=brief"
            ]
        );
        Ok(())
    }
}
