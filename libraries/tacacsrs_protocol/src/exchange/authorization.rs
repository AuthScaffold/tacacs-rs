//! Fixed authorization exchanges.

use crate::authorization::{reply::AuthorizationReply, request::AuthorizationRequest};
use crate::enumerations::{TacacsMinorVersion, TacacsType};
#[cfg(test)]
use crate::body::TacacsBodyTrait;
use crate::exchange::{FixedExchange, PreparedBody};

/// One TACACS+ authorization request followed by one authorization reply.
#[derive(Debug)]
pub struct AuthorizationExchange {
    body: PreparedBody,
}

impl AuthorizationExchange {
    /// Creates an authorization exchange from its protocol request body.
    ///
    /// # Errors
    /// Returns an error for invalid privilege, arguments, or codec field limits.
    pub fn new(request: AuthorizationRequest) -> anyhow::Result<Self> {
        crate::privilege::PrivilegeLevel::try_from(request.priv_lvl)?;
        let arguments = request
            .args
            .iter()
            .map(|argument| crate::operations::AuthorizationArg::parse(argument))
            .collect::<anyhow::Result<Vec<_>>>()?;
        crate::operations::AuthorizationOperation::validate_service_and_command(
            arguments
                .iter()
                .find(|argument| argument.name == "service")
                .map(|argument| argument.value.as_str()),
            arguments.iter().any(|argument| argument.name == "cmd"),
        )?;
        Self::prepare(request)
    }

    pub(crate) fn from_operation(
        operation: &crate::operations::AuthorizationOperation,
    ) -> anyhow::Result<Self> {
        Self::prepare(operation.to_request()?)
    }

    fn prepare(request: AuthorizationRequest) -> anyhow::Result<Self> {
        Ok(Self {
            body: PreparedBody::encode(&request)?,
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

    fn request_body(&self) -> &PreparedBody {
        &self.body
    }

    fn decode_reply(&self, body: &[u8]) -> anyhow::Result<Self::Reply> {
        AuthorizationReply::from_bytes(body)
    }
}

#[cfg(test)]
mod tests {
    use crate::operations::{AuthorizationAuthenticationContext, AuthorizationOperation};
    use crate::enumerations::{
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
        })?;
        let request = AuthorizationRequest::from_bytes(exchange.request_body().as_bytes())?;
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
        let exchange = AuthorizationOperation::builder(
            "admin",
            15,
            AuthorizationAuthenticationContext::TacacsPap,
        )
        .port("tty0")
        .remote_address("192.0.2.1")
        .service("shell")
        .command("")
        .build()?
        .exchange()?;
        let request = AuthorizationRequest::from_bytes(exchange.request_body().as_bytes())?;

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
        let exchange = AuthorizationOperation::builder(
            "admin",
            15,
            AuthorizationAuthenticationContext::TacacsAscii,
        )
        .port("tty0")
        .remote_address("192.0.2.1")
        .service("shell")
        .command("show")
        .command_args(["users", "brief"])
        .build()?
        .exchange()?;
        let request = AuthorizationRequest::from_bytes(exchange.request_body().as_bytes())?;

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
