//! Fixed authorization exchanges.

use crate::authorization::{reply::AuthorizationReply, request::AuthorizationRequest};
use crate::enumerations::{TacacsMinorVersion, TacacsType};
use crate::traits::TacacsBodyTrait;
use crate::exchange::FixedExchange;

/// One TACACS+ authorization request followed by one authorization reply.
#[derive(Debug)]
pub struct AuthorizationExchange {
    request: AuthorizationRequest,
}

impl AuthorizationExchange {
    /// Creates an authorization exchange from its protocol request body.
    #[must_use]
    pub const fn new(request: AuthorizationRequest) -> Self {
        Self { request }
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
