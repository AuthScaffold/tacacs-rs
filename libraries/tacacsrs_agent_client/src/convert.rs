//! Protobuf conversions for the shared protocol operations.

use anyhow::{Context, bail};
use tacacsrs_secrets::SecretBytes;
use tacacsrs_protocol::privilege::PrivilegeLevel;

use tacacsrs_protocol::operations::{
    AccountingOperation, AccountingOperationResponse, AccountingResponseStatus,
    AuthenticationResponseStatus, AuthorizationArg, AuthorizationAuthenticationContext,
    AuthorizationOperation, AuthorizationOperationResponse, AuthorizationResponseStatus,
    PapAuthenticationOperation, PapAuthenticationOperationResponse, ServiceError,
};
use crate::ipc;

fn authorization_status(value: i32) -> anyhow::Result<AuthorizationResponseStatus> {
    match u8::try_from(value).context("IPC authorization status value is out of u8 range")? {
        0 => bail!("IPC authorization status must not be unspecified"),
        0x01 => Ok(AuthorizationResponseStatus::PassAdd),
        0x02 => Ok(AuthorizationResponseStatus::PassRepl),
        0x10 => Ok(AuthorizationResponseStatus::Fail),
        0x11 => Ok(AuthorizationResponseStatus::Error),
        0x21 => Ok(AuthorizationResponseStatus::Follow),
        _ => bail!("IPC authorization status value is not recognized"),
    }
}

fn accounting_status(value: i32) -> anyhow::Result<AccountingResponseStatus> {
    match u8::try_from(value).context("IPC accounting status value is out of u8 range")? {
        0 => bail!("IPC accounting status must not be unspecified"),
        0x01 => Ok(AccountingResponseStatus::Success),
        0x02 => Ok(AccountingResponseStatus::Error),
        0x21 => Ok(AccountingResponseStatus::Follow),
        _ => bail!("IPC accounting status value is not recognized"),
    }
}

fn authentication_status(value: i32) -> anyhow::Result<AuthenticationResponseStatus> {
    match u8::try_from(value).context("IPC authentication status value is out of u8 range")? {
        0 => bail!("IPC authentication status must not be unspecified"),
        0x01 => Ok(AuthenticationResponseStatus::Pass),
        0x02 => Ok(AuthenticationResponseStatus::Fail),
        0x07 => Ok(AuthenticationResponseStatus::Error),
        _ => bail!("IPC authentication status value is not recognized"),
    }
}

fn encode_authentication_context(value: AuthorizationAuthenticationContext) -> i32 {
    match value {
        AuthorizationAuthenticationContext::TacacsAscii => 1,
        AuthorizationAuthenticationContext::TacacsPap => 2,
        AuthorizationAuthenticationContext::Unauthenticated => 3,
    }
}

fn decode_authentication_context(value: i32) -> anyhow::Result<AuthorizationAuthenticationContext> {
    match value {
        0 => bail!("IPC authorization authentication context must not be unspecified"),
        1 => Ok(AuthorizationAuthenticationContext::TacacsAscii),
        2 => Ok(AuthorizationAuthenticationContext::TacacsPap),
        3 => Ok(AuthorizationAuthenticationContext::Unauthenticated),
        _ => bail!("IPC authorization authentication context is not recognized"),
    }
}

impl From<ServiceError> for ipc::ServiceError {
    fn from(value: ServiceError) -> Self {
        Self {
            message: value.message,
            server: value.server.unwrap_or_default(),
            retriable: value.retriable,
        }
    }
}

impl From<ipc::ServiceError> for ServiceError {
    fn from(proto: ipc::ServiceError) -> Self {
        Self {
            message: proto.message,
            server: (!proto.server.is_empty()).then_some(proto.server),
            retriable: proto.retriable,
        }
    }
}

impl From<AccountingOperation> for ipc::AccountingRequest {
    fn from(value: AccountingOperation) -> Self {
        Self {
            user: value.user,
            port: value.port,
            remote_address: value.remote_address,
            command: value.command,
            command_arguments: value.command_arguments,
        }
    }
}

impl From<&AccountingOperation> for ipc::AccountingRequest {
    fn from(value: &AccountingOperation) -> Self {
        Self {
            user: value.user.clone(),
            port: value.port.clone(),
            remote_address: value.remote_address.clone(),
            command: value.command.clone(),
            command_arguments: value.command_arguments.clone(),
        }
    }
}

impl TryFrom<ipc::AccountingRequest> for AccountingOperation {
    type Error = anyhow::Error;

    fn try_from(value: ipc::AccountingRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            user: value.user,
            port: value.port,
            remote_address: value.remote_address,
            command: value.command,
            command_arguments: value.command_arguments,
        })
    }
}

impl From<PapAuthenticationOperation> for ipc::PapAuthenticationRequest {
    fn from(value: PapAuthenticationOperation) -> Self {
        Self {
            user: value.user,
            password: value.password.into_unprotected_vec(),
            port: value.port,
            remote_address: value.remote_address,
            privilege_level: value.privilege_level.into(),
        }
    }
}

impl TryFrom<ipc::PapAuthenticationRequest> for PapAuthenticationOperation {
    type Error = anyhow::Error;

    fn try_from(value: ipc::PapAuthenticationRequest) -> Result<Self, Self::Error> {
        let operation = Self {
            user: value.user,
            password: SecretBytes::new(value.password),
            port: value.port,
            remote_address: value.remote_address,
            privilege_level: PrivilegeLevel::try_from(value.privilege_level)?,
        };
        operation.validate()?;
        Ok(operation)
    }
}

// ---------------------------------------------------------------------------
// Protobuf ↔ domain conversions for AuthorizationOperation
// ---------------------------------------------------------------------------

impl From<AuthorizationOperation> for ipc::AuthorizationRequest {
    fn from(value: AuthorizationOperation) -> Self {
        Self {
            user: value.user,
            port: value.port,
            remote_address: value.remote_address,
            privilege_level: value.privilege_level.into(),
            authentication_context: encode_authentication_context(value.authentication_context),
            args: value
                .args
                .into_iter()
                .map(ipc::AuthorizationArg::from)
                .collect(),
        }
    }
}

impl From<&AuthorizationOperation> for ipc::AuthorizationRequest {
    fn from(value: &AuthorizationOperation) -> Self {
        Self {
            user: value.user.clone(),
            port: value.port.clone(),
            remote_address: value.remote_address.clone(),
            privilege_level: value.privilege_level.into(),
            authentication_context: encode_authentication_context(value.authentication_context),
            args: value
                .args
                .iter()
                .cloned()
                .map(ipc::AuthorizationArg::from)
                .collect(),
        }
    }
}

impl TryFrom<ipc::AuthorizationRequest> for AuthorizationOperation {
    type Error = anyhow::Error;

    fn try_from(value: ipc::AuthorizationRequest) -> Result<Self, Self::Error> {
        let operation = Self {
            user: value.user,
            port: value.port,
            remote_address: value.remote_address,
            privilege_level: PrivilegeLevel::try_from(value.privilege_level)?,
            authentication_context: decode_authentication_context(value.authentication_context)?,
            args: value.args.into_iter().map(AuthorizationArg::from).collect(),
        };
        operation.validate()?;
        Ok(operation)
    }
}

// ---------------------------------------------------------------------------
// Protobuf ↔ domain conversions for AccountingOperationResponse
// ---------------------------------------------------------------------------

impl From<AccountingOperationResponse> for ipc::AccountingResponse {
    fn from(value: AccountingOperationResponse) -> Self {
        Self {
            server: value.server,
            status: i32::from(value.status.code()),
            server_message: value.server_message,
            data: value.data,
        }
    }
}

impl TryFrom<ipc::AccountingResponse> for AccountingOperationResponse {
    type Error = anyhow::Error;

    fn try_from(proto: ipc::AccountingResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            server: proto.server,
            status: accounting_status(proto.status)?,
            server_message: proto.server_message,
            data: proto.data,
        })
    }
}

impl From<PapAuthenticationOperationResponse> for ipc::PapAuthenticationResponse {
    fn from(value: PapAuthenticationOperationResponse) -> Self {
        Self {
            server: value.server,
            status: i32::from(value.status.code()),
            server_message: value.server_message,
            data: value.data,
        }
    }
}

impl TryFrom<ipc::PapAuthenticationResponse> for PapAuthenticationOperationResponse {
    type Error = anyhow::Error;

    fn try_from(proto: ipc::PapAuthenticationResponse) -> Result<Self, Self::Error> {
        Ok(Self {
            server: proto.server,
            status: authentication_status(proto.status)?,
            server_message: proto.server_message,
            data: proto.data,
        })
    }
}

// ---------------------------------------------------------------------------
// Protobuf ↔ domain conversions for AuthorizationOperationResponse
// ---------------------------------------------------------------------------

impl From<AuthorizationOperationResponse> for ipc::AuthorizationResponse {
    fn from(value: AuthorizationOperationResponse) -> Self {
        Self {
            server: value.server,
            status: i32::from(value.status.code()),
            server_message: value.server_message,
            args: value
                .args
                .into_iter()
                .map(ipc::AuthorizationArg::from)
                .collect(),
            data: value.data,
        }
    }
}

impl TryFrom<ipc::AuthorizationResponse> for AuthorizationOperationResponse {
    type Error = anyhow::Error;

    fn try_from(proto: ipc::AuthorizationResponse) -> Result<Self, Self::Error> {
        let response = Self {
            server: proto.server,
            status: authorization_status(proto.status)?,
            server_message: proto.server_message,
            args: proto.args.into_iter().map(AuthorizationArg::from).collect(),
            data: proto.data,
        };
        for arg in &response.args {
            arg.validate()?;
        }
        Ok(response)
    }
}

impl From<AuthorizationArg> for ipc::AuthorizationArg {
    fn from(arg: AuthorizationArg) -> Self {
        Self {
            name: arg.name,
            mandatory: arg.mandatory,
            value: arg.value,
        }
    }
}

impl From<ipc::AuthorizationArg> for AuthorizationArg {
    fn from(arg: ipc::AuthorizationArg) -> Self {
        Self {
            name: arg.name,
            mandatory: arg.mandatory,
            value: arg.value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacacsrs_protocol::exchange::FixedExchange;

    #[test]
    fn direct_and_ipc_authorization_have_identical_wire_bodies() -> anyhow::Result<()> {
        for context in [
            AuthorizationAuthenticationContext::TacacsAscii,
            AuthorizationAuthenticationContext::TacacsPap,
            AuthorizationAuthenticationContext::Unauthenticated,
        ] {
            for command in ["", "show"] {
                let direct = AuthorizationOperation::builder("admin", 15, context)
                    .port("tty0")
                    .remote_address("192.0.2.1")
                    .service("shell")
                    .command(command)
                    .command_args(["interfaces", "brief"])
                    .arg(AuthorizationArg::optional("protocol", "ssh"))
                    .build()?;
                let decoded =
                    AuthorizationOperation::try_from(ipc::AuthorizationRequest::from(&direct))?;
                assert_eq!(
                    direct.exchange()?.encode_request()?,
                    decoded.exchange()?.encode_request()?
                );
                assert_eq!(direct, decoded);
            }
        }
        Ok(())
    }

    #[test]
    fn direct_and_ipc_accounting_have_identical_wire_bodies() -> anyhow::Result<()> {
        let direct = AccountingOperation {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "192.0.2.1".to_owned(),
            command: "show".to_owned(),
            command_arguments: vec!["users".to_owned(), "brief".to_owned()],
        };
        let decoded = AccountingOperation::try_from(ipc::AccountingRequest::from(&direct))?;
        assert_eq!(direct.exchange().encode_request()?, decoded.exchange().encode_request()?);
        Ok(())
    }

    #[test]
    fn direct_and_ipc_pap_have_identical_wire_bodies() -> anyhow::Result<()> {
        let direct = PapAuthenticationOperation {
            user: "admin".to_owned(),
            password: SecretBytes::new(b"conformance-secret".to_vec()),
            port: "tty0".to_owned(),
            remote_address: "192.0.2.1".to_owned(),
            privilege_level: PrivilegeLevel::MAX,
        };
        let decoded = PapAuthenticationOperation::try_from(ipc::PapAuthenticationRequest::from(
            direct.clone(),
        ))?;
        assert_eq!(direct.exchange()?.encode_request()?, decoded.exchange()?.encode_request()?);
        assert!(!format!("{decoded:?}").contains("conformance-secret"));
        Ok(())
    }

    #[test]
    fn ipc_rejects_privilege_values_outside_the_domain() {
        let operation = AuthorizationOperation::builder(
            "admin",
            15,
            AuthorizationAuthenticationContext::TacacsAscii,
        )
        .service("shell")
        .command("show")
        .build()
        .unwrap();
        for level in [16, 255, u32::MAX] {
            let mut proto = ipc::AuthorizationRequest::from(&operation);
            proto.privilege_level = level;
            assert!(AuthorizationOperation::try_from(proto).is_err());
            let proto = ipc::PapAuthenticationRequest {
                user: "admin".to_owned(),
                password: Vec::new(),
                port: String::new(),
                remote_address: String::new(),
                privilege_level: level,
            };
            assert!(PapAuthenticationOperation::try_from(proto).is_err());
        }
    }

    #[test]
    fn pap_authentication_proto_round_trip_redacts_password() {
        let request = PapAuthenticationOperation {
            user: "admin".to_owned(),
            password: SecretBytes::new(b"sentinel-secret".to_vec()),
            port: "tty0".to_owned(),
            remote_address: "192.0.2.1".to_owned(),
            privilege_level: PrivilegeLevel::MAX,
        };
        assert!(!format!("{request:?}").contains("sentinel-secret"));

        let proto = ipc::PapAuthenticationRequest::from(request);
        let decoded = PapAuthenticationOperation::try_from(proto).unwrap();
        assert_eq!(decoded.user, "admin");
        assert_eq!(decoded.password.expose_secret(), b"sentinel-secret");
        assert_eq!(decoded.privilege_level, PrivilegeLevel::MAX);
    }

    #[test]
    fn pap_authentication_response_proto_round_trip() {
        let response = PapAuthenticationOperationResponse {
            server: "server:49".to_owned(),
            status: AuthenticationResponseStatus::Pass,
            server_message: "ok".to_owned(),
            data: vec![1, 2],
        };
        let decoded = PapAuthenticationOperationResponse::try_from(
            ipc::PapAuthenticationResponse::from(response),
        )
        .unwrap();
        assert_eq!(decoded.status, AuthenticationResponseStatus::Pass);
        assert_eq!(decoded.data, vec![1, 2]);
    }

    #[test]
    fn test_accounting_operation_proto_round_trip() {
        let request = AccountingOperation {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            command: "show".to_owned(),
            command_arguments: vec!["users".to_owned()],
        };

        let encoded: ipc::AccountingRequest = (&request).into();
        let decoded = AccountingOperation::try_from(encoded).unwrap();
        assert_eq!(decoded, request);
    }

    #[test]
    fn test_authorization_operation_proto_round_trip() {
        let request = AuthorizationOperation::builder(
            "admin",
            15,
            AuthorizationAuthenticationContext::TacacsAscii,
        )
        .port("tty0")
        .remote_address("127.0.0.1")
        .service("shell")
        .command("show")
        .command_args(vec!["users".to_owned()])
        .build()
        .unwrap();

        let encoded: ipc::AuthorizationRequest = (&request).into();
        let decoded = AuthorizationOperation::try_from(encoded).unwrap();
        assert_eq!(decoded, request);
        assert_eq!(decoded.service(), Some("shell"));
        assert_eq!(decoded.command(), Some("show"));
        assert_eq!(decoded.command_arguments().collect::<Vec<_>>(), vec!["users"]);
    }

    #[test]
    fn test_authorization_operation_rejects_invalid_proto_arg_name() {
        let request = ipc::AuthorizationRequest {
            user: "admin".to_owned(),
            port: "tty0".to_owned(),
            remote_address: "127.0.0.1".to_owned(),
            privilege_level: 15,
            authentication_context: encode_authentication_context(
                AuthorizationAuthenticationContext::TacacsAscii,
            ),
            args: vec![
                ipc::AuthorizationArg {
                    name: "service".to_owned(),
                    mandatory: true,
                    value: "shell".to_owned(),
                },
                ipc::AuthorizationArg {
                    name: "cmd".to_owned(),
                    mandatory: true,
                    value: "show".to_owned(),
                },
                ipc::AuthorizationArg {
                    name: "bad=name".to_owned(),
                    mandatory: true,
                    value: "value".to_owned(),
                },
            ],
        };

        let error = AuthorizationOperation::try_from(request).unwrap_err();
        assert!(error.to_string().contains("contains a separator"));
    }

    #[test]
    fn test_authorization_response_proto_round_trip() {
        let response = AuthorizationOperationResponse {
            server: "server-a:49".to_owned(),
            status: AuthorizationResponseStatus::PassRepl,
            server_message: "replace arguments".to_owned(),
            args: vec![
                AuthorizationArg {
                    name: "cmd".to_owned(),
                    mandatory: true,
                    value: "show".to_owned(),
                },
                AuthorizationArg {
                    name: "cmd-arg".to_owned(),
                    mandatory: true,
                    value: "users".to_owned(),
                },
            ],
            data: "display this".to_owned(),
        };

        let decoded = AuthorizationOperationResponse::try_from(ipc::AuthorizationResponse::from(
            response.clone(),
        ))
        .unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn test_authorization_response_rejects_invalid_proto_arg_name() {
        let response = ipc::AuthorizationResponse {
            server: "server-a:49".to_owned(),
            status: i32::from(AuthorizationResponseStatus::PassAdd.code()),
            server_message: String::new(),
            args: vec![ipc::AuthorizationArg {
                name: "bad*name".to_owned(),
                mandatory: false,
                value: "value".to_owned(),
            }],
            data: String::new(),
        };

        let error = AuthorizationOperationResponse::try_from(response).unwrap_err();
        assert!(error.to_string().contains("contains a separator"));
    }

    #[test]
    fn test_service_error_proto_round_trip() {
        let error = ServiceError::new("failed")
            .with_server("server-a:49")
            .retriable(true);

        let decoded = ServiceError::from(ipc::ServiceError::from(error.clone()));
        assert_eq!(decoded, error);
    }
}
