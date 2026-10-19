//! Pure descriptions of fixed TACACS+ request/reply exchanges.

pub mod accounting;
pub mod authentication;
pub mod authorization;

use crate::enumerations::{TacacsMinorVersion, TacacsType};
use crate::body::TacacsBodyTrait;
use tacacsrs_secrets::SecretBytes;

/// Immutable unobfuscated codec output with a checked TACACS+ body length.
#[derive(Debug)]
pub struct PreparedBody {
    bytes: SecretBytes,
    wire_length: u32,
}

impl PreparedBody {
    /// Encodes a body once and checks its 32-bit wire length.
    ///
    /// The supplied codec validates its own fields. This factory does not
    /// validate operation-specific AAA semantics.
    ///
    /// # Errors
    /// Returns an error if the codec rejects the body or its length exceeds `u32`.
    pub fn encode(body: &impl TacacsBodyTrait) -> anyhow::Result<Self> {
        let bytes = SecretBytes::new(body.to_bytes()?);
        let wire_length = u32::try_from(bytes.expose_secret().len()).map_err(|_| {
            anyhow::anyhow!("fixed TACACS+ request body exceeds the protocol length field")
        })?;
        Ok(Self { bytes, wire_length })
    }

    /// Returns the unobfuscated body without mutable access.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.expose_secret()
    }

    /// Returns the checked body length, excluding the packet header.
    #[must_use]
    pub const fn wire_length(&self) -> u32 {
        self.wire_length
    }
}

/// Describes one TACACS+ request and its single reply without performing I/O.
///
/// The executor supplies headers, session identifiers, sequence numbers, and
/// transport flags. An exchange retains its prepared body and decodes a validated reply.
pub trait FixedExchange: Send + Sync {
    /// Typed reply produced by this exchange.
    type Reply: Send;

    /// Returns the TACACS+ packet type for the request and reply.
    fn packet_type(&self) -> TacacsType;

    /// Returns the protocol minor version required by the exchange.
    fn minor_version(&self) -> TacacsMinorVersion;

    /// Returns the immutable request body prepared before execution.
    fn request_body(&self) -> &PreparedBody;

    /// Decodes the reply body after the executor validates its header.
    ///
    /// # Errors
    ///
    /// Returns an error if the reply body is invalid for this exchange.
    fn decode_reply(&self, body: &[u8]) -> anyhow::Result<Self::Reply>;
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::operations::{
        AccountingOperation, AuthorizationAuthenticationContext, AuthorizationOperation,
        PapAuthenticationOperation,
    };
    use crate::privilege::PrivilegeLevel;

    use super::*;

    #[test]
    fn prepared_body_encodes_once_and_checks_exact_length() -> anyhow::Result<()> {
        struct CountedBody<'counter>(&'counter AtomicUsize);
        impl TacacsBodyTrait for CountedBody<'_> {
            fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(vec![1, 2, 3])
            }
        }
        let count = AtomicUsize::new(0);
        let body = PreparedBody::encode(&CountedBody(&count))?;
        for _ in 0..3 {
            assert_eq!(body.as_bytes(), [1, 2, 3]);
            assert_eq!(body.wire_length(), 3);
        }
        assert_eq!(count.load(Ordering::Relaxed), 1);
        assert!(!format!("{body:?}").contains("[1, 2, 3]"));
        Ok(())
    }

    #[test]
    fn prepared_snapshots_are_independent_and_redacted() -> anyhow::Result<()> {
        let mut accounting = AccountingOperation {
            user: "snapshot-user".into(),
            port: "tty0".into(),
            remote_address: String::new(),
            command: "show".into(),
            command_arguments: vec!["users".into()],
        };
        let prepared = accounting.exchange()?;
        let bytes = prepared.request_body().as_bytes().to_vec();
        accounting.user.clear();
        accounting.command_arguments.clear();
        assert_eq!(prepared.request_body().as_bytes(), bytes);
        assert!(!format!("{prepared:?}").contains("snapshot-user"));

        let mut authorization = AuthorizationOperation::builder(
            "snapshot-user",
            15,
            AuthorizationAuthenticationContext::TacacsAscii,
        )
        .service("shell")
        .command("show")
        .command_args(["users"])
        .build()?;
        let prepared = authorization.exchange()?;
        let bytes = prepared.request_body().as_bytes().to_vec();
        authorization.args.clear();
        assert!(authorization.exchange().is_err());
        assert_eq!(prepared.request_body().as_bytes(), bytes);

        let mut pap = PapAuthenticationOperation {
            user: "snapshot-user".into(),
            password: SecretBytes::new(vec![0, 255, 128, 42]),
            port: "tty0".into(),
            remote_address: String::new(),
            privilege_level: PrivilegeLevel::MAX,
        };
        let prepared = pap.exchange()?;
        pap.user.clear();
        pap.password = SecretBytes::new(Vec::new());
        let decoded = crate::authentication::start::AuthenticationStart::from_bytes(
            prepared.request_body().as_bytes(),
        )?;
        assert_eq!(decoded.data, [0, 255, 128, 42]);
        let debug = format!("{prepared:?}");
        assert!(!debug.contains("snapshot-user"));
        assert!(!debug.contains("255"));
        Ok(())
    }

    #[test]
    fn concrete_preparation_checks_byte_fields_and_argument_counts() -> anyhow::Result<()> {
        for length in [255, 256] {
            let valid = length == 255;
            let accounting = AccountingOperation {
                user: "x".repeat(length),
                port: String::new(),
                remote_address: String::new(),
                command: String::new(),
                command_arguments: Vec::new(),
            };
            assert_eq!(accounting.exchange().is_ok(), valid);
            let mut authorization = AuthorizationOperation::builder(
                "x".repeat(length),
                15,
                AuthorizationAuthenticationContext::TacacsAscii,
            )
            .service("shell")
            .command("")
            .build()?;
            assert_eq!(authorization.exchange().is_ok(), valid);
            authorization.user = "admin".into();
            authorization.args =
                vec![crate::operations::AuthorizationArg::mandatory("service", "test"); length];
            assert_eq!(authorization.exchange().is_ok(), valid);
            let pap = PapAuthenticationOperation {
                user: "admin".into(),
                password: SecretBytes::new(vec![0xff; length]),
                port: String::new(),
                remote_address: String::new(),
                privilege_level: PrivilegeLevel::MIN,
            };
            assert_eq!(pap.exchange().is_ok(), valid);
        }
        let unicode = PapAuthenticationOperation {
            user: "\u{e9}".repeat(128),
            password: SecretBytes::new(Vec::new()),
            port: String::new(),
            remote_address: String::new(),
            privilege_level: PrivilegeLevel::MIN,
        };
        assert!(unicode.exchange().is_err());
        Ok(())
    }
}
