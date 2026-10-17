//! Transport-independent TACACS+ operations and outcomes.
//!
//! This module is the logical-operation layer. It sits above the wire layer and
//! the exchange layer:
//!
//! 1. Wire bodies ([`crate::accounting`], [`crate::authentication`],
//!    [`crate::authorization`]) encode and decode RFC 8907 request and reply
//!    octets.
//! 2. Exchanges ([`crate::exchange`]) pair one request body with its single
//!    reply and describe the transfer without performing I/O.
//! 3. Logical operations (this module) express what a caller wants in
//!    transport-independent types. [`AccountingOperation`],
//!    [`PapAuthenticationOperation`], and [`AuthorizationOperation`] convert to
//!    exchanges, and the response types decode a validated reply with
//!    `from_reply`.
//!
//! Responses and errors are distinct outcomes. A successful operation returns a
//! response type ([`AccountingOperationResponse`],
//! [`PapAuthenticationOperationResponse`], or
//! [`AuthorizationOperationResponse`]). A failed operation returns a
//! [`crate::failure::ServiceError`] with structured failure facts. A reply
//! status is not a failure: callers interpret [`AuthorizationResponseStatus`]
//! and the other status enums directly. [`UnchangedExecutionDecision`] shows how
//! a host that cannot apply response attributes turns an authorization reply
//! into an execute-or-deny decision without inventing an unavailable-service
//! outcome.
//!
//! The submodules organize the code by AAA concept, with a separate module for
//! the authorization argument-value pairs, the well-known key dictionary, and
//! the request builder. The facade re-exports every core type, so callers keep
//! using `tacacsrs_protocol::operations::<Type>`.

mod accounting;
mod arguments;
mod authentication;
mod authorization;
mod enforcement;
mod wire;

pub use accounting::{AccountingOperation, AccountingOperationResponse, AccountingResponseStatus};
pub use arguments::{AuthorizationArg, AuthorizationKey, AuthorizationRequestBuilder};
pub use authentication::{
    AuthenticationResponseStatus, PapAuthenticationOperation, PapAuthenticationOperationResponse,
};
pub use authorization::{
    AuthorizationAuthenticationContext, AuthorizationOperation, AuthorizationOperationResponse,
    AuthorizationResponseStatus,
};
pub use enforcement::UnchangedExecutionDecision;
