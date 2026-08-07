#![doc = include_str!("../README.md")]

mod error;
mod fake;
mod material;
mod request;
mod resolver;
mod result_set;
mod runtime_server;

pub use error::{ProviderErrorKind, ResolutionError, ResolutionErrorKind};
pub use fake::FakeCredentialResolver;
pub use material::{
    CertificateBagMaterial, CertificateWithKeyMaterial, PublicBytes, ResolvedCredential,
};
pub use tacacsrs_secrets::SecretBytes;
pub use request::{
    CredentialKind, CredentialReference, CredentialRequest, RequestContext, RequestSlot,
    ResolutionPlan,
};
pub use resolver::{CredentialResolver, resolve_plan};
pub use result_set::{ResolvedCredentialSet, ResolvedResponse};
pub use runtime_server::RuntimeServer;
