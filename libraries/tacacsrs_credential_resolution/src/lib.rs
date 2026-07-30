#![doc = include_str!("../README.md")]

mod error;
mod fake;
mod material;
mod request;
mod resolver;
mod result_set;

pub use error::{ProviderErrorKind, ResolutionError, ResolutionErrorKind};
pub use fake::FakeCredentialResolver;
pub use material::{
    CertificateBagMaterial, CertificateWithKeyMaterial, PublicBytes, ResolvedCredential,
    SecretBytes,
};
pub use request::{
    CredentialKind, CredentialReference, CredentialRequest, RequestContext, RequestSlot,
    ResolutionPlan,
};
pub use resolver::{CredentialResolver, resolve_plan};
pub use result_set::{ResolvedCredentialSet, ResolvedResponse};
