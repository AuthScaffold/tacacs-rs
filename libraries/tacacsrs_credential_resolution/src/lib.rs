#![doc = include_str!("../README.md")]

mod error;
mod change;
mod fake;
mod material;
mod request;
mod resolver;
mod result_set;

pub use error::{ProviderErrorKind, ResolutionError, ResolutionErrorKind};
pub use change::{
    CredentialChangeError, CredentialChangeEvent, CredentialChangeScope, CredentialChangeSource,
    CredentialChangeStream,
};
pub use fake::FakeCredentialResolver;
pub use material::{
    CertificateBagMaterial, CertificateWithKeyMaterial, NamedCertificateMaterial, PublicBytes,
    ResolvedCredential, SymmetricKeyMaterial, PrivateKeyFormat, PublicKeyFormat,
    SymmetricKeyFormat,
};
pub use tacacsrs_secrets::SecretBytes;
pub use request::{
    CredentialKind, CredentialReference, CredentialRequest, RequestContext, RequestSlot,
    ResolutionPlan,
};
pub use resolver::{CredentialResolver, resolve_plan};
pub use result_set::{ResolvedCredentialSet, ResolvedResponse};
