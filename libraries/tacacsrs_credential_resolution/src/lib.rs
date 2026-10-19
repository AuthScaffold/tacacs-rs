#![doc = include_str!("../README.md")]

mod error;
mod change;
mod fake;
mod material;
mod request;
mod resolver;
mod result_set;
mod validity;
mod work;

pub use error::{ProviderErrorKind, ResolutionError, ResolutionErrorKind};
pub use change::{
    CredentialChangeError, CredentialChangeEvent, CredentialChangeScope, CredentialChangeSource,
    CredentialChangeStream,
};
pub use fake::FakeCredentialResolver;
pub use material::{
    OcspResponseMaterial, CertificateBagMaterial, CertificateWithKeyMaterial,
    NamedCertificateMaterial, PublicBytes, CertificateRevocationListsMaterial, ResolvedCredential,
    SymmetricKeyMaterial, PrivateKeyFormat, PublicKeyFormat, SymmetricKeyFormat,
};
pub use tacacsrs_secrets::SecretBytes;
pub use request::{
    CredentialKind, CredentialReference, CredentialRequest, RequestContext, RequestSlot,
    ResolutionPlan,
};
pub use resolver::{CredentialResolver, resolve_plan};
pub use validity::{CredentialValidity, InvalidCredentialValidity};
pub use result_set::{ResolvedCredentialSet, ResolvedResponse};
pub use work::{WorkScope, WorkScopeControl};
