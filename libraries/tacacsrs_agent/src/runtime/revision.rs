//! Controller-local identities for canonical source and credential observations.
//!
//! These counters identify accepted inputs, not hashes of configuration or secret
//! material. Values from different controller instances must not be compared.

/// Revision of an accepted canonical source candidate, including repeated observations.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct SourceRevision(u64);

impl SourceRevision {
    pub(crate) fn advance(&mut self) {
        self.0 = self
            .0
            .checked_add(1)
            .expect("source revision space exhausted");
    }

    /// Returns the controller-local diagnostic counter.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Revision of a relevant credential invalidation, independent of source changes.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct CredentialRevision(u64);

impl CredentialRevision {
    pub(crate) fn advance(&mut self) {
        self.0 = self
            .0
            .checked_add(1)
            .expect("credential revision space exhausted");
    }

    /// Returns the controller-local diagnostic counter.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Source and credential observations used to prepare an applied server set.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct MaterializationRevision {
    pub(crate) source: SourceRevision,
    pub(crate) credentials: CredentialRevision,
}

impl MaterializationRevision {
    /// Returns the accepted canonical source revision.
    #[must_use]
    pub const fn source(self) -> SourceRevision {
        self.source
    }

    /// Returns the independently observed credential revision.
    #[must_use]
    pub const fn credentials(self) -> CredentialRevision {
        self.credentials
    }
}
