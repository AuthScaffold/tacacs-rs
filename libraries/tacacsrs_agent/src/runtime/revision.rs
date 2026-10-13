//! Controller-local identities for source, credential, and policy observations.
//!
//! These counters identify observed inputs, not hashes of configuration or secret
//! material. Values from different controller instances must not be compared.

/// Revision of source admission or rejection, assigned before host filtering.
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

/// Identifies policy admission before validation or publication waits.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct PolicyRevision(u64);

impl PolicyRevision {
    pub(crate) fn advance(&mut self) {
        self.0 = self
            .0
            .checked_add(1)
            .expect("policy revision space exhausted");
    }

    /// Returns the runtime-local diagnostic counter.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Result of a policy candidate processed by the runtime publication controller.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PolicyUpdate {
    /// The candidate and its health metadata committed together.
    Applied(PolicyRevision),
    /// The current candidate was invalid. The applied policy is unchanged.
    Rejected(PolicyRevision),
    /// A newer admission replaced this candidate before its decision.
    Superseded,
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

pub(crate) struct MaterializationCommit {
    pub(crate) revision: MaterializationRevision,
    pub(crate) source_current: bool,
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
