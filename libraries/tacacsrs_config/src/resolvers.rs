use crate::generated::tacacs_plus::TacacsPlus;
use anyhow::Result;

/// Type of credential reference that requires resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRefType {
    /// Reference to a client-credentials bundle
    ClientCredential,
    /// Reference to a server-credentials bundle
    ServerCredential,
    /// Reference to a central keystore entry
    Keystore,
    /// Reference to a central truststore entry
    Truststore,
}

/// Trait for resolving credential references to inline material.
///
/// Implementations can handle different credential sources:
/// - Bundle references: look up in client/server credential lists
/// - Keystore references: fetch from system keystore
/// - Truststore references: fetch from system truststore
/// - Filesystem references: read from files
/// - Environment: retrieve from environment variables
/// - etc.
pub trait CredentialResolver: Send + Sync {
    /// Resolve a credential reference key to inline PEM or key material.
    ///
    /// The `ref_type` parameter lets implementations specialize by credential type
    /// (e.g., a keystore resolver only handles Keystore/Truststore refs).
    ///
    /// Returns the resolved material (e.g., certificate or key bytes) if found.
    /// Returns `None` if this resolver does not handle this credential type.
    /// Returns an error if resolution fails.
    ///
    /// # Errors
    ///
    /// Returns an error if resolution fails or the credential is invalid.
    fn resolve(&self, key: &str, ref_type: CredentialRefType) -> Result<Option<String>>;

    /// Validate that a credential reference can be resolved.
    ///
    /// This is called during the validation phase to catch missing credentials early.
    /// Implementations can specialize validation by credential type.
    ///
    /// Returns `Ok(())` if the credential can be resolved or is not handled by this resolver.
    /// Returns an error if the credential is invalid or cannot be resolved.
    ///
    /// # Errors
    ///
    /// Returns an error if the credential is invalid or cannot be resolved.
    fn validate(&self, key: &str, ref_type: CredentialRefType) -> Result<()> {
        // Default implementation: attempt resolution
        match self.resolve(key, ref_type)? {
            Some(_) | None => Ok(()), // Not handled by this resolver or found
        }
    }
}

/// A view over a single resolved server, with credentials materialized on-demand.
///
/// This type allows accessing a server's resolved credentials without materializing
/// the entire config, reducing the risk of accidentally leaking secrets.
#[derive(Debug, Clone)]
pub struct ResolvedServer {
    // Server data will be populated during resolution
    // For now, this is a placeholder
}

/// Get a resolved view of a single server by name.
///
/// Credentials are resolved only for the requested server, not for the entire config.
/// This reduces the risk of secrets being accidentally serialized or leaked.
///
/// # Errors
///
/// Returns an error if:
/// - The server is not found
/// - A credential reference cannot be resolved
/// - Resolution fails unexpectedly
pub fn get_resolved_server(
    config: &TacacsPlus,
    server_name: &str,
    _resolvers: &[Box<dyn CredentialResolver>],
) -> Result<ResolvedServer> {
    let _server = config
        .server
        .iter()
        .find(|s| s.name == server_name)
        .ok_or_else(|| anyhow::anyhow!("server '{server_name}' not found"))?;

    // For now, this is a placeholder that documents the design.
    // Implementation will follow.
    Ok(ResolvedServer {})
}

/// Validate all credential references in a config are resolvable.
///
/// This checks that all credential references in the config (client-credentials,
/// server-credentials, keystore, truststore references) can be resolved by the
/// provided resolvers. Call this during config validation to catch missing
/// credentials early, before attempting to use any server.
///
/// # Errors
///
/// Returns an error if any credential reference cannot be validated.
pub fn validate_credential_references(
    _config: &TacacsPlus,
    _resolvers: &[Box<dyn CredentialResolver>],
) -> Result<()> {
    // For now, this is a placeholder that documents the design.
    // Implementation will follow once we flesh out the resolver chain logic.

    // Future implementation will:
    // 1. Iterate through all servers
    // 2. For each server, check all credential references
    // 3. Call resolver.validate() for each reference with the appropriate CredentialRefType
    // 4. Collect validation errors

    Ok(())
}

