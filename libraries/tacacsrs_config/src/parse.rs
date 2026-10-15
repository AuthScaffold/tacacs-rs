//! Canonical parsing entry points for RFC 7951 / YANG JSON configuration.
//!
//! This module is the single parsing API for the crate. The crate root
//! re-exports every function here, so callers use short paths such as
//! [`crate::parse_yang_json`].
//!
//! Parsing is the first stage of the configuration flow:
//!
//! ```text
//! parse  ->  enumerate  ->  resolve  ->  materialize  ->  prepare
//! ```
//!
//! Two layers are available:
//!
//! - [`parse_root_json`] and [`parse_root_json_file`] decode the raw
//!   [`YangConfigRoot`] without validation. Use them for round trips, reports,
//!   and custom processing that must preserve the submitted structure.
//! - [`parse_yang_json`] and its variants decode and validate the canonical
//!   [`TacacsPlus`] model. This is the standard entry point for loading
//!   configuration.
//!
//! Parsing never changes the submitted data. Credential references stay intact
//! for enumeration and later resolution.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::bail;

use crate::generated::YangConfigRoot;
use crate::validation;
use crate::{TacacsPlus, ValidationOptions};

/// Parse RFC 7951 JSON into the root generated model without applying
/// credential resolution or validation.
///
/// # Errors
///
/// Returns an error if the JSON is malformed or does not match the model.
pub fn parse_root_json(json: &str) -> anyhow::Result<YangConfigRoot> {
    let mut deserializer = serde_json::Deserializer::from_str(json);
    let mut ignored_paths = BTreeSet::new();

    let root = serde_ignored::deserialize(&mut deserializer, |path| {
        ignored_paths.insert(path.to_string());
    })
    .map_err(|e| anyhow::anyhow!("failed to parse configuration: {e}"))?;

    deserializer
        .end()
        .map_err(|error| anyhow::anyhow!("unexpected data after configuration: {error}"))?;

    if !ignored_paths.is_empty() {
        let paths = ignored_paths.into_iter().collect::<Vec<_>>().join(", ");
        bail!("failed to parse configuration: unknown field(s): {paths}");
    }

    Ok(root)
}

/// Read and parse RFC 7951 JSON from a file into the root generated model
/// without applying credential resolution or validation.
///
/// # Errors
///
/// Returns an error if the file cannot be read, or if the JSON is malformed
/// or does not match the model.
pub fn parse_root_json_file(path: &Path) -> anyhow::Result<YangConfigRoot> {
    let contents = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!("failed to read configuration file {}: {e}", path.display())
    })?;

    parse_root_json(&contents)
}

/// Parse a YANG JSON configuration string and validate it.
///
/// This is the standard API for loading YANG configuration. It parses and
/// validates the configuration without changing it. The result preserves the
/// submitted structure and all credential references. Callers can safely use
/// the result for round trips, reports, and credential resolution.
///
/// Validation makes sure that:
/// - At least one server is configured
/// - Server addresses and ports are unique
/// - SNI-enabled servers have domain names
/// - Security configuration is present and valid
/// - Credential bundle references have matching definitions
///
/// To inline shared `client-credentials` / `server-credentials` bundles for
/// per-server processing, call [`crate::enumerate_servers`] or
/// [`crate::enumerate_server`].
///
/// # Errors
///
/// Returns an error if the JSON is malformed, does not match the YANG schema,
/// or does not satisfy a validation constraint.
pub fn parse_yang_json(json: &str) -> anyhow::Result<TacacsPlus> {
    parse_yang_json_with_options(json, &ValidationOptions::default())
}

/// Parse a YANG JSON configuration string with the supplied validation options.
///
/// This function applies the supplied [`ValidationOptions`] during validation.
/// It otherwise behaves like [`parse_yang_json`].
///
/// # Errors
///
/// Returns an error if the JSON is malformed, does not match the YANG schema,
/// or does not satisfy a constraint enabled by `options`.
pub fn parse_yang_json_with_options(
    json: &str,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    let root: YangConfigRoot = parse_root_json(json)?;

    let config = root.tacacs_plus;
    validation::validate_config_with_options(&config, options)?;

    Ok(config)
}

/// Parse and validate a YANG JSON configuration file without changing its data.
///
/// This function behaves like [`parse_yang_json`]. The result preserves the
/// submitted structure and all credential references.
///
/// Validation makes sure that:
/// - At least one server is configured
/// - Server addresses and ports are unique
/// - SNI-enabled servers have domain names
/// - Security configuration is present and valid
/// - Credential bundle references have matching definitions
///
/// # Errors
///
/// Returns an error if the file cannot be read, the JSON is malformed, the
/// JSON does not match the YANG schema, or validation fails.
pub fn parse_yang_json_file(path: &Path) -> anyhow::Result<TacacsPlus> {
    parse_yang_json_file_with_options(path, &ValidationOptions::default())
}

/// Parse a YANG JSON configuration file with the supplied validation options.
///
/// This function applies the supplied [`ValidationOptions`] during validation.
/// It otherwise behaves like [`parse_yang_json_file`].
///
/// # Errors
///
/// Returns an error if the file cannot be read or the JSON is malformed. It
/// also returns an error if the JSON or `options` do not pass validation.
pub fn parse_yang_json_file_with_options(
    path: &Path,
    options: &ValidationOptions,
) -> anyhow::Result<TacacsPlus> {
    let root: YangConfigRoot = parse_root_json_file(path)?;

    let config = root.tacacs_plus;
    validation::validate_config_with_options(&config, options)?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"{
        "ietf-system-tacacs-plus:tacacs-plus": {
            "server": [
                {
                    "name": "primary",
                    "server-type": "accounting",
                    "address": "10.0.0.15",
                    "port": 49,
                    "shared-secret": "abc"
                }
            ]
        }
    }"#;

    #[test]
    fn parse_root_json_reads_root_without_validation() {
        let root = parse_root_json(VALID).expect("valid document must parse at the root");
        assert_eq!(root.tacacs_plus.server.len(), 1);
        assert_eq!(root.tacacs_plus.server[0].name, "primary");
    }

    #[test]
    fn parse_root_json_rejects_unknown_fields() {
        let json = r#"{
            "ietf-system-tacacs-plus:tacacs-plus": {
                "server": [
                    {
                        "name": "primary",
                        "server-type": "accounting",
                        "address": "10.0.0.15",
                        "port": 49,
                        "shared-secret": "abc"
                    }
                ]
            },
            "unexpected-field": true
        }"#;
        let err = parse_root_json(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "unexpected error: {err}");
    }

    #[test]
    fn parse_yang_json_validates_and_returns_canonical_model() {
        let config = parse_yang_json(VALID).expect("valid document must parse and validate");
        assert_eq!(config.server.len(), 1);
        assert_eq!(config.server[0].address, "10.0.0.15");
    }

    #[test]
    fn parse_yang_json_rejects_malformed_json() {
        assert!(parse_yang_json("not valid json").is_err());
    }
}
