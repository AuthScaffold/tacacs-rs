//! Pure functions that translate SONiC ConfigDB rows into the
//! `ietf-system-tacacs-plus` YANG model used by the rest of the workspace.
//!
//! All Redis I/O lives in [`crate::store`]; this module is intentionally
//! decoupled from any particular client so that it can be exhaustively tested
//! offline.
//!
//! # SONiC table shape
//!
//! SONiC stores each ConfigDB row as a Redis hash keyed by `<TABLE>|<key>`:
//!
//! ```text
//! TACPLUS|global                                    auth_type "pap"
//!                                                   timeout   "5"
//!                                                   passkey   "optional-shared-secret"
//!                                                   src_intf  "Management0"
//!
//! TACPLUS_SERVER|192.0.2.10                         priority  "64"
//!                                                   tcp_port  "49"
//!                                                   timeout   "10"
//!                                                   use_tls   "true"
//!                                                   passkey   "optional-per-server-secret"
//! ```
//!
//! See [`crate`] documentation for the schema extensions that the bridge
//! recognises on top of the upstream SONiC schema.

use std::collections::BTreeMap;

use anyhow::{bail, Context};
use tacacsrs_config::{
    TacacsPlus, TacacsPlusBuilder, TacacsPlusServerBuilder, TacacsPlusServerType,
    ValidationOptions, ValidationRelaxation,
};

/// Default TCP port used by TACACS+ when `tcp_port` is missing.
pub const DEFAULT_TACACS_TCP_PORT: u16 = 49;

/// Default per-server timeout (seconds) when neither the global nor per-server
/// `timeout` field is set.
pub const DEFAULT_TIMEOUT_SECONDS: u16 = 5;

/// Hash table keyed by ConfigDB column name.
///
/// SONiC's `TACPLUS_SERVER|<addr>` and `TACPLUS|global` entries are exposed as
/// Redis hashes. The bridge reads them as `BTreeMap<String, String>` so that
/// ordering is deterministic in tests and logs.
pub type SonicHash = BTreeMap<String, String>;

/// Snapshot of SONiC's TACACS+ tables as observed from ConfigDB.
///
/// Construct one with [`SonicTacacsTables::new`] from the global and
/// per-server hashes obtained from Redis, then call
/// [`map_sonic_tables_to_tacacs_plus`] to translate the snapshot into the
/// validated YANG configuration.
#[derive(Debug, Clone, Default)]
pub struct SonicTacacsTables {
    /// Contents of the `TACPLUS|global` hash.
    pub global: SonicHash,
    /// One entry per `TACPLUS_SERVER|<addr>` row, keyed by `<addr>` as
    /// stored by SONiC (typically a literal IPv4/IPv6 address or hostname).
    pub servers: BTreeMap<String, SonicHash>,
}

impl SonicTacacsTables {
    /// Construct a new snapshot from the global and per-server hashes.
    #[must_use]
    pub fn new(global: SonicHash, servers: BTreeMap<String, SonicHash>) -> Self {
        Self { global, servers }
    }

    /// Returns `true` if no rows were observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.global.is_empty() && self.servers.is_empty()
    }
}

/// Translate a SONiC ConfigDB snapshot into the YANG `TacacsPlus` root.
///
/// Each `TACPLUS_SERVER|<addr>` row becomes one
/// [`tacacsrs_config::TacacsPlusServer`]. Servers are ordered by descending
/// `priority` in SONiC's `1..64` range (with stable address-based
/// tiebreaking) so that the daemon's failover semantics — index 0 is preferred
/// — line up with SONiC's administrator intent.
///
/// Per-row fields fall back to the matching `TACPLUS|global` field when the
/// per-server value is absent (this matches SONiC's `pam_tacplus` behavior).
/// The forward-compatible `use_tls` extension key selects the same empty
/// `server-authentication` TLS container that `tacon --use-tls` constructs
/// when no explicit client/server certificate material is configured.
///
/// # Errors
///
/// Returns an error if a row has an invalid numeric value (priority, port, or
/// timeout), if priority is outside SONiC's `1..64` range, or if the resulting
/// non-empty configuration fails validation.
pub fn map_sonic_tables_to_tacacs_plus(tables: &SonicTacacsTables) -> anyhow::Result<TacacsPlus> {
    if tables.servers.is_empty() {
        return Ok(TacacsPlus::empty());
    }

    let global = SonicGlobal::from_hash(&tables.global)?;

    let mut rows = tables
        .servers
        .iter()
        .map(|(address, fields)| SonicServerRow::from_hash(address, fields))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // SONiC convention: priority is 1..64, and higher numbers are preferred.
    // Ties are broken by lexicographic address for deterministic tests/logs.
    rows.sort_by(|a, b| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| a.address.cmp(&b.address))
    });

    let mut builder = TacacsPlusBuilder::new();
    for row in &rows {
        let server = row.to_server(&global);
        builder = builder.with_server(server);
    }

    let validation_options = ValidationOptions::new()
        .with_relaxation(ValidationRelaxation::AllowPlainTcpWithoutSharedSecret);

    builder
        .build_with_options(&validation_options)
        .context("SONiC ConfigDB rows produced an invalid TACACS+ configuration")
}

/// Strongly-typed view of `TACPLUS|global` defaults.
#[derive(Debug, Default, Clone)]
struct SonicGlobal {
    timeout: Option<u16>,
    passkey: Option<String>,
    src_intf: Option<String>,
    use_tls: Option<bool>,
}

impl SonicGlobal {
    fn from_hash(hash: &SonicHash) -> anyhow::Result<Self> {
        let mut g = Self::default();
        for (key, value) in hash {
            match key.as_str() {
                "timeout" => {
                    g.timeout = Some(parse_timeout(value).context("TACPLUS|global.timeout")?);
                }
                "passkey" => {
                    if !value.is_empty() {
                        g.passkey = Some(value.clone());
                    }
                }
                "src_intf" => {
                    if !value.is_empty() {
                        g.src_intf = Some(value.clone());
                    }
                }
                "use_tls" => {
                    g.use_tls = Some(parse_bool(value).context("TACPLUS|global.use_tls")?);
                }
                // `auth_type` controls PAM-side defaults (PAP vs CHAP). The
                // agent does not expose authentication types yet, so the
                // value is recorded only for log surface.
                "auth_type" => {
                    log::debug!("Ignoring TACPLUS|global.auth_type='{value}': agent has no PAM-style authentication selector yet");
                }
                other => {
                    log::warn!("Ignoring unknown TACPLUS|global field '{other}'='{value}'");
                }
            }
        }
        Ok(g)
    }
}

/// Strongly-typed view of one `TACPLUS_SERVER|<addr>` row.
#[derive(Debug, Clone)]
struct SonicServerRow {
    address: String,
    priority: u8,
    tcp_port: u16,
    timeout: Option<u16>,
    passkey: Option<String>,
    domain_name: Option<String>,
    sni_enabled: Option<bool>,
    use_tls: Option<bool>,
    single_connection: bool,
    vrf_name: Option<String>,
    src_ip: Option<String>,
    src_intf: Option<String>,
    server_type: TacacsPlusServerType,
}

impl SonicServerRow {
    fn from_hash(address: &str, hash: &SonicHash) -> anyhow::Result<Self> {
        let mut row = Self {
            address: address.to_string(),
            priority: 1,
            tcp_port: DEFAULT_TACACS_TCP_PORT,
            timeout: None,
            passkey: None,
            domain_name: None,
            sni_enabled: None,
            use_tls: None,
            single_connection: false,
            vrf_name: None,
            src_ip: None,
            src_intf: None,
            server_type: TacacsPlusServerType::all(),
        };

        for (key, value) in hash {
            match key.as_str() {
                "priority" => {
                    row.priority = parse_priority(value)
                        .with_context(|| format!("TACPLUS_SERVER|{address}.priority='{value}'"))?;
                }
                "tcp_port" => {
                    row.tcp_port = value.parse::<u16>().with_context(|| {
                        format!(
                            "TACPLUS_SERVER|{address}.tcp_port='{value}' is not a valid TCP port"
                        )
                    })?;
                }
                "timeout" => {
                    row.timeout = Some(
                        parse_timeout(value)
                            .with_context(|| format!("TACPLUS_SERVER|{address}.timeout"))?,
                    );
                }
                "passkey" => {
                    if !value.is_empty() {
                        row.passkey = Some(value.clone());
                    }
                }
                "domain_name" => {
                    if !value.is_empty() {
                        row.domain_name = Some(value.clone());
                    }
                }
                "sni_enabled" => {
                    row.sni_enabled = Some(parse_bool(value).with_context(|| {
                        format!("TACPLUS_SERVER|{address}.sni_enabled='{value}' is not a boolean")
                    })?);
                }
                "use_tls" => {
                    row.use_tls = Some(parse_bool(value).with_context(|| {
                        format!("TACPLUS_SERVER|{address}.use_tls='{value}' is not a boolean")
                    })?);
                }
                "single_connection" => {
                    row.single_connection = parse_bool(value).with_context(|| {
                        format!(
                            "TACPLUS_SERVER|{address}.single_connection='{value}' is not a boolean"
                        )
                    })?;
                }
                "vrf_name" => {
                    if !value.is_empty() {
                        row.vrf_name = Some(value.clone());
                    }
                }
                "src_ip" => {
                    if !value.is_empty() {
                        row.src_ip = Some(value.clone());
                    }
                }
                "src_intf" => {
                    if !value.is_empty() {
                        row.src_intf = Some(value.clone());
                    }
                }
                "server_type" => {
                    row.server_type = parse_server_type(value).with_context(|| {
                        format!("TACPLUS_SERVER|{address}.server_type='{value}'")
                    })?;
                }
                // SONiC's `pam_tacplus` historically has accepted a small
                // set of additional, deployment-specific keys. Log and skip
                // rather than fail so the agent does not refuse to start
                // because of operator-level annotations.
                other => {
                    log::warn!(
                        "Ignoring unknown TACPLUS_SERVER|{address} field '{other}'='{value}'"
                    );
                }
            }
        }

        Ok(row)
    }

    fn to_server(&self, global: &SonicGlobal) -> tacacsrs_config::TacacsPlusServer {
        let timeout = self
            .timeout
            .or(global.timeout)
            .unwrap_or(DEFAULT_TIMEOUT_SECONDS);

        let use_tls = self.use_tls.or(global.use_tls).unwrap_or(false);

        let mut builder = TacacsPlusServerBuilder::new(
            sonic_server_name(&self.address),
            self.server_type,
            self.address.clone(),
            self.tcp_port,
        )
        .with_timeout(timeout);

        if use_tls {
            builder = builder.with_tls_server_authentication();
        }

        if let Some(passkey) = self.passkey.clone().or_else(|| global.passkey.clone()) {
            if use_tls {
                log::debug!(
                    "Ignoring SONiC passkey for server '{}': use_tls selects TLS server-authentication instead of shared-secret obfuscation",
                    self.address
                );
            } else {
                builder = builder.with_shared_secret(passkey);
            }
        }

        let mut server = builder.build();

        server.domain_name.clone_from(&self.domain_name);
        server.sni_enabled = self.sni_enabled;
        server.single_connection = self.single_connection;
        server.vrf_instance.clone_from(&self.vrf_name);

        // The YANG model treats `source-ip` and `source-interface` as
        // mutually exclusive. Honour any per-server value verbatim, then
        // fall back to the global `src_intf` only when nothing was set on
        // the row.
        if self.src_ip.is_some() {
            server.source_ip.clone_from(&self.src_ip);
            server.source_interface = None;
        } else if let Some(intf) = self.src_intf.as_ref().or(global.src_intf.as_ref()) {
            server.source_interface = Some(intf.clone());
        }

        server
    }
}

/// Build the YANG server `name` for a SONiC row.
///
/// SONiC stores upstream servers indexed by address (its primary key) with no
/// dedicated human-friendly name. The YANG model requires a unique `name`, so
/// the bridge synthesizes one from the stable ConfigDB key. It intentionally
/// does not include priority or sorted position so deltas remain stable when a
/// higher-priority server is inserted.
#[must_use]
pub fn sonic_server_name(address: &str) -> String {
    format!("sonic-server-{address}")
}

/// Parse SONiC boolean strings.
///
/// SONiC stores booleans as `"true"` / `"false"` (the YANG-canonical form
/// accepted by `sonic-cfggen`) but legacy templates have used `"yes"`/`"no"`,
/// `"1"`/`"0"`, `"on"`/`"off"`, and `"enabled"`/`"disabled"`. All of those
/// variants are accepted (case-insensitive) so the bridge does not refuse a
/// boolean value that any prior SONiC tooling was willing to write.
fn parse_bool(value: &str) -> anyhow::Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" | "enabled" => Ok(true),
        "false" | "no" | "0" | "off" | "disabled" => Ok(false),
        other => bail!("expected boolean, got '{other}'"),
    }
}

fn parse_timeout(value: &str) -> anyhow::Result<u16> {
    value
        .parse::<u16>()
        .with_context(|| format!("expected timeout in seconds, got '{value}'"))
}

fn parse_priority(value: &str) -> anyhow::Result<u8> {
    let priority = value
        .parse::<u8>()
        .with_context(|| format!("expected priority in range 1..64, got '{value}'"))?;
    if !(1..=64).contains(&priority) {
        bail!("expected priority in range 1..64, got '{value}'");
    }
    Ok(priority)
}

fn parse_server_type(value: &str) -> anyhow::Result<TacacsPlusServerType> {
    let mut bits = TacacsPlusServerType::empty();
    for token in value.split(|c: char| c.is_whitespace() || c == ',' || c == '|') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        match token.to_ascii_lowercase().as_str() {
            "all" => return Ok(TacacsPlusServerType::all()),
            "authentication" | "auth" => bits |= TacacsPlusServerType::AUTHENTICATION,
            "authorization" | "author" => bits |= TacacsPlusServerType::AUTHORIZATION,
            "accounting" | "acct" => bits |= TacacsPlusServerType::ACCOUNTING,
            other => bail!("unknown server-type token '{other}'"),
        }
    }
    if bits.is_empty() {
        bail!("expected at least one of: authentication, authorization, accounting, all");
    }
    Ok(bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacacsrs_datastore::ConfigDelta;

    fn h(pairs: &[(&str, &str)]) -> SonicHash {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    fn tables() -> SonicTacacsTables {
        let mut servers = BTreeMap::new();
        servers.insert("192.0.2.10".to_string(), h(&[("priority", "1"), ("tcp_port", "49")]));
        servers.insert(
            "192.0.2.20".to_string(),
            h(&[("priority", "5"), ("passkey", "per-server-secret")]),
        );
        SonicTacacsTables::new(h(&[("timeout", "7"), ("passkey", "default-secret")]), servers)
    }

    #[test]
    fn maps_global_defaults_into_each_server() {
        let cfg = map_sonic_tables_to_tacacs_plus(&tables()).expect("mapping succeeds");
        assert_eq!(cfg.server.len(), 2);
        // Higher priority -> higher preference (index 0).
        assert_eq!(cfg.server[0].address, "192.0.2.20");
        assert_eq!(cfg.server[0].port, 49);
        assert_eq!(cfg.server[0].timeout, 7);
        assert_eq!(cfg.server[0].shared_secret.as_deref(), Some("per-server-secret"));

        // Per-server passkey absent -> falls back to global.
        assert_eq!(cfg.server[1].address, "192.0.2.10");
        assert_eq!(cfg.server[1].shared_secret.as_deref(), Some("default-secret"));
        // Per-server tcp_port absent -> default 49.
        assert_eq!(cfg.server[1].port, DEFAULT_TACACS_TCP_PORT);
        // Per-server timeout absent -> falls back to global.
        assert_eq!(cfg.server[1].timeout, 7);
    }

    #[test]
    fn missing_passkey_and_no_global_default_maps_unobfuscated_plain_tcp() {
        let mut servers = BTreeMap::new();
        servers.insert("192.0.2.50".to_string(), h(&[("priority", "1")]));
        let tables = SonicTacacsTables::new(SonicHash::new(), servers);
        let cfg = map_sonic_tables_to_tacacs_plus(&tables).expect("mapping succeeds");
        assert_eq!(cfg.server.len(), 1);
        assert_eq!(cfg.server[0].address, "192.0.2.50");
        assert_eq!(cfg.server[0].shared_secret, None);
    }

    #[test]
    fn empty_servers_table_maps_to_empty_config() {
        let tables = SonicTacacsTables::default();
        let cfg = map_sonic_tables_to_tacacs_plus(&tables).expect("empty ConfigDB should map");
        assert!(cfg.server.is_empty());
    }

    #[test]
    fn invalid_priority_is_an_error() {
        let mut servers = BTreeMap::new();
        servers.insert("192.0.2.99".to_string(), h(&[("priority", "70"), ("passkey", "x")]));
        let tables = SonicTacacsTables::new(SonicHash::new(), servers);
        let err = map_sonic_tables_to_tacacs_plus(&tables).unwrap_err();
        assert!(format!("{err:#}").contains("1..64"));
    }

    #[test]
    fn unknown_fields_are_warnings_not_errors() {
        let mut servers = BTreeMap::new();
        servers.insert(
            "192.0.2.10".to_string(),
            h(&[
                ("priority", "1"),
                ("passkey", "x"),
                ("operator_tag", "north-dc"),
            ]),
        );
        let tables = SonicTacacsTables::new(
            h(&[("auth_type", "pap"), ("ad_hoc_field", "ignored")]),
            servers,
        );
        let cfg = map_sonic_tables_to_tacacs_plus(&tables).expect("unknown fields are warnings");
        assert_eq!(cfg.server.len(), 1);
    }

    #[test]
    fn extension_keys_populate_yang_fields() {
        let mut servers = BTreeMap::new();
        servers.insert(
            "tacacs.example.com".to_string(),
            h(&[
                ("priority", "1"),
                ("tcp_port", "49"),
                ("passkey", "topsecret"),
                ("domain_name", "tacacs.example.com"),
                ("sni_enabled", "true"),
                ("use_tls", "true"),
                ("single_connection", "yes"),
                ("vrf_name", "mgmt"),
                ("src_intf", "Loopback0"),
                ("server_type", "authentication accounting"),
            ]),
        );
        let cfg =
            map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(SonicHash::new(), servers))
                .expect("mapping succeeds");
        let s = &cfg.server[0];
        assert_eq!(s.domain_name.as_deref(), Some("tacacs.example.com"));
        assert_eq!(s.sni_enabled, Some(true));
        assert!(s.server_authentication.is_some());
        assert_eq!(s.shared_secret, None);
        assert!(s.single_connection);
        assert_eq!(s.vrf_instance.as_deref(), Some("mgmt"));
        assert_eq!(s.source_ip, None);
        assert_eq!(s.source_interface.as_deref(), Some("Loopback0"));
        assert!(s.server_type.contains(TacacsPlusServerType::AUTHENTICATION));
        assert!(s.server_type.contains(TacacsPlusServerType::ACCOUNTING));
        assert!(!s.server_type.contains(TacacsPlusServerType::AUTHORIZATION));
    }

    #[test]
    fn global_use_tls_falls_back_when_row_does_not_override_it() {
        let mut servers = BTreeMap::new();
        servers.insert(
            "192.0.2.10".to_string(),
            h(&[("priority", "1"), ("passkey", "ignored-when-tls")]),
        );

        let cfg = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(
            h(&[("use_tls", "true")]),
            servers,
        ))
        .expect("mapping succeeds");

        let server = &cfg.server[0];
        assert!(server.server_authentication.is_some());
        assert_eq!(server.shared_secret, None);
    }

    #[test]
    fn per_server_src_ip_takes_precedence_over_global_src_intf() {
        let mut servers = BTreeMap::new();
        servers.insert(
            "192.0.2.10".to_string(),
            h(&[("priority", "1"), ("passkey", "x"), ("src_ip", "10.0.0.1")]),
        );
        let cfg = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(
            h(&[("src_intf", "Management0")]),
            servers,
        ))
        .expect("mapping succeeds");
        assert_eq!(cfg.server[0].source_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(cfg.server[0].source_interface, None);
    }

    #[test]
    fn priority_orders_failover_with_stable_address_tiebreak() {
        let mut servers = BTreeMap::new();
        for (addr, prio) in [
            ("192.0.2.30", "1"),
            ("192.0.2.10", "1"),
            ("192.0.2.20", "2"),
        ] {
            servers.insert(addr.to_string(), h(&[("priority", prio), ("passkey", "x")]));
        }
        let cfg =
            map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(SonicHash::new(), servers))
                .expect("mapping succeeds");
        let order = cfg
            .server
            .iter()
            .map(|s| s.address.clone())
            .collect::<Vec<_>>();
        assert_eq!(order, vec!["192.0.2.20", "192.0.2.10", "192.0.2.30"]);
    }

    #[test]
    fn inserting_higher_priority_server_keeps_existing_server_names_stable() {
        let mut previous_servers = BTreeMap::new();
        previous_servers
            .insert("192.0.2.20".to_string(), h(&[("priority", "5"), ("passkey", "x")]));
        let previous = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(
            SonicHash::new(),
            previous_servers,
        ))
        .expect("previous mapping succeeds");

        let mut new_servers = BTreeMap::new();
        new_servers.insert("192.0.2.10".to_string(), h(&[("priority", "10"), ("passkey", "x")]));
        new_servers.insert("192.0.2.20".to_string(), h(&[("priority", "5"), ("passkey", "x")]));
        let new =
            map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(SonicHash::new(), new_servers))
                .expect("new mapping succeeds");

        let delta = ConfigDelta::diff(Some(&previous), &new);
        assert_eq!(delta.added_servers, vec!["sonic-server-192.0.2.10"]);
        assert!(delta.removed_servers.is_empty());
        assert!(delta.modified_servers.is_empty());
        assert_eq!(new.server[1].name, "sonic-server-192.0.2.20");
    }
}
