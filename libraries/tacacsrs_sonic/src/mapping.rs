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
//!                                                   passkey   "optional-per-server-secret"
//!
//! TACPLUS_SERVER_TLS|tacacs.example.test            priority  "48"
//!                                                   tcp_port  "449"
//!                                                   psk_identity "client"
//!                                                   psk_secret_ref "epsk-object"
//! ```
//!
//! See [`crate`] documentation for the schema extensions that the bridge
//! recognises on top of the upstream SONiC schema.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use anyhow::{bail, Context};
use tacacsrs_config::{
    EpskSupportedHash, PskDheKeSupportedGroup, TacacsPlus, TacacsPlusBuilder,
    TacacsPlusServerBuilder, TacacsPlusServerType, Tls13Epsk, TlsClientClientIdentity,
    ValidationOptions, ValidationRelaxation,
};

/// Default TCP port used by TACACS+ when `tcp_port` is missing.
pub const DEFAULT_TACACS_TCP_PORT: u16 = 49;

/// Default per-server timeout (seconds) when neither the global nor per-server
/// `timeout` field is set.
pub const DEFAULT_TIMEOUT_SECONDS: u16 = 5;

/// Default TCP port for TACACS+ over TLS.
pub const DEFAULT_TACACS_TLS_PORT: u16 = 449;

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
    /// One entry per `TACPLUS_SERVER_TLS|<addr>` row.
    pub tls_servers: BTreeMap<String, SonicHash>,
    /// Contents of `TACPLUS_FORWARDER|global`.
    pub forwarder: SonicHash,
}

impl SonicTacacsTables {
    /// Construct a new snapshot from the global and per-server hashes.
    #[must_use]
    pub fn new(global: SonicHash, servers: BTreeMap<String, SonicHash>) -> Self {
        Self {
            global,
            servers,
            tls_servers: BTreeMap::new(),
            forwarder: SonicHash::new(),
        }
    }

    /// Construct a complete snapshot including version-1 central-agent tables.
    #[must_use]
    pub fn with_extended_tables(
        global: SonicHash,
        servers: BTreeMap<String, SonicHash>,
        tls_servers: BTreeMap<String, SonicHash>,
        forwarder: SonicHash,
    ) -> Self {
        Self {
            global,
            servers,
            tls_servers,
            forwarder,
        }
    }

    /// Returns `true` if no rows were observed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.global.is_empty()
            && self.servers.is_empty()
            && self.tls_servers.is_empty()
            && self.forwarder.is_empty()
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
enum NormalizedHost {
    Loopback,
    Ip(IpAddr),
    Name(String),
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct EndpointIdentity {
    host: NormalizedHost,
    port: u16,
}

/// Validated bind-time local forwarder settings.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SonicForwarderSettings {
    listen_address: IpAddr,
    listen_port: u16,
}

impl SonicForwarderSettings {
    /// Parses `TACPLUS_FORWARDER|global`.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown fields, a missing/non-loopback address,
    /// or an invalid port.
    pub fn from_hash(hash: &SonicHash) -> anyhow::Result<Option<Self>> {
        if hash.is_empty() {
            return Ok(None);
        }

        reject_unknown_fields(
            "TACPLUS_FORWARDER|global",
            hash,
            &["local_listen_address", "local_listen_port"],
        )?;
        let listen_address =
            required_non_empty_field("TACPLUS_FORWARDER|global", hash, "local_listen_address")?;
        let listen_address = listen_address
            .parse::<IpAddr>()
            .context("TACPLUS_FORWARDER|global.local_listen_address must be an IP address")?;
        if !listen_address.is_loopback() {
            bail!("TACPLUS_FORWARDER|global.local_listen_address must be loopback");
        }
        let listen_port = parse_optional_port(
            "TACPLUS_FORWARDER|global",
            hash.get("local_listen_port"),
            DEFAULT_TACACS_TCP_PORT,
        )?;
        Ok(Some(Self {
            listen_address,
            listen_port,
        }))
    }

    /// Returns the configured loopback address.
    #[must_use]
    pub const fn listen_address(self) -> IpAddr {
        self.listen_address
    }

    /// Returns the configured listener TCP port.
    #[must_use]
    pub const fn listen_port(self) -> u16 {
        self.listen_port
    }

    /// Returns the complete local proxy endpoint.
    #[must_use]
    pub const fn socket_address(self) -> std::net::SocketAddr {
        std::net::SocketAddr::new(self.listen_address, self.listen_port)
    }

    fn endpoint(self) -> EndpointIdentity {
        EndpointIdentity {
            host: NormalizedHost::Loopback,
            port: self.listen_port,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum SonicPskKeyExchange {
    PskDhe,
    PskOnly,
}

#[derive(Debug, Clone)]
struct SonicTlsServerRow {
    address: String,
    normalized_host: NormalizedHost,
    priority: u8,
    tcp_port: u16,
    timeout: u16,
    domain_name: Option<String>,
    sni_enabled: bool,
    single_connection: bool,
    psk_identity: String,
    psk_secret_ref: String,
    psk_hash: EpskSupportedHash,
    psk_dhe_groups: Vec<PskDheKeSupportedGroup>,
}

impl SonicTlsServerRow {
    fn from_hash(address: &str, hash: &SonicHash) -> anyhow::Result<Self> {
        const FIELDS: &[&str] = &[
            "priority",
            "tcp_port",
            "timeout",
            "domain_name",
            "sni_enabled",
            "single_connection",
            "psk_identity",
            "psk_secret_ref",
            "psk_hash",
            "psk_key_exchange",
            "psk_key_exchange_groups",
        ];
        let row_name = format!("TACPLUS_SERVER_TLS|{address}");
        reject_unknown_fields(&row_name, hash, FIELDS)?;

        let priority = hash
            .get("priority")
            .map_or(Ok(1), |value| parse_priority(value).context("priority"))
            .with_context(|| format!("{row_name}.priority"))?;
        let tcp_port =
            parse_optional_port(&row_name, hash.get("tcp_port"), DEFAULT_TACACS_TLS_PORT)?;
        let timeout = hash
            .get("timeout")
            .map_or(Ok(DEFAULT_TIMEOUT_SECONDS), |value| parse_timeout(value))
            .with_context(|| format!("{row_name}.timeout"))?;
        let domain_name =
            optional_non_empty_field(&row_name, hash, "domain_name")?.map(str::to_owned);
        let sni_enabled =
            parse_optional_bool(&row_name, "sni_enabled", hash.get("sni_enabled"), false)?;
        if sni_enabled && domain_name.is_none() {
            bail!("{row_name}.sni_enabled requires domain_name");
        }
        let single_connection = parse_optional_bool(
            &row_name,
            "single_connection",
            hash.get("single_connection"),
            false,
        )?;
        let psk_identity = required_non_empty_field(&row_name, hash, "psk_identity")?.to_owned();
        let psk_secret_ref =
            required_non_empty_field(&row_name, hash, "psk_secret_ref")?.to_owned();
        validate_opaque_id(&psk_secret_ref)
            .with_context(|| format!("{row_name}.psk_secret_ref is invalid"))?;
        let psk_hash = match hash.get("psk_hash").map_or("sha-256", String::as_str) {
            "sha-256" => EpskSupportedHash::Sha256,
            "sha-384" => EpskSupportedHash::Sha384,
            _ => bail!("{row_name}.psk_hash is unsupported"),
        };
        let psk_key_exchange = match hash
            .get("psk_key_exchange")
            .map_or("psk-dhe", String::as_str)
        {
            "psk-dhe" => SonicPskKeyExchange::PskDhe,
            "psk-only" => SonicPskKeyExchange::PskOnly,
            _ => bail!("{row_name}.psk_key_exchange is unsupported"),
        };
        let configured_groups = hash
            .get("psk_key_exchange_groups")
            .map_or_else(|| Ok(Vec::new()), |value| parse_psk_groups(&row_name, value))?;
        if psk_key_exchange == SonicPskKeyExchange::PskOnly && !configured_groups.is_empty() {
            bail!("{row_name}.psk-only cannot configure DHE groups");
        }
        let psk_dhe_groups = match psk_key_exchange {
            SonicPskKeyExchange::PskOnly => Vec::new(),
            SonicPskKeyExchange::PskDhe if configured_groups.is_empty() => {
                tacacsrs_config::builders::DEFAULT_PSK_DHE_KE_GROUPS.to_vec()
            }
            SonicPskKeyExchange::PskDhe => configured_groups,
        };

        Ok(Self {
            address: address.to_owned(),
            normalized_host: normalize_host(address),
            priority,
            tcp_port,
            timeout,
            domain_name,
            sni_enabled,
            single_connection,
            psk_identity,
            psk_secret_ref,
            psk_hash,
            psk_dhe_groups,
        })
    }

    fn endpoint(&self) -> EndpointIdentity {
        EndpointIdentity {
            host: self.normalized_host.clone(),
            port: self.tcp_port,
        }
    }

    fn to_server(&self) -> tacacsrs_config::TacacsPlusServer {
        let mut server = TacacsPlusServerBuilder::new(
            sonic_server_name(&self.address),
            TacacsPlusServerType::all(),
            self.address.clone(),
            self.tcp_port,
        )
        .with_timeout(self.timeout)
        .build();
        server.domain_name.clone_from(&self.domain_name);
        server.sni_enabled = Some(self.sni_enabled);
        server.single_connection = self.single_connection;
        server.client_identity = Some(TlsClientClientIdentity {
            credentials_reference: None,
            certificate: None,
            tls13_epsk: Some(Tls13Epsk {
                inline_definition: None,
                central_keystore_reference: Some(self.psk_secret_ref.clone()),
                external_identity: self.psk_identity.clone(),
                hash: self.psk_hash,
                context: None,
                target_protocol: None,
                target_kdf: None,
                psk_dhe_ke_groups: self.psk_dhe_groups.clone(),
            }),
        });
        server
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
/// TLS rows map to RFC 9950 central-keystore EPSK references. The mapper never
/// reads provider files or places resolved key bytes into generated values.
///
/// # Errors
///
/// Returns an error if a row has an invalid numeric value (priority, port, or
/// timeout), if priority is outside SONiC's `1..64` range, or if the resulting
/// non-empty configuration fails validation.
pub fn map_sonic_tables_to_tacacs_plus(tables: &SonicTacacsTables) -> anyhow::Result<TacacsPlus> {
    let parsed = ParsedSonicTables::from_tables(tables)?;
    if parsed.candidates.is_empty() {
        return Ok(TacacsPlus::empty());
    }

    let mut builder = TacacsPlusBuilder::new();
    for candidate in &parsed.candidates {
        match candidate {
            SonicCandidateRow::Compatibility(row) => {
                builder = builder.with_server(row.to_server(&parsed.global));
            }
            SonicCandidateRow::Tls(row) => {
                builder = builder.with_server(row.to_server());
            }
        }
    }

    let validation_options = ValidationOptions::new()
        .with_relaxation(ValidationRelaxation::AllowPlainTcpWithoutSharedSecret);

    builder
        .build_with_options(&validation_options)
        .context("SONiC ConfigDB rows produced an invalid TACACS+ configuration")
}

#[derive(Debug, Clone)]
enum SonicCandidateRow {
    Compatibility(SonicServerRow),
    Tls(SonicTlsServerRow),
}

impl SonicCandidateRow {
    fn priority(&self) -> u8 {
        match self {
            Self::Compatibility(row) => row.priority,
            Self::Tls(row) => row.priority,
        }
    }

    fn normalized_host(&self) -> &NormalizedHost {
        match self {
            Self::Compatibility(row) => &row.normalized_host,
            Self::Tls(row) => &row.normalized_host,
        }
    }

    fn endpoint(&self) -> EndpointIdentity {
        match self {
            Self::Compatibility(row) => row.endpoint(),
            Self::Tls(row) => row.endpoint(),
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedSonicTables {
    global: SonicGlobal,
    candidates: Vec<SonicCandidateRow>,
}

impl ParsedSonicTables {
    fn from_tables(tables: &SonicTacacsTables) -> anyhow::Result<Self> {
        let global = SonicGlobal::from_hash(&tables.global)?;
        let forwarder = SonicForwarderSettings::from_hash(&tables.forwarder)?;
        let mut candidates = Vec::with_capacity(tables.servers.len() + tables.tls_servers.len());

        for (address, fields) in &tables.servers {
            let row = SonicServerRow::from_hash(address, fields)?;
            if forwarder
                .as_ref()
                .is_some_and(|settings| row.endpoint() == settings.endpoint())
            {
                continue;
            }
            candidates.push(SonicCandidateRow::Compatibility(row));
        }

        for (address, fields) in &tables.tls_servers {
            let row = SonicTlsServerRow::from_hash(address, fields)?;
            if forwarder
                .as_ref()
                .is_some_and(|settings| row.endpoint() == settings.endpoint())
            {
                bail!("TACPLUS_SERVER_TLS|{address} targets the local forwarder endpoint");
            }
            candidates.push(SonicCandidateRow::Tls(row));
        }

        let mut logical_names = BTreeSet::new();
        let mut endpoints = BTreeSet::new();
        for candidate in &candidates {
            if !endpoints.insert(candidate.endpoint()) {
                bail!("TACACS+ candidate has a duplicate normalized endpoint");
            }
            if !logical_names.insert(candidate.normalized_host().clone()) {
                bail!("TACACS+ candidate has a duplicate normalized logical name");
            }
        }

        candidates.sort_by(|left, right| {
            right
                .priority()
                .cmp(&left.priority())
                .then_with(|| left.normalized_host().cmp(right.normalized_host()))
                .then_with(|| left.endpoint().port.cmp(&right.endpoint().port))
        });

        Ok(Self { global, candidates })
    }
}

/// Strongly-typed view of `TACPLUS|global` defaults.
#[derive(Debug, Default, Clone)]
struct SonicGlobal {
    timeout: Option<u16>,
    passkey: Option<String>,
    src_intf: Option<String>,
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
                "use_tls" | "domain_name" | "sni_enabled" => {
                    bail!("TACPLUS|global contains unsupported TLS field '{key}'");
                }
                // `auth_type` controls PAM-side defaults (PAP vs CHAP). The
                // agent does not expose authentication types yet, so the
                // value is recorded only for log surface.
                "auth_type" => {
                    log::debug!("Ignoring TACPLUS|global.auth_type: agent has no PAM-style authentication selector yet");
                }
                other => {
                    log::warn!("Ignoring unknown TACPLUS|global field '{other}'");
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
    normalized_host: NormalizedHost,
    priority: u8,
    tcp_port: u16,
    timeout: Option<u16>,
    passkey: Option<String>,
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
            normalized_host: normalize_host(address),
            priority: 1,
            tcp_port: DEFAULT_TACACS_TCP_PORT,
            timeout: None,
            passkey: None,
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
                "domain_name" | "sni_enabled" | "use_tls" => {
                    bail!("TACPLUS_SERVER|{address} contains unsupported TLS field '{key}'");
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
                    log::warn!("Ignoring unknown TACPLUS_SERVER|{address} field '{other}'");
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

        let mut builder = TacacsPlusServerBuilder::new(
            sonic_server_name(&self.address),
            self.server_type,
            self.address.clone(),
            self.tcp_port,
        )
        .with_timeout(timeout);

        if let Some(passkey) = self.passkey.clone().or_else(|| global.passkey.clone()) {
            builder = builder.with_shared_secret(passkey);
        }

        let mut server = builder.build();

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

    fn endpoint(&self) -> EndpointIdentity {
        EndpointIdentity {
            host: self.normalized_host.clone(),
            port: self.tcp_port,
        }
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

fn normalize_host(value: &str) -> NormalizedHost {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized == "localhost" {
        return NormalizedHost::Loopback;
    }
    if let Ok(address) = normalized.parse::<IpAddr>() {
        let address = match address {
            IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4),
            ipv4 @ IpAddr::V4(_) => ipv4,
        };
        if address.is_loopback() {
            NormalizedHost::Loopback
        } else {
            NormalizedHost::Ip(address)
        }
    } else {
        NormalizedHost::Name(normalized)
    }
}

fn reject_unknown_fields(row: &str, hash: &SonicHash, allowed: &[&str]) -> anyhow::Result<()> {
    for field in hash.keys() {
        if !allowed.contains(&field.as_str()) {
            bail!("{row} contains unsupported field '{field}'");
        }
    }
    Ok(())
}

fn required_non_empty_field<'a>(
    row: &str,
    hash: &'a SonicHash,
    field: &str,
) -> anyhow::Result<&'a str> {
    optional_non_empty_field(row, hash, field)?
        .ok_or_else(|| anyhow::anyhow!("{row}.{field} is required"))
}

fn optional_non_empty_field<'a>(
    row: &str,
    hash: &'a SonicHash,
    field: &str,
) -> anyhow::Result<Option<&'a str>> {
    match hash.get(field) {
        Some(value) if value.trim().is_empty() => bail!("{row}.{field} must not be empty"),
        Some(value) => Ok(Some(value.as_str())),
        None => Ok(None),
    }
}

fn parse_optional_port(row: &str, value: Option<&String>, default: u16) -> anyhow::Result<u16> {
    let port = value
        .map_or(Ok(default), |value| value.parse::<u16>())
        .with_context(|| format!("{row}.tcp_port is not a valid TCP port"))?;
    if port == 0 {
        bail!("{row}.tcp_port must be in range 1..65535");
    }
    Ok(port)
}

fn parse_optional_bool(
    row: &str,
    field: &str,
    value: Option<&String>,
    default: bool,
) -> anyhow::Result<bool> {
    match value.map(String::as_str) {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => bail!("{row}.{field} must be true or false"),
    }
}

fn validate_opaque_id(value: &str) -> anyhow::Result<()> {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        bail!("opaque object ID must not be empty");
    };
    if value.len() > 64
        || !first.is_ascii_alphanumeric()
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        bail!("opaque object ID must match the reviewed grammar");
    }
    Ok(())
}

fn parse_psk_groups(row: &str, value: &str) -> anyhow::Result<Vec<PskDheKeSupportedGroup>> {
    if value.is_empty() {
        bail!("{row}.psk_key_exchange_groups must not be empty");
    }
    let mut seen = BTreeSet::new();
    let mut groups = Vec::new();
    for group in value.split(':') {
        if !seen.insert(group) {
            bail!("{row}.psk_key_exchange_groups contains a duplicate group");
        }
        let parsed = PskDheKeSupportedGroup::from_rfc7951_str(group).ok_or_else(|| {
            anyhow::anyhow!("{row}.psk_key_exchange_groups contains an unsupported group")
        })?;
        groups.push(parsed);
    }
    Ok(groups)
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
    let timeout = value
        .parse::<u16>()
        .context("expected timeout in seconds")?;
    if !(1..=60).contains(&timeout) {
        bail!("expected timeout in range 1..60");
    }
    Ok(timeout)
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
        assert_eq!(
            cfg.server[0]
                .shared_secret
                .as_ref()
                .unwrap()
                .expose_secret(),
            "per-server-secret",
        );

        // Per-server passkey absent -> falls back to global.
        assert_eq!(cfg.server[1].address, "192.0.2.10");
        assert_eq!(
            cfg.server[1]
                .shared_secret
                .as_ref()
                .unwrap()
                .expose_secret(),
            "default-secret",
        );
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
    fn compatibility_rows_reject_tls_extension_fields() {
        let mut servers = BTreeMap::new();
        servers.insert(
            "tacacs.example.com".to_string(),
            h(&[("priority", "1"), ("domain_name", "tacacs.example.com")]),
        );
        let error =
            map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(SonicHash::new(), servers))
                .expect_err("compatibility TLS extensions must be rejected");
        assert!(error
            .to_string()
            .contains("unsupported TLS field 'domain_name'"));
    }

    #[test]
    fn global_tls_extension_is_rejected() {
        let mut servers = BTreeMap::new();
        servers.insert("192.0.2.10".to_string(), h(&[("priority", "1")]));

        let error = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::new(
            h(&[("use_tls", "true")]),
            servers,
        ))
        .expect_err("global TLS extension must be rejected");
        assert!(error
            .to_string()
            .contains("unsupported TLS field 'use_tls'"));
    }

    fn tls_fields(priority: &str) -> SonicHash {
        h(&[
            ("priority", priority),
            ("psk_identity", "client"),
            ("psk_secret_ref", "epsk-object"),
        ])
    }

    #[test]
    fn typed_snapshot_orders_mixed_candidates_independent_of_insertion_order() {
        let mut compatibility = BTreeMap::new();
        compatibility.insert("192.0.2.30".to_owned(), h(&[("priority", "16")]));
        compatibility.insert("192.0.2.10".to_owned(), h(&[("priority", "48")]));
        let mut tls = BTreeMap::new();
        tls.insert("tls-b.example".to_owned(), tls_fields("32"));
        tls.insert("tls-a.example".to_owned(), tls_fields("32"));

        let parsed = ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            compatibility,
            tls,
            h(&[("local_listen_address", "127.0.0.1")]),
        ))
        .expect("typed snapshot");
        let order = parsed
            .candidates
            .iter()
            .map(|candidate| (candidate.priority(), candidate.normalized_host().clone()))
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            [
                (48, NormalizedHost::Ip("192.0.2.10".parse().expect("IPv4"))),
                (32, NormalizedHost::Name("tls-a.example".to_owned())),
                (32, NormalizedHost::Name("tls-b.example".to_owned())),
                (16, NormalizedHost::Ip("192.0.2.30".parse().expect("IPv4"))),
            ]
        );
    }

    #[test]
    fn normalized_loopback_compatibility_alias_is_filtered() {
        let mut compatibility = BTreeMap::new();
        compatibility.insert("localhost".to_owned(), h(&[("priority", "64")]));
        compatibility.insert("192.0.2.10".to_owned(), h(&[("priority", "16")]));
        let parsed = ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            compatibility,
            BTreeMap::new(),
            h(&[("local_listen_address", "::1"), ("local_listen_port", "49")]),
        ))
        .expect("typed snapshot");
        assert_eq!(parsed.candidates.len(), 1);
        assert_eq!(
            parsed.candidates[0].normalized_host(),
            &NormalizedHost::Ip("192.0.2.10".parse().expect("IPv4"))
        );
    }

    #[test]
    fn compatibility_loopback_forms_filter_only_the_active_forwarder_port() {
        for address in ["127.0.0.1", "::1", "::ffff:127.0.0.1", "localhost"] {
            let mut compatibility = BTreeMap::new();
            compatibility.insert(address.to_owned(), h(&[("priority", "64"), ("tcp_port", "49")]));
            compatibility
                .insert("127.0.0.1".to_owned(), h(&[("priority", "32"), ("tcp_port", "50")]));
            let parsed = ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
                SonicHash::new(),
                compatibility,
                BTreeMap::new(),
                h(&[
                    ("local_listen_address", "127.0.0.1"),
                    ("local_listen_port", "49"),
                ]),
            ))
            .expect("loopback compatibility snapshot");

            assert_eq!(parsed.candidates.len(), 1, "address {address}");
            assert_eq!(parsed.candidates[0].endpoint().port, 50);
        }
    }

    #[test]
    fn tls_self_target_and_cross_table_duplicates_are_rejected() {
        let mut tls = BTreeMap::new();
        tls.insert("::ffff:127.0.0.1".to_owned(), tls_fields("48"));
        let error = ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            BTreeMap::new(),
            tls,
            h(&[
                ("local_listen_address", "127.0.0.1"),
                ("local_listen_port", "449"),
            ]),
        ))
        .expect_err("mapped loopback TLS target must fail");
        assert!(error.to_string().contains("local forwarder endpoint"));

        let mut compatibility = BTreeMap::new();
        compatibility.insert("EXAMPLE.test.".to_owned(), h(&[("priority", "16")]));
        let mut tls = BTreeMap::new();
        tls.insert("example.test".to_owned(), tls_fields("48"));
        let error = ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            compatibility,
            tls,
            SonicHash::new(),
        ))
        .expect_err("normalized duplicate names must fail");
        assert!(error
            .to_string()
            .contains("duplicate normalized logical name"));

        let mut compatibility = BTreeMap::new();
        compatibility
            .insert("192.0.2.10".to_owned(), h(&[("priority", "16"), ("tcp_port", "449")]));
        let mut tls = BTreeMap::new();
        tls.insert("::ffff:192.0.2.10".to_owned(), tls_fields("48"));
        let error = ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            compatibility,
            tls,
            SonicHash::new(),
        ))
        .expect_err("normalized duplicate endpoints must fail");
        assert!(error.to_string().contains("duplicate normalized endpoint"));
    }

    #[test]
    fn tls_and_forwarder_fields_are_strictly_validated_without_values_in_errors() {
        let mut tls = BTreeMap::new();
        tls.insert(
            "192.0.2.20".to_owned(),
            h(&[
                ("sni_enabled", "enabled"),
                ("psk_identity", "sensitive-identity"),
                ("psk_secret_ref", "sensitive-reference"),
            ]),
        );
        let error = ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            BTreeMap::new(),
            tls,
            SonicHash::new(),
        ))
        .expect_err("non-canonical TLS boolean must fail");
        let message = error.to_string();
        assert!(message.contains("sni_enabled must be true or false"));
        assert!(!message.contains("sensitive-identity"));
        assert!(!message.contains("sensitive-reference"));

        let error = ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            h(&[("local_listen_address", "192.0.2.30")]),
        ))
        .expect_err("non-loopback listener must fail");
        assert!(error.to_string().contains("must be loopback"));
    }

    #[test]
    fn forwarder_settings_apply_default_port_and_support_ipv6_loopback() {
        let settings = SonicForwarderSettings::from_hash(&h(&[("local_listen_address", "::1")]))
            .expect("valid forwarder")
            .expect("configured forwarder");

        assert_eq!(settings.listen_address(), "::1".parse::<IpAddr>().expect("IPv6"));
        assert_eq!(settings.listen_port(), 49);
        assert_eq!(settings.socket_address(), "[::1]:49".parse().expect("socket"));
    }

    #[test]
    fn deleted_and_malformed_forwarder_rows_are_distinct() {
        assert_eq!(
            SonicForwarderSettings::from_hash(&SonicHash::new()).expect("deleted row"),
            None
        );

        let error = SonicForwarderSettings::from_hash(&h(&[
            ("local_listen_address", "127.0.0.1"),
            ("local_listen_port", "0"),
        ]))
        .expect_err("zero port must be rejected");
        assert!(error.to_string().contains("1..65535"));
    }

    #[test]
    fn tls_unknown_fields_invalid_ids_and_duplicate_groups_are_rejected() {
        for fields in [
            h(&[
                ("psk_identity", "client"),
                ("psk_secret_ref", "epsk-object"),
                ("cipher_suites", "unsupported"),
            ]),
            h(&[("psk_identity", "client"), ("psk_secret_ref", "../escape")]),
            h(&[
                ("psk_identity", "client"),
                ("psk_secret_ref", "epsk-object"),
                ("psk_key_exchange_groups", "x25519:x25519"),
            ]),
        ] {
            let mut tls = BTreeMap::new();
            tls.insert("192.0.2.20".to_owned(), fields);
            ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
                SonicHash::new(),
                BTreeMap::new(),
                tls,
                SonicHash::new(),
            ))
            .expect_err("invalid TLS row must fail");
        }
    }

    #[test]
    fn deferred_certificate_and_mutual_tls_fields_are_explicitly_rejected() {
        for field in [
            "client_certificate_ref",
            "client_private_key_ref",
            "server_ca_certificate_ref",
            "server_end_entity_certificate_ref",
            "mutual_tls_enabled",
        ] {
            let mut fields = tls_fields("48");
            fields.insert(field.to_owned(), "sensitive-deferred-value".to_owned());
            let mut tls = BTreeMap::new();
            tls.insert("192.0.2.20".to_owned(), fields);
            let error = ParsedSonicTables::from_tables(&SonicTacacsTables::with_extended_tables(
                SonicHash::new(),
                BTreeMap::new(),
                tls,
                SonicHash::new(),
            ))
            .expect_err("deferred certificate field must fail");
            let message = error.to_string();
            assert!(message.contains(field));
            assert!(!message.contains("sensitive-deferred-value"));
        }
    }

    #[test]
    fn tls_epsk_row_maps_to_central_rfc_identity_without_inline_material() {
        let mut tls = BTreeMap::new();
        tls.insert(
            "tacacs.example.test".to_owned(),
            h(&[
                ("priority", "48"),
                ("tcp_port", "449"),
                ("timeout", "10"),
                ("domain_name", "sni.example.test"),
                ("sni_enabled", "true"),
                ("single_connection", "true"),
                ("psk_identity", "client-identity"),
                ("psk_secret_ref", "epsk-object-01"),
                ("psk_hash", "sha-384"),
                ("psk_key_exchange", "psk-dhe"),
                ("psk_key_exchange_groups", "x25519:secp384r1"),
            ]),
        );
        let config = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            BTreeMap::new(),
            tls,
            SonicHash::new(),
        ))
        .expect("central EPSK mapping");

        let server = &config.server[0];
        assert_eq!(server.address, "tacacs.example.test");
        assert_eq!(server.port, 449);
        assert_eq!(server.timeout, 10);
        assert_eq!(server.domain_name.as_deref(), Some("sni.example.test"));
        assert_eq!(server.sni_enabled, Some(true));
        assert!(server.single_connection);
        assert!(server.shared_secret.is_none());
        assert!(server.server_authentication.is_none());
        let epsk = server
            .client_identity
            .as_ref()
            .and_then(|identity| identity.tls13_epsk.as_ref())
            .expect("central EPSK identity");
        assert!(epsk.inline_definition.is_none());
        assert_eq!(epsk.central_keystore_reference.as_deref(), Some("epsk-object-01"));
        assert_eq!(epsk.external_identity, "client-identity");
        assert_eq!(epsk.hash, EpskSupportedHash::Sha384);
        assert_eq!(
            epsk.psk_dhe_ke_groups,
            [
                PskDheKeSupportedGroup::X25519,
                PskDheKeSupportedGroup::Secp384r1
            ]
        );
    }

    #[test]
    fn tls_epsk_exchange_defaults_and_psk_only_map_distinctly() {
        let mut tls = BTreeMap::new();
        tls.insert("dhe.example.test".to_owned(), tls_fields("48"));
        tls.insert(
            "only.example.test".to_owned(),
            h(&[
                ("priority", "32"),
                ("psk_identity", "client"),
                ("psk_secret_ref", "epsk-only"),
                ("psk_key_exchange", "psk-only"),
            ]),
        );
        let config = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            BTreeMap::new(),
            tls,
            SonicHash::new(),
        ))
        .expect("EPSK exchange mapping");

        let dhe = config.server[0]
            .client_identity
            .as_ref()
            .and_then(|identity| identity.tls13_epsk.as_ref())
            .expect("default DHE EPSK");
        assert_eq!(dhe.psk_dhe_ke_groups, tacacsrs_config::builders::DEFAULT_PSK_DHE_KE_GROUPS);
        assert_eq!(dhe.hash, EpskSupportedHash::Sha256);

        let psk_only = config.server[1]
            .client_identity
            .as_ref()
            .and_then(|identity| identity.tls13_epsk.as_ref())
            .expect("PSK-only EPSK");
        assert!(psk_only.psk_dhe_ke_groups.is_empty());
    }

    #[test]
    fn mixed_tcp_and_tls_projection_preserves_typed_priority_order() {
        let mut compatibility = BTreeMap::new();
        compatibility.insert("192.0.2.10".to_owned(), h(&[("priority", "16")]));
        let mut tls = BTreeMap::new();
        tls.insert("tls.example.test".to_owned(), tls_fields("48"));
        let config = map_sonic_tables_to_tacacs_plus(&SonicTacacsTables::with_extended_tables(
            SonicHash::new(),
            compatibility,
            tls,
            SonicHash::new(),
        ))
        .expect("mixed projection");

        assert_eq!(
            config
                .server
                .iter()
                .map(|server| server.address.as_str())
                .collect::<Vec<_>>(),
            ["tls.example.test", "192.0.2.10"]
        );
        assert!(config.server[0].client_identity.is_some());
        assert!(config.server[1].client_identity.is_none());
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
