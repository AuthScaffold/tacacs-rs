use std::env;
use std::fs;
use std::os::raw::c_int;
use std::sync::Mutex;
use std::time::SystemTime;

use tacacsrs_agent_client::IpcEndpoint;

use crate::logging::debug_log;

const DEFAULT_CONFIG_FILE: &str = "/etc/tacplus_nss.conf";
const DEFAULT_AGENTD_CONFIG_FILE: &str = "/etc/tacacsrs-agentd/config.ini";
const CONFIG_FILE_ENV: &str = "TACACSRS_BASH_PLUGIN_CONFIG";
const IPC_ENDPOINT_ENV: &str = "TACACSRS_AGENT_ENDPOINT";

pub(crate) const DEBUG_FLAG: c_int = 0x01;
pub(crate) const LOCAL_AUTHORIZATION_FLAG: c_int = 0x40;
pub(crate) const TACACS_AUTHORIZATION_FLAG: c_int = 0x80;

#[derive(Debug, Clone, Default)]
struct PluginConfig {
    flags: c_int,
    modified: Option<SystemTime>,
    ipc_endpoint: Option<String>,
}

static CONFIG: Mutex<PluginConfig> = Mutex::new(PluginConfig {
    flags: 0,
    modified: None,
    ipc_endpoint: None,
});

pub(crate) fn current_flags() -> c_int {
    CONFIG.lock().map_or(0, |config| config.flags)
}

pub(crate) fn reload_config(force: bool) -> c_int {
    let path = config_path();
    let modified = fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .ok();

    let Ok(mut config) = CONFIG.lock() else {
        return 0;
    };

    if !force && config.modified == modified {
        return config.flags;
    }

    let parsed_config = parse_config_file(&path);
    debug_log(
        parsed_config.flags,
        &format!(
            "loaded plugin config from {path}; flags={}; ipc_endpoint={}",
            format_flags(parsed_config.flags),
            parsed_config.ipc_endpoint.as_deref().unwrap_or("<none>")
        ),
    );
    config.flags = parsed_config.flags;
    config.ipc_endpoint = parsed_config.ipc_endpoint;
    config.modified = modified;
    config.flags
}

pub(crate) fn ipc_endpoint() -> anyhow::Result<IpcEndpoint> {
    if let Some(endpoint) = CONFIG
        .lock()
        .ok()
        .and_then(|config| config.ipc_endpoint.clone())
    {
        debug_log(
            current_flags(),
            &format!("using IPC endpoint from plugin config: {endpoint}"),
        );
        return endpoint.parse();
    }

    match env::var(IPC_ENDPOINT_ENV) {
        Ok(value) if !value.trim().is_empty() => {
            let endpoint = value.trim();
            debug_log(
                current_flags(),
                &format!("using IPC endpoint from {IPC_ENDPOINT_ENV}: {endpoint}"),
            );
            endpoint.parse()
        }
        _ => {
            if let Some(endpoint) = agentd_config_ipc_endpoint() {
                debug_log(
                    current_flags(),
                    &format!(
                        "using IPC endpoint from {DEFAULT_AGENTD_CONFIG_FILE}: {endpoint}"
                    ),
                );
                return endpoint.parse();
            }

            let endpoint = IpcEndpoint::default_local();
            debug_log(
                current_flags(),
                &format!(
                    "using built-in default IPC endpoint: {}",
                    format_endpoint(&endpoint)
                ),
            );
            Ok(endpoint)
        }
    }
}

fn config_path() -> String {
    env::var(CONFIG_FILE_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_FILE.to_owned())
}

fn agentd_config_path() -> String {
    DEFAULT_AGENTD_CONFIG_FILE.to_owned()
}

fn agentd_config_ipc_endpoint() -> Option<String> {
    parse_agentd_config_ipc_endpoint(&agentd_config_path())
}

fn parse_config_file(path: &str) -> PluginConfig {
    let Ok(contents) = fs::read_to_string(path) else {
        return PluginConfig::default();
    };

    let mut config = PluginConfig::default();
    for line in contents.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        for item in trimmed.split(|ch: char| ch == ',' || ch.is_ascii_whitespace()) {
            parse_config_token(item, &mut config);
        }
    }
    config
}

fn parse_config_token(token: &str, config: &mut PluginConfig) {
    let Some((name, value)) = token.split_once('=') else {
        config.flags |= flag_for_token(token);
        return;
    };

    if name == "ipc_endpoint" && !value.trim().is_empty() {
        config.ipc_endpoint = Some(value.trim().to_owned());
        return;
    }

    let enabled = matches!(value, "1" | "on" | "true" | "yes");
    if enabled {
        config.flags |= flag_for_token(name);
    }
}

fn parse_agentd_config_ipc_endpoint(path: &str) -> Option<String> {
    let Ok(contents) = fs::read_to_string(path) else {
        return None;
    };

    contents.lines().find_map(parse_agentd_config_line)
}

fn parse_agentd_config_line(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let (name, value) = trimmed.split_once('=')?;
    if name.trim() != "ipc_endpoint" {
        return None;
    }

    let value = value.trim();
    if value.is_empty() {
        return None;
    }

    Some(value.to_owned())
}

fn flag_for_token(token: &str) -> c_int {
    match token {
        "debug" => DEBUG_FLAG,
        "local_authorization" => LOCAL_AUTHORIZATION_FLAG,
        "tacacs_authorization" => TACACS_AUTHORIZATION_FLAG,
        _ => 0,
    }
}

pub(crate) fn format_flags(flags: c_int) -> String {
    let mut names = Vec::new();
    if flags & DEBUG_FLAG != 0 {
        names.push("debug");
    }
    if flags & LOCAL_AUTHORIZATION_FLAG != 0 {
        names.push("local_authorization");
    }
    if flags & TACACS_AUTHORIZATION_FLAG != 0 {
        names.push("tacacs_authorization");
    }

    if names.is_empty() {
        return "none".to_owned();
    }

    names.join(",")
}

pub(crate) fn format_endpoint(endpoint: &IpcEndpoint) -> String {
    #[cfg(unix)]
    if let IpcEndpoint::Unix(path) = endpoint {
        return path.display().to_string();
    }

    match endpoint {
        IpcEndpoint::Tcp(address) => address.to_string(),
        #[cfg(unix)]
        IpcEndpoint::Unix(_) => unreachable!("unix endpoint handled above"),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{parse_agentd_config_ipc_endpoint, parse_config_file};

    #[test]
    fn parse_config_file_reads_ipc_endpoint_token() {
        let path = test_file_path("plugin-config.txt");
        fs::write(
            &path,
            "debug=on\nlocal_authorization\nipc_endpoint=/run/tacacs/custom.sock\n",
        )
        .expect("plugin config should be written");

        let config = parse_config_file(path.to_str().expect("temp path should be valid UTF-8"));
        assert_eq!(config.ipc_endpoint.as_deref(), Some("/run/tacacs/custom.sock"));

        fs::remove_file(path).expect("temp plugin config should be removed");
    }

    #[test]
    fn parse_agentd_config_ipc_endpoint_reads_value() {
        let path = test_file_path("agentd-config.ini");
        fs::write(
            &path,
            "# package defaults\nconfig_source=unset\nipc_endpoint=/run/tacacs/custom.sock\n",
        )
        .expect("agentd config should be written");

        let endpoint = parse_agentd_config_ipc_endpoint(
            path.to_str().expect("temp path should be valid UTF-8"),
        );
        assert_eq!(endpoint.as_deref(), Some("/run/tacacs/custom.sock"));

        fs::remove_file(path).expect("temp agentd config should be removed");
    }

    #[test]
    fn parse_agentd_config_ipc_endpoint_ignores_empty_values() {
        let path = test_file_path("agentd-config-empty.ini");
        fs::write(&path, "ipc_endpoint=\n").expect("agentd config should be written");

        let endpoint = parse_agentd_config_ipc_endpoint(
            path.to_str().expect("temp path should be valid UTF-8"),
        );
        assert_eq!(endpoint, None);

        fs::remove_file(path).expect("temp agentd config should be removed");
    }

    fn test_file_path(name: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "tacacsrs-bash-plugin-config-tests-{name}-{}",
            std::process::id()
        ));
        path
    }
}
