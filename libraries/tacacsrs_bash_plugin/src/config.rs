use std::env;
use std::fs;
use std::os::raw::c_int;
use std::sync::Mutex;
use std::time::SystemTime;

use tacacsrs_agent_client::IpcEndpoint;

const DEFAULT_CONFIG_FILE: &str = "/etc/tacplus_nss.conf";
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
        return endpoint.parse();
    }

    match env::var(IPC_ENDPOINT_ENV) {
        Ok(value) if !value.trim().is_empty() => value.parse(),
        _ => Ok(IpcEndpoint::default_local()),
    }
}

fn config_path() -> String {
    env::var(CONFIG_FILE_ENV).unwrap_or_else(|_| DEFAULT_CONFIG_FILE.to_owned())
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

fn flag_for_token(token: &str) -> c_int {
    match token {
        "debug" => DEBUG_FLAG,
        "local_authorization" => LOCAL_AUTHORIZATION_FLAG,
        "tacacs_authorization" => TACACS_AUTHORIZATION_FLAG,
        _ => 0,
    }
}
