use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use clap::Parser;
use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_agent_ipc_emulator::IpcEmulator;

#[derive(Debug, Parser)]
#[command(name = "tacacsrs-agent-ipc-emulatord", version, author)]
#[command(about = "JSON-driven TACACS+ agent IPC emulator for integration tests")]
struct Cli {
    /// Path to the JSON emulator scenario file.
    #[arg(long, value_name = "FILE")]
    scenario: PathBuf,

    /// IPC endpoint to listen on. TCP port 0 chooses an ephemeral loopback port.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen_endpoint: String,

    /// Increase verbosity level (-v, -vv, -vvv, -vvvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn init_logger(verbose: u8) {
    let level = match verbose {
        0 => return,
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .try_init();
}

fn endpoint_string(endpoint: &IpcEndpoint) -> String {
    match endpoint {
        IpcEndpoint::Tcp(address) => address.to_string(),
        #[cfg(unix)]
        IpcEndpoint::Unix(path) => path.display().to_string(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_logger(cli.verbose);

    let endpoint = IpcEndpoint::from_str(&cli.listen_endpoint)
        .with_context(|| format!("Invalid listen endpoint {}", cli.listen_endpoint))?;
    let (emulator, bound_endpoint) = IpcEmulator::from_file_at_endpoint(&cli.scenario, endpoint)
        .await
        .with_context(|| format!("Failed to start IPC emulator from {}", cli.scenario.display()))?;

    println!("{}", endpoint_string(&bound_endpoint));
    log::info!("IPC emulator listening on {}", endpoint_string(&bound_endpoint));
    emulator.wait().await
}
