use std::path::PathBuf;
use std::io::Write;
use std::str::FromStr;

use anyhow::Context;
use clap::Parser;
use tacacsrs_agent_client::IpcEndpoint;
use tacacsrs_agent_ipc_emulator::{EmulatorPolicy, IpcEmulator};

#[derive(Debug, Parser)]
#[command(name = "tacacsrs-agent-ipc-emulatord", version, author)]
#[command(about = "OPA/Rego-driven TACACS+ agent IPC emulator for integration tests")]
struct Cli {
    /// Path to the Rego policy file evaluated for every IPC request.
    #[arg(long, value_name = "FILE")]
    policy: PathBuf,

    /// Optional JSON policy data document fixed at startup.
    #[arg(long, value_name = "FILE")]
    data: Option<PathBuf>,

    /// IPC endpoint to listen on. TCP port 0 chooses an ephemeral loopback port.
    #[arg(long, default_value = "127.0.0.1:0")]
    listen_endpoint: String,

    /// Increase verbosity level (-v, -vv, -vvv, -vvvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Suppress emulator diagnostics and print only the bound endpoint.
    #[arg(long)]
    quiet: bool,
}

fn init_logger(verbose: u8, quiet: bool) {
    if quiet {
        return;
    }
    let level = match verbose {
        0 | 1 => "warn,tacacsrs_agent_ipc_emulatord=info,tacacsrs_agent_ipc_emulator=info",
        2 => "warn,tacacsrs_agent_ipc_emulatord=debug,tacacsrs_agent_ipc_emulator=debug",
        3 => "warn,tacacsrs_agent_ipc_emulatord=trace,tacacsrs_agent_ipc_emulator=trace",
        _ => "trace",
    };
    let show_target = verbose >= 2;
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .format(move |formatter, record| {
            if show_target {
                writeln!(
                    formatter,
                    "{} {:<5} {}: {}",
                    formatter.timestamp_millis(),
                    record.level(),
                    record.target(),
                    record.args()
                )
            } else {
                writeln!(
                    formatter,
                    "{} {:<5} {}",
                    formatter.timestamp_millis(),
                    record.level(),
                    record.args()
                )
            }
        })
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
    init_logger(cli.verbose, cli.quiet);

    let endpoint = IpcEndpoint::from_str(&cli.listen_endpoint)
        .with_context(|| format!("Invalid listen endpoint {}", cli.listen_endpoint))?;
    log::info!(
        "starting IPC emulator policy={} data={} listen_endpoint={}",
        cli.policy.display(),
        cli.data
            .as_ref()
            .map_or_else(|| "<none>".to_owned(), |path| path.display().to_string()),
        cli.listen_endpoint
    );
    let policy = match &cli.data {
        Some(data) => EmulatorPolicy::from_files_async(&cli.policy, data).await,
        None => EmulatorPolicy::from_file_async(&cli.policy).await,
    }
    .with_context(|| format!("Failed to load IPC emulator policy from {}", cli.policy.display()))?;
    let (emulator, bound_endpoint) = IpcEmulator::from_policy_at_endpoint(policy, endpoint)
        .await
        .with_context(|| format!("Failed to start IPC emulator from {}", cli.policy.display()))?;

    println!("{}", endpoint_string(&bound_endpoint));
    log::info!(
        "IPC emulator ready endpoint={} policy={}",
        endpoint_string(&bound_endpoint),
        cli.policy.display()
    );
    emulator.wait().await
}
