//! Exec probe for the agent's standard gRPC health service.

use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use tacacsrs_ipc::health::{LIVENESS_HEALTH_SERVICE, READINESS_HEALTH_SERVICE, STARTUP_HEALTH_SERVICE};
use tacacsrs_ipc::{HealthClient, IpcEndpoint};
use tonic_health::pb::health_check_response::ServingStatus;

const EXIT_NOT_SERVING: u8 = 1;
const EXIT_INVOCATION_ERROR: u8 = 2;
const EXIT_CHECK_ERROR: u8 = 3;
const DEFAULT_PROBE_TIMEOUT_SECONDS: u64 = 2;
const DEFAULT_QUERY_TIMEOUT_SECONDS: u64 = 5;

mod details;
mod statistics;

#[derive(Debug, Subcommand)]
enum Command {
    /// Report read-only agent, connection, and server statistics.
    Statistics(statistics::StatisticsArgs),
    /// Report the detailed runtime health behind the health probes.
    Details(details::DetailsArgs),
}

impl Command {
    const fn name(&self) -> &'static str {
        match self {
            Self::Statistics(_) => "statistics",
            Self::Details(_) => "details",
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HealthCheck {
    Startup,
    Liveness,
    Readiness,
}

impl HealthCheck {
    const fn service_name(self) -> &'static str {
        match self {
            Self::Startup => STARTUP_HEALTH_SERVICE,
            Self::Liveness => LIVENESS_HEALTH_SERVICE,
            Self::Readiness => READINESS_HEALTH_SERVICE,
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "tacacsrs-agent-health", version, author)]
#[command(
    about = "Report agent health or read-only operational statistics",
    subcommand_negates_reqs = true
)]
struct Cli {
    /// Client API Unix domain socket path or loopback TCP endpoint.
    #[arg(long, global = true, default_value = "/run/tacacs/tacacs.sock")]
    endpoint: String,

    /// Health check to run.
    #[arg(long, value_enum, required = true)]
    check: Option<HealthCheck>,

    #[command(subcommand)]
    command: Option<Command>,

    /// Maximum duration in seconds (default: 2 for --check, 5 for subcommands).
    #[arg(long, global = true, value_parser = clap::value_parser!(u64).range(1..))]
    timeout_seconds: Option<u64>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = error.print();
            return if informational {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(EXIT_INVOCATION_ERROR)
            };
        }
    };
    let Ok(endpoint) = IpcEndpoint::from_str(&cli.endpoint) else {
        eprintln!("invalid health endpoint: {}", cli.endpoint);
        return ExitCode::from(EXIT_INVOCATION_ERROR);
    };

    if let Some(command) = cli.command {
        if cli.check.is_some() {
            eprintln!("--check cannot be combined with {}", command.name());
            return ExitCode::from(EXIT_INVOCATION_ERROR);
        }
        let timeout =
            Duration::from_secs(cli.timeout_seconds.unwrap_or(DEFAULT_QUERY_TIMEOUT_SECONDS));
        let result = match &command {
            Command::Statistics(arguments) => {
                tokio::time::timeout(timeout, statistics::query(endpoint, arguments)).await
            }
            Command::Details(arguments) => {
                tokio::time::timeout(timeout, details::query(&endpoint, arguments)).await
            }
        };
        return match result {
            Ok(Ok(output)) => {
                println!("{output}");
                ExitCode::SUCCESS
            }
            Ok(Err(error)) => {
                eprintln!("The {} query failed: {error}", command.name());
                ExitCode::from(EXIT_CHECK_ERROR)
            }
            Err(_) => {
                eprintln!("The {} query timed out", command.name());
                ExitCode::from(EXIT_CHECK_ERROR)
            }
        };
    }
    let Some(check) = cli.check else {
        return ExitCode::from(EXIT_INVOCATION_ERROR);
    };
    let probe_timeout = cli.timeout_seconds.unwrap_or(DEFAULT_PROBE_TIMEOUT_SECONDS);
    match tokio::time::timeout(Duration::from_secs(probe_timeout), check_health(&endpoint, check))
        .await
    {
        Ok(Ok(ServingStatus::Serving)) => ExitCode::SUCCESS,
        Ok(Ok(ServingStatus::NotServing | ServingStatus::Unknown)) => {
            eprintln!("{} health check is not serving", check.service_name());
            ExitCode::from(EXIT_NOT_SERVING)
        }
        Ok(Err(())) => {
            eprintln!("health check failed for endpoint {}", cli.endpoint);
            ExitCode::from(EXIT_CHECK_ERROR)
        }
        Err(_) => {
            eprintln!("health check timed out for endpoint {}", cli.endpoint);
            ExitCode::from(EXIT_CHECK_ERROR)
        }
        Ok(Ok(ServingStatus::ServiceUnknown)) => {
            eprintln!("{} health check is unknown", check.service_name());
            ExitCode::from(EXIT_NOT_SERVING)
        }
    }
}

async fn check_health(endpoint: &IpcEndpoint, check: HealthCheck) -> Result<ServingStatus, ()> {
    let mut client = HealthClient::connect(endpoint).await.map_err(|_| ())?;
    client.check(check.service_name()).await.map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_accepts_documented_contract() {
        let cli = Cli::try_parse_from([
            "tacacsrs-agent-health",
            "--endpoint",
            "127.0.0.1:9049",
            "--check",
            "readiness",
            "--timeout-seconds",
            "2",
        ])
        .expect("documented CLI must parse");

        assert_eq!(cli.endpoint, "127.0.0.1:9049");
        assert_eq!(cli.check.unwrap().service_name(), READINESS_HEALTH_SERVICE);
        assert_eq!(cli.timeout_seconds, Some(2));
    }

    #[test]
    fn cli_rejects_zero_timeout() {
        let result = Cli::try_parse_from([
            "tacacsrs-agent-health",
            "--check",
            "liveness",
            "--timeout-seconds",
            "0",
        ]);

        assert!(result.is_err());
    }
}
