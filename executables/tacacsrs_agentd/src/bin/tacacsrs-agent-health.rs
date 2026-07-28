//! Exec probe for the agent's standard gRPC health service.

use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use tacacsrs_agent_client::health::{
    LIVENESS_HEALTH_SERVICE, READINESS_HEALTH_SERVICE, STARTUP_HEALTH_SERVICE,
};
use tacacsrs_agent_client::{HealthClient, IpcEndpoint};
use tonic_health::pb::health_check_response::ServingStatus;

const EXIT_NOT_SERVING: u8 = 1;
const EXIT_INVOCATION_ERROR: u8 = 2;
const EXIT_CHECK_ERROR: u8 = 3;

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
#[command(about = "Check tacacsrs-agentd startup, liveness, or readiness")]
struct Cli {
    /// Client API Unix socket path or loopback TCP endpoint.
    #[arg(long, default_value = "/run/tacacs/tacacs.sock")]
    endpoint: String,

    /// Health view to check.
    #[arg(long, value_enum)]
    check: HealthCheck,

    /// Maximum total check duration.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..))]
    timeout_seconds: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let _ = error.print();
            return ExitCode::from(EXIT_INVOCATION_ERROR);
        }
    };
    let Ok(endpoint) = IpcEndpoint::from_str(&cli.endpoint) else {
        eprintln!("invalid health endpoint: {}", cli.endpoint);
        return ExitCode::from(EXIT_INVOCATION_ERROR);
    };

    match tokio::time::timeout(
        Duration::from_secs(cli.timeout_seconds),
        check_health(&endpoint, cli.check),
    )
    .await
    {
        Ok(Ok(ServingStatus::Serving)) => ExitCode::SUCCESS,
        Ok(Ok(ServingStatus::NotServing | ServingStatus::Unknown)) => {
            eprintln!("{} health check is not serving", cli.check.service_name());
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
            eprintln!("{} health check is unknown", cli.check.service_name());
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
        .expect("documented CLI should parse");

        assert_eq!(cli.endpoint, "127.0.0.1:9049");
        assert_eq!(cli.check.service_name(), READINESS_HEALTH_SERVICE);
        assert_eq!(cli.timeout_seconds, 2);
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
