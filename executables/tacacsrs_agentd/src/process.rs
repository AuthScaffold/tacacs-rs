//! Process controls normalized before logger and Tokio construction.

use std::num::NonZeroUsize;

use anyhow::Context;

use crate::cli::{Cli, HostIntegrationMode};

pub(crate) struct ProcessOptions {
    pub(crate) worker_threads: NonZeroUsize,
    pub(crate) host_integration: HostIntegrationMode,
    pub(crate) logging: Logging,
}

pub(crate) enum Logging {
    Standard {
        verbose: u8,
    },
    Explicit {
        filter: String,
        style: env_logger::WriteStyle,
    },
}

impl ProcessOptions {
    pub(crate) fn from_cli(cli: &Cli) -> Self {
        Self {
            worker_threads: cli.worker_threads,
            host_integration: cli.host_integration,
            logging: Logging::Standard {
                verbose: cli.verbose,
            },
        }
    }
}

impl Logging {
    pub(crate) fn explicit(filter: String, style: &str) -> anyhow::Result<Self> {
        env_filter::Builder::new()
            .try_parse(&filter)
            .map_err(|_| anyhow::anyhow!("The configured log filter is invalid"))?;
        let style = match style {
            "auto" => env_logger::WriteStyle::Auto,
            "always" => env_logger::WriteStyle::Always,
            "never" => env_logger::WriteStyle::Never,
            _ => anyhow::bail!("The configured log style must be auto, always, or never"),
        };
        Ok(Self::Explicit { filter, style })
    }

    pub(crate) fn initialize(&self) -> anyhow::Result<()> {
        match self {
            Self::Explicit { filter, style } => {
                env_logger::Builder::new()
                    .parse_filters(filter)
                    .write_style(*style)
                    .try_init()
                    .context("Failed to initialize logging")?;
            }
            Self::Standard { verbose } => initialize_standard(*verbose)?,
        }
        Ok(())
    }
}

#[cfg(all(feature = "console", tokio_unstable))]
fn initialize_standard(_verbose: u8) -> anyhow::Result<()> {
    console_subscriber::init();
    Ok(())
}

#[cfg(not(all(feature = "console", tokio_unstable)))]
fn initialize_standard(verbose: u8) -> anyhow::Result<()> {
    #[cfg(feature = "console")]
    eprintln!("Tokio Console profiling is disabled. Rebuild with RUSTFLAGS=\"--cfg tokio_unstable\" to enable it.");
    let level = match verbose {
        0 => return Ok(()),
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level))
        .try_init()
        .context("Failed to initialize logging")?;
    Ok(())
}
