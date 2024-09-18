mod commands;

use anyhow::Context;
use clap::{arg, Parser, Subcommand};
use commands::accounting::send_accounting_request;
use tacacsrs_messages::enumerations::TacacsType;

// Define the CLI struct
#[derive(Parser)]
#[command(name = "TACAS Client Cli", version, author)]
#[command(about = "A CLI app with subcommands", long_about = None)]
pub struct Cli {
    #[arg(short, long, action = clap::ArgAction::Count, help = "Increase verbosity")]
    verbose: u8,

    #[arg(short, long, value_name= "BATCH_FILE", help = "Run in batch mode (single connect mode)")]
    batch: Option<String>,

    #[clap(short, long, required_unless_present = "batch")]
    user: Option<String>,
    #[clap(short, long, required_unless_present = "batch")]
    port: Option<String>,
    #[clap(short, long, required_unless_present = "batch")]
    rem_addr: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Accounting command
    Accounting {
        /// The command to run
        cmd: String,

        /// The arguments to pass to the command
        #[arg(value_name= "CMD-ARGS")]
        cmd_args: Option<Vec<String>>,
    },
    /// Authentication command
    Authentication,
    /// Authorization command
    Authorization,
}

pub fn run(cli: Cli) -> anyhow::Result<()> {
    println!("Running with verbose level: {}", cli.verbose);
    if cli.verbose > 0 {
        println!("Verbose level: {}", cli.verbose);
    }

    if let Some(batch_file) = &cli.batch {
        if cli.command.is_some() {
            let message = "Error: --batch flag cannot be used with subcommands.";
            return Err(anyhow::Error::msg(message))
        }
        println!("Running in batch mode, with file: {}", batch_file);
    }


    if let Some(command) = &cli.command {
        println!("Running command: {:?}", command);
        match command {
            Commands::Accounting { cmd, cmd_args } => {
                if cmd.is_empty() {
                    // Print help message and return an error
                    return Err(anyhow::Error::msg("Accounting command requires a positional cmd argument"));
                } else {
                    let user = cli.user.as_ref().ok_or_else(|| anyhow::Error::msg("User is required"))?;
                    let port = cli.port.as_ref().ok_or_else(|| anyhow::Error::msg("Port is required"))?;
                    let rem_addr = cli.rem_addr.as_ref().ok_or_else(|| anyhow::Error::msg("Remote address is required"))?;

                    // let session = session_manager.create_session(TacacsType::TacPlusAccounting)?;
                    // println!("Session created: {:?}", session.session_id);

                    // send_accounting_request(&session, user, port, rem_addr, cmd, cmd_args)?;
                }
            }
            Commands::Authentication => {
                println!("Authentication");
            }
            Commands::Authorization => {
                println!("Authorization");
            }
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli).context("run failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accounting_subcommand() {
        let cli = Cli::parse_from(vec![
            "tacon", "-vv", "--user", "test_user", "--port", "test_port", "--rem-addr", "test_rem_address", "accounting", "cmd", "cmd-arg1", "cmd-arg2", 
        ]);
        
        let output = std::panic::catch_unwind(|| {
            run(cli)
        });

        assert!(output.is_ok());
    }

    #[test]
    fn test_accounting_subcommand_no_command() {
        let output = std::panic::catch_unwind(|| {
            let cli = Cli::try_parse_from(vec!["tacon", "-vv", "--user", "test_user", "--port", "test_port", "--rem-addr", "test_rem_address", "accounting"])?;
            run(cli)
        });

        assert!(output.is_ok());
        let output = output.unwrap();
        assert!(output.is_err());


        let error = output.unwrap_err();
        assert_eq!(error.to_string(), "error: the following required arguments were not provided:\n  <CMD>\n\nUsage: tacon accounting <CMD> [CMD-ARGS]...\n\nFor more information, try '--help'.\n");

    }

    #[test]
    fn test_authentication_subcommand() {
        let cli = Cli::parse_from(vec!["tacon", "--verbose", "--user", "test_user", "--port", "test_port", "--rem-addr", "test_rem_address", "authentication"]);
        
        let output = std::panic::catch_unwind(|| {
            run(cli)
        });

        assert!(output.is_ok());
    }

    #[test]
    fn test_authorization_subcommand() {
        let cli = Cli::parse_from(vec!["tacon", "--verbose", "--user", "test_user", "--port", "test_port", "--rem-addr", "test_rem_address", "authorization"]);
        
        let output = std::panic::catch_unwind(|| {
            run(cli)
        });

        assert!(output.is_ok());
    }

    #[test]
    fn test_subcommand_no_user_port_remaddr() {
        let output = std::panic::catch_unwind(|| {
            let cli = Cli::try_parse_from(vec!["tacon", "-vv", "accounting", "test-cmd"])?;
            run(cli)
        });

        assert!(output.is_ok());
        let output = output.unwrap();
        assert!(output.is_err());


        let error = output.unwrap_err();
        assert_eq!(error.to_string(), "error: the following required arguments were not provided:\n  --user <USER>\n  --port <PORT>\n  --rem-addr <REM_ADDR>\n\nUsage: tacon --verbose... --user <USER> --port <PORT> --rem-addr <REM_ADDR>\n\nFor more information, try '--help'.\n");

    }

    #[test]
    fn test_batch_mode() {
        let cli = Cli::parse_from(vec!["tacon", "--batch", "batch_file.txt", "--verbose"]);
        
        let output = std::panic::catch_unwind(|| {
            run(cli)
        });

        assert!(output.is_ok());
    }

    #[test]
    fn test_batch_mode_with_user_port_remaddr() {
        // This test will succeed because the user, port, and rem-addr flags ARE allowed when using the --batch flag, to override the values in the batch file.
        let cli = Cli::parse_from(vec!["tacon", "--batch", "batch_file.txt", "--verbose", "--user", "test_user", "--port", "test_port", "--rem-addr", "test_rem_address"]);
        
        let output = std::panic::catch_unwind(|| {
            run(cli)
        });

        assert!(output.is_ok());
    }

    #[test]
    fn test_batch_mode_with_subcommand() {
        let cli = Cli::parse_from(vec!["tacon", "--batch", "batch_file.txt", "accounting", "test_value"]);
        
        let output = std::panic::catch_unwind(|| {
            run(cli)
        });

        assert!(output.is_ok());
        let output = output.unwrap();
        assert!(output.is_err());


        let error = output.unwrap_err();
        assert_eq!(error.to_string(), "Error: --batch flag cannot be used with subcommands.");
    }
}