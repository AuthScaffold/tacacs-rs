use clap::{arg, Parser, Subcommand};

mod packet;

#[derive(Parser)]
#[command(name = "TACAS Client Cli", version, author)]
#[command(about = "A CLI app with subcommands", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Accounting command
    Accounting {
        /// An arg of the item
        #[arg(long, short)]
        arg1: String,
    },
    /// Authentication command
    Authentication,
    /// Authorization command
    Authorization,
}

pub fn run(cli: Cli) {
    match &cli.command {
        Commands::Accounting { arg1 } => {
            println!("Accounting with arg1: {}", arg1);
        }
        Commands::Authentication => {
            println!("Authentication");
        }
        Commands::Authorization => {
            println!("Authorization");
        }
    }
}

fn main() {
    let cli = Cli::parse();
    run(cli);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run() {
        let cli = Cli::parse_from(vec!["tacon", "accounting", "--arg1", "test_value"]);
        
        let output = std::panic::catch_unwind(|| {
            run(cli);
        });

        assert!(output.is_ok());
    }

    // #[test]
    // fn test_generate_packet() {
    //     let packet = packet::generate_packet(None, None, None, None, None, None, None);
    //     assert_eq!(packet, [16, 1, 1, 1, 222, 173, 190, 239, 0, 0, 0, 1]);
    // }

    // #[test]
    // fn test_generate_default_packet() {
    //     let packet = packet::generate_default_packet();
    //     assert_eq!(packet, [16, 1, 1, 1, 222, 173, 190, 239, 0, 0, 0, 1]);
    // }
}
