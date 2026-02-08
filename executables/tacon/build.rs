use std::env;
use std::fs;
use std::path::PathBuf;

use clap::CommandFactory;

// Include the CLI module to generate the man page from the actual CLI definitions.
// This is safe because cli.rs only depends on clap, which is available in build-dependencies.
// This ensures the man page is always in sync with the actual CLI implementation.
include!("src/cli.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate man page using clap_mangen
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let man_dir = out_dir.join("man");
    fs::create_dir_all(&man_dir)?;

    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;

    fs::write(man_dir.join("tacon.1"), buffer)?;

    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=src/main.rs");

    Ok(())
}

