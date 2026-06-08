use std::env;
use std::fs;

use clap::CommandFactory;

mod cli {
    include!("src/cli.rs");
}

use cli::Cli;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(env::var("OUT_DIR")?);
    let man_dir = out_dir.join("man");
    fs::create_dir_all(&man_dir)?;

    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    let mut buffer = Vec::new();
    man.render(&mut buffer)?;

    fs::write(man_dir.join("tacacsrs-agentd.1"), buffer)?;

    println!("cargo:rerun-if-changed=src/cli.rs");
    println!("cargo:rerun-if-changed=src/main.rs");

    Ok(())
}
