use anyhow::Result;
use clap::{Parser, Subcommand};
use container_runtime::spec::config::load_config;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "crun")]
#[command(about = "A minimal Linux container runtime written in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run { bundle: PathBuf },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run { bundle } => {
            let config_path = bundle.join("config.json");
            let config = load_config(config_path)?;

            println!("args: {:?}", config.process.args);
            println!("env: {:?}", config.process.env);
            println!("rootfs: {}", config.root.path);

            if let Some(linux) = config.linux {
                for ns in linux.namespaces {
                    println!("namespaces: {}", ns.namespace_type);
                }
            }
        }
    }

    Ok(())
}
