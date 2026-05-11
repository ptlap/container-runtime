use anyhow::Result;
use clap::{Parser, Subcommand};
use container_runtime::container::run_process;
use container_runtime::namespace::namespace_flags;
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
        Command::Run { bundle } => run_container(bundle)?,
    }

    Ok(())
}

fn run_container(bundle: PathBuf) -> Result<()> {
    let config_path = bundle.join("config.json");
    let config = load_config(config_path)?;

    let rootfs = bundle.join(&config.root.path);

    println!("args: {:?}", config.process.args);
    println!("env: {:?}", config.process.env);
    println!("rootfs: {}", rootfs.display());

    let namespaces = config
        .linux
        .map(|linux| {
            linux
                .namespaces
                .into_iter()
                .map(|ns| ns.namespace_type)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let flags = namespace_flags(&namespaces);

    println!("namespaces: {:?}", namespaces);
    println!("clone flags: {:?}", flags);

    run_process(&config.process.args, &rootfs, flags)?;

    Ok(())
}
