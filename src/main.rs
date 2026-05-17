use anyhow::Result;
use clap::{Parser, Subcommand};
use container_runtime::cgroup::CgroupConfig;
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
        .as_ref()
        .map(|linux| {
            linux
                .namespaces
                .iter()
                .map(|ns| ns.namespace_type.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let flags = namespace_flags(&namespaces);

    println!("namespaces: {:?}", namespaces);
    println!("clone flags: {:?}", flags);

    let cgroup_config = config.linux.as_ref().and_then(|linux| {
        linux.resources.as_ref().map(|resources| CgroupConfig {
            memory_limit: resources.memory.as_ref().and_then(|m| m.limit),
            cpu_quota: resources.cpu.as_ref().and_then(|c| c.quota),
            cpu_period: resources.cpu.as_ref().and_then(|c| c.period),
        })
    });

    run_process(
        &config.process.args,
        &config.process.env,
        config.process.cwd.as_deref(),
        &rootfs,
        flags,
        cgroup_config,
    )?;

    Ok(())
}
