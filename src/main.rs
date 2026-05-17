use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use container_runtime::cgroup::CgroupConfig;
use container_runtime::container::{run_process, ProcessConfig};
use container_runtime::namespace::namespace_flags;
use container_runtime::spec::config::load_config;
use container_runtime::state::{self, ContainerState};
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
    Run {
        id: String,
        bundle: PathBuf,
    },
    State {
        id: String,
        #[arg(long)]
        json: bool,
    },
    Delete {
        id: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run { id, bundle } => run_container(id, bundle)?,
        Command::State { id, json } => show_state(&id, json)?,
        Command::Delete { id } => delete_container(&id)?,
    }

    Ok(())
}

fn run_container(id: String, bundle: PathBuf) -> Result<()> {
    if state::exists(&id)? {
        bail!("container id already exists: {id}");
    }

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

    let mut running_state = None;
    let mut save_started_state = |pid| {
        let state = ContainerState::running(&id, &bundle, pid)?;
        state::save(&state)?;
        running_state = Some(state);
        Ok(())
    };

    let process_config = ProcessConfig {
        args: &config.process.args,
        env: &config.process.env,
        cwd: config.process.cwd.as_deref(),
        rootfs: &rootfs,
        readonly_rootfs: config.root.readonly,
        flags,
        cgroup_config,
    };

    let process_exit = run_process(process_config, &mut save_started_state)?;

    if let Some(mut state) = running_state {
        state
            .mark_stopped(process_exit.code, process_exit.signal)
            .context("failed to update stopped state")?;
        state::save(&state)?;
    }

    Ok(())
}

fn show_state(id: &str, json: bool) -> Result<()> {
    let state = state::load(id)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&state)?);
    } else {
        println!("id: {}", state.id);
        println!("status: {:?}", state.status);
        println!(
            "pid: {}",
            state.pid.map_or("-".to_string(), |pid| pid.to_string())
        );
        println!("bundle: {}", state.bundle);
        println!("created_at_unix: {}", state.created_at_unix);
        println!("updated_at_unix: {}", state.updated_at_unix);
        if let Some(code) = state.exit_code {
            println!("exit_code: {code}");
        }
        if let Some(signal) = state.signal {
            println!("signal: {signal}");
        }
    }

    Ok(())
}

fn delete_container(id: &str) -> Result<()> {
    state::delete(id)?;
    println!("deleted container state: {id}");
    Ok(())
}
