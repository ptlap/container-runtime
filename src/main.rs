use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use container_runtime::cgroup::{read_stats, CgroupConfig};
use container_runtime::container::{run_process, ProcessConfig};
use container_runtime::container_exec::{exec_in_container, ExecConfig};
use container_runtime::namespace::namespace_flags;
use container_runtime::network::NetworkMode;
use container_runtime::security::SecurityProfile;
use container_runtime::signal::{parse_signal, send_signal, DEFAULT_SIGNAL};
use container_runtime::spec::config::load_config;
use container_runtime::state::{
    self, ContainerState, ContainerStatus, RuntimeMetadata, StartedResources,
};
use container_runtime::userns::{UserNamespaceMap, UserNamespaceMode};
use nix::sched::CloneFlags;
use std::io::IsTerminal;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};
use std::{fs, io};

const DEFAULT_STOP_TIMEOUT_SECS: u64 = 10;

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
        #[arg(long, value_enum, default_value_t = CliNetworkMode::Bridge)]
        net: CliNetworkMode,
        #[arg(long, value_enum, default_value_t = CliSecurityProfile::Default)]
        security: CliSecurityProfile,
        #[arg(long, value_enum, default_value_t = CliLogMode::Auto)]
        log: CliLogMode,
        #[arg(long, value_enum, default_value_t = CliUsernsMode::Host)]
        userns: CliUsernsMode,
        id: String,
        bundle: PathBuf,
    },
    Create {
        #[arg(long, value_enum, default_value_t = CliNetworkMode::Bridge)]
        net: CliNetworkMode,
        #[arg(long, value_enum, default_value_t = CliSecurityProfile::Default)]
        security: CliSecurityProfile,
        #[arg(long, value_enum, default_value_t = CliLogMode::Auto)]
        log: CliLogMode,
        #[arg(long, value_enum, default_value_t = CliUsernsMode::Host)]
        userns: CliUsernsMode,
        id: String,
        bundle: PathBuf,
    },
    Start {
        id: String,
    },
    State {
        id: String,
        #[arg(long)]
        json: bool,
    },
    Stats {
        id: String,
        #[arg(long)]
        json: bool,
    },
    Ps {
        #[arg(long)]
        json: bool,
    },
    Exec {
        id: String,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    Logs {
        id: String,
        #[arg(long)]
        follow: bool,
    },
    Kill {
        id: String,
        #[arg(long, default_value = DEFAULT_SIGNAL)]
        signal: String,
    },
    Stop {
        id: String,
        #[arg(long, default_value_t = DEFAULT_STOP_TIMEOUT_SECS)]
        timeout: u64,
    },
    Delete {
        id: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliNetworkMode {
    Host,
    None,
    Bridge,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSecurityProfile {
    Default,
    Unconfined,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliLogMode {
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliUsernsMode {
    Host,
    Private,
}

#[derive(Debug, Clone, Copy)]
enum LogMode {
    Auto,
    On,
    Off,
}

impl From<CliNetworkMode> for NetworkMode {
    fn from(value: CliNetworkMode) -> Self {
        match value {
            CliNetworkMode::Host => Self::Host,
            CliNetworkMode::None => Self::None,
            CliNetworkMode::Bridge => Self::Bridge,
        }
    }
}

impl From<CliSecurityProfile> for SecurityProfile {
    fn from(value: CliSecurityProfile) -> Self {
        match value {
            CliSecurityProfile::Default => Self::Default,
            CliSecurityProfile::Unconfined => Self::Unconfined,
        }
    }
}

impl From<CliLogMode> for LogMode {
    fn from(value: CliLogMode) -> Self {
        match value {
            CliLogMode::Auto => Self::Auto,
            CliLogMode::On => Self::On,
            CliLogMode::Off => Self::Off,
        }
    }
}

impl LogMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::On => "on",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Clone)]
struct RunOptions {
    id: String,
    bundle: PathBuf,
    network_mode: NetworkMode,
    security_profile: SecurityProfile,
    log_mode: LogMode,
    userns_mode: UserNamespaceMode,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Run {
            net,
            security,
            log,
            userns,
            id,
            bundle,
        } => run_container(RunOptions {
            id,
            bundle,
            network_mode: net.into(),
            security_profile: security.into(),
            log_mode: log.into(),
            userns_mode: userns_mode_from_cli(userns)?,
        })?,
        Command::Create {
            net,
            security,
            log,
            userns,
            id,
            bundle,
        } => create_container(RunOptions {
            id,
            bundle,
            network_mode: net.into(),
            security_profile: security.into(),
            log_mode: log.into(),
            userns_mode: userns_mode_from_cli(userns)?,
        })?,
        Command::Start { id } => start_container(&id)?,
        Command::State { id, json } => show_state(&id, json)?,
        Command::Stats { id, json } => show_stats(&id, json)?,
        Command::Ps { json } => list_containers(json)?,
        Command::Exec { id, args } => exec_container(&id, &args)?,
        Command::Logs { id, follow } => show_logs(&id, follow)?,
        Command::Kill { id, signal } => kill_container(&id, &signal)?,
        Command::Stop { id, timeout } => stop_container(&id, timeout)?,
        Command::Delete { id } => delete_container(&id)?,
    }

    Ok(())
}

fn run_container(options: RunOptions) -> Result<()> {
    if state::exists(&options.id)? {
        bail!("container id already exists: {}", options.id);
    }

    execute_container(options, None)
}

fn create_container(options: RunOptions) -> Result<()> {
    if state::exists(&options.id)? {
        bail!("container id already exists: {}", options.id);
    }

    load_config(options.bundle.join("config.json"))?;

    let state = ContainerState::created(
        &options.id,
        &options.bundle,
        RuntimeMetadata {
            network_mode: options.network_mode.as_str(),
            security_profile: options.security_profile.as_str(),
            log_mode: options.log_mode.as_str(),
            userns_mode: options.userns_mode.as_str(),
        },
    )?;
    state::save(&state)?;
    println!("created container: {}", options.id);

    Ok(())
}

fn start_container(id: &str) -> Result<()> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Created {
        bail!("container {id} is not created");
    }

    let options = RunOptions {
        id: state.id.clone(),
        bundle: PathBuf::from(&state.bundle),
        network_mode: parse_network_mode(&state.network_mode)?,
        security_profile: parse_security_profile(&state.security_profile)?,
        log_mode: parse_log_mode(&state.log_mode)?,
        userns_mode: parse_userns_mode(&state.userns_mode)?,
    };

    execute_container(options, Some(state))
}

fn execute_container(
    options: RunOptions,
    mut existing_state: Option<ContainerState>,
) -> Result<()> {
    let id = options.id;
    let bundle = options.bundle;
    let network_mode = options.network_mode;
    let security_profile = options.security_profile;
    let log_mode = options.log_mode;
    let userns_mode = options.userns_mode;

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

    let flags = apply_userns_mode(
        apply_network_mode(namespace_flags(&namespaces), network_mode),
        userns_mode,
    );

    println!("namespaces: {:?}", namespaces);
    println!("clone flags: {:?}", flags);
    println!("network mode: {}", network_mode.as_str());
    println!("security profile: {}", security_profile.as_str());
    println!("log mode: {}", log_mode.as_str());
    println!("user namespace: {}", userns_mode.as_str());

    let cgroup_config = config.linux.as_ref().and_then(|linux| {
        linux.resources.as_ref().map(|resources| CgroupConfig {
            memory_limit: resources.memory.as_ref().and_then(|m| m.limit),
            cpu_quota: resources.cpu.as_ref().and_then(|c| c.quota),
            cpu_period: resources.cpu.as_ref().and_then(|c| c.period),
            pids_limit: resources.pids.as_ref().and_then(|p| p.limit),
        })
    });

    let log_path = state::log_path(&id)?;
    let capture_logs = should_capture_logs(log_mode);
    let mut running_state = None;
    let mut save_started_state = |started: container_runtime::container::StartedProcess| {
        let cgroup_path = started
            .cgroup_path
            .as_ref()
            .map(|path| path.display().to_string());
        let network_subnet = started.network_subnet.clone();
        let log_path = capture_logs.then(|| log_path.display().to_string());
        let resources = StartedResources {
            cgroup_path,
            network_subnet,
            log_path,
        };
        let state = if let Some(mut state) = existing_state.take() {
            state.mark_running(started.pid, resources, log_mode.as_str())?;
            state
        } else {
            ContainerState::running(
                &id,
                &bundle,
                started.pid,
                resources,
                RuntimeMetadata {
                    network_mode: network_mode.as_str(),
                    security_profile: security_profile.as_str(),
                    log_mode: log_mode.as_str(),
                    userns_mode: userns_mode.as_str(),
                },
            )?
        };
        state::save(&state)?;
        running_state = Some(state);
        Ok(())
    };

    let process_config = ProcessConfig {
        id: &id,
        hostname: config.hostname.as_deref(),
        args: &config.process.args,
        env: &config.process.env,
        cwd: config.process.cwd.as_deref(),
        rootfs: &rootfs,
        readonly_rootfs: config.root.readonly,
        mounts: &config.mounts,
        log_path: capture_logs.then_some(log_path.as_path()),
        flags,
        cgroup_config,
        network_mode,
        security_profile,
        userns_mode,
    };

    let process_exit = run_process(process_config, &mut save_started_state)?;
    let exit_code = process_exit.code;
    let exit_signal = process_exit.signal.clone();
    let child_error = process_exit.error.clone();

    if let Some(mut state) = running_state {
        state
            .mark_stopped(exit_code, exit_signal.clone())
            .context("failed to update stopped state")?;
        state::save(&state)?;
    }

    if let Some(error) = child_error {
        bail!("container child failed: {error}");
    }

    exit_with_process_status(exit_code, exit_signal.as_deref());
}

fn parse_network_mode(value: &str) -> Result<NetworkMode> {
    match value {
        "host" => Ok(NetworkMode::Host),
        "none" => Ok(NetworkMode::None),
        "bridge" => Ok(NetworkMode::Bridge),
        _ => bail!("invalid network mode in state: {value}"),
    }
}

fn parse_security_profile(value: &str) -> Result<SecurityProfile> {
    match value {
        "default" => Ok(SecurityProfile::Default),
        "unconfined" => Ok(SecurityProfile::Unconfined),
        _ => bail!("invalid security profile in state: {value}"),
    }
}

fn parse_log_mode(value: &str) -> Result<LogMode> {
    match value {
        "auto" => Ok(LogMode::Auto),
        "on" => Ok(LogMode::On),
        "off" => Ok(LogMode::Off),
        _ => bail!("invalid log mode in state: {value}"),
    }
}

fn parse_userns_mode(value: &str) -> Result<UserNamespaceMode> {
    match value {
        "host" => Ok(UserNamespaceMode::Host),
        "private" => Ok(UserNamespaceMode::Private(invoking_user_map()?)),
        _ => bail!("invalid user namespace mode in state: {value}"),
    }
}

fn userns_mode_from_cli(value: CliUsernsMode) -> Result<UserNamespaceMode> {
    match value {
        CliUsernsMode::Host => Ok(UserNamespaceMode::Host),
        CliUsernsMode::Private => Ok(UserNamespaceMode::Private(invoking_user_map()?)),
    }
}

fn invoking_user_map() -> Result<UserNamespaceMap> {
    let current_uid = nix::unistd::getuid().as_raw();
    let current_gid = nix::unistd::getgid().as_raw();

    if current_uid == 0 {
        return Ok(UserNamespaceMap {
            host_uid: 0,
            host_gid: current_gid,
        });
    }

    Ok(UserNamespaceMap {
        host_uid: env_uid("SUDO_UID")?.unwrap_or(current_uid),
        host_gid: env_uid("SUDO_GID")?.unwrap_or(current_gid),
    })
}

fn env_uid(key: &str) -> Result<Option<u32>> {
    let Some(value) = std::env::var_os(key) else {
        return Ok(None);
    };
    let value = value.to_string_lossy();
    let parsed = value
        .parse::<u32>()
        .with_context(|| format!("{key} is not a valid uid/gid: {value}"))?;
    Ok(Some(parsed))
}

fn show_state(id: &str, json: bool) -> Result<()> {
    let state = state::load_current(id)?;

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
        println!(
            "cgroup_path: {}",
            state.cgroup_path.as_deref().unwrap_or("-")
        );
        println!("network_mode: {}", state.network_mode);
        if let Some(subnet) = state.network_subnet {
            println!("network_subnet: {subnet}");
        }
        if let Some(log_path) = state.log_path {
            println!("log_path: {log_path}");
        }
        println!("log_mode: {}", state.log_mode);
        println!("security_profile: {}", state.security_profile);
        println!("userns_mode: {}", state.userns_mode);
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

fn apply_network_mode(mut flags: CloneFlags, network_mode: NetworkMode) -> CloneFlags {
    match network_mode {
        NetworkMode::Host => flags.remove(CloneFlags::CLONE_NEWNET),
        NetworkMode::None | NetworkMode::Bridge => flags.insert(CloneFlags::CLONE_NEWNET),
    }

    flags
}

fn apply_userns_mode(mut flags: CloneFlags, userns_mode: UserNamespaceMode) -> CloneFlags {
    match userns_mode {
        UserNamespaceMode::Host => flags.remove(CloneFlags::CLONE_NEWUSER),
        UserNamespaceMode::Private(_) => flags.insert(CloneFlags::CLONE_NEWUSER),
    }

    flags
}

fn show_stats(id: &str, json: bool) -> Result<()> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Running {
        bail!("container {id} is not running");
    }

    let Some(cgroup_path) = state.cgroup_path.as_deref() else {
        bail!("container {id} has no cgroup path");
    };

    let cgroup_path = Path::new(cgroup_path);
    if !cgroup_path.exists() {
        bail!("cgroup path does not exist: {}", cgroup_path.display());
    }

    let stats = read_stats(cgroup_path)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        println!("id: {id}");
        println!("cgroup_path: {}", stats.path);
        if let Some(value) = stats.memory_current {
            println!("memory_current: {value}");
        }
        if let Some(value) = stats.memory_max {
            println!("memory_max: {value}");
        }
        if let Some(value) = stats.cpu_usage_usec {
            println!("cpu_usage_usec: {value}");
        }
        if let Some(value) = stats.cpu_user_usec {
            println!("cpu_user_usec: {value}");
        }
        if let Some(value) = stats.cpu_system_usec {
            println!("cpu_system_usec: {value}");
        }
        if let Some(value) = stats.pids_current {
            println!("pids_current: {value}");
        }
        if let Some(value) = stats.pids_max {
            println!("pids_max: {value}");
        }
    }

    Ok(())
}

fn list_containers(json: bool) -> Result<()> {
    let states = state::list()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&states)?);
        return Ok(());
    }

    println!(
        "{:<24} {:<10} {:<8} {:<8} {:<11} {:<8} BUNDLE",
        "ID", "STATUS", "PID", "NET", "SECURITY", "USERNS"
    );
    for state in states {
        println!(
            "{:<24} {:<10} {:<8} {:<8} {:<11} {:<8} {}",
            state.id,
            format!("{:?}", state.status).to_lowercase(),
            state.pid.map_or("-".to_string(), |pid| pid.to_string()),
            state.network_mode,
            state.security_profile,
            state.userns_mode,
            state.bundle
        );
    }

    Ok(())
}

fn exec_container(id: &str, args: &[String]) -> Result<()> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Running {
        bail!("container {id} is not running");
    }

    let Some(pid) = state.pid else {
        bail!("container {id} has no pid");
    };

    let config = load_config(PathBuf::from(&state.bundle).join("config.json"))?;

    let exit = exec_in_container(ExecConfig {
        target_pid: pid,
        args,
        env: &config.process.env,
        cwd: config.process.cwd.as_deref(),
        cgroup_path: state.cgroup_path.as_deref(),
    })?;

    let exit_code = exit.code;
    let exit_signal = exit.signal.clone();

    match (exit_code, exit_signal.as_deref()) {
        (Some(code), _) => println!("exec process exited with code: {code}"),
        (None, Some(signal)) => println!("exec process killed by signal: {signal}"),
        (None, None) => println!("exec process ended without exit status"),
    }

    exit_with_process_status(exit_code, exit_signal.as_deref());
}

fn exit_with_process_status(code: Option<i32>, signal: Option<&str>) -> ! {
    std::process::exit(process_exit_status(code, signal));
}

fn process_exit_status(code: Option<i32>, signal: Option<&str>) -> i32 {
    match (code, signal) {
        (Some(code), _) if (0..=255).contains(&code) => code,
        (Some(code), _) if code < 0 => 1,
        (Some(_), _) => 255,
        (None, Some(_)) => 128,
        (None, None) => 1,
    }
}

fn should_capture_logs(log_mode: LogMode) -> bool {
    match log_mode {
        LogMode::Auto => !io::stdin().is_terminal(),
        LogMode::On => true,
        LogMode::Off => false,
    }
}

fn show_logs(id: &str, follow: bool) -> Result<()> {
    let state = state::load_current(id)?;
    let log_path = state
        .log_path
        .as_deref()
        .map(PathBuf::from)
        .unwrap_or(state::log_path(id)?);

    if follow {
        follow_logs(&log_path)?;
    } else {
        let content = fs::read_to_string(&log_path)
            .with_context(|| format!("failed to read log file: {}", log_path.display()))?;
        print!("{content}");
    }

    Ok(())
}

fn follow_logs(log_path: &Path) -> Result<()> {
    let mut position = 0usize;

    loop {
        if let Ok(content) = fs::read_to_string(log_path) {
            if content.len() > position {
                print!("{}", &content[position..]);
                position = content.len();
            }
        }

        io::Write::flush(&mut io::stdout()).context("failed to flush stdout")?;
        thread::sleep(Duration::from_millis(250));
    }
}

fn kill_container(id: &str, signal: &str) -> Result<()> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Running {
        bail!("container {id} is not running");
    }

    let Some(pid) = state.pid else {
        bail!("container {id} has no pid");
    };

    let signal_number = parse_signal(signal)?;
    send_signal(pid, signal_number).with_context(|| {
        format!("failed to send signal {signal} ({signal_number}) to container {id} pid {pid}")
    })?;
    println!("sent signal {signal} to container {id} pid {pid}");

    Ok(())
}

fn stop_container(id: &str, timeout_secs: u64) -> Result<()> {
    kill_container(id, "SIGTERM")?;

    if wait_for_stopped(id, Duration::from_secs(timeout_secs))? {
        println!("container stopped: {id}");
        return Ok(());
    }

    println!("container {id} did not stop after {timeout_secs}s; sending SIGKILL");
    kill_container(id, "SIGKILL")?;

    if wait_for_stopped(id, Duration::from_secs(5))? {
        println!("container killed: {id}");
        return Ok(());
    }

    bail!("container {id} did not stop after SIGKILL");
}

fn wait_for_stopped(id: &str, timeout: Duration) -> Result<bool> {
    let deadline = Instant::now() + timeout;

    loop {
        if state::load_current(id)?.status == ContainerStatus::Stopped {
            return Ok(true);
        }

        if Instant::now() >= deadline {
            return Ok(false);
        }

        thread::sleep(Duration::from_millis(100));
    }
}

fn delete_container(id: &str) -> Result<()> {
    state::delete(id)?;
    println!("deleted container state: {id}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_process_exit_code_to_cli_status() {
        assert_eq!(process_exit_status(Some(0), None), 0);
        assert_eq!(process_exit_status(Some(42), None), 42);
    }

    #[test]
    fn clamps_process_exit_code_to_shell_range() {
        assert_eq!(process_exit_status(Some(300), None), 255);
        assert_eq!(process_exit_status(Some(-1), None), 1);
    }

    #[test]
    fn maps_signal_and_missing_status_to_nonzero_cli_status() {
        assert_eq!(process_exit_status(None, Some("SIGKILL")), 128);
        assert_eq!(process_exit_status(None, None), 1);
    }

    #[test]
    fn does_not_capture_logs_for_interactive_shell() {
        assert!(should_capture_logs(LogMode::On));
        assert!(!should_capture_logs(LogMode::Off));
    }
}
