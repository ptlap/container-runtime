use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use container_runtime::audit_log::{self, AuditEvent as RuntimeEvent};
use container_runtime::cgroup::read_container_stats;
use container_runtime::checkpoint::{self, CheckpointOptions, RestoreOptions};
use container_runtime::cli_runtime::{process_exit_status, should_capture_logs};
use container_runtime::doctor;
use container_runtime::error::LifecycleError;
use container_runtime::events::stream_counter_events;
use container_runtime::health::{self, HealthResult};
use container_runtime::image;
use container_runtime::inspect_security;
use container_runtime::lifecycle::{self, CreateOptions};
use container_runtime::modes::{
    parse_log_mode, parse_network_mode, parse_security_profile, LogMode,
};
use container_runtime::network::NetworkMode;
use container_runtime::policy;
use container_runtime::rootfs_diff;
use container_runtime::security::SecurityProfile;
use container_runtime::selfexec::{
    current_exe_link, ensure_reexecuted_from_memfd, is_running_from_memfd,
};
use container_runtime::signal::DEFAULT_SIGNAL;
use container_runtime::spec::config::load_config;
use container_runtime::state::{self, ContainerState};
use container_runtime::trace::{self, ProcessNode, TraceOptions, TraceReport};
use container_runtime::userns::{UserNamespaceMap, UserNamespaceMode};
use std::io::IsTerminal;
use std::path::Path;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;
use std::{fs, io};

const DEFAULT_STOP_TIMEOUT_SECS: u64 = 10;
const DEFAULT_EVENTS_INTERVAL_MS: u64 = 1000;

#[derive(Debug, Parser)]
#[command(name = "crun")]
#[command(about = "A minimal Linux container runtime written in Rust")]
struct Cli {
    #[arg(long, default_value = "info", global = true)]
    log_level: String,

    #[arg(long, default_value = "text", global = true)]
    log_format: String,

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
        #[arg(short, long)]
        tty: bool,
        id: String,
        bundle: PathBuf,
    },
    RunImage {
        #[arg(long, value_enum, default_value_t = CliNetworkMode::Bridge)]
        net: CliNetworkMode,
        #[arg(long, value_enum, default_value_t = CliSecurityProfile::Default)]
        security: CliSecurityProfile,
        #[arg(long, value_enum, default_value_t = CliLogMode::Auto)]
        log: CliLogMode,
        #[arg(long, value_enum, default_value_t = CliUsernsMode::Host)]
        userns: CliUsernsMode,
        #[arg(short, long)]
        tty: bool,
        name: String,
        id: String,
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
        #[arg(short, long)]
        tty: bool,
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
    Events {
        id: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        history: bool,
        #[arg(long)]
        snapshot: bool,
        #[arg(long)]
        once: bool,
        #[arg(long, default_value_t = DEFAULT_EVENTS_INTERVAL_MS)]
        interval_ms: u64,
    },
    Health {
        id: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        watch: bool,
        #[arg(long, default_value_t = DEFAULT_EVENTS_INTERVAL_MS)]
        interval_ms: u64,
    },
    Ps {
        #[arg(long)]
        json: bool,
    },
    Exec {
        #[arg(short, long)]
        tty: bool,
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
    Doctor {
        #[arg(long)]
        fix: bool,
        #[arg(long)]
        json: bool,
    },
    InspectSecurity {
        id: String,
        #[arg(long)]
        json: bool,
    },
    Diff {
        id: String,
        #[arg(long)]
        json: bool,
    },
    Validate {
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    Trace {
        id: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        strace: bool,
        #[arg(long, default_value_t = 1000)]
        duration_ms: u64,
    },
    Checkpoint {
        id: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        images_dir: Option<PathBuf>,
    },
    Restore {
        id: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        images_dir: Option<PathBuf>,
    },
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    Debug {
        #[command(subcommand)]
        command: DebugCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ImageCommand {
    Import {
        rootfs_tar: PathBuf,
        name: String,
    },
    List {
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
enum DebugCommand {
    SelfExec,
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

#[derive(Debug, Clone)]
struct RunOptions {
    id: String,
    bundle: PathBuf,
    network_mode: NetworkMode,
    security_profile: SecurityProfile,
    log_mode: LogMode,
    userns_mode: UserNamespaceMode,
    tty: bool,
}

#[derive(Debug, Clone)]
struct RunImageOptions {
    name: String,
    id: String,
    network_mode: NetworkMode,
    security_profile: SecurityProfile,
    log_mode: LogMode,
    userns_mode: UserNamespaceMode,
    tty: bool,
}

fn init_logging(log_level: &str, log_format: &str) -> Result<()> {
    use tracing_subscriber::filter::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    if log_format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
            .map_err(|e| anyhow::anyhow!("failed to initialize json logger: {e}"))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .map_err(|e| anyhow::anyhow!("failed to initialize text logger: {e}"))?;
    }
    Ok(())
}

fn main() -> Result<()> {
    ensure_reexecuted_from_memfd()?;

    let cli = Cli::parse();
    init_logging(&cli.log_level, &cli.log_format)?;

    match cli.command {
        Command::Run {
            net,
            security,
            log,
            userns,
            tty,
            id,
            bundle,
        } => run_container(RunOptions {
            id,
            bundle,
            network_mode: net.into(),
            security_profile: security.into(),
            log_mode: log.into(),
            userns_mode: userns_mode_from_cli(userns)?,
            tty,
        })?,
        Command::Create {
            net,
            security,
            log,
            userns,
            tty,
            id,
            bundle,
        } => create_container(RunOptions {
            id,
            bundle,
            network_mode: net.into(),
            security_profile: security.into(),
            log_mode: log.into(),
            userns_mode: userns_mode_from_cli(userns)?,
            tty,
        })?,
        Command::Start { id } => start_container(&id)?,
        Command::State { id, json } => show_state(&id, json)?,
        Command::Stats { id, json } => show_stats(&id, json)?,
        Command::Events {
            id,
            json,
            history,
            snapshot,
            once,
            interval_ms,
        } => stream_events(&id, json, history, snapshot, once, interval_ms)?,
        Command::Health {
            id,
            json,
            watch,
            interval_ms,
        } => run_healthcheck(&id, json, watch, interval_ms)?,
        Command::Ps { json } => list_containers(json)?,
        Command::Exec { tty, id, args } => exec_container(&id, &args, tty)?,
        Command::Logs { id, follow } => show_logs(&id, follow)?,
        Command::Kill { id, signal } => kill_container(&id, &signal)?,
        Command::Stop { id, timeout } => stop_container(&id, timeout)?,
        Command::Delete { id } => delete_container(&id)?,
        Command::Doctor { fix, json } => run_doctor(fix, json)?,
        Command::InspectSecurity { id, json } => inspect_security_command(&id, json)?,
        Command::Diff { id, json } => diff_rootfs(&id, json)?,
        Command::Validate { bundle, json } => validate_bundle(&bundle, json)?,
        Command::Trace {
            id,
            json,
            strace,
            duration_ms,
        } => trace_container(&id, json, strace, duration_ms)?,
        Command::Checkpoint {
            id,
            json,
            images_dir,
        } => checkpoint_container(&id, json, images_dir)?,
        Command::Restore {
            id,
            json,
            images_dir,
        } => restore_container(&id, json, images_dir)?,
        Command::Image { command } => image_command(command)?,
        Command::RunImage {
            net,
            security,
            log,
            userns,
            tty,
            name,
            id,
        } => run_image(RunImageOptions {
            name,
            id,
            network_mode: net.into(),
            security_profile: security.into(),
            log_mode: log.into(),
            userns_mode: userns_mode_from_cli(userns)?,
            tty,
        })?,
        Command::Debug { command } => debug_command(command)?,
    }

    Ok(())
}

fn image_command(command: ImageCommand) -> Result<()> {
    match command {
        ImageCommand::Import { rootfs_tar, name } => import_image(&rootfs_tar, &name),
        ImageCommand::List { json } => list_images(json),
    }
}

fn import_image(rootfs_tar: &Path, name: &str) -> Result<()> {
    let image = image::import(rootfs_tar, name)?;
    println!("imported image: {}", image.name);
    println!("path: {}", image.path);
    println!("rootfs: {}", image.rootfs);
    Ok(())
}

fn list_images(json: bool) -> Result<()> {
    let images = image::list()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&images)?);
        return Ok(());
    }

    println!("{:<24} {:<48} ROOTFS", "NAME", "PATH");
    for image in images {
        println!("{:<24} {:<48} {}", image.name, image.path, image.rootfs);
    }

    Ok(())
}

fn run_image(options: RunImageOptions) -> Result<()> {
    let bundle = image::bundle_path(&options.name)?;
    run_container(RunOptions {
        id: options.id,
        bundle,
        network_mode: options.network_mode,
        security_profile: options.security_profile,
        log_mode: options.log_mode,
        userns_mode: options.userns_mode,
        tty: options.tty,
    })
}

fn debug_command(command: DebugCommand) -> Result<()> {
    match command {
        DebugCommand::SelfExec => debug_self_exec(),
    }
}

fn debug_self_exec() -> Result<()> {
    println!("exe: {}", current_exe_link()?.display());
    println!("running_from_memfd: {}", is_running_from_memfd()?);
    Ok(())
}

fn trace_container(id: &str, json: bool, strace: bool, duration_ms: u64) -> Result<()> {
    if duration_ms == 0 {
        bail!("trace duration must be greater than zero");
    }

    let report = trace::trace(
        id,
        TraceOptions {
            strace,
            strace_duration: Duration::from_millis(duration_ms),
        },
    )?;
    print_trace_report(&report, json)
}

fn print_trace_report(report: &TraceReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!("id: {}", report.id);
    println!("pid: {}", report.pid);
    println!("runtime_status: {}", report.runtime_status);
    if let Some(name) = report.proc_status.get("Name") {
        println!("process_name: {name}");
    }
    if let Some(state) = report.proc_status.get("State") {
        println!("process_state: {state}");
    }
    if let Some(nnp) = report.proc_status.get("NoNewPrivs") {
        println!("no_new_privs: {nnp}");
    }
    println!("process_tree:");
    print_process_node(&report.process_tree, 0);
    println!("strace_available: {}", report.strace.available);
    println!("strace_requested: {}", report.strace.requested);
    if let Some(duration_ms) = report.strace.duration_ms {
        println!("strace_duration_ms: {duration_ms}");
    }
    if let Some(summary) = report.strace.summary.as_deref() {
        println!("strace_summary:");
        println!("{summary}");
    }
    if let Some(error) = report.strace.error.as_deref() {
        println!("strace_error: {error}");
    }
    println!("ebpf: {}", report.ebpf);

    Ok(())
}

fn print_process_node(node: &ProcessNode, depth: usize) {
    let indent = "  ".repeat(depth);
    println!("{indent}- {} {}", node.pid, node.command);
    for child in &node.children {
        print_process_node(child, depth + 1);
    }
}

fn checkpoint_container(id: &str, json: bool, images_dir: Option<PathBuf>) -> Result<()> {
    let report = checkpoint::checkpoint(id, CheckpointOptions { images_dir })?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("experimental: {}", report.experimental);
    println!("id: {}", report.id);
    println!("pid: {}", report.pid);
    println!("images_dir: {}", report.images_dir);
    println!("criu_available: {}", report.criu.available);
    if let Some(version) = report.criu.version.as_deref() {
        println!("criu_version: {version}");
    }
    println!("command: {}", report.command.join(" "));

    Ok(())
}

fn restore_container(id: &str, json: bool, images_dir: Option<PathBuf>) -> Result<()> {
    let report = checkpoint::restore(id, RestoreOptions { images_dir })?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("experimental: {}", report.experimental);
    println!("id: {}", report.id);
    println!("images_dir: {}", report.images_dir);
    println!("criu_available: {}", report.criu.available);
    if let Some(version) = report.criu.version.as_deref() {
        println!("criu_version: {version}");
    }
    println!("command: {}", report.command.join(" "));

    Ok(())
}

fn run_container(options: RunOptions) -> Result<()> {
    lifecycle::record_run_created(&options.id)?;
    execute_container(options, None)
}

fn create_container(options: RunOptions) -> Result<()> {
    lifecycle::create(CreateOptions {
        id: &options.id,
        bundle: &options.bundle,
        network_mode: options.network_mode,
        security_profile: options.security_profile,
        log_mode: options.log_mode,
        userns_mode: options.userns_mode,
        tty: options.tty,
    })?;
    println!("created container: {}", options.id);

    Ok(())
}

fn start_container(id: &str) -> Result<()> {
    let state = lifecycle::load_created(id)?;

    let options = RunOptions {
        id: state.id.clone(),
        bundle: PathBuf::from(&state.bundle),
        network_mode: parse_network_mode(&state.network_mode)?,
        security_profile: parse_security_profile(&state.security_profile)?,
        log_mode: parse_log_mode(&state.log_mode)?,
        userns_mode: parse_userns_mode(&state.userns_mode)?,
        tty: state.tty,
    };

    execute_container(options, Some(state))
}

fn execute_container(options: RunOptions, existing_state: Option<ContainerState>) -> Result<()> {
    let network_mode = options.network_mode.to_effective();
    if network_mode != options.network_mode {
        eprintln!(
            "warn: bridge networking is not supported in rootless mode, falling back to none"
        );
    }

    let config_path = options.bundle.join("config.json");
    let config = load_config(config_path)?;
    let effective_policy = policy::resolve_effective_policy(
        config.crun.as_ref(),
        config
            .linux
            .as_ref()
            .and_then(|linux| linux.resources.as_ref()),
        options.security_profile,
        options.log_mode,
    )?;
    let log_mode = effective_policy.log_mode;
    let capture_logs = !options.tty && should_capture_logs(log_mode, io::stdin().is_terminal());

    let run_options = lifecycle::ContainerRunOptions {
        id: &options.id,
        bundle: &options.bundle,
        network_mode: options.network_mode,
        security_profile: options.security_profile,
        log_mode: options.log_mode,
        userns_mode: options.userns_mode,
        tty: options.tty,
        capture_logs,
    };

    let report = lifecycle::run_container_process(run_options, existing_state)?;

    if let Some(error) = report.child_error {
        return Err(LifecycleError::ChildFailed { error }.into());
    }

    exit_with_process_status(report.exit_code, report.exit_signal.as_deref());
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
        println!("rootfs_mode: {}", state.rootfs_mode);
        println!("policy_profile: {}", state.policy_profile);
        if let Some(health) = state.health.as_ref() {
            println!("health_status: {}", health.status);
            println!("health_checked_at_unix: {}", health.checked_at_unix);
        }
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

fn show_stats(id: &str, json: bool) -> Result<()> {
    let stats = read_container_stats(id)?;
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
        if let Some(value) = stats.cpu.nr_periods {
            println!("cpu_nr_periods: {value}");
        }
        if let Some(value) = stats.cpu.nr_throttled {
            println!("cpu_nr_throttled: {value}");
        }
        if let Some(value) = stats.cpu.throttled_usec {
            println!("cpu_throttled_usec: {value}");
        }
        for (event, value) in &stats.memory.events {
            println!("memory_event_{event}: {value}");
        }
        for (event, value) in &stats.pids.events {
            println!("pids_event_{event}: {value}");
        }
        if let Some(value) = stats.memory.pressure.as_deref() {
            println!("memory_pressure: {value}");
        }
        if let Some(value) = stats.cpu.pressure.as_deref() {
            println!("cpu_pressure: {value}");
        }
        for device in &stats.io {
            println!(
                "io_device {}: rbytes={} wbytes={} rios={} wios={} dbytes={} dios={}",
                device.device,
                device.rbytes.unwrap_or(0),
                device.wbytes.unwrap_or(0),
                device.rios.unwrap_or(0),
                device.wios.unwrap_or(0),
                device.dbytes.unwrap_or(0),
                device.dios.unwrap_or(0)
            );
        }
    }

    Ok(())
}

fn stream_events(
    id: &str,
    json: bool,
    history: bool,
    snapshot: bool,
    once: bool,
    interval_ms: u64,
) -> Result<()> {
    if history {
        return show_event_history(id, json);
    }

    stream_counter_events(
        id,
        snapshot,
        once,
        Duration::from_millis(interval_ms),
        |event| print_event(event, json, true),
    )
}

fn print_event(event: RuntimeEvent, json: bool, audit: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(&event)?);
    } else if let Some(status) = event.status.as_deref() {
        println!(
            "{} {} {} status={}",
            event.timestamp_unix, event.source, event.name, status
        );
    } else if let Some(fields) = event.fields.as_ref() {
        let fields = fields
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "{} {} {} {}",
            event.timestamp_unix, event.source, event.name, fields
        );
    } else {
        println!(
            "{} {} {} value={} delta={}",
            event.timestamp_unix,
            event.source,
            event.name,
            event.value.unwrap_or(0),
            event.delta.unwrap_or(0)
        );
    }

    if audit {
        audit_log::append(&event)?;
    }

    Ok(())
}

fn show_event_history(id: &str, json: bool) -> Result<()> {
    for event in audit_log::read_history(id)? {
        print_event(event, json, false)?;
    }

    Ok(())
}

fn run_healthcheck(id: &str, json: bool, watch: bool, interval_ms: u64) -> Result<()> {
    health::run(id, watch, Duration::from_millis(interval_ms), |result| {
        print_health_result(&result, json)
    })
}

fn print_health_result(result: &HealthResult, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("id: {}", result.id);
        println!("status: {}", result.status);
        println!("checked_at_unix: {}", result.checked_at_unix);
        println!("attempts: {}", result.attempts);
        println!("command: {:?}", result.command);
        if let Some(code) = result.exit_code {
            println!("exit_code: {code}");
        }
        if let Some(signal) = result.signal.as_deref() {
            println!("signal: {signal}");
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
        "{:<24} {:<10} {:<8} {:<8} {:<11} {:<8} {:<8} {:<10} {:<10} BUNDLE",
        "ID", "STATUS", "PID", "NET", "SECURITY", "USERNS", "ROOTFS", "PROFILE", "HEALTH"
    );
    for state in states {
        println!(
            "{:<24} {:<10} {:<8} {:<8} {:<11} {:<8} {:<8} {:<10} {:<10} {}",
            state.id,
            format!("{:?}", state.status).to_lowercase(),
            state.pid.map_or("-".to_string(), |pid| pid.to_string()),
            state.network_mode,
            state.security_profile,
            state.userns_mode,
            state.rootfs_mode,
            state.policy_profile,
            state
                .health
                .as_ref()
                .map(|health| health.status.as_str())
                .unwrap_or("-"),
            state.bundle
        );
    }

    Ok(())
}

fn exec_container(id: &str, args: &[String], tty: bool) -> Result<()> {
    let report = lifecycle::exec(id, args, tty)?;

    match (report.code, report.signal.as_deref()) {
        (Some(code), _) => println!("exec process exited with code: {code}"),
        (None, Some(signal)) => println!("exec process killed by signal: {signal}"),
        (None, None) => println!("exec process ended without exit status"),
    }

    exit_with_process_status(report.code, report.signal.as_deref());
}

fn exit_with_process_status(code: Option<i32>, signal: Option<&str>) -> ! {
    std::process::exit(process_exit_status(code, signal));
}

fn show_logs(id: &str, follow: bool) -> Result<()> {
    if follow {
        let log_path = lifecycle::log_path(id)?;
        follow_logs(&log_path)?;
    } else {
        print!("{}", lifecycle::read_logs(id)?);
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
    let report = lifecycle::send_container_signal(id, signal)
        .with_context(|| format!("failed to send signal {signal} to container {id}"))?;
    println!(
        "sent signal {} to container {} pid {}",
        report.signal, report.id, report.pid
    );

    Ok(())
}

fn stop_container(id: &str, timeout_secs: u64) -> Result<()> {
    kill_container(id, "SIGTERM")?;

    if lifecycle::wait_for_stopped(id, Duration::from_secs(timeout_secs))? {
        println!("container stopped: {id}");
        return Ok(());
    }

    println!("container {id} did not stop after {timeout_secs}s; sending SIGKILL");
    kill_container(id, "SIGKILL")?;

    if lifecycle::wait_for_stopped(id, Duration::from_secs(5))? {
        println!("container killed: {id}");
        return Ok(());
    }

    Err(LifecycleError::StopDidNotComplete { id: id.to_string() }.into())
}

fn delete_container(id: &str) -> Result<()> {
    lifecycle::delete(id)?;
    println!("deleted container state: {id}");
    Ok(())
}

fn run_doctor(fix: bool, json: bool) -> Result<()> {
    let report = doctor::run(fix)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if report.issues.is_empty() {
        println!("doctor: ok");
        return Ok(());
    }

    for issue in &report.issues {
        let fixed = if issue.fixed { "fixed" } else { "unfixed" };
        let id = issue.id.as_deref().unwrap_or("-");
        let path = issue.path.as_deref().unwrap_or("-");
        println!(
            "{} id={} path={} status={} message={}",
            issue.kind, id, path, fixed, issue.message
        );
    }

    if !report.is_clean() {
        bail!("doctor found unfixed issues");
    }

    Ok(())
}

fn inspect_security_command(id: &str, json: bool) -> Result<()> {
    let inspection = inspect_security::inspect(id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&inspection)?);
        return Ok(());
    }

    println!("id: {}", inspection.id);
    println!("pid: {}", inspection.pid);
    println!("security_profile: {}", inspection.security_profile);
    println!("userns_mode: {}", inspection.userns_mode);
    println!("rootfs_mode: {}", inspection.rootfs_mode);
    println!("readonly_rootfs: {}", inspection.readonly_rootfs);
    println!("mount_count: {}", inspection.mount_count);
    if let Some(value) = inspection.no_new_privs {
        println!("no_new_privs: {value}");
    }
    if let Some(mode) = inspection.seccomp.mode {
        println!("seccomp_mode: {mode}");
    }
    if let Some(filters) = inspection.seccomp.filters {
        println!("seccomp_filters: {filters}");
    }
    if let Some(value) = inspection.capabilities.effective.as_deref() {
        println!("cap_effective: {value}");
    }
    if let Some(value) = inspection.capabilities.permitted.as_deref() {
        println!("cap_permitted: {value}");
    }
    if let Some(value) = inspection.resources.memory_limit.as_deref() {
        println!("memory_limit: {value}");
    }
    if let Some(value) = inspection.resources.pids_limit.as_deref() {
        println!("pids_limit: {value}");
    }
    if let Some(value) = inspection.resources.cpu_quota {
        println!("cpu_quota: {value}");
    }
    if let Some(value) = inspection.resources.cpu_period {
        println!("cpu_period: {value}");
    }
    for warning in &inspection.warnings {
        println!("warning: {warning}");
    }

    Ok(())
}

fn diff_rootfs(id: &str, json: bool) -> Result<()> {
    let report = rootfs_diff::diff_container(id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("id: {}", report.id);
    println!("lowerdir: {}", report.lowerdir);
    println!("upperdir: {}", report.upperdir);
    if report.entries.is_empty() {
        println!("no changes");
        return Ok(());
    }

    for entry in &report.entries {
        println!("{} {}", entry.kind.as_label(), entry.path);
    }

    Ok(())
}

fn validate_bundle(bundle: &Path, json: bool) -> Result<()> {
    let report = container_runtime::spec::config::validate_bundle(bundle)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("valid: {}", report.valid);
    println!("bundle: {}", report.bundle);
    for warning in &report.warnings {
        println!("warning: {warning}");
    }

    Ok(())
}
