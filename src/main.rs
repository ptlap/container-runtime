use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use container_runtime::cli_runtime::{process_exit_status, should_capture_logs};
use container_runtime::error::LifecycleError;
use container_runtime::image;
use container_runtime::lifecycle::{self, CreateOptions, StopOutcome};
use container_runtime::modes::{
    parse_log_mode, parse_network_mode, parse_security_profile, LogMode,
};
use container_runtime::network::NetworkMode;
use container_runtime::policy;
use container_runtime::seccomp::{self, SeccompAction, SeccompMode, SeccompOptions, SyscallOrder};
use container_runtime::security::SecurityProfile;
use container_runtime::selfexec::{
    current_exe_link, ensure_reexecuted_from_memfd, is_running_from_memfd,
};
use container_runtime::signal::DEFAULT_SIGNAL;
use container_runtime::spec::config::load_config;
use container_runtime::state::ContainerState;
use container_runtime::userns::{UserNamespaceMap, UserNamespaceMode};
use std::io;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

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
        #[arg(long, value_enum, default_value_t = CliSecurityProfile::Denylist)]
        security: CliSecurityProfile,
        #[arg(long, value_enum, default_value_t = CliLogMode::Auto)]
        log: CliLogMode,
        #[arg(long, value_enum, default_value_t = CliUsernsMode::Host)]
        userns: CliUsernsMode,
        #[arg(long, value_enum, default_value_t = CliSeccompMode::Off)]
        seccomp: CliSeccompMode,
        #[arg(long)]
        seccomp_profile: Option<PathBuf>,
        #[arg(long)]
        seccomp_out: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = CliSeccompAction::Errno)]
        seccomp_action: CliSeccompAction,
        #[arg(long, value_enum, default_value_t = CliSyscallOrder::ByFrequency)]
        seccomp_order: CliSyscallOrder,
        #[arg(long)]
        seccomp_log: bool,
        #[arg(short, long)]
        tty: bool,
        id: String,
        bundle: PathBuf,
    },
    RunImage {
        #[arg(long, value_enum, default_value_t = CliNetworkMode::Bridge)]
        net: CliNetworkMode,
        #[arg(long, value_enum, default_value_t = CliSecurityProfile::Denylist)]
        security: CliSecurityProfile,
        #[arg(long, value_enum, default_value_t = CliLogMode::Auto)]
        log: CliLogMode,
        #[arg(long, value_enum, default_value_t = CliUsernsMode::Host)]
        userns: CliUsernsMode,
        #[arg(long, value_enum, default_value_t = CliSeccompMode::Off)]
        seccomp: CliSeccompMode,
        #[arg(long)]
        seccomp_profile: Option<PathBuf>,
        #[arg(long)]
        seccomp_out: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = CliSeccompAction::Errno)]
        seccomp_action: CliSeccompAction,
        #[arg(long, value_enum, default_value_t = CliSyscallOrder::ByFrequency)]
        seccomp_order: CliSyscallOrder,
        #[arg(long)]
        seccomp_log: bool,
        #[arg(short, long)]
        tty: bool,
        name: String,
        id: String,
    },
    Create {
        #[arg(long, value_enum, default_value_t = CliNetworkMode::Bridge)]
        net: CliNetworkMode,
        #[arg(long, value_enum, default_value_t = CliSecurityProfile::Denylist)]
        security: CliSecurityProfile,
        #[arg(long, value_enum, default_value_t = CliLogMode::Auto)]
        log: CliLogMode,
        #[arg(long, value_enum, default_value_t = CliUsernsMode::Host)]
        userns: CliUsernsMode,
        #[arg(long, value_enum, default_value_t = CliSeccompMode::Off)]
        seccomp: CliSeccompMode,
        #[arg(long)]
        seccomp_profile: Option<PathBuf>,
        #[arg(long)]
        seccomp_out: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = CliSeccompAction::Errno)]
        seccomp_action: CliSeccompAction,
        #[arg(long, value_enum, default_value_t = CliSyscallOrder::ByFrequency)]
        seccomp_order: CliSyscallOrder,
        #[arg(long)]
        seccomp_log: bool,
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
        #[arg(long)]
        interval_ms: Option<u64>,
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
    Seccomp {
        #[command(subcommand)]
        command: SeccompCommand,
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
enum SeccompCommand {
    /// Build a profile from one or more syscall captures.
    Generate {
        #[arg(long = "container", value_name = "ID")]
        containers: Vec<String>,
        #[arg(long = "capture", value_name = "PATH")]
        captures: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, value_enum, default_value_t = CliSeccompAction::Errno)]
        action: CliSeccompAction,
        #[arg(long)]
        compat: bool,
        #[arg(long, value_name = "PATH")]
        merge: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Show what a profile allows.
    Inspect {
        profile: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Measure a profile against a baseline and a CVE map.
    Compare {
        profile: PathBuf,
        #[arg(long, value_name = "PATH")]
        baseline: Option<PathBuf>,
        #[arg(long = "cve-map", value_name = "PATH")]
        cve_map: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Compile a profile to a filter without running anything.
    Compile {
        profile: PathBuf,
        #[arg(long, value_enum, default_value_t = CliSeccompAction::Errno)]
        action: CliSeccompAction,
        #[arg(long, value_enum, default_value_t = CliSyscallOrder::ByFrequency)]
        order: CliSyscallOrder,
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
    #[value(name = "denylist", alias = "default")]
    Denylist,
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSeccompMode {
    Off,
    Learn,
    Enforce,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSeccompAction {
    Errno,
    Enosys,
    Kill,
    Log,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliSyscallOrder {
    AsListed,
    ByNumber,
    ByFrequency,
}

impl From<CliSeccompMode> for SeccompMode {
    fn from(value: CliSeccompMode) -> Self {
        match value {
            CliSeccompMode::Off => Self::Off,
            CliSeccompMode::Learn => Self::Learn,
            CliSeccompMode::Enforce => Self::Enforce,
        }
    }
}

impl From<CliSeccompAction> for SeccompAction {
    fn from(value: CliSeccompAction) -> Self {
        match value {
            CliSeccompAction::Errno => Self::Errno,
            CliSeccompAction::Enosys => Self::Enosys,
            CliSeccompAction::Kill => Self::Kill,
            CliSeccompAction::Log => Self::Log,
        }
    }
}

impl From<CliSyscallOrder> for SyscallOrder {
    fn from(value: CliSyscallOrder) -> Self {
        match value {
            CliSyscallOrder::AsListed => Self::AsListed,
            CliSyscallOrder::ByNumber => Self::ByNumber,
            CliSyscallOrder::ByFrequency => Self::ByFrequency,
        }
    }
}

/// Flags that describe what the container should do about seccomp.
#[derive(Debug, Clone)]
struct SeccompArgs {
    mode: CliSeccompMode,
    profile: Option<PathBuf>,
    out: Option<PathBuf>,
    action: CliSeccompAction,
    order: CliSyscallOrder,
    log: bool,
}

impl SeccompArgs {
    fn resolve(self, id: &str) -> Result<SeccompOptions> {
        let default_capture = container_runtime::state::capture_path(id)?;
        seccomp::resolve_options(
            self.mode.into(),
            self.profile,
            self.out,
            self.action.into(),
            self.order.into(),
            self.log,
            &default_capture,
        )
        .map_err(Into::into)
    }
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
            CliSecurityProfile::Denylist => Self::Denylist,
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
    seccomp: SeccompOptions,
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
    seccomp: SeccompOptions,
}

fn init_logging(log_level: &str, log_format: &str) -> Result<()> {
    use tracing_subscriber::filter::EnvFilter;

    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_level))
        .unwrap_or_else(|_| EnvFilter::new("info"));

    // Logs go to stderr so stdout carries command output only and stays
    // machine-readable for scripted runs.
    if log_format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(io::stderr)
            .json()
            .try_init()
            .map_err(|e| anyhow::anyhow!("failed to initialize json logger: {e}"))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(io::stderr)
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
            seccomp,
            seccomp_profile,
            seccomp_out,
            seccomp_action,
            seccomp_order,
            seccomp_log,
            tty,
            id,
            bundle,
        } => {
            let seccomp = SeccompArgs {
                mode: seccomp,
                profile: seccomp_profile,
                out: seccomp_out,
                action: seccomp_action,
                order: seccomp_order,
                log: seccomp_log,
            }
            .resolve(&id)?;
            run_container(RunOptions {
                id,
                bundle,
                network_mode: net.into(),
                security_profile: security.into(),
                log_mode: log.into(),
                userns_mode: userns_mode_from_cli(userns)?,
                tty,
                seccomp,
            })?
        }
        Command::Create {
            net,
            security,
            log,
            userns,
            seccomp,
            seccomp_profile,
            seccomp_out,
            seccomp_action,
            seccomp_order,
            seccomp_log,
            tty,
            id,
            bundle,
        } => {
            let seccomp = SeccompArgs {
                mode: seccomp,
                profile: seccomp_profile,
                out: seccomp_out,
                action: seccomp_action,
                order: seccomp_order,
                log: seccomp_log,
            }
            .resolve(&id)?;
            create_container(RunOptions {
                id,
                bundle,
                network_mode: net.into(),
                security_profile: security.into(),
                log_mode: log.into(),
                userns_mode: userns_mode_from_cli(userns)?,
                tty,
                seccomp,
            })?
        }
        Command::Start { id } => start_container(&id)?,
        Command::State { id, json } => container_runtime::cli_runtime::show_state(&id, json)?,
        Command::Stats { id, json } => container_runtime::cli_runtime::show_stats(&id, json)?,
        Command::Events {
            id,
            json,
            history,
            snapshot,
            once,
            interval_ms,
        } => container_runtime::cli_runtime::stream_events(
            &id,
            json,
            history,
            snapshot,
            once,
            interval_ms,
        )?,
        Command::Health {
            id,
            json,
            watch,
            interval_ms,
        } => container_runtime::cli_runtime::run_healthcheck(&id, json, watch, interval_ms)?,
        Command::Ps { json } => container_runtime::cli_runtime::list_containers(json)?,
        Command::Exec { tty, id, args } => exec_container(&id, &args, tty)?,
        Command::Logs { id, follow } => container_runtime::cli_runtime::show_logs(&id, follow)?,
        Command::Kill { id, signal } => kill_container(&id, &signal)?,
        Command::Stop { id, timeout } => stop_container(&id, timeout)?,
        Command::Delete { id } => delete_container(&id)?,
        Command::Doctor { fix, json } => container_runtime::cli_runtime::run_doctor(fix, json)?,
        Command::InspectSecurity { id, json } => {
            container_runtime::cli_runtime::inspect_security_command(&id, json)?
        }
        Command::Diff { id, json } => container_runtime::cli_runtime::diff_rootfs(&id, json)?,
        Command::Validate { bundle, json } => {
            container_runtime::cli_runtime::validate_bundle(&bundle, json)?
        }
        Command::Trace {
            id,
            json,
            strace,
            duration_ms,
        } => container_runtime::cli_runtime::trace_container(&id, json, strace, duration_ms)?,
        Command::Checkpoint {
            id,
            json,
            images_dir,
        } => container_runtime::cli_runtime::checkpoint_container(&id, json, images_dir)?,
        Command::Restore {
            id,
            json,
            images_dir,
        } => container_runtime::cli_runtime::restore_container(&id, json, images_dir)?,
        Command::Image { command } => image_command(command)?,
        Command::Seccomp { command } => seccomp_command(command)?,
        Command::RunImage {
            net,
            security,
            log,
            userns,
            seccomp,
            seccomp_profile,
            seccomp_out,
            seccomp_action,
            seccomp_order,
            seccomp_log,
            tty,
            name,
            id,
        } => {
            let seccomp = SeccompArgs {
                mode: seccomp,
                profile: seccomp_profile,
                out: seccomp_out,
                action: seccomp_action,
                order: seccomp_order,
                log: seccomp_log,
            }
            .resolve(&id)?;
            run_image(RunImageOptions {
                name,
                id,
                network_mode: net.into(),
                security_profile: security.into(),
                log_mode: log.into(),
                userns_mode: userns_mode_from_cli(userns)?,
                tty,
                seccomp,
            })?
        }
        Command::Debug { command } => debug_command(command)?,
    }

    Ok(())
}

fn seccomp_command(command: SeccompCommand) -> Result<()> {
    match command {
        SeccompCommand::Generate {
            containers,
            captures,
            output,
            name,
            action,
            compat,
            merge,
            json,
        } => container_runtime::cli_runtime::seccomp_generate(
            container_runtime::cli_runtime::SeccompGenerateRequest {
                capture_paths: &captures,
                container_ids: &containers,
                output: &output,
                workload: name.as_deref(),
                action: action.into(),
                include_compat: compat,
                merge_into: merge.as_deref(),
                json,
            },
        ),
        SeccompCommand::Inspect { profile, json } => {
            container_runtime::cli_runtime::seccomp_inspect(&profile, json)
        }
        SeccompCommand::Compare {
            profile,
            baseline,
            cve_map,
            json,
        } => container_runtime::cli_runtime::seccomp_compare(
            &profile,
            baseline.as_deref(),
            cve_map.as_deref(),
            json,
        ),
        SeccompCommand::Compile {
            profile,
            action,
            order,
            json,
        } => container_runtime::cli_runtime::seccomp_compile(
            &profile,
            action.into(),
            order.into(),
            json,
        ),
    }
}

fn image_command(command: ImageCommand) -> Result<()> {
    match command {
        ImageCommand::Import { rootfs_tar, name } => {
            container_runtime::cli_runtime::import_image(&rootfs_tar, &name)
        }
        ImageCommand::List { json } => container_runtime::cli_runtime::list_images(json),
    }
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
        seccomp: options.seccomp,
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
        seccomp: options.seccomp.clone(),
    })?;
    println!("created container: {}", options.id);

    Ok(())
}

fn start_container(id: &str) -> Result<()> {
    let state = lifecycle::load_created(id)?;
    if state.schema_version != container_runtime::state::STATE_SCHEMA_VERSION {
        bail!(
            "container state schema {} cannot be started by this runtime; recreate the container",
            state.schema_version
        );
    }

    let seccomp = seccomp_options_from_state(&state)?;
    let options = RunOptions {
        id: state.id.clone(),
        bundle: PathBuf::from(&state.bundle),
        network_mode: parse_network_mode(&state.network_mode)?,
        security_profile: parse_security_profile(&state.security_profile)?,
        log_mode: parse_log_mode(&state.log_mode)?,
        userns_mode: parse_userns_mode(&state.userns_mode, state.userns_map)?,
        tty: state.tty,
        seccomp,
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
        seccomp: options.seccomp.clone(),
    };

    let report = lifecycle::run_container_process(run_options, existing_state)?;

    if let Some(error) = report.child_error {
        return Err(LifecycleError::ChildFailed { error }.into());
    }

    exit_with_process_status(report.exit_code, report.exit_signal.as_deref());
}

/// Rebuilds the seccomp options recorded at create time so `crun start` runs
/// the container the way `crun create` described it.
fn seccomp_options_from_state(state: &ContainerState) -> Result<SeccompOptions> {
    let mode = seccomp::parse_mode(&state.seccomp_mode)?;
    let action = state
        .seccomp_action
        .as_deref()
        .map(seccomp::parse_action)
        .transpose()?
        .unwrap_or(SeccompAction::Errno);
    let default_capture = container_runtime::state::capture_path(&state.id)?;

    seccomp::resolve_options(
        mode,
        state.seccomp_profile.as_deref().map(PathBuf::from),
        None,
        action,
        seccomp::parse_order(&state.seccomp_order)?,
        state.seccomp_log,
        &default_capture,
    )
    .map_err(Into::into)
}

fn parse_userns_mode(
    value: &str,
    persisted_map: Option<UserNamespaceMap>,
) -> Result<UserNamespaceMode> {
    match value {
        "host" => Ok(UserNamespaceMode::Host),
        "private" => persisted_map
            .map(UserNamespaceMode::Private)
            .ok_or_else(|| anyhow::anyhow!("private user namespace state has no persisted UID/GID mapping; recreate the container")),
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
    let outcome = lifecycle::stop(
        id,
        Duration::from_secs(timeout_secs),
        |report| {
            println!(
                "sent signal {} to container {} pid {}",
                report.signal, report.id, report.pid
            );
        },
        || {
            println!("container {id} did not stop after {timeout_secs}s; sending SIGKILL");
        },
    )?;

    match outcome {
        StopOutcome::StoppedViaSigterm => println!("container stopped: {id}"),
        StopOutcome::StoppedViaSigkill => println!("container killed: {id}"),
    }

    Ok(())
}

fn delete_container(id: &str) -> Result<()> {
    lifecycle::delete(id)?;
    println!("deleted container state: {id}");
    Ok(())
}
