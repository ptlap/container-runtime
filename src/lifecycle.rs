use anyhow::Context;
use anyhow::Result;
use nix::libc;
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::audit_log::{self, AuditEvent};
use crate::container::{run_process, ProcessConfig, StartedProcess};
use crate::container_exec::{exec_in_container, ExecConfig};
use crate::error::LifecycleError;
use crate::filesystem::resolve_rootfs;
use crate::modes::{parse_security_profile, LogMode};
use crate::namespace::effective_namespace_flags;
use crate::network::NetworkMode;
use crate::policy;
use crate::seccomp::capture::CaptureFile;
use crate::seccomp::{self, SeccompOptions};
use crate::security::SecurityProfile;
use crate::signal::{parse_signal, send_signal};
use crate::spec::config::load_config;
use crate::state::{self, ContainerState, ContainerStatus, RuntimeMetadata, StartedResources};
use crate::userns::{validate_process_user, UserNamespaceMode};
use tracing::info;

#[derive(Debug, Clone)]
pub struct ContainerRunOptions<'a> {
    pub id: &'a str,
    pub bundle: &'a Path,
    pub network_mode: NetworkMode,
    pub security_profile: SecurityProfile,
    pub log_mode: LogMode,
    pub userns_mode: UserNamespaceMode,
    pub tty: bool,
    pub capture_logs: bool,
    pub seccomp: SeccompOptions,
}

#[derive(Debug, Clone)]
pub struct ContainerRunReport {
    pub exit_code: Option<i32>,
    pub exit_signal: Option<String>,
    pub child_error: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    StoppedViaSigterm,
    StoppedViaSigkill,
}

#[derive(Debug, Clone)]
pub struct CreateOptions<'a> {
    pub id: &'a str,
    pub bundle: &'a Path,
    pub network_mode: NetworkMode,
    pub security_profile: SecurityProfile,
    pub log_mode: LogMode,
    pub userns_mode: UserNamespaceMode,
    pub tty: bool,
    pub seccomp: SeccompOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillReport {
    pub id: String,
    pub pid: i32,
    pub signal: String,
    pub signal_number: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecReport {
    pub code: Option<i32>,
    pub signal: Option<String>,
}

pub fn record_run_created(id: &str) -> Result<()> {
    ensure_container_absent(id)?;
    record_created_event(id)
}

pub fn create(options: CreateOptions<'_>) -> Result<ContainerState> {
    ensure_container_absent(options.id)?;

    let config = load_config(options.bundle.join("config.json"))?;
    validate_process_user(options.userns_mode, config.process.user.as_ref())?;
    let effective_policy = policy::resolve_effective_policy(
        config.crun.as_ref(),
        config
            .linux
            .as_ref()
            .and_then(|linux| linux.resources.as_ref()),
        options.security_profile,
        options.log_mode,
    )?;
    let rootfs_mode = resolve_rootfs(options.bundle, &config.root.path, config.crun.as_ref()).mode;
    let seccomp_profile_path = options
        .seccomp
        .profile_path
        .as_ref()
        .map(|path| path.display().to_string());

    let state = ContainerState::created(
        options.id,
        options.bundle,
        RuntimeMetadata {
            network_mode: options.network_mode.as_str(),
            security_profile: effective_policy.security_profile.as_str(),
            log_mode: effective_policy.log_mode.as_str(),
            userns_mode: options.userns_mode.as_str(),
            userns_map: match options.userns_mode {
                UserNamespaceMode::Host => None,
                UserNamespaceMode::Private(map) => Some(map),
            },
            rootfs_mode: rootfs_mode.as_str(),
            policy_profile: effective_policy.profile.as_str(),
            tty: options.tty,
            seccomp_mode: options.seccomp.mode.as_str(),
            seccomp_profile: seccomp_profile_path.as_deref(),
            seccomp_action: Some(options.seccomp.action.as_str()),
            seccomp_order: options.seccomp.order.as_str(),
            seccomp_log: options.seccomp.log,
        },
    )?;
    state::save(&state)?;
    record_created_event(options.id)?;

    Ok(state)
}

pub fn load_created(id: &str) -> Result<ContainerState> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Created {
        return Err(LifecycleError::ContainerNotCreated { id: id.to_string() }.into());
    }

    Ok(state)
}

pub fn send_container_signal(id: &str, signal: &str) -> Result<KillReport> {
    let pid = running_pid(id)?;
    let signal_number = parse_signal(signal)?;
    send_signal(pid, signal_number)?;

    Ok(KillReport {
        id: id.to_string(),
        pid,
        signal: signal.to_string(),
        signal_number,
    })
}

pub fn stop(
    id: &str,
    timeout: Duration,
    mut on_signal_sent: impl FnMut(&KillReport),
    mut on_sigkill_warning: impl FnMut(),
) -> Result<StopOutcome> {
    let report = send_container_signal(id, "SIGTERM")?;
    on_signal_sent(&report);

    if wait_for_stopped(id, timeout)? {
        return Ok(StopOutcome::StoppedViaSigterm);
    }

    on_sigkill_warning();
    let report = send_container_signal(id, "SIGKILL")?;
    on_signal_sent(&report);

    if wait_for_stopped(id, Duration::from_secs(5))? {
        return Ok(StopOutcome::StoppedViaSigkill);
    }

    Err(LifecycleError::StopDidNotComplete { id: id.to_string() }.into())
}

pub fn exec(id: &str, args: &[String], tty: bool) -> Result<ExecReport> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Running {
        return Err(LifecycleError::ContainerNotRunning { id: id.to_string() }.into());
    }

    let pid = state
        .pid
        .ok_or_else(|| LifecycleError::ContainerHasNoPid { id: id.to_string() })?;
    let config = load_config(Path::new(&state.bundle).join("config.json"))?;
    let compiled = exec_seccomp_program(&state)?;
    let security_profile = parse_security_profile(&state.security_profile)?;

    let exit = exec_in_container(ExecConfig {
        target_pid: pid,
        args,
        env: &config.process.env,
        cwd: config.process.cwd.as_deref(),
        process_user: config.process.user.as_ref(),
        security_profile,
        cgroup_path: state.cgroup_path.as_deref(),
        tty,
        seccomp_program: compiled.as_ref().map(|compiled| &compiled.program),
        seccomp_flags: if state.seccomp_log {
            libc::SECCOMP_FILTER_FLAG_LOG
        } else {
            0
        },
        timeout: None,
    })?;

    let report = ExecReport {
        code: exit.code,
        signal: exit.signal,
    };
    audit_exec(id, &report)?;

    Ok(report)
}

/// Compiles the container's own profile so an exec'd process is confined the
/// same way its main process is.
///
/// Joining namespaces with `setns` does not carry seccomp across, so without
/// this an exec session runs unfiltered inside an otherwise confined container.
fn exec_seccomp_program(state: &ContainerState) -> Result<Option<seccomp::CompiledProfile>> {
    let Some(path) = state.seccomp_profile.as_deref() else {
        return Ok(None);
    };
    if state.seccomp_mode != "enforce" {
        return Ok(None);
    }

    let action = state
        .seccomp_action
        .as_deref()
        .map(seccomp::parse_action)
        .transpose()?
        .unwrap_or(seccomp::SeccompAction::Errno);

    let profile = seccomp::profile::SeccompProfile::load(Path::new(path))?;
    let compiled = seccomp::compile::compile(
        &profile,
        seccomp::CompileOptions {
            default_action: action,
            order: seccomp::parse_order(&state.seccomp_order)?,
        },
    )?;

    Ok(Some(compiled))
}

pub fn delete(id: &str) -> Result<()> {
    audit_log::append_simple(id, "lifecycle", "deleted", Some("deleted"))?;
    let runtime_log = audit_log::read_raw(id).ok();
    state::delete(id)?;
    if let Some(runtime_log) = runtime_log {
        audit_log::write_raw(id, &runtime_log)?;
    }

    Ok(())
}

pub fn log_path(id: &str) -> Result<PathBuf> {
    let state = state::load_current(id)?;
    state
        .log_path
        .as_deref()
        .map(PathBuf::from)
        .map(Ok)
        .unwrap_or_else(|| state::log_path(id))
}

pub fn read_logs(id: &str) -> Result<String> {
    let log_path = log_path(id)?;
    fs::read_to_string(&log_path)
        .with_context(|| format!("failed to read log file: {}", log_path.display()))
}

fn audit_exec(id: &str, report: &ExecReport) -> Result<()> {
    let mut event = AuditEvent::new(id, "exec", "exec");
    if let Some(code) = report.code.and_then(|code| u64::try_from(code).ok()) {
        event = event.with_value(code);
    }
    if report.signal.is_some() {
        event = event.with_status("signaled");
    } else {
        event = event.with_status("exited");
    }
    audit_log::append(&event)
}

pub fn wait_for_stopped(id: &str, timeout: Duration) -> Result<bool> {
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

pub fn running_pid(id: &str) -> Result<i32> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Running {
        return Err(LifecycleError::ContainerNotRunning { id: id.to_string() }.into());
    }

    state
        .pid
        .ok_or_else(|| LifecycleError::ContainerHasNoPid { id: id.to_string() }.into())
}

fn ensure_container_absent(id: &str) -> Result<()> {
    if state::exists(id)? {
        return Err(LifecycleError::ContainerAlreadyExists { id: id.to_string() }.into());
    }

    Ok(())
}

fn record_created_event(id: &str) -> Result<()> {
    audit_log::reset(id)?;
    audit_log::append_simple(id, "lifecycle", "created", Some("created"))
}

pub fn run_container_process(
    options: ContainerRunOptions<'_>,
    mut existing_state: Option<ContainerState>,
) -> Result<ContainerRunReport> {
    let id = options.id;
    let bundle = options.bundle;
    let network_mode = options.network_mode.to_effective();
    let userns_mode = options.userns_mode;

    let config_path = bundle.join("config.json");
    let config = load_config(&config_path)?;
    validate_process_user(userns_mode, config.process.user.as_ref())?;
    let effective_policy = policy::resolve_effective_policy(
        config.crun.as_ref(),
        config
            .linux
            .as_ref()
            .and_then(|linux| linux.resources.as_ref()),
        options.security_profile,
        options.log_mode,
    )?;
    let security_profile = effective_policy.security_profile;
    let log_mode = effective_policy.log_mode;
    let policy_profile = effective_policy.profile;

    let rootfs = resolve_rootfs(bundle, &config.root.path, config.crun.as_ref());

    let namespaces = config
        .linux
        .as_ref()
        .map(|linux| {
            linux
                .namespaces
                .iter()
                .map(|ns| ns.namespace_type.as_str())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let flags = effective_namespace_flags(&namespaces, network_mode, userns_mode)?;

    // Environment values may carry secrets, so only their count is recorded.
    info!(
        container_id = id,
        args = ?config.process.args,
        env_count = config.process.env.len(),
        rootfs = %rootfs.path.display(),
        namespaces = ?namespaces,
        clone_flags = ?flags,
        network_mode = network_mode.as_str(),
        security_profile = security_profile.as_str(),
        log_mode = log_mode.as_str(),
        userns_mode = userns_mode.as_str(),
        rootfs_mode = rootfs.mode.as_str(),
        policy_profile = policy_profile.as_str(),
        "starting container process"
    );

    let masked_paths = config
        .linux
        .as_ref()
        .map(|linux| linux.masked_paths.as_slice())
        .unwrap_or(&[]);
    let readonly_paths = config
        .linux
        .as_ref()
        .map(|linux| linux.readonly_paths.as_slice())
        .unwrap_or(&[]);

    // Compiled before fork: the child installs its filter after pivot_root,
    // when the profile path on the host no longer resolves, and a broken
    // profile should fail before any cgroup or veth is created.
    let compiled_profile = seccomp::prepare(&options.seccomp)?;
    let seccomp_profile_path = options
        .seccomp
        .profile_path
        .as_ref()
        .map(|path| path.display().to_string());
    let seccomp_action = options.seccomp.action.as_str();

    let log_path = state::log_path(id)?;
    let mut running_state = None;
    let mut save_started_state = |started: StartedProcess| {
        let cgroup_path = started
            .cgroup_path
            .as_ref()
            .map(|path| path.display().to_string());
        let log_path_string = options.capture_logs.then(|| log_path.display().to_string());
        let resources = StartedResources {
            cgroup_path: cgroup_path.as_deref().map(Cow::Borrowed),
            network_subnet: started.network_subnet.as_deref().map(Cow::Borrowed),
            nat_lease: started.nat_lease.clone(),
            log_path: log_path_string.as_deref().map(Cow::Borrowed),
        };
        let state = if let Some(mut state) = existing_state.take() {
            state.mark_running(started.pid, resources, log_mode.as_str())?;
            state
        } else {
            ContainerState::running(
                id,
                bundle,
                started.pid,
                resources,
                RuntimeMetadata {
                    network_mode: network_mode.as_str(),
                    security_profile: security_profile.as_str(),
                    log_mode: log_mode.as_str(),
                    userns_mode: userns_mode.as_str(),
                    userns_map: match userns_mode {
                        UserNamespaceMode::Host => None,
                        UserNamespaceMode::Private(map) => Some(map),
                    },
                    rootfs_mode: rootfs.mode.as_str(),
                    policy_profile: policy_profile.as_str(),
                    tty: options.tty,
                    seccomp_mode: options.seccomp.mode.as_str(),
                    seccomp_profile: seccomp_profile_path.as_deref(),
                    seccomp_action: Some(seccomp_action),
                    seccomp_order: options.seccomp.order.as_str(),
                    seccomp_log: options.seccomp.log,
                },
            )?
        };
        state::save(&state)?;
        audit_log::append_simple(id, "lifecycle", "started", Some("running"))?;
        running_state = Some(state);
        Ok(())
    };

    let process_config = ProcessConfig::builder()
        .id(id)
        .hostname(config.hostname.as_deref())
        .args(&config.process.args)
        .env(&config.process.env)
        .cwd(config.process.cwd.as_deref())
        .rootfs(&rootfs.path)
        .overlay_config(rootfs.overlay_config)
        .readonly_rootfs(config.root.readonly)
        .mounts(&config.mounts)
        .process_user(config.process.user.as_ref())
        .rlimits(&config.process.rlimits)
        .masked_paths(masked_paths)
        .readonly_paths(readonly_paths)
        .log_path(options.capture_logs.then_some(&log_path))
        .flags(flags)
        .cgroup_config(effective_policy.cgroup_config)
        .network_mode(network_mode)
        .security_profile(security_profile)
        .userns_mode(userns_mode)
        .tty(options.tty)
        .seccomp_mode(options.seccomp.mode)
        .seccomp_program(compiled_profile.as_ref().map(|compiled| &compiled.program))
        .seccomp_flags(options.seccomp.filter_flags())
        .build()?;

    let process_exit = run_process(process_config, &mut save_started_state)?;

    if let Some(capture) = process_exit.capture.as_ref() {
        let path = options
            .seccomp
            .capture_path
            .clone()
            .unwrap_or(state::capture_path(id)?);
        let file = CaptureFile::from_capture(id, &config.process.args, capture);
        file.save(&path)?;

        let mut event = AuditEvent::new(id, "seccomp", "captured").with_status("captured");
        event = event.with_value(file.syscalls.len() as u64);
        audit_log::append(&event)?;
    }

    let exit_code = process_exit.code;
    let exit_signal = process_exit.signal.clone();
    let child_error = process_exit.error.clone();

    if let Some(mut state) = running_state {
        state
            .mark_stopped(exit_code, exit_signal.clone())
            .context("failed to update stopped state")?;
        state::save(&state)?;
        let mut event = AuditEvent::new(id, "lifecycle", "stopped").with_status("stopped");
        if let Some(code) = exit_code.and_then(|code| u64::try_from(code).ok()) {
            event = event.with_value(code);
        }
        audit_log::append(&event)?;
    }

    Ok(ContainerRunReport {
        exit_code,
        exit_signal,
        child_error,
        warnings: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_non_created_state_with_typed_error() {
        let error = LifecycleError::ContainerNotCreated {
            id: "demo".to_string(),
        };

        assert_eq!(error.to_string(), "container demo is not created");
    }

    #[test]
    fn formats_stop_timeout_error() {
        let error = LifecycleError::StopDidNotComplete {
            id: "demo".to_string(),
        };

        assert_eq!(
            error.to_string(),
            "container demo did not stop after SIGKILL"
        );
    }

    #[test]
    fn audits_exec_report_statuses() {
        let exited = ExecReport {
            code: Some(0),
            signal: None,
        };
        assert_eq!(exited.code, Some(0));

        let signaled = ExecReport {
            code: None,
            signal: Some("SIGTERM".to_string()),
        };
        assert_eq!(signaled.signal.as_deref(), Some("SIGTERM"));
    }

    #[test]
    fn kill_report_keeps_signal_details() {
        let report = KillReport {
            id: "demo".to_string(),
            pid: 42,
            signal: "SIGTERM".to_string(),
            signal_number: 15,
        };

        assert_eq!(report.id, "demo");
        assert_eq!(report.pid, 42);
        assert_eq!(report.signal_number, 15);
    }

    #[test]
    fn exec_report_keeps_exit_details() {
        let report = ExecReport {
            code: Some(2),
            signal: None,
        };

        assert_eq!(report.code, Some(2));
        assert!(report.signal.is_none());
    }
}
