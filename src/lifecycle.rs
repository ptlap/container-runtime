use anyhow::Result;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use crate::audit_log::{self, AuditEvent};
use crate::container_exec::{exec_in_container, ExecConfig};
use crate::error::LifecycleError;
use crate::filesystem::resolve_rootfs;
use crate::modes::LogMode;
use crate::network::NetworkMode;
use crate::policy;
use crate::security::SecurityProfile;
use crate::signal::{parse_signal, send_signal};
use crate::spec::config::load_config;
use crate::state::{self, ContainerState, ContainerStatus, RuntimeMetadata};
use crate::userns::UserNamespaceMode;

#[derive(Debug, Clone, Copy)]
pub struct CreateOptions<'a> {
    pub id: &'a str,
    pub bundle: &'a Path,
    pub network_mode: NetworkMode,
    pub security_profile: SecurityProfile,
    pub log_mode: LogMode,
    pub userns_mode: UserNamespaceMode,
    pub tty: bool,
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

    let state = ContainerState::created(
        options.id,
        options.bundle,
        RuntimeMetadata {
            network_mode: options.network_mode.as_str(),
            security_profile: effective_policy.security_profile.as_str(),
            log_mode: effective_policy.log_mode.as_str(),
            userns_mode: options.userns_mode.as_str(),
            rootfs_mode: rootfs_mode.as_str(),
            policy_profile: effective_policy.profile.as_str(),
            tty: options.tty,
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

pub fn exec(id: &str, args: &[String], tty: bool) -> Result<ExecReport> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Running {
        return Err(LifecycleError::ContainerNotRunning { id: id.to_string() }.into());
    }

    let pid = state
        .pid
        .ok_or_else(|| LifecycleError::ContainerHasNoPid { id: id.to_string() })?;
    let config = load_config(Path::new(&state.bundle).join("config.json"))?;

    let exit = exec_in_container(ExecConfig {
        target_pid: pid,
        args,
        env: &config.process.env,
        cwd: config.process.cwd.as_deref(),
        cgroup_path: state.cgroup_path.as_deref(),
        tty,
    })?;

    let report = ExecReport {
        code: exit.code,
        signal: exit.signal,
    };
    audit_exec(id, &report)?;

    Ok(report)
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
}
