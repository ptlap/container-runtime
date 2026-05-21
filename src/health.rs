use anyhow::Result;
use serde::Serialize;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::audit_log::{self, AuditEvent};
use crate::container_exec::{exec_in_container, ExecConfig};
use crate::error::{HealthRunError, HealthcheckError};
use crate::spec::config::load_config;
use crate::spec::config::Healthcheck;
use crate::state::{self, ContainerStatus, HealthState};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HealthResult {
    pub id: String,
    pub checked_at_unix: u64,
    pub status: String,
    pub attempts: u32,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub command: Vec<String>,
}

pub fn command_args(healthcheck: &Healthcheck) -> Result<Vec<String>, HealthcheckError> {
    let Some((kind, rest)) = healthcheck.test.split_first() else {
        return Err(HealthcheckError::EmptyTest);
    };

    match kind.as_str() {
        "NONE" => Err(HealthcheckError::Disabled),
        "CMD" => {
            if rest.is_empty() {
                return Err(HealthcheckError::MissingCommand { kind: "CMD" });
            }
            Ok(rest.to_vec())
        }
        "CMD-SHELL" => {
            if rest.is_empty() {
                return Err(HealthcheckError::MissingCommand { kind: "CMD-SHELL" });
            }
            Ok(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                rest.join(" "),
            ])
        }
        _ => Ok(healthcheck.test.clone()),
    }
}

pub fn attempts(healthcheck: &Healthcheck) -> u32 {
    healthcheck.retries.unwrap_or(0).saturating_add(1)
}

pub fn run_once(id: &str) -> Result<HealthResult> {
    let mut state = state::load_current(id)?;
    if state.status != ContainerStatus::Running {
        return Err(HealthRunError::ContainerNotRunning { id: id.to_string() }.into());
    }

    let Some(pid) = state.pid else {
        return Err(HealthRunError::ContainerHasNoPid { id: id.to_string() }.into());
    };

    let config = load_config(Path::new(&state.bundle).join("config.json"))?;
    let healthcheck = config
        .healthcheck
        .as_ref()
        .ok_or(HealthRunError::NoHealthcheckConfigured)?;
    let args = command_args(healthcheck)?;
    let max_attempts = attempts(healthcheck);

    let mut attempts = 0;
    let mut exit = None;
    while attempts < max_attempts {
        attempts += 1;
        let current_exit = exec_in_container(ExecConfig {
            target_pid: pid,
            args: &args,
            env: &config.process.env,
            cwd: config.process.cwd.as_deref(),
            cgroup_path: state.cgroup_path.as_deref(),
            tty: false,
        })?;

        let healthy = current_exit.code == Some(0) && current_exit.signal.is_none();
        exit = Some(current_exit);
        if healthy {
            break;
        }
    }
    let exit = exit.ok_or(HealthRunError::HealthcheckDidNotRun)?;

    let healthy = exit.code == Some(0) && exit.signal.is_none();
    let checked_at_unix = unix_timestamp();
    let health = HealthState {
        status: if healthy { "healthy" } else { "unhealthy" }.to_string(),
        exit_code: exit.code,
        signal: exit.signal,
        command: args,
        checked_at_unix,
    };
    state.mark_health(health.clone())?;
    state::save(&state)?;
    let mut event =
        AuditEvent::new(id, "health", health.status.as_str()).with_status(health.status.as_str());
    if let Some(code) = health.exit_code.and_then(|code| u64::try_from(code).ok()) {
        event = event.with_value(code);
    }
    audit_log::append(&event)?;

    Ok(HealthResult {
        id: id.to_string(),
        checked_at_unix,
        status: health.status,
        attempts,
        exit_code: health.exit_code,
        signal: health.signal,
        command: health.command,
    })
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_cmd_healthcheck_args() {
        let healthcheck = Healthcheck {
            test: vec!["CMD".to_string(), "/bin/true".to_string()],
            interval: None,
            timeout: None,
            retries: None,
        };

        assert_eq!(
            command_args(&healthcheck).expect("valid healthcheck"),
            ["/bin/true".to_string()]
        );
    }

    #[test]
    fn builds_cmd_shell_healthcheck_args() {
        let healthcheck = Healthcheck {
            test: vec![
                "CMD-SHELL".to_string(),
                "echo".to_string(),
                "ok".to_string(),
            ],
            interval: None,
            timeout: None,
            retries: None,
        };

        assert_eq!(
            command_args(&healthcheck).expect("valid healthcheck"),
            [
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo ok".to_string()
            ]
        );
    }

    #[test]
    fn rejects_disabled_healthcheck_args_with_typed_error() {
        let healthcheck = Healthcheck {
            test: vec!["NONE".to_string()],
            interval: None,
            timeout: None,
            retries: None,
        };

        assert!(matches!(
            command_args(&healthcheck),
            Err(HealthcheckError::Disabled)
        ));
    }

    #[test]
    fn rejects_empty_cmd_with_typed_error() {
        let healthcheck = Healthcheck {
            test: vec!["CMD".to_string()],
            interval: None,
            timeout: None,
            retries: None,
        };

        assert!(matches!(
            command_args(&healthcheck),
            Err(HealthcheckError::MissingCommand { kind: "CMD" })
        ));
    }

    #[test]
    fn computes_healthcheck_attempts_from_retries() {
        let default_retries = Healthcheck {
            test: vec!["CMD".to_string(), "true".to_string()],
            interval: None,
            timeout: None,
            retries: None,
        };
        let configured_retries = Healthcheck {
            test: vec!["CMD".to_string(), "true".to_string()],
            interval: None,
            timeout: None,
            retries: Some(3),
        };

        assert_eq!(attempts(&default_retries), 1);
        assert_eq!(attempts(&configured_retries), 4);
    }
}
