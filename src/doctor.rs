use crate::command::{self, CommandError, EXTERNAL_COMMAND_TIMEOUT};
use crate::error::DoctorError;
use crate::network::{cleanup_nat_lease, cleanup_veth_host, release_bridge_network, VethPair};
use crate::process_identity::ProcessIdentity;
use crate::state::{self, ContainerState, ContainerStatus};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CGROUP_ROOT: &str = "/sys/fs/cgroup/container-runtime";
const NETWORK_STATE_ROOT: &str = "/run/crun-rs/network";
const SECCOMP_ACTIONS_AVAIL: &str = "/proc/sys/kernel/seccomp/actions_avail";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DoctorReport {
    pub issues: Vec<DoctorIssue>,
}

impl DoctorReport {
    pub fn is_clean(&self) -> bool {
        self.issues.iter().all(|issue| issue.fixed)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DoctorIssue {
    pub kind: String,
    pub id: Option<String>,
    pub path: Option<String>,
    pub message: String,
    pub fixed: bool,
}

#[derive(Debug, Deserialize)]
struct BridgeAllocations {
    containers: std::collections::BTreeMap<String, u8>,
}

pub fn run(fix: bool) -> Result<DoctorReport> {
    let mut issues = Vec::new();
    let states = state::list_raw().context("failed to list container states")?;

    check_stale_running_states(&states, fix, &mut issues)?;
    check_orphan_cgroups(&states, Path::new(CGROUP_ROOT), fix, &mut issues)?;
    check_stale_network_allocations(&states, Path::new(NETWORK_STATE_ROOT), fix, &mut issues)?;
    check_orphan_veth_links(&states, fix, &mut issues)?;
    check_seccomp_log_action(Path::new(SECCOMP_ACTIONS_AVAIL), &mut issues);

    Ok(DoctorReport { issues })
}

/// Reports whether the kernel can log denied syscalls.
///
/// `--seccomp-action log` is how a generated profile is validated without
/// breaking the workload, and it needs `SECCOMP_RET_LOG`. Nothing is broken
/// without it, so this is informational rather than fixable.
fn check_seccomp_log_action(path: &Path, issues: &mut Vec<DoctorIssue>) {
    let Ok(actions) = fs::read_to_string(path) else {
        issues.push(DoctorIssue {
            kind: "seccomp-log-unknown".to_string(),
            id: None,
            path: Some(path.display().to_string()),
            message: "cannot read the available seccomp actions; --seccomp-action log may not work"
                .to_string(),
            fixed: false,
        });
        return;
    };

    if !actions.split_whitespace().any(|action| action == "log") {
        issues.push(DoctorIssue {
            kind: "seccomp-log-unavailable".to_string(),
            id: None,
            path: Some(path.display().to_string()),
            message: "this kernel does not offer SECCOMP_RET_LOG, so --seccomp-action log cannot record denied syscalls"
                .to_string(),
            fixed: false,
        });
    }
}

fn check_stale_running_states(
    states: &[state::ContainerState],
    fix: bool,
    issues: &mut Vec<DoctorIssue>,
) -> Result<()> {
    let protected_veths = active_veth_names(states);

    for state in states {
        if state.status != ContainerStatus::Running || !is_stale_process(state) {
            continue;
        }

        let mut fixed = false;
        let mut message = format!(
            "state is running but pid {:?} does not match the stored process identity",
            state.pid
        );
        if fix {
            match cleanup_stale_resources(state, &protected_veths)
                .and_then(|()| mark_stale_state_stopped(state))
            {
                Ok(()) => fixed = true,
                Err(error) => {
                    message.push_str(&format!("; recovery failed: {error}"));
                }
            }
        }

        issues.push(DoctorIssue {
            kind: "stale_state".to_string(),
            id: Some(state.id.clone()),
            path: None,
            message,
            fixed,
        });
    }

    Ok(())
}

fn is_stale_process(state: &ContainerState) -> bool {
    state
        .pid
        .map(|pid| ProcessIdentity::open(pid, state.process_starttime).is_err())
        .unwrap_or(true)
}

fn active_veth_names(states: &[ContainerState]) -> BTreeSet<String> {
    states
        .iter()
        .filter(|state| state.status == ContainerStatus::Running && !is_stale_process(state))
        .flat_map(|state| {
            let mut names = vec![VethPair::for_container_id(&state.id).host_name];
            if let Some(pid) = state.pid {
                names.push(VethPair::for_pid(pid).host_name);
            }
            names
        })
        .collect()
}

fn cleanup_stale_resources(
    state: &ContainerState,
    protected_veths: &BTreeSet<String>,
) -> Result<()> {
    let mut errors = Vec::new();

    if let Some(lease) = state.nat_lease.as_ref() {
        if let Err(error) = cleanup_nat_lease(lease) {
            errors.push(format!("NAT cleanup failed: {error}"));
        }
    }

    if state.network_mode == "bridge" {
        let mut host_names = vec![VethPair::for_container_id(&state.id).host_name];
        if let Some(pid) = state.pid {
            host_names.push(VethPair::for_pid(pid).host_name);
        }
        for host_name in host_names {
            if !protected_veths.contains(&host_name) {
                if let Err(error) = cleanup_veth_host(&host_name) {
                    errors.push(format!("veth {host_name} cleanup failed: {error}"));
                }
            }
        }
        if let Err(error) = release_bridge_network(&state.id) {
            errors.push(format!("bridge allocation cleanup failed: {error}"));
        }
    }

    if let Some(path) = state.cgroup_path.as_deref() {
        if let Err(error) = remove_stale_cgroup(Path::new(path)) {
            errors.push(format!("cgroup cleanup failed: {error}"));
        }
    }

    if let Some(overlay) = state.overlay_ownership.as_ref() {
        if let Err(error) = overlay.cleanup() {
            errors.push(format!("overlay cleanup failed: {error}"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(errors.join("; ")))
    }
}

fn remove_stale_cgroup(path: &Path) -> Result<()> {
    for _ in 0..10 {
        let procs = fs::read_to_string(path.join("cgroup.procs")).unwrap_or_default();
        if procs.trim().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    if path.exists() {
        fs::remove_dir(path)
            .with_context(|| format!("failed to remove cgroup {}", path.display()))?;
    }
    Ok(())
}

fn mark_stale_state_stopped(state: &ContainerState) -> Result<()> {
    let mut fixed_state = state.clone();
    fixed_state
        .mark_stopped(None, Some("STALE".to_string()))
        .with_context(|| format!("failed to mark stale state stopped: {}", state.id))?;
    state::save(&fixed_state)
        .with_context(|| format!("failed to save stale state fix: {}", state.id))
}

fn check_orphan_cgroups(
    states: &[state::ContainerState],
    cgroup_root: &Path,
    fix: bool,
    issues: &mut Vec<DoctorIssue>,
) -> Result<()> {
    if !cgroup_root.exists() {
        return Ok(());
    }

    let referenced = states
        .iter()
        .filter_map(|state| state.cgroup_path.as_deref())
        .map(PathBuf::from)
        .collect::<BTreeSet<_>>();

    for entry in fs::read_dir(cgroup_root)
        .with_context(|| format!("failed to read cgroup root: {}", cgroup_root.display()))?
    {
        let entry = entry.context("failed to read cgroup directory entry")?;
        if !entry
            .file_type()
            .context("failed to read cgroup directory entry type")?
            .is_dir()
        {
            continue;
        }

        let path = entry.path();
        if referenced.contains(&path) {
            continue;
        }

        let mut fixed = false;
        if fix && fs::remove_dir(&path).is_ok() {
            fixed = true;
        }

        issues.push(DoctorIssue {
            kind: "orphan_cgroup".to_string(),
            id: None,
            path: Some(path.display().to_string()),
            message: "cgroup is not referenced by any container state".to_string(),
            fixed,
        });
    }

    Ok(())
}

fn check_stale_network_allocations(
    states: &[state::ContainerState],
    network_root: &Path,
    fix: bool,
    issues: &mut Vec<DoctorIssue>,
) -> Result<()> {
    let allocations_path = network_root.join("allocations.json");
    if !allocations_path.exists() {
        return Ok(());
    }

    let content = fs::read_to_string(&allocations_path)
        .with_context(|| format!("failed to read {}", allocations_path.display()))?;
    let allocations = serde_json::from_str::<BridgeAllocations>(&content)
        .context("failed to parse network allocations")?;
    let active_bridge_ids = states
        .iter()
        .filter(|state| {
            state.status == ContainerStatus::Running
                && state.network_mode == "bridge"
                && !is_stale_process(state)
        })
        .map(|state| state.id.as_str())
        .collect::<BTreeSet<_>>();

    for id in allocations.containers.keys() {
        if active_bridge_ids.contains(id.as_str()) {
            continue;
        }

        let mut fixed = false;
        if fix {
            release_bridge_network(id)
                .with_context(|| format!("failed to release stale bridge allocation: {id}"))?;
            fixed = true;
        }

        issues.push(DoctorIssue {
            kind: "stale_network_allocation".to_string(),
            id: Some(id.clone()),
            path: Some(allocations_path.display().to_string()),
            message: "bridge allocation is not owned by a running bridge container".to_string(),
            fixed,
        });
    }

    Ok(())
}

fn check_orphan_veth_links(
    states: &[state::ContainerState],
    fix: bool,
    issues: &mut Vec<DoctorIssue>,
) -> Result<()> {
    let mut ip = Command::new("ip");
    ip.args(["-o", "link", "show"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output =
        command::output(ip, "ip -o link show", EXTERNAL_COMMAND_TIMEOUT).map_err(|error| {
            match error {
                CommandError::TimedOut {
                    command,
                    timeout_ms,
                } => anyhow::Error::new(DoctorError::CommandTimedOut {
                    command,
                    timeout_ms,
                }),
                error => anyhow::Error::new(error),
            }
        })?;
    if !output.status.success() {
        return Ok(());
    }

    let expected = states
        .iter()
        .filter(|state| state.status == ContainerStatus::Running && state.network_mode == "bridge")
        .filter_map(|state| state.pid)
        .map(|pid| format!("vethh{pid}"))
        .collect::<BTreeSet<_>>();

    let stdout = String::from_utf8_lossy(&output.stdout);
    for iface in parse_veth_links(&stdout) {
        if expected.contains(&iface) {
            continue;
        }

        let mut fixed = false;
        if fix && cleanup_veth_host(&iface).is_ok() {
            fixed = true;
        }

        issues.push(DoctorIssue {
            kind: "orphan_veth".to_string(),
            id: None,
            path: Some(iface.clone()),
            message: "host veth is not owned by a running bridge container".to_string(),
            fixed,
        });
    }

    Ok(())
}

fn parse_veth_links(ip_output: &str) -> Vec<String> {
    ip_output
        .lines()
        .filter_map(|line| {
            let (_, rest) = line.split_once(": ")?;
            let (name, _) = rest.split_once(':')?;
            let name = name.split('@').next().unwrap_or(name);
            if name.starts_with("vethh") {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{RuntimeMetadata, StartedResources};

    #[test]
    fn detects_pid_reuse_using_process_starttime() {
        let pid = i32::try_from(std::process::id()).expect("test pid should fit i32");
        let state = ContainerState::running(
            "identity",
            Path::new("/tmp/bundle"),
            pid,
            StartedResources {
                cgroup_path: None,
                network_subnet: None,
                nat_lease: None,
                overlay_ownership: None,
                log_path: None,
            },
            RuntimeMetadata {
                network_mode: "none",
                security_profile: "denylist",
                log_mode: "off",
                userns_mode: "host",
                userns_map: None,
                rootfs_mode: "direct",
                policy_profile: "none",
                tty: false,
                seccomp_mode: "off",
                seccomp_profile: None,
                seccomp_action: None,
                seccomp_order: "by_frequency",
                seccomp_log: false,
            },
        )
        .expect("current process state should build");
        assert!(!is_stale_process(&state));

        let mut reused = state;
        reused.process_starttime = reused.process_starttime.map(|start| start + 1);
        assert!(is_stale_process(&reused));
    }

    #[test]
    fn reports_a_kernel_without_the_seccomp_log_action() {
        let path = std::env::temp_dir().join(format!("crun-actions-{}", std::process::id()));
        std::fs::write(&path, "kill_process kill_thread trap errno trace allow\n")
            .expect("actions file should write");
        let mut issues = Vec::new();

        check_seccomp_log_action(&path, &mut issues);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].kind, "seccomp-log-unavailable");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stays_quiet_when_the_seccomp_log_action_exists() {
        let path = std::env::temp_dir().join(format!("crun-actions-ok-{}", std::process::id()));
        std::fs::write(
            &path,
            "kill_process kill_thread trap errno trace log allow\n",
        )
        .expect("actions file should write");
        let mut issues = Vec::new();

        check_seccomp_log_action(&path, &mut issues);

        assert!(issues.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reports_when_the_available_actions_cannot_be_read() {
        let mut issues = Vec::new();

        check_seccomp_log_action(Path::new("/definitely/not/here"), &mut issues);

        assert_eq!(issues.len(), 1);
        assert_eq!(issues[0].kind, "seccomp-log-unknown");
    }

    #[test]
    fn parses_host_veth_names_from_ip_output() {
        let output = "\
1: lo: <LOOPBACK> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
12: vethh123@if11: <BROADCAST,MULTICAST> mtu 1500 state UP mode DEFAULT group default
13: vethp123@if14: <BROADCAST,MULTICAST> mtu 1500 state UP mode DEFAULT group default
";

        assert_eq!(parse_veth_links(output), ["vethh123".to_string()]);
    }
}
