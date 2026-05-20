use crate::network::{cleanup_veth_host, release_bridge_network};
use crate::state::{self, ContainerStatus};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const CGROUP_ROOT: &str = "/sys/fs/cgroup/container-runtime";
const NETWORK_STATE_ROOT: &str = "/run/crun-rs/network";

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

    Ok(DoctorReport { issues })
}

fn check_stale_running_states(
    states: &[state::ContainerState],
    fix: bool,
    issues: &mut Vec<DoctorIssue>,
) -> Result<()> {
    for state in states {
        if state.status != ContainerStatus::Running {
            continue;
        }

        let stale = state
            .pid
            .map(|pid| !state::pid_is_alive(pid))
            .unwrap_or(true);
        if !stale {
            continue;
        }

        let mut fixed = false;
        if fix {
            let mut fixed_state = state.clone();
            fixed_state
                .mark_stopped(None, Some("STALE".to_string()))
                .with_context(|| format!("failed to mark stale state stopped: {}", state.id))?;
            state::save(&fixed_state)
                .with_context(|| format!("failed to save stale state fix: {}", state.id))?;
            fixed = true;
        }

        issues.push(DoctorIssue {
            kind: "stale_state".to_string(),
            id: Some(state.id.clone()),
            path: None,
            message: format!("state is running but pid {:?} is not alive", state.pid),
            fixed,
        });
    }

    Ok(())
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
                && state.pid.map(state::pid_is_alive).unwrap_or(false)
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
    let output = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .context("failed to execute ip -o link show")?;
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
