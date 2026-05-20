use crate::cgroup::read_stats;
use crate::spec::config::{load_config, OciConfig};
use crate::state::{self, ContainerStatus};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityInspection {
    pub id: String,
    pub pid: i32,
    pub security_profile: String,
    pub userns_mode: String,
    pub rootfs_mode: String,
    pub readonly_rootfs: bool,
    pub mount_count: usize,
    pub no_new_privs: Option<bool>,
    pub seccomp: SeccompInspection,
    pub capabilities: CapabilityInspection,
    pub resources: ResourceInspection,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SeccompInspection {
    pub mode: Option<u64>,
    pub filters: Option<u64>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapabilityInspection {
    pub inheritable: Option<String>,
    pub permitted: Option<String>,
    pub effective: Option<String>,
    pub effective_zero: Option<bool>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ResourceInspection {
    pub memory_limit: Option<String>,
    pub pids_limit: Option<String>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcSecurityStatus {
    no_new_privs: Option<bool>,
    seccomp_mode: Option<u64>,
    seccomp_filters: Option<u64>,
    cap_inheritable: Option<String>,
    cap_permitted: Option<String>,
    cap_effective: Option<String>,
}

pub fn inspect(id: &str) -> Result<SecurityInspection> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Running {
        bail!("container {id} is not running");
    }
    let Some(pid) = state.pid else {
        bail!("container {id} has no pid");
    };

    let config_path = Path::new(&state.bundle).join("config.json");
    let config = load_config(&config_path)?;
    let proc_status = read_proc_security_status(pid)?;
    let resources = inspect_resources(&config, state.cgroup_path.as_deref())?;
    let seccomp = SeccompInspection {
        mode: proc_status.seccomp_mode,
        filters: proc_status.seccomp_filters,
        enabled: proc_status.seccomp_mode.unwrap_or(0) != 0,
    };
    let capabilities = CapabilityInspection {
        inheritable: proc_status.cap_inheritable,
        permitted: proc_status.cap_permitted,
        effective_zero: proc_status
            .cap_effective
            .as_deref()
            .and_then(hex_capability_is_zero),
        effective: proc_status.cap_effective,
    };

    let mut inspection = SecurityInspection {
        id: state.id,
        pid,
        security_profile: state.security_profile,
        userns_mode: state.userns_mode,
        rootfs_mode: state.rootfs_mode,
        readonly_rootfs: config.root.readonly,
        mount_count: config.mounts.len(),
        no_new_privs: proc_status.no_new_privs,
        seccomp,
        capabilities,
        resources,
        warnings: Vec::new(),
    };
    inspection.warnings = security_warnings(&inspection);

    Ok(inspection)
}

fn inspect_resources(config: &OciConfig, cgroup_path: Option<&str>) -> Result<ResourceInspection> {
    let configured = config
        .linux
        .as_ref()
        .and_then(|linux| linux.resources.as_ref());
    let mut memory_limit = configured
        .and_then(|resources| resources.memory.as_ref())
        .and_then(|memory| memory.limit)
        .map(|value| value.to_string());
    let mut pids_limit = configured
        .and_then(|resources| resources.pids.as_ref())
        .and_then(|pids| pids.limit)
        .map(|value| value.to_string());
    let cpu_quota = configured
        .and_then(|resources| resources.cpu.as_ref())
        .and_then(|cpu| cpu.quota);
    let cpu_period = configured
        .and_then(|resources| resources.cpu.as_ref())
        .and_then(|cpu| cpu.period);

    if let Some(cgroup_path) = cgroup_path {
        let path = PathBuf::from(cgroup_path);
        if path.exists() {
            let stats = read_stats(&path)?;
            if memory_limit.is_none() {
                memory_limit = stats.memory.max;
            }
            if pids_limit.is_none() {
                pids_limit = stats.pids.max;
            }
        }
    }

    Ok(ResourceInspection {
        memory_limit,
        pids_limit,
        cpu_quota,
        cpu_period,
    })
}

fn read_proc_security_status(pid: i32) -> Result<ProcSecurityStatus> {
    let path = Path::new("/proc").join(pid.to_string()).join("status");
    let content =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(parse_proc_security_status(&content))
}

fn parse_proc_security_status(content: &str) -> ProcSecurityStatus {
    let fields = content
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_string(), value.trim().to_string()))
        .collect::<BTreeMap<_, _>>();

    ProcSecurityStatus {
        no_new_privs: fields
            .get("NoNewPrivs")
            .and_then(|value| value.parse::<u64>().ok())
            .map(|value| value != 0),
        seccomp_mode: fields
            .get("Seccomp")
            .and_then(|value| value.parse::<u64>().ok()),
        seccomp_filters: fields
            .get("Seccomp_filters")
            .and_then(|value| value.parse::<u64>().ok()),
        cap_inheritable: fields.get("CapInh").cloned(),
        cap_permitted: fields.get("CapPrm").cloned(),
        cap_effective: fields.get("CapEff").cloned(),
    }
}

fn hex_capability_is_zero(value: &str) -> Option<bool> {
    u128::from_str_radix(value, 16).ok().map(|value| value == 0)
}

fn security_warnings(inspection: &SecurityInspection) -> Vec<String> {
    let mut warnings = Vec::new();

    if inspection.security_profile == "unconfined" {
        warnings.push("security profile is unconfined".to_string());
    }
    if inspection.userns_mode == "host" {
        warnings.push(
            "user namespace is host; container root maps to host root when run as root".to_string(),
        );
    }
    if inspection.no_new_privs != Some(true) {
        warnings.push("no_new_privs is not enabled".to_string());
    }
    if !inspection.seccomp.enabled {
        warnings.push("seccomp is disabled".to_string());
    }
    if inspection.capabilities.effective_zero == Some(false) {
        warnings.push("effective capabilities are not fully dropped".to_string());
    }
    if !inspection.readonly_rootfs {
        warnings.push("root filesystem is writable".to_string());
    }
    if inspection
        .resources
        .memory_limit
        .as_deref()
        .is_none_or(is_unlimited)
    {
        warnings.push("memory limit is not configured".to_string());
    }
    if inspection
        .resources
        .pids_limit
        .as_deref()
        .is_none_or(is_unlimited)
    {
        warnings.push("pids limit is not configured".to_string());
    }
    if inspection.resources.cpu_quota.is_none() {
        warnings.push("cpu quota is not configured".to_string());
    }

    warnings
}

fn is_unlimited(value: &str) -> bool {
    value == "max" || value == "-1" || value == "0"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_security_status() {
        let status = parse_proc_security_status(
            "\
Name:\tsh
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
NoNewPrivs:\t1
Seccomp:\t2
Seccomp_filters:\t1
",
        );

        assert_eq!(status.no_new_privs, Some(true));
        assert_eq!(status.seccomp_mode, Some(2));
        assert_eq!(status.seccomp_filters, Some(1));
        assert_eq!(status.cap_effective.as_deref(), Some("0000000000000000"));
    }

    #[test]
    fn detects_zero_capabilities() {
        assert_eq!(hex_capability_is_zero("0000000000000000"), Some(true));
        assert_eq!(hex_capability_is_zero("0000000000000001"), Some(false));
        assert_eq!(hex_capability_is_zero("not-hex"), None);
    }

    #[test]
    fn warns_for_weak_security_posture() {
        let inspection = SecurityInspection {
            id: "demo".to_string(),
            pid: 1,
            security_profile: "unconfined".to_string(),
            userns_mode: "host".to_string(),
            rootfs_mode: "direct".to_string(),
            readonly_rootfs: false,
            mount_count: 0,
            no_new_privs: Some(false),
            seccomp: SeccompInspection {
                mode: Some(0),
                filters: Some(0),
                enabled: false,
            },
            capabilities: CapabilityInspection {
                inheritable: Some("0000000000000000".to_string()),
                permitted: Some("0000000000000001".to_string()),
                effective: Some("0000000000000001".to_string()),
                effective_zero: Some(false),
            },
            resources: ResourceInspection {
                memory_limit: Some("max".to_string()),
                pids_limit: None,
                cpu_quota: None,
                cpu_period: None,
            },
            warnings: Vec::new(),
        };

        let warnings = security_warnings(&inspection);

        assert!(warnings
            .iter()
            .any(|warning| warning.contains("unconfined")));
        assert!(warnings.iter().any(|warning| warning.contains("seccomp")));
        assert!(warnings.iter().any(|warning| warning.contains("memory")));
    }
}
