use crate::error::CgroupError;
use crate::state::{self, ContainerStatus};
use anyhow::{Context, Result};
use nix::unistd::Pid;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

const CGROUP_ROOT_NAME: &str = "container-runtime";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupConfig {
    pub memory_limit: Option<i64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<u64>,
    pub pids_limit: Option<i64>,
}

impl CgroupConfig {
    pub fn validate(&self) -> std::result::Result<(), CgroupError> {
        if let Some(memory_limit) = self.memory_limit {
            if memory_limit <= 0 {
                return Err(CgroupError::InvalidMemoryLimit {
                    value: memory_limit,
                });
            }
        }

        if let Some(cpu_quota) = self.cpu_quota {
            if cpu_quota <= 0 {
                return Err(CgroupError::InvalidCpuQuota { value: cpu_quota });
            }
        }
        if let Some(cpu_period) = self.cpu_period {
            if cpu_period == 0 {
                return Err(CgroupError::InvalidCpuPeriod { value: cpu_period });
            }
        }
        if let Some(pids_limit) = self.pids_limit {
            if pids_limit <= 0 {
                return Err(CgroupError::InvalidPidsLimit { value: pids_limit });
            }
        }

        Ok(())
    }
}

pub fn cgroup_root() -> Result<PathBuf> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .context("failed to read /proc/self/mountinfo")?;
    find_cgroup2_mountpoint(&mountinfo).ok_or_else(|| CgroupError::CgroupV2Unavailable.into())
}

fn find_cgroup2_mountpoint(mountinfo: &str) -> Option<PathBuf> {
    for line in mountinfo.lines() {
        let Some((mount_fields, filesystem_fields)) = line.split_once(" - ") else {
            continue;
        };
        if filesystem_fields.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let mountpoint = mount_fields.split_whitespace().nth(4)?;
        return Some(PathBuf::from(unescape_mountinfo_path(mountpoint)));
    }
    None
}

fn unescape_mountinfo_path(path: &str) -> String {
    path.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn required_controllers(config: &CgroupConfig) -> BTreeSet<&'static str> {
    let mut required = BTreeSet::new();
    if config.memory_limit.is_some() {
        required.insert("memory");
    }
    if config.cpu_quota.is_some() {
        required.insert("cpu");
    }
    if config.pids_limit.is_some() {
        required.insert("pids");
    }
    required
}

#[derive(Debug, Default)]
struct ControllerActivation {
    previous: String,
    added: Vec<String>,
}

fn enable_required_controllers(root: &Path, config: &CgroupConfig) -> Result<ControllerActivation> {
    let required = required_controllers(config);
    if required.is_empty() {
        return Ok(ControllerActivation::default());
    }

    let available = fs::read_to_string(root.join("cgroup.controllers"))
        .with_context(|| format!("failed to read cgroup controllers: {}", root.display()))?;
    for controller in &required {
        if !available
            .split_whitespace()
            .any(|value| value == *controller)
        {
            return Err(CgroupError::ControllerUnavailable {
                controller: (*controller).to_string(),
            }
            .into());
        }
    }

    let previous = fs::read_to_string(root.join("cgroup.subtree_control"))
        .with_context(|| format!("failed to read cgroup subtree control: {}", root.display()))?;
    let current = previous.split_whitespace().collect::<BTreeSet<_>>();
    let newly_enabled = required
        .iter()
        .filter(|controller| !current.contains(**controller))
        .map(|controller| (*controller).to_string())
        .collect::<Vec<_>>();
    if newly_enabled.is_empty() {
        return Ok(ControllerActivation {
            previous,
            added: newly_enabled,
        });
    }

    let value = newly_enabled
        .iter()
        .map(|controller| format!("+{controller}"))
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(root.join("cgroup.subtree_control"), value)
        .with_context(|| format!("failed to enable cgroup controllers: {}", root.display()))?;
    Ok(ControllerActivation {
        previous,
        added: newly_enabled,
    })
}

fn rollback_enabled_controllers(root: &Path, activation: &ControllerActivation) {
    if activation.added.is_empty() {
        return;
    }
    if let Err(error) = fs::write(root.join("cgroup.subtree_control"), &activation.previous) {
        tracing::warn!("failed to rollback cgroup controllers: {error}");
    }
}

#[derive(Debug)]
pub struct Cgroup {
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CgroupStats {
    pub path: String,
    pub memory_current: Option<u64>,
    pub memory_max: Option<String>,
    pub cpu_usage_usec: Option<u64>,
    pub cpu_user_usec: Option<u64>,
    pub cpu_system_usec: Option<u64>,
    pub pids_current: Option<u64>,
    pub pids_max: Option<String>,
    pub memory: MemoryStats,
    pub cpu: CpuStats,
    pub pids: PidsStats,
    pub io: Vec<IoDeviceStats>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MemoryStats {
    pub current: Option<u64>,
    pub max: Option<String>,
    pub events: BTreeMap<String, u64>,
    pub pressure: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CpuStats {
    pub usage_usec: Option<u64>,
    pub user_usec: Option<u64>,
    pub system_usec: Option<u64>,
    pub nr_periods: Option<u64>,
    pub nr_throttled: Option<u64>,
    pub throttled_usec: Option<u64>,
    pub pressure: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct PidsStats {
    pub current: Option<u64>,
    pub max: Option<String>,
    pub events: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IoDeviceStats {
    pub device: String,
    pub rbytes: Option<u64>,
    pub wbytes: Option<u64>,
    pub rios: Option<u64>,
    pub wios: Option<u64>,
    pub dbytes: Option<u64>,
    pub dios: Option<u64>,
    pub raw: BTreeMap<String, u64>,
}

impl Cgroup {
    pub fn new(id: &str, config: &CgroupConfig) -> Result<Self> {
        let root = cgroup_root()?.join(CGROUP_ROOT_NAME);
        Self::new_at(&root, id, config)
    }

    fn new_at(root: &Path, id: &str, config: &CgroupConfig) -> Result<Self> {
        state::validate_id(id)?;
        config.validate()?;
        fs::create_dir_all(root).context("failed to create cgroup root")?;
        let activation = enable_required_controllers(root, config)?;
        let path = root.join(id);
        if let Err(error) = fs::create_dir_all(&path)
            .with_context(|| format!("failed to create container cgroup: {}", path.display()))
            .and_then(|()| {
                if let Some(memory_limit) = config.memory_limit {
                    fs::write(path.join("memory.max"), memory_limit.to_string())
                        .context("failed to write memory.max")?;
                }
                if let Some(cpu_quota) = config.cpu_quota {
                    let cpu_period = config.cpu_period.unwrap_or(100_000);
                    fs::write(path.join("cpu.max"), format!("{cpu_quota} {cpu_period}"))
                        .context("failed to write cpu.max")?;
                }
                if let Some(pids_limit) = config.pids_limit {
                    fs::write(path.join("pids.max"), pids_limit.to_string())
                        .context("failed to write pids.max")?;
                }
                Ok::<(), anyhow::Error>(())
            })
        {
            let _ = fs::remove_dir(&path);
            rollback_enabled_controllers(root, &activation);
            return Err(error);
        }

        Ok(Self { path })
    }

    pub fn add_process(&self, pid: Pid) -> Result<()> {
        fs::write(self.path.join("cgroup.procs"), pid.as_raw().to_string())
            .context("failed to add process to cgroup")?;

        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn delete(&self) -> Result<()> {
        for _ in 0..10 {
            let procs = fs::read_to_string(self.path.join("cgroup.procs")).unwrap_or_default();

            if procs.trim().is_empty() {
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        if self.path.exists() {
            fs::remove_dir(&self.path).context("failed to remove cgroup")?;
        }

        Ok(())
    }
}

pub fn read_stats(path: &Path) -> Result<CgroupStats> {
    let cpu_stat = read_keyed_u64(path.join("cpu.stat"))?;
    let memory_current = read_optional_u64(path.join("memory.current"))?;
    let memory_max = read_optional_string(path.join("memory.max"))?;
    let pids_current = read_optional_u64(path.join("pids.current"))?;
    let pids_max = read_optional_string(path.join("pids.max"))?;

    Ok(CgroupStats {
        path: path.display().to_string(),
        memory_current,
        memory_max: memory_max.clone(),
        cpu_usage_usec: cpu_stat.get("usage_usec").copied(),
        cpu_user_usec: cpu_stat.get("user_usec").copied(),
        cpu_system_usec: cpu_stat.get("system_usec").copied(),
        pids_current,
        pids_max: pids_max.clone(),
        memory: MemoryStats {
            current: memory_current,
            max: memory_max,
            events: read_keyed_u64_btree(path.join("memory.events"))?,
            pressure: read_optional_string(path.join("memory.pressure"))?,
        },
        cpu: CpuStats {
            usage_usec: cpu_stat.get("usage_usec").copied(),
            user_usec: cpu_stat.get("user_usec").copied(),
            system_usec: cpu_stat.get("system_usec").copied(),
            nr_periods: cpu_stat.get("nr_periods").copied(),
            nr_throttled: cpu_stat.get("nr_throttled").copied(),
            throttled_usec: cpu_stat.get("throttled_usec").copied(),
            pressure: read_optional_string(path.join("cpu.pressure"))?,
        },
        pids: PidsStats {
            current: pids_current,
            max: pids_max,
            events: read_keyed_u64_btree(path.join("pids.events"))?,
        },
        io: read_io_stats(path.join("io.stat"))?,
    })
}

pub fn read_container_stats(id: &str) -> Result<CgroupStats> {
    let cgroup_path = running_cgroup_path(id)?;
    read_stats(&cgroup_path)
}

pub fn running_cgroup_path(id: &str) -> Result<PathBuf> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Running {
        return Err(CgroupError::ContainerNotRunning { id: id.to_string() }.into());
    }

    let Some(cgroup_path) = state.cgroup_path.as_deref() else {
        return Err(CgroupError::ContainerHasNoPath { id: id.to_string() }.into());
    };

    let cgroup_path = PathBuf::from(cgroup_path);
    if !cgroup_path.exists() {
        return Err(CgroupError::PathDoesNotExist {
            path: cgroup_path.display().to_string(),
        }
        .into());
    }

    Ok(cgroup_path)
}

fn read_optional_u64(path: PathBuf) -> Result<Option<u64>> {
    let Some(value) = read_optional_string(path)? else {
        return Ok(None);
    };

    Ok(value.parse().ok())
}

fn read_optional_string(path: PathBuf) -> Result<Option<String>> {
    match fs::read_to_string(&path) {
        Ok(value) => Ok(Some(value.trim().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn read_keyed_u64(path: PathBuf) -> Result<HashMap<String, u64>> {
    let Some(content) = read_optional_string(path)? else {
        return Ok(HashMap::new());
    };

    let mut values = HashMap::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next() else {
            continue;
        };
        if let Ok(value) = value.parse::<u64>() {
            values.insert(key.to_string(), value);
        }
    }

    Ok(values)
}

fn read_keyed_u64_btree(path: PathBuf) -> Result<BTreeMap<String, u64>> {
    let Some(content) = read_optional_string(path)? else {
        return Ok(BTreeMap::new());
    };

    Ok(parse_keyed_u64_btree(&content))
}

fn parse_keyed_u64_btree(content: &str) -> BTreeMap<String, u64> {
    let mut values = BTreeMap::new();
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next() else {
            continue;
        };
        if let Ok(value) = value.parse::<u64>() {
            values.insert(key.to_string(), value);
        }
    }

    values
}

fn read_io_stats(path: PathBuf) -> Result<Vec<IoDeviceStats>> {
    let Some(content) = read_optional_string(path)? else {
        return Ok(Vec::new());
    };

    Ok(parse_io_stats(&content))
}

fn parse_io_stats(content: &str) -> Vec<IoDeviceStats> {
    content
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let device = parts.next()?.to_string();
            let mut raw = BTreeMap::new();

            for metric in parts {
                let Some((key, value)) = metric.split_once('=') else {
                    continue;
                };
                if let Ok(value) = value.parse::<u64>() {
                    raw.insert(key.to_string(), value);
                }
            }

            Some(IoDeviceStats {
                device,
                rbytes: raw.get("rbytes").copied(),
                wbytes: raw.get("wbytes").copied(),
                rios: raw.get("rios").copied(),
                wios: raw.get("wios").copied(),
                dbytes: raw.get("dbytes").copied(),
                dios: raw.get("dios").copied(),
                raw,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cgroup_stats_from_files() {
        let root = std::env::temp_dir().join(format!("crun-rs-cgroup-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create temp cgroup");
        fs::write(root.join("memory.current"), "1024\n").expect("write memory.current");
        fs::write(root.join("memory.max"), "268435456\n").expect("write memory.max");
        fs::write(
            root.join("cpu.stat"),
            "usage_usec 100\nuser_usec 70\nsystem_usec 30\nnr_periods 8\nnr_throttled 2\nthrottled_usec 40\n",
        )
        .expect("write cpu.stat");
        fs::write(
            root.join("memory.events"),
            "low 0\nhigh 1\nmax 2\noom 0\noom_kill 0\n",
        )
        .expect("write memory.events");
        fs::write(
            root.join("memory.pressure"),
            "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        )
        .expect("write memory.pressure");
        fs::write(root.join("pids.current"), "2\n").expect("write pids.current");
        fs::write(root.join("pids.max"), "max\n").expect("write pids.max");
        fs::write(root.join("pids.events"), "max 3\n").expect("write pids.events");
        fs::write(
            root.join("io.stat"),
            "8:0 rbytes=1024 wbytes=2048 rios=3 wios=4 dbytes=0 dios=0\n",
        )
        .expect("write io.stat");

        let stats = read_stats(&root).expect("read stats");
        assert_eq!(stats.memory_current, Some(1024));
        assert_eq!(stats.memory_max.as_deref(), Some("268435456"));
        assert_eq!(stats.cpu_usage_usec, Some(100));
        assert_eq!(stats.cpu_user_usec, Some(70));
        assert_eq!(stats.cpu_system_usec, Some(30));
        assert_eq!(stats.pids_current, Some(2));
        assert_eq!(stats.pids_max.as_deref(), Some("max"));
        assert_eq!(stats.memory.current, Some(1024));
        assert_eq!(stats.memory.events.get("high"), Some(&1));
        assert!(stats
            .memory
            .pressure
            .as_deref()
            .unwrap_or("")
            .contains("avg10"));
        assert_eq!(stats.cpu.nr_periods, Some(8));
        assert_eq!(stats.cpu.nr_throttled, Some(2));
        assert_eq!(stats.cpu.throttled_usec, Some(40));
        assert_eq!(stats.pids.events.get("max"), Some(&3));
        assert_eq!(stats.io.len(), 1);
        assert_eq!(stats.io[0].device, "8:0");
        assert_eq!(stats.io[0].rbytes, Some(1024));
        assert_eq!(stats.io[0].wbytes, Some(2048));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn parses_keyed_event_files() {
        let values = parse_keyed_u64_btree("oom 1\noom_kill 2\ninvalid nope\n");

        assert_eq!(values.get("oom"), Some(&1));
        assert_eq!(values.get("oom_kill"), Some(&2));
        assert!(!values.contains_key("invalid"));
    }

    #[test]
    fn parses_io_stat_lines() {
        let stats =
            parse_io_stats("8:0 rbytes=10 wbytes=20 rios=1 wios=2\n259:0 rbytes=30 unknown=99\n");

        assert_eq!(stats.len(), 2);
        assert_eq!(stats[0].device, "8:0");
        assert_eq!(stats[0].rbytes, Some(10));
        assert_eq!(stats[0].wios, Some(2));
        assert_eq!(stats[1].device, "259:0");
        assert_eq!(stats[1].raw.get("unknown"), Some(&99));
    }

    #[test]
    fn discovers_cgroup2_mountpoint_from_mountinfo() {
        let mountinfo =
            "36 29 0:32 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw";
        assert_eq!(
            find_cgroup2_mountpoint(mountinfo),
            Some(PathBuf::from("/sys/fs/cgroup"))
        );
        assert_eq!(
            find_cgroup2_mountpoint("1 2 0:1 / /tmp rw - tmpfs tmpfs rw"),
            None
        );
    }

    #[test]
    fn rejects_missing_requested_controller() {
        let root =
            std::env::temp_dir().join(format!("crun-rs-cgroup-controller-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create cgroup root");
        fs::write(root.join("cgroup.controllers"), "memory cpu\n").expect("write controllers");
        fs::write(root.join("cgroup.subtree_control"), "\n").expect("write subtree control");

        let error = Cgroup::new_at(
            &root,
            "missing-pids",
            &CgroupConfig {
                memory_limit: None,
                cpu_quota: None,
                cpu_period: None,
                pids_limit: Some(4),
            },
        )
        .expect_err("missing pids controller should fail closed");
        assert!(matches!(
            error.downcast_ref::<CgroupError>(),
            Some(CgroupError::ControllerUnavailable { controller }) if controller == "pids"
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rolls_back_controller_enablement_when_setup_fails() {
        let root =
            std::env::temp_dir().join(format!("crun-rs-cgroup-rollback-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create cgroup root");
        fs::write(root.join("cgroup.controllers"), "memory\n").expect("write controllers");
        fs::write(root.join("cgroup.subtree_control"), "memory\n").expect("write subtree control");
        fs::write(root.join("broken"), "not a directory").expect("create broken path");

        let error = Cgroup::new_at(
            &root,
            "broken",
            &CgroupConfig {
                memory_limit: Some(1024),
                cpu_quota: None,
                cpu_period: None,
                pids_limit: None,
            },
        )
        .expect_err("existing non-directory should fail setup");
        assert!(error.to_string().contains("container cgroup"));
        assert_eq!(
            fs::read_to_string(root.join("cgroup.subtree_control")).expect("read control"),
            "memory\n"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_invalid_cgroup_limits_with_typed_errors() {
        let memory_error = CgroupConfig {
            memory_limit: Some(0),
            cpu_quota: None,
            cpu_period: None,
            pids_limit: None,
        }
        .validate()
        .expect_err("zero memory limit should be rejected");

        assert!(matches!(
            memory_error,
            CgroupError::InvalidMemoryLimit { value: 0 }
        ));

        let pids_error = CgroupConfig {
            memory_limit: None,
            cpu_quota: None,
            cpu_period: None,
            pids_limit: Some(-1),
        }
        .validate()
        .expect_err("negative pids limit should be rejected");

        assert!(matches!(
            pids_error,
            CgroupError::InvalidPidsLimit { value: -1 }
        ));
    }
}
