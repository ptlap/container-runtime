use anyhow::{Context, Result};
use nix::unistd::Pid;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup/container-runtime";

#[derive(Debug, Clone)]
pub struct CgroupConfig {
    pub memory_limit: Option<i64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<u64>,
    pub pids_limit: Option<i64>,
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
        let root = Path::new(CGROUP_ROOT);

        fs::create_dir_all(root).context("failed to create cgroup root")?;

        // Enable controllers for children of container-runtime.
        // Ignore failure because some systems may not allow some controllers here.
        let subtree_control = root.join("cgroup.subtree_control");
        let _ = fs::write(&subtree_control, "+memory +cpu +pids");

        let path = root.join(id);
        fs::create_dir_all(&path).context("failed to create container cgroup")?;

        if let Some(memory_limit) = config.memory_limit {
            if memory_limit <= 0 {
                anyhow::bail!("memory_limit must > 0, got {memory_limit}");
            }
            fs::write(path.join("memory.max"), memory_limit.to_string())
                .context("failed to write memory.max")?;
        }

        if let Some(cpu_quota) = config.cpu_quota {
            let cpu_period = config.cpu_period.unwrap_or(100_000);
            fs::write(path.join("cpu.max"), format!("{cpu_quota} {cpu_period}"))
                .context("failed to write cpu.max")?;
        }

        if let Some(pids_limit) = config.pids_limit {
            if pids_limit <= 0 {
                anyhow::bail!("pids_limit must > 0, got {pids_limit}");
            }
            fs::write(path.join("pids.max"), pids_limit.to_string())
                .context("failed to write pids.max")?;
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
}
