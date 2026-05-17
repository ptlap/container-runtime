use anyhow::{Context, Result};
use nix::unistd::Pid;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const CGROUP_ROOT: &str = "/sys/fs/cgroup/container-runtime";

#[derive(Debug, Clone)]
pub struct CgroupConfig {
    pub memory_limit: Option<i64>,
    pub cpu_quota: Option<i64>,
    pub cpu_period: Option<u64>,
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

    Ok(CgroupStats {
        path: path.display().to_string(),
        memory_current: read_optional_u64(path.join("memory.current"))?,
        memory_max: read_optional_string(path.join("memory.max"))?,
        cpu_usage_usec: cpu_stat.get("usage_usec").copied(),
        cpu_user_usec: cpu_stat.get("user_usec").copied(),
        cpu_system_usec: cpu_stat.get("system_usec").copied(),
        pids_current: read_optional_u64(path.join("pids.current"))?,
        pids_max: read_optional_string(path.join("pids.max"))?,
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
            "usage_usec 100\nuser_usec 70\nsystem_usec 30\n",
        )
        .expect("write cpu.stat");
        fs::write(root.join("pids.current"), "2\n").expect("write pids.current");
        fs::write(root.join("pids.max"), "max\n").expect("write pids.max");

        let stats = read_stats(&root).expect("read stats");
        assert_eq!(stats.memory_current, Some(1024));
        assert_eq!(stats.memory_max.as_deref(), Some("268435456"));
        assert_eq!(stats.cpu_usage_usec, Some(100));
        assert_eq!(stats.cpu_user_usec, Some(70));
        assert_eq!(stats.cpu_system_usec, Some(30));
        assert_eq!(stats.pids_current, Some(2));
        assert_eq!(stats.pids_max.as_deref(), Some("max"));

        let _ = fs::remove_dir_all(&root);
    }
}
