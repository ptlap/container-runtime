use anyhow::{Context, Result};
use nix::unistd::Pid;
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

    pub fn delete(&self) -> Result<()> {
        // Đợi tất cả processes exit khỏi cgroup
        for _ in 0..10 {
            let procs = fs::read_to_string(self.path.join("cgroup.procs")).unwrap_or_default();
            if procs.trim().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        fs::remove_dir(&self.path).context("failed to remove cgroup")?;
        Ok(())
    }
}
