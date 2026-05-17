use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_STATE_ROOT: &str = "/run/crun-rs";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainerStatus {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerState {
    pub id: String,
    pub pid: Option<i32>,
    pub status: ContainerStatus,
    pub bundle: String,
    pub cgroup_path: Option<String>,
    #[serde(default = "default_network_mode")]
    pub network_mode: String,
    #[serde(default = "default_security_profile")]
    pub security_profile: String,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
}

impl ContainerState {
    pub fn running(
        id: &str,
        bundle: &Path,
        pid: i32,
        cgroup_path: Option<String>,
        network_mode: &str,
        security_profile: &str,
    ) -> Result<Self> {
        validate_id(id)?;
        let now = unix_timestamp()?;

        Ok(Self {
            id: id.to_string(),
            pid: Some(pid),
            status: ContainerStatus::Running,
            bundle: bundle.display().to_string(),
            cgroup_path,
            network_mode: network_mode.to_string(),
            security_profile: security_profile.to_string(),
            created_at_unix: now,
            updated_at_unix: now,
            exit_code: None,
            signal: None,
        })
    }

    pub fn mark_stopped(&mut self, exit_code: Option<i32>, signal: Option<String>) -> Result<()> {
        self.status = ContainerStatus::Stopped;
        self.updated_at_unix = unix_timestamp()?;
        self.exit_code = exit_code;
        self.signal = signal;
        Ok(())
    }
}

fn default_network_mode() -> String {
    "bridge".to_string()
}

fn default_security_profile() -> String {
    "default".to_string()
}

pub fn load(id: &str) -> Result<ContainerState> {
    load_from(Path::new(DEFAULT_STATE_ROOT), id)
}

pub fn save(state: &ContainerState) -> Result<()> {
    save_to(Path::new(DEFAULT_STATE_ROOT), state)
}

pub fn delete(id: &str) -> Result<()> {
    delete_from(Path::new(DEFAULT_STATE_ROOT), id)
}

pub fn exists(id: &str) -> Result<bool> {
    validate_id(id)?;
    Ok(state_file(Path::new(DEFAULT_STATE_ROOT), id).exists())
}

fn load_from(root: &Path, id: &str) -> Result<ContainerState> {
    validate_id(id)?;
    let path = state_file(root, id);
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read state file: {}", path.display()))?;
    let state = serde_json::from_str(&content).context("failed to parse state file")?;

    Ok(state)
}

fn save_to(root: &Path, state: &ContainerState) -> Result<()> {
    validate_id(&state.id)?;
    let dir = container_dir(root, &state.id);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create state directory: {}", dir.display()))?;

    let path = state_file(root, &state.id);
    let content = serde_json::to_string_pretty(state).context("failed to serialize state")?;
    fs::write(&path, content).with_context(|| format!("failed to write state: {}", path.display()))
}

fn delete_from(root: &Path, id: &str) -> Result<()> {
    let state = load_from(root, id)?;
    if state.status == ContainerStatus::Running {
        bail!("container {id} is running; stop it before delete");
    }

    let dir = container_dir(root, id);
    fs::remove_dir_all(&dir)
        .with_context(|| format!("failed to remove state directory: {}", dir.display()))
}

fn container_dir(root: &Path, id: &str) -> PathBuf {
    root.join(id)
}

fn state_file(root: &Path, id: &str) -> PathBuf {
    container_dir(root, id).join("state.json")
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() {
        bail!("container id must not be empty");
    }

    if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("container id may only contain ASCII letters, numbers, '.', '_' and '-'");
    }

    Ok(())
}

fn unix_timestamp() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX_EPOCH")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_container_ids() {
        assert!(validate_id("").is_err());
        assert!(validate_id("../demo").is_err());
        assert!(validate_id("demo/one").is_err());
        assert!(validate_id("demo one").is_err());
        assert!(validate_id("demo_01.2-3").is_ok());
    }

    #[test]
    fn saves_loads_and_deletes_stopped_state() {
        let root = std::env::temp_dir().join(format!("crun-rs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let mut state = ContainerState::running(
            "demo",
            Path::new("/tmp/bundle"),
            1234,
            Some("/sys/fs/cgroup/container-runtime/crun-1234".to_string()),
            "bridge",
            "default",
        )
        .expect("state should be valid");
        save_to(&root, &state).expect("state should save");

        let loaded = load_from(&root, "demo").expect("state should load");
        assert_eq!(loaded.id, "demo");
        assert_eq!(loaded.pid, Some(1234));
        assert_eq!(loaded.status, ContainerStatus::Running);
        assert_eq!(
            loaded.cgroup_path.as_deref(),
            Some("/sys/fs/cgroup/container-runtime/crun-1234")
        );
        assert_eq!(loaded.network_mode, "bridge");
        assert_eq!(loaded.security_profile, "default");

        state.mark_stopped(Some(0), None).expect("mark stopped");
        save_to(&root, &state).expect("stopped state should save");
        delete_from(&root, "demo").expect("stopped state should delete");
        assert!(!container_dir(&root, "demo").exists());
    }
}
