use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_STATE_ROOT: &str = "/run/crun-rs";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainerStatus {
    Created,
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
    pub fn created(
        id: &str,
        bundle: &Path,
        network_mode: &str,
        security_profile: &str,
    ) -> Result<Self> {
        validate_id(id)?;
        let now = unix_timestamp()?;

        Ok(Self {
            id: id.to_string(),
            pid: None,
            status: ContainerStatus::Created,
            bundle: bundle.display().to_string(),
            cgroup_path: None,
            network_mode: network_mode.to_string(),
            security_profile: security_profile.to_string(),
            created_at_unix: now,
            updated_at_unix: now,
            exit_code: None,
            signal: None,
        })
    }

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

    pub fn mark_running(&mut self, pid: i32, cgroup_path: Option<String>) -> Result<()> {
        self.pid = Some(pid);
        self.status = ContainerStatus::Running;
        self.cgroup_path = cgroup_path;
        self.updated_at_unix = unix_timestamp()?;
        self.exit_code = None;
        self.signal = None;
        Ok(())
    }

    pub fn mark_stopped(&mut self, exit_code: Option<i32>, signal: Option<String>) -> Result<()> {
        self.pid = None;
        self.status = ContainerStatus::Stopped;
        self.updated_at_unix = unix_timestamp()?;
        self.cgroup_path = None;
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

pub fn load_current(id: &str) -> Result<ContainerState> {
    load_current_from(Path::new(DEFAULT_STATE_ROOT), id)
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

pub fn list() -> Result<Vec<ContainerState>> {
    list_from(Path::new(DEFAULT_STATE_ROOT))
}

fn load_from(root: &Path, id: &str) -> Result<ContainerState> {
    validate_id(id)?;
    let path = state_file(root, id);
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read state file: {}", path.display()))?;
    let state = serde_json::from_str(&content).context("failed to parse state file")?;

    Ok(state)
}

fn load_current_from(root: &Path, id: &str) -> Result<ContainerState> {
    let mut state = load_from(root, id)?;
    refresh_liveness(root, &mut state)?;
    Ok(state)
}

fn list_from(root: &Path) -> Result<Vec<ContainerState>> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut states = Vec::new();
    for entry in fs::read_dir(root)
        .with_context(|| format!("failed to read state root: {}", root.display()))?
    {
        let entry = entry.context("failed to read state directory entry")?;
        if !entry
            .file_type()
            .context("failed to read state directory entry type")?
            .is_dir()
        {
            continue;
        }

        let id = entry.file_name().to_string_lossy().into_owned();
        states.push(load_current_from(root, &id)?);
    }

    states.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(states)
}

fn refresh_liveness(root: &Path, state: &mut ContainerState) -> Result<()> {
    if state.status != ContainerStatus::Running {
        return Ok(());
    }

    let Some(pid) = state.pid else {
        state.mark_stopped(None, Some("STALE".to_string()))?;
        save_to(root, state)?;
        return Ok(());
    };

    if pid_is_alive(pid) {
        return Ok(());
    }

    state.mark_stopped(None, Some("STALE".to_string()))?;
    save_to(root, state)
}

fn pid_is_alive(pid: i32) -> bool {
    let proc_dir = Path::new("/proc").join(pid.to_string());
    if !proc_dir.exists() {
        return false;
    }

    let Ok(stat) = fs::read_to_string(proc_dir.join("stat")) else {
        return true;
    };

    let Some((_, after_comm)) = stat.rsplit_once(") ") else {
        return true;
    };

    !after_comm.starts_with('Z')
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
    let state = load_current_from(root, id)?;
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

    #[test]
    fn saves_loads_and_deletes_created_state() {
        let root =
            std::env::temp_dir().join(format!("crun-rs-created-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let state =
            ContainerState::created("demo-created", Path::new("/tmp/bundle"), "none", "default")
                .expect("created state should be valid");
        save_to(&root, &state).expect("created state should save");

        let loaded = load_from(&root, "demo-created").expect("created state should load");
        assert_eq!(loaded.status, ContainerStatus::Created);
        assert_eq!(loaded.pid, None);
        assert_eq!(loaded.network_mode, "none");
        assert_eq!(loaded.security_profile, "default");

        delete_from(&root, "demo-created").expect("created state should delete");
        assert!(!container_dir(&root, "demo-created").exists());
    }

    #[test]
    fn lists_container_states_sorted_by_id() {
        let root = std::env::temp_dir().join(format!("crun-rs-list-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let beta = ContainerState::created("beta", Path::new("/tmp/beta"), "bridge", "default")
            .expect("beta state should be valid");
        let alpha = ContainerState::created("alpha", Path::new("/tmp/alpha"), "none", "default")
            .expect("alpha state should be valid");

        save_to(&root, &beta).expect("beta state should save");
        save_to(&root, &alpha).expect("alpha state should save");

        let states = list_from(&root).expect("states should list");
        let ids = states
            .iter()
            .map(|state| state.id.as_str())
            .collect::<Vec<_>>();

        assert_eq!(ids, vec!["alpha", "beta"]);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn lists_empty_when_state_root_does_not_exist() {
        let root =
            std::env::temp_dir().join(format!("crun-rs-missing-list-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let states = list_from(&root).expect("missing root should list as empty");

        assert!(states.is_empty());
    }

    #[test]
    fn load_current_marks_missing_running_pid_as_stale() {
        let root = std::env::temp_dir().join(format!("crun-rs-stale-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let state = ContainerState::running(
            "stale",
            Path::new("/tmp/bundle"),
            -1,
            Some("/sys/fs/cgroup/container-runtime/crun-stale".to_string()),
            "bridge",
            "default",
        )
        .expect("running state should be valid");
        save_to(&root, &state).expect("state should save");

        let loaded = load_current_from(&root, "stale").expect("state should refresh");

        assert_eq!(loaded.status, ContainerStatus::Stopped);
        assert_eq!(loaded.pid, None);
        assert_eq!(loaded.cgroup_path, None);
        assert_eq!(loaded.signal.as_deref(), Some("STALE"));

        let _ = fs::remove_dir_all(&root);
    }
}
