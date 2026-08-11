use crate::error::StateError;
use crate::network::{cleanup_nat_lease, release_bridge_network, NatLease};
use crate::userns::UserNamespaceMap;
use anyhow::{Context, Result};
use nix::fcntl::{Flock, FlockArg};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

pub const DEFAULT_STATE_ROOT: &str = "/run/crun-rs";
pub const STATE_SCHEMA_VERSION: u32 = 4;

const STATE_LOCK_FILE: &str = "state.lock";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainerStatus {
    Created,
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContainerState {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub id: String,
    pub pid: Option<i32>,
    /// `/proc/<pid>/stat` starttime ticks, paired with pid to prevent PID reuse.
    #[serde(default)]
    pub process_starttime: Option<u64>,
    pub status: ContainerStatus,
    pub bundle: String,
    pub cgroup_path: Option<String>,
    #[serde(default = "default_network_mode")]
    pub network_mode: String,
    #[serde(default)]
    pub network_subnet: Option<String>,
    #[serde(default)]
    pub nat_lease: Option<NatLease>,
    #[serde(default)]
    pub log_path: Option<String>,
    #[serde(default = "default_log_mode")]
    pub log_mode: String,
    #[serde(default = "default_security_profile")]
    pub security_profile: String,
    #[serde(default = "default_userns_mode")]
    pub userns_mode: String,
    #[serde(default)]
    pub userns_map: Option<UserNamespaceMap>,
    #[serde(default = "default_rootfs_mode")]
    pub rootfs_mode: String,
    #[serde(default = "default_policy_profile")]
    pub policy_profile: String,
    #[serde(default = "default_seccomp_mode")]
    pub seccomp_mode: String,
    #[serde(default)]
    pub seccomp_profile: Option<String>,
    #[serde(default)]
    pub seccomp_action: Option<String>,
    #[serde(default = "default_seccomp_order")]
    pub seccomp_order: String,
    #[serde(default)]
    pub seccomp_log: bool,
    #[serde(default)]
    pub tty: bool,
    #[serde(default)]
    pub health: Option<HealthState>,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthState {
    pub status: String,
    pub exit_code: Option<i32>,
    pub signal: Option<String>,
    pub command: Vec<String>,
    pub checked_at_unix: u64,
}

#[derive(Debug, Clone)]
pub struct StartedResources<'a> {
    pub cgroup_path: Option<Cow<'a, str>>,
    pub network_subnet: Option<Cow<'a, str>>,
    pub nat_lease: Option<NatLease>,
    pub log_path: Option<Cow<'a, str>>,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeMetadata<'a> {
    pub network_mode: &'a str,
    pub security_profile: &'a str,
    pub log_mode: &'a str,
    pub userns_mode: &'a str,
    pub userns_map: Option<UserNamespaceMap>,
    pub rootfs_mode: &'a str,
    pub policy_profile: &'a str,
    pub tty: bool,
    pub seccomp_mode: &'a str,
    pub seccomp_profile: Option<&'a str>,
    pub seccomp_action: Option<&'a str>,
    pub seccomp_order: &'a str,
    pub seccomp_log: bool,
}

impl ContainerState {
    pub fn created(id: &str, bundle: &Path, metadata: RuntimeMetadata<'_>) -> Result<Self> {
        validate_id(id)?;
        let now = unix_timestamp()?;

        Ok(Self {
            schema_version: STATE_SCHEMA_VERSION,
            id: id.to_string(),
            pid: None,
            process_starttime: None,
            status: ContainerStatus::Created,
            bundle: bundle.display().to_string(),
            cgroup_path: None,
            network_mode: metadata.network_mode.to_string(),
            network_subnet: None,
            nat_lease: None,
            log_path: Some(log_file(id).display().to_string()),
            log_mode: metadata.log_mode.to_string(),
            security_profile: metadata.security_profile.to_string(),
            userns_mode: metadata.userns_mode.to_string(),
            userns_map: metadata.userns_map,
            rootfs_mode: metadata.rootfs_mode.to_string(),
            policy_profile: metadata.policy_profile.to_string(),
            seccomp_mode: metadata.seccomp_mode.to_string(),
            seccomp_profile: metadata.seccomp_profile.map(str::to_string),
            seccomp_action: metadata.seccomp_action.map(str::to_string),
            seccomp_order: metadata.seccomp_order.to_string(),
            seccomp_log: metadata.seccomp_log,
            tty: metadata.tty,
            health: None,
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
        resources: StartedResources<'_>,
        metadata: RuntimeMetadata<'_>,
    ) -> Result<Self> {
        validate_id(id)?;
        let now = unix_timestamp()?;

        Ok(Self {
            schema_version: STATE_SCHEMA_VERSION,
            id: id.to_string(),
            pid: Some(pid),
            process_starttime: process_starttime(pid).ok(),
            status: ContainerStatus::Running,
            bundle: bundle.display().to_string(),
            cgroup_path: resources.cgroup_path.map(Cow::into_owned),
            network_mode: metadata.network_mode.to_string(),
            network_subnet: resources.network_subnet.map(Cow::into_owned),
            nat_lease: resources.nat_lease,
            log_path: resources.log_path.map(Cow::into_owned),
            log_mode: metadata.log_mode.to_string(),
            security_profile: metadata.security_profile.to_string(),
            userns_mode: metadata.userns_mode.to_string(),
            userns_map: metadata.userns_map,
            rootfs_mode: metadata.rootfs_mode.to_string(),
            policy_profile: metadata.policy_profile.to_string(),
            seccomp_mode: metadata.seccomp_mode.to_string(),
            seccomp_profile: metadata.seccomp_profile.map(str::to_string),
            seccomp_action: metadata.seccomp_action.map(str::to_string),
            seccomp_order: metadata.seccomp_order.to_string(),
            seccomp_log: metadata.seccomp_log,
            tty: metadata.tty,
            health: None,
            created_at_unix: now,
            updated_at_unix: now,
            exit_code: None,
            signal: None,
        })
    }

    pub fn mark_running(
        &mut self,
        pid: i32,
        resources: StartedResources<'_>,
        log_mode: &str,
    ) -> Result<()> {
        self.pid = Some(pid);
        self.process_starttime = Some(process_starttime(pid)?);
        self.status = ContainerStatus::Running;
        self.cgroup_path = resources.cgroup_path.map(Cow::into_owned);
        self.network_subnet = resources.network_subnet.map(Cow::into_owned);
        self.nat_lease = resources.nat_lease;
        self.log_path = resources.log_path.map(Cow::into_owned);
        self.log_mode = log_mode.to_string();
        self.updated_at_unix = unix_timestamp()?;
        self.exit_code = None;
        self.signal = None;
        Ok(())
    }

    pub fn mark_health(&mut self, health: HealthState) -> Result<()> {
        self.health = Some(health);
        self.updated_at_unix = unix_timestamp()?;
        Ok(())
    }

    /// Mark the container as stopped. The `log_path` is intentionally preserved
    /// so that `crun logs` can read container output after the container exits.
    pub fn mark_stopped(&mut self, exit_code: Option<i32>, signal: Option<String>) -> Result<()> {
        self.pid = None;
        self.process_starttime = None;
        self.status = ContainerStatus::Stopped;
        self.updated_at_unix = unix_timestamp()?;
        self.cgroup_path = None;
        self.network_subnet = None;
        self.nat_lease = None;
        self.exit_code = exit_code;
        self.signal = signal;
        Ok(())
    }
}

/// State files written before the seccomp fields existed carry no version, so
/// they are read as version 1 rather than claiming to be current.
fn default_schema_version() -> u32 {
    1
}

fn default_network_mode() -> String {
    "bridge".to_string()
}

fn default_log_mode() -> String {
    "auto".to_string()
}

fn default_security_profile() -> String {
    "default".to_string()
}

fn default_userns_mode() -> String {
    "host".to_string()
}

fn default_seccomp_order() -> String {
    "by-frequency".to_string()
}

fn default_rootfs_mode() -> String {
    "direct".to_string()
}

fn default_policy_profile() -> String {
    "none".to_string()
}

fn default_seccomp_mode() -> String {
    "off".to_string()
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

pub fn list_raw() -> Result<Vec<ContainerState>> {
    list_raw_from(Path::new(DEFAULT_STATE_ROOT))
}

pub fn log_path(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(log_file(id))
}

pub fn runtime_log_path(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(runtime_log_file(id))
}

/// Where learn mode writes the syscalls a container made.
pub fn capture_path(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(capture_file(id))
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
    let _guard = lock_state(root, id)?;
    let mut state = load_from(root, id)?;
    if refresh_liveness(&mut state)? {
        write_state_atomic(root, &state)?;
    }

    Ok(state)
}

fn list_from(root: &Path) -> Result<Vec<ContainerState>> {
    let mut states = Vec::new();
    for id in container_ids(root)? {
        states.push(load_current_from(root, &id)?);
    }

    states.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(states)
}

fn list_raw_from(root: &Path) -> Result<Vec<ContainerState>> {
    let mut states = Vec::new();
    for id in container_ids(root)? {
        states.push(load_from(root, &id)?);
    }

    states.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(states)
}

fn container_ids(root: &Path) -> Result<Vec<String>> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut ids = Vec::new();
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
        if !state_file(root, &id).exists() {
            continue;
        }
        ids.push(id);
    }

    Ok(ids)
}

/// Marks a running state as stopped when its process is gone.
///
/// Returns `true` when the state changed and has to be persisted. The caller
/// owns the state lock, so this function never writes by itself.
fn refresh_liveness(state: &mut ContainerState) -> Result<bool> {
    if state.status != ContainerStatus::Running {
        return Ok(false);
    }

    let Some(pid) = state.pid else {
        return Ok(false);
    };

    if pid_is_alive(pid) {
        match state.process_starttime {
            Some(expected) if process_starttime(pid).ok() == Some(expected) => {
                return Ok(false);
            }
            Some(_) => {
                cleanup_stale_resources(state, false);
                release_state_network_allocation(state);
                state.mark_stopped(None, Some("STALE_PID_REUSED".to_string()))?;
            }
            None => {
                cleanup_stale_resources(state, false);
                release_state_network_allocation(state);
                state.mark_stopped(None, Some("STALE_IDENTITY_MISSING".to_string()))?;
            }
        }
        return Ok(true);
    }

    cleanup_stale_resources(state, true);
    release_state_network_allocation(state);
    state.mark_stopped(None, Some("STALE".to_string()))?;

    Ok(true)
}

fn cleanup_stale_resources(state: &ContainerState, pid_identity_owned: bool) {
    if let Some(cgroup_path) = &state.cgroup_path {
        let path = Path::new(cgroup_path);
        if path.exists() {
            let _ = fs::remove_dir(path);
        }
    }

    if state.network_mode == "bridge" {
        if let Some(lease) = &state.nat_lease {
            let _ = cleanup_nat_lease(lease);
        }
    }

    if pid_identity_owned {
        if let Some(pid) = state.pid {
            let host_veth = format!("vethh{pid}");
            let _ = crate::network::cleanup_veth_host(&host_veth);
        }
    }
}

fn release_state_network_allocation(state: &ContainerState) {
    if state.network_mode != "bridge" {
        return;
    }

    if let Err(error) = release_bridge_network(&state.id) {
        warn!(
            "failed to release bridge subnet for stale container {}: {error}",
            state.id
        );
    }
}

pub fn pid_is_alive(pid: i32) -> bool {
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

/// Reads field 22 of `/proc/<pid>/stat`, the process starttime in clock ticks.
pub fn process_starttime(pid: i32) -> Result<u64> {
    let path = Path::new("/proc").join(pid.to_string()).join("stat");
    let stat = fs::read_to_string(&path)
        .with_context(|| format!("failed to read process identity: {}", path.display()))?;
    let (_, after_comm) = stat
        .rsplit_once(") ")
        .context("malformed /proc/<pid>/stat process identity")?;
    after_comm
        .split_whitespace()
        .nth(19)
        .context("missing process starttime in /proc/<pid>/stat")?
        .parse()
        .context("invalid process starttime in /proc/<pid>/stat")
}

fn save_to(root: &Path, state: &ContainerState) -> Result<()> {
    let _guard = lock_state(root, &state.id)?;
    write_state_atomic(root, state)
}

/// Takes the per-container state lock.
///
/// `flock` is tied to the open file description, so nesting two guards for the
/// same container inside one process deadlocks. Every caller must hold at most
/// one guard and write through [`write_state_atomic`] while holding it.
fn lock_state(root: &Path, id: &str) -> Result<Flock<File>> {
    validate_id(id)?;
    let dir = container_dir(root, id);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create state directory: {}", dir.display()))?;

    let path = dir.join(STATE_LOCK_FILE);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("failed to open state lock: {}", path.display()))?;

    Flock::lock(file, FlockArg::LockExclusive).map_err(|(_, errno)| {
        StateError::LockFailed {
            id: id.to_string(),
            errno: errno.to_string(),
        }
        .into()
    })
}

/// Writes the state through a temporary file and renames it into place so a
/// concurrent reader never observes a partially written file.
fn write_state_atomic(root: &Path, state: &ContainerState) -> Result<()> {
    validate_id(&state.id)?;
    let dir = container_dir(root, &state.id);
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create state directory: {}", dir.display()))?;

    let content = serde_json::to_string_pretty(state).context("failed to serialize state")?;
    let temp_path = dir.join(format!("state.json.tmp.{}", std::process::id()));
    let mut file = File::create(&temp_path)
        .with_context(|| format!("failed to create temporary state: {}", temp_path.display()))?;
    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to write temporary state: {}", temp_path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to flush temporary state: {}", temp_path.display()))?;
    drop(file);

    let path = state_file(root, &state.id);
    fs::rename(&temp_path, &path)
        .with_context(|| format!("failed to replace state: {}", path.display()))
}

fn delete_from(root: &Path, id: &str) -> Result<()> {
    let state = load_current_from(root, id)?;
    if state.status == ContainerStatus::Running {
        return Err(StateError::ContainerIsRunning { id: id.to_string() }.into());
    }

    release_state_network_allocation(&state);

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

fn log_file(id: &str) -> PathBuf {
    container_dir(Path::new(DEFAULT_STATE_ROOT), id).join("container.log")
}

fn runtime_log_file(id: &str) -> PathBuf {
    container_dir(Path::new(DEFAULT_STATE_ROOT), id).join("runtime.log")
}

fn capture_file(id: &str) -> PathBuf {
    container_dir(Path::new(DEFAULT_STATE_ROOT), id).join("syscalls.json")
}

pub(crate) fn validate_id(id: &str) -> std::result::Result<(), StateError> {
    if id.is_empty() {
        return Err(StateError::EmptyContainerId);
    }

    if matches!(id, "." | "..")
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(StateError::InvalidContainerId);
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

    fn stopped_state(id: &str) -> ContainerState {
        let mut state = ContainerState::created(
            id,
            Path::new("/tmp/bundle"),
            RuntimeMetadata {
                network_mode: "none",
                security_profile: "default",
                log_mode: "off",
                userns_mode: "host",
                userns_map: None,
                rootfs_mode: "direct",
                policy_profile: "none",
                tty: false,
                seccomp_mode: "off",
                seccomp_profile: None,
                seccomp_action: None,
                seccomp_order: "by-frequency",
                seccomp_log: false,
            },
        )
        .expect("state should be valid");
        state
            .mark_stopped(Some(0), None)
            .expect("state should stop");
        state
    }

    #[test]
    fn leaves_no_temporary_file_after_saving_state() {
        let root = std::env::temp_dir().join(format!("crun-rs-atomic-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let state = stopped_state("atomic");

        save_to(&root, &state).expect("state should save");

        let leftovers = fs::read_dir(container_dir(&root, "atomic"))
            .expect("state directory should exist")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("state.json.tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
        assert!(load_from(&root, "atomic").is_ok());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn concurrent_writers_keep_state_readable() {
        let root = std::env::temp_dir().join(format!("crun-rs-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        save_to(&root, &stopped_state("shared")).expect("state should save");

        std::thread::scope(|scope| {
            for worker in 0..8 {
                let root = root.clone();
                scope.spawn(move || {
                    for round in 0..50 {
                        let mut state = stopped_state("shared");
                        state.exit_code = Some(worker * 100 + round);
                        save_to(&root, &state).expect("concurrent save should succeed");
                        load_from(&root, "shared").expect("state must stay parseable");
                    }
                });
            }
        });

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_invalid_container_ids() {
        assert!(matches!(validate_id(""), Err(StateError::EmptyContainerId)));
        assert!(matches!(
            validate_id("../demo"),
            Err(StateError::InvalidContainerId)
        ));
        assert!(matches!(
            validate_id("demo/one"),
            Err(StateError::InvalidContainerId)
        ));
        assert!(matches!(
            validate_id("demo one"),
            Err(StateError::InvalidContainerId)
        ));
        assert!(matches!(
            validate_id("."),
            Err(StateError::InvalidContainerId)
        ));
        assert!(matches!(
            validate_id(".."),
            Err(StateError::InvalidContainerId)
        ));
        assert!(validate_id("demo_01.2-3").is_ok());
    }

    #[test]
    fn saves_loads_and_deletes_stopped_state() {
        let root = std::env::temp_dir().join(format!("crun-rs-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let metadata = RuntimeMetadata {
            network_mode: "none",
            security_profile: "default",
            log_mode: "on",
            userns_mode: "private",
            userns_map: Some(UserNamespaceMap {
                host_uid: 1000,
                host_gid: 1000,
            }),
            rootfs_mode: "overlay",
            policy_profile: "restricted",
            tty: false,
            seccomp_mode: "off",
            seccomp_profile: None,
            seccomp_action: None,
            seccomp_order: "by-frequency",
            seccomp_log: false,
        };

        let mut state = ContainerState::running(
            "demo",
            Path::new("/tmp/bundle"),
            1234,
            StartedResources {
                cgroup_path: Some(Cow::Borrowed("/sys/fs/cgroup/container-runtime/crun-1234")),
                network_subnet: None,
                nat_lease: None,
                log_path: Some(Cow::Borrowed("/run/crun-rs/demo/container.log")),
            },
            metadata,
        )
        .expect("state should be valid");
        save_to(&root, &state).expect("state should save");

        let loaded = load_from(&root, "demo").expect("state should load");
        assert_eq!(loaded.schema_version, STATE_SCHEMA_VERSION);
        assert_eq!(loaded.id, "demo");
        assert_eq!(loaded.pid, Some(1234));
        assert_eq!(loaded.status, ContainerStatus::Running);
        assert_eq!(
            loaded.cgroup_path.as_deref(),
            Some("/sys/fs/cgroup/container-runtime/crun-1234")
        );
        assert_eq!(loaded.network_mode, "none");
        assert_eq!(loaded.network_subnet, None);
        assert_eq!(
            loaded.log_path.as_deref(),
            Some("/run/crun-rs/demo/container.log")
        );
        assert_eq!(loaded.log_mode, "on");
        assert_eq!(loaded.security_profile, "default");
        assert_eq!(loaded.userns_mode, "private");
        assert_eq!(loaded.rootfs_mode, "overlay");
        assert_eq!(loaded.policy_profile, "restricted");
        assert_eq!(loaded.health, None);

        state
            .mark_health(HealthState {
                status: "healthy".to_string(),
                exit_code: Some(0),
                signal: None,
                command: vec!["/bin/true".to_string()],
                checked_at_unix: 42,
            })
            .expect("mark health");
        save_to(&root, &state).expect("healthy state should save");
        let loaded = load_from(&root, "demo").expect("healthy state should load");
        assert_eq!(
            loaded.health.as_ref().map(|health| health.status.as_str()),
            Some("healthy")
        );
        assert_eq!(
            loaded
                .health
                .as_ref()
                .map(|health| health.command.as_slice()),
            Some(["/bin/true".to_string()].as_slice())
        );

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

        let state = ContainerState::created(
            "demo-created",
            Path::new("/tmp/bundle"),
            RuntimeMetadata {
                network_mode: "none",
                security_profile: "default",
                log_mode: "auto",
                userns_mode: "host",
                userns_map: None,
                rootfs_mode: "direct",
                policy_profile: "none",
                tty: false,
                seccomp_mode: "off",
                seccomp_profile: None,
                seccomp_action: None,
                seccomp_order: "by-frequency",
                seccomp_log: false,
            },
        )
        .expect("created state should be valid");
        save_to(&root, &state).expect("created state should save");

        let loaded = load_from(&root, "demo-created").expect("created state should load");
        assert_eq!(loaded.schema_version, STATE_SCHEMA_VERSION);
        assert_eq!(loaded.status, ContainerStatus::Created);
        assert_eq!(loaded.pid, None);
        assert_eq!(loaded.network_mode, "none");
        assert_eq!(
            loaded.log_path.as_deref(),
            Some("/run/crun-rs/demo-created/container.log")
        );
        assert_eq!(loaded.log_mode, "auto");
        assert_eq!(loaded.security_profile, "default");
        assert_eq!(loaded.userns_mode, "host");
        assert_eq!(loaded.rootfs_mode, "direct");
        assert_eq!(loaded.policy_profile, "none");

        delete_from(&root, "demo-created").expect("created state should delete");
        assert!(!container_dir(&root, "demo-created").exists());
    }

    #[test]
    fn lists_container_states_sorted_by_id() {
        let root = std::env::temp_dir().join(format!("crun-rs-list-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let beta = ContainerState::created(
            "beta",
            Path::new("/tmp/beta"),
            RuntimeMetadata {
                network_mode: "bridge",
                security_profile: "default",
                log_mode: "auto",
                userns_mode: "host",
                userns_map: None,
                rootfs_mode: "direct",
                policy_profile: "none",
                tty: false,
                seccomp_mode: "off",
                seccomp_profile: None,
                seccomp_action: None,
                seccomp_order: "by-frequency",
                seccomp_log: false,
            },
        )
        .expect("beta state should be valid");
        let alpha = ContainerState::created(
            "alpha",
            Path::new("/tmp/alpha"),
            RuntimeMetadata {
                network_mode: "none",
                security_profile: "default",
                log_mode: "auto",
                userns_mode: "host",
                userns_map: None,
                rootfs_mode: "direct",
                policy_profile: "none",
                tty: false,
                seccomp_mode: "off",
                seccomp_profile: None,
                seccomp_action: None,
                seccomp_order: "by-frequency",
                seccomp_log: false,
            },
        )
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
    fn load_current_marks_pid_reuse_as_stale_without_veth_cleanup() {
        let root =
            std::env::temp_dir().join(format!("crun-rs-pid-reuse-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let metadata = RuntimeMetadata {
            network_mode: "none",
            security_profile: "default",
            log_mode: "auto",
            userns_mode: "host",
            userns_map: None,
            rootfs_mode: "direct",
            policy_profile: "none",
            tty: false,
            seccomp_mode: "off",
            seccomp_profile: None,
            seccomp_action: None,
            seccomp_order: "by-frequency",
            seccomp_log: false,
        };
        let pid = std::process::id() as i32;
        let mut state = ContainerState::running(
            "pid-reuse",
            Path::new("/tmp/bundle"),
            pid,
            StartedResources {
                cgroup_path: None,
                network_subnet: None,
                nat_lease: None,
                log_path: None,
            },
            metadata,
        )
        .expect("running state should be valid");
        state.process_starttime = Some(
            process_starttime(pid)
                .expect("current process starttime should be readable")
                .saturating_add(1),
        );
        save_to(&root, &state).expect("state should save");

        let loaded = load_current_from(&root, "pid-reuse").expect("state should refresh");
        assert_eq!(loaded.status, ContainerStatus::Stopped);
        assert_eq!(loaded.signal.as_deref(), Some("STALE_PID_REUSED"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_current_marks_missing_running_pid_as_stale() {
        let root = std::env::temp_dir().join(format!("crun-rs-stale-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let metadata = RuntimeMetadata {
            network_mode: "none",
            security_profile: "default",
            log_mode: "auto",
            userns_mode: "host",
            userns_map: None,
            rootfs_mode: "direct",
            policy_profile: "none",
            tty: false,
            seccomp_mode: "off",
            seccomp_profile: None,
            seccomp_action: None,
            seccomp_order: "by-frequency",
            seccomp_log: false,
        };

        let state = ContainerState::running(
            "stale",
            Path::new("/tmp/bundle"),
            -1,
            StartedResources {
                cgroup_path: Some(Cow::Borrowed("/sys/fs/cgroup/container-runtime/crun-stale")),
                network_subnet: Some(Cow::Borrowed("10.88.20.0/24")),
                nat_lease: None,
                log_path: Some(Cow::Borrowed("/run/crun-rs/stale/container.log")),
            },
            metadata,
        )
        .expect("running state should be valid");
        save_to(&root, &state).expect("state should save");

        let loaded = load_current_from(&root, "stale").expect("state should refresh");

        assert_eq!(loaded.status, ContainerStatus::Stopped);
        assert_eq!(loaded.pid, None);
        assert_eq!(loaded.cgroup_path, None);
        assert_eq!(loaded.network_subnet, None);
        assert_eq!(loaded.signal.as_deref(), Some("STALE"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn loads_legacy_state_without_schema_version() {
        let content = r#"{
  "id": "legacy",
  "pid": null,
  "status": "created",
  "bundle": "/tmp/bundle",
  "cgroup_path": null,
  "network_mode": "none",
  "security_profile": "default",
  "created_at_unix": 1,
  "updated_at_unix": 1,
  "exit_code": null,
  "signal": null
}"#;

        let state: ContainerState =
            serde_json::from_str(content).expect("legacy state should deserialize");

        // A file written before the seccomp fields existed reports itself as
        // version 1 rather than claiming to be current.
        assert_eq!(state.schema_version, 1);
        assert_eq!(state.id, "legacy");
        assert_eq!(state.status, ContainerStatus::Created);
        assert_eq!(state.userns_mode, "host");
        assert_eq!(state.rootfs_mode, "direct");
        assert_eq!(state.health, None);
        assert_eq!(state.seccomp_mode, "off");
        assert_eq!(state.seccomp_profile, None);
        assert_eq!(state.seccomp_action, None);
    }

    #[test]
    fn new_state_carries_the_current_schema_version() {
        let state = stopped_state("versioned");

        assert_eq!(state.schema_version, STATE_SCHEMA_VERSION);
        assert_eq!(STATE_SCHEMA_VERSION, 4);
    }
}
