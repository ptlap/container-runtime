use crate::error::AuditLogError;
use crate::state;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_RUNTIME_LOG_BYTES: usize = 1024 * 1024;
const ROTATED_RUNTIME_LOG_SUFFIX: &str = ".1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub timestamp_unix: u64,
    pub id: String,
    pub source: String,
    pub name: String,
    pub value: Option<u64>,
    pub delta: Option<u64>,
    pub fields: Option<BTreeMap<String, u64>>,
    pub status: Option<String>,
}

impl AuditEvent {
    pub fn new(id: &str, source: &str, name: &str) -> Self {
        Self {
            timestamp_unix: unix_timestamp(),
            id: id.to_string(),
            source: source.to_string(),
            name: name.to_string(),
            value: None,
            delta: None,
            fields: None,
            status: None,
        }
    }

    pub fn with_status(mut self, status: impl Into<String>) -> Self {
        self.status = Some(status.into());
        self
    }

    pub fn with_value(mut self, value: u64) -> Self {
        self.value = Some(value);
        self
    }

    pub fn with_delta(mut self, delta: u64) -> Self {
        self.delta = Some(delta);
        self
    }

    pub fn with_fields(mut self, fields: BTreeMap<String, u64>) -> Self {
        self.fields = Some(fields);
        self
    }
}

pub fn reset(id: &str) -> Result<()> {
    let path = state::runtime_log_path(id)?;
    let _lock = acquire_lock(&path)?;
    ensure_parent(&path)?;
    remove_if_exists(&rotated_path(&path))?;
    write_synced(&path, b"")
}

pub fn append(event: &AuditEvent) -> Result<()> {
    let path = state::runtime_log_path(&event.id)?;
    append_at_path(&path, event)
}

fn append_at_path(path: &Path, event: &AuditEvent) -> Result<()> {
    let line = serde_json::to_vec(event).context("failed to serialize runtime event")?;
    if line.len() + 1 > MAX_RUNTIME_LOG_BYTES {
        return Err(AuditLogError::RecordTooLarge {
            size: line.len() + 1,
            limit: MAX_RUNTIME_LOG_BYTES,
        }
        .into());
    }

    let _lock = acquire_lock(path)?;
    ensure_parent(path)?;
    rotate_if_needed(path, line.len() + 1)?;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open runtime log: {}", path.display()))?;
    file.write_all(&line)
        .and_then(|()| file.write_all(b"\n"))
        .with_context(|| format!("failed to write runtime log: {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync runtime log: {}", path.display()))
}

pub fn append_simple(id: &str, source: &str, name: &str, status: Option<&str>) -> Result<()> {
    let event = if let Some(status) = status {
        AuditEvent::new(id, source, name).with_status(status)
    } else {
        AuditEvent::new(id, source, name)
    };
    append(&event)
}

pub fn read_history(id: &str) -> Result<Vec<AuditEvent>> {
    let raw = read_raw(id)?;
    parse_history(&raw)
}

fn parse_history(raw: &str) -> Result<Vec<AuditEvent>> {
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("failed to parse runtime log event"))
        .collect()
}

pub fn read_raw(id: &str) -> Result<String> {
    let path = state::runtime_log_path(id)?;
    read_raw_at_path(&path)
}

fn read_raw_at_path(path: &Path) -> Result<String> {
    let _lock = acquire_lock(path)?;
    let rotated = read_optional(&rotated_path(path))?;
    let current = read_optional(path)?;
    match (rotated, current) {
        (Some(rotated), Some(current)) => Ok(format!("{rotated}{current}")),
        (Some(rotated), None) => Ok(rotated),
        (None, Some(current)) => Ok(current),
        (None, None) => Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("runtime log does not exist: {}", path.display()),
        ))
        .with_context(|| format!("failed to read runtime log: {}", path.display())),
    }
}

pub fn write_raw(id: &str, content: &str) -> Result<()> {
    let path = state::runtime_log_path(id)?;
    let _lock = acquire_lock(&path)?;
    ensure_parent(&path)?;
    remove_if_exists(&rotated_path(&path))?;
    let retained = retain_tail(content);
    write_synced(&path, retained.as_bytes())
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create runtime log dir: {}", parent.display()))?;
    }
    Ok(())
}

fn acquire_lock(path: &Path) -> Result<LogLock> {
    let lock_path = lock_path(path);
    ensure_parent(&lock_path)?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("failed to open runtime log lock: {}", lock_path.display()))?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to lock runtime log: {}", lock_path.display()));
    }
    Ok(LogLock { file })
}

struct LogLock {
    file: File,
}

impl Drop for LogLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn rotate_if_needed(path: &Path, incoming_bytes: usize) -> Result<()> {
    let current_size = fs::metadata(path)
        .map(|metadata| metadata.len() as usize)
        .unwrap_or(0);
    if current_size.saturating_add(incoming_bytes) <= MAX_RUNTIME_LOG_BYTES {
        return Ok(());
    }

    let rotated = rotated_path(path);
    remove_if_exists(&rotated)?;
    if path.exists() {
        fs::rename(path, &rotated).with_context(|| {
            format!(
                "failed to rotate runtime log {} to {}",
                path.display(),
                rotated.display()
            )
        })?;
        sync_parent(path)?;
    }
    Ok(())
}

fn write_synced(path: &Path, content: &[u8]) -> Result<()> {
    let mut file = File::create(path)
        .with_context(|| format!("failed to create runtime log: {}", path.display()))?;
    file.write_all(content)
        .with_context(|| format!("failed to write runtime log: {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("failed to sync runtime log: {}", path.display()))?;
    sync_parent(path)
}

fn sync_parent(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    File::open(parent)
        .with_context(|| format!("failed to open runtime log directory: {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync runtime log directory: {}", parent.display()))
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn read_optional(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("failed to read runtime log: {}", path.display()))
        }
    }
}

fn retain_tail(content: &str) -> String {
    if content.len() <= MAX_RUNTIME_LOG_BYTES {
        return content.to_string();
    }
    let start = content.len() - MAX_RUNTIME_LOG_BYTES;
    let boundary = content[start..]
        .find('\n')
        .map(|offset| start + offset + 1)
        .unwrap_or(start);
    content[boundary..].to_string()
}

fn lock_path(path: &Path) -> PathBuf {
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    PathBuf::from(lock)
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut rotated = path.as_os_str().to_os_string();
    rotated.push(ROTATED_RUNTIME_LOG_SUFFIX);
    PathBuf::from(rotated)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "crun-rs-audit-{label}-{}-{}-runtime.log",
            std::process::id(),
            unix_timestamp()
        ))
    }

    fn cleanup_test_log(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(lock_path(path));
        let _ = fs::remove_file(rotated_path(path));
    }

    #[test]
    fn builds_status_event() {
        let event = AuditEvent::new("demo", "lifecycle", "created").with_status("created");

        assert_eq!(event.id, "demo");
        assert_eq!(event.source, "lifecycle");
        assert_eq!(event.name, "created");
        assert_eq!(event.status.as_deref(), Some("created"));
    }

    #[test]
    fn concurrent_appends_remain_parseable() {
        let path = Arc::new(test_path("concurrent"));
        cleanup_test_log(&path);
        let mut workers = Vec::new();
        for worker in 0..8 {
            let path = Arc::clone(&path);
            workers.push(thread::spawn(move || {
                for item in 0..20 {
                    append_at_path(
                        &path,
                        &AuditEvent::new("concurrent", "test", &format!("{worker}-{item}")),
                    )
                    .expect("concurrent append should succeed");
                }
            }));
        }
        for worker in workers {
            worker.join().expect("append worker should join");
        }

        let raw = read_raw_at_path(&path).expect("history should remain readable");
        let history = parse_history(&raw).expect("history should remain parseable");
        assert_eq!(history.len(), 160);
        cleanup_test_log(&path);
    }

    #[test]
    fn rotates_and_bounds_runtime_history() {
        let path = test_path("rotation");
        cleanup_test_log(&path);
        let name = "x".repeat(900);
        for _ in 0..4_000 {
            append_at_path(&path, &AuditEvent::new("rotation", "test", &name))
                .expect("append should succeed");
        }

        assert!(rotated_path(&path).is_file());
        let raw = read_raw_at_path(&path).expect("rotated history should read");
        assert!(raw.len() <= MAX_RUNTIME_LOG_BYTES * 2);
        assert!(
            parse_history(&raw)
                .expect("rotated history should parse")
                .len()
                < 4_000
        );
        cleanup_test_log(&path);
    }

    #[test]
    fn rejects_an_oversized_single_record() {
        let path = test_path("oversized");
        let name = "x".repeat(MAX_RUNTIME_LOG_BYTES);
        let event = AuditEvent::new("oversized", "test", &name);
        let error = append_at_path(&path, &event).expect_err("oversized record should be rejected");
        assert!(matches!(
            error.downcast_ref::<AuditLogError>(),
            Some(AuditLogError::RecordTooLarge { .. })
        ));
        cleanup_test_log(&path);
    }
}
