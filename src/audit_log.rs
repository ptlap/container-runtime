use crate::state;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

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
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create runtime log dir: {}", parent.display()))?;
    }
    fs::write(&path, "").with_context(|| format!("failed to reset runtime log: {}", path.display()))
}

pub fn append(event: &AuditEvent) -> Result<()> {
    let path = state::runtime_log_path(&event.id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create runtime log dir: {}", parent.display()))?;
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open runtime log: {}", path.display()))?;
    let line = serde_json::to_string(event).context("failed to serialize runtime event")?;
    writeln!(file, "{line}")
        .with_context(|| format!("failed to write runtime log: {}", path.display()))
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
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).context("failed to parse runtime log event"))
        .collect()
}

pub fn read_raw(id: &str) -> Result<String> {
    let path = state::runtime_log_path(id)?;
    fs::read_to_string(&path)
        .with_context(|| format!("failed to read runtime log: {}", path.display()))
}

pub fn write_raw(id: &str, content: &str) -> Result<()> {
    let path = state::runtime_log_path(id)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create runtime log dir: {}", parent.display()))?;
    }
    fs::write(&path, content)
        .with_context(|| format!("failed to write runtime log: {}", path.display()))
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

    #[test]
    fn builds_status_event() {
        let event = AuditEvent::new("demo", "lifecycle", "created").with_status("created");

        assert_eq!(event.id, "demo");
        assert_eq!(event.source, "lifecycle");
        assert_eq!(event.name, "created");
        assert_eq!(event.status.as_deref(), Some("created"));
    }
}
