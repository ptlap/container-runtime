//! On-disk record of the syscalls a container actually made.

use super::arch::{AUDIT_ARCH_NATIVE, NATIVE_ARCH_NAME};
use super::syscalls;
use crate::error::SeccompError;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const CAPTURE_SCHEMA_VERSION: u32 = 1;

/// What the tracer accumulates while a container runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capture {
    pub audit_arch: u32,
    /// Syscall number to how often it was seen and when it first appeared.
    pub counts: BTreeMap<i64, SyscallObservation>,
    /// Calls trapped from a non-native architecture, by audit arch value.
    pub foreign_arch_counts: BTreeMap<u32, u64>,
    pub processes_seen: u64,
    pub started_at_unix: u64,
    pub duration_ms: u64,
    pub events: u64,
    /// Set when collection stopped early, so a partial capture is never
    /// mistaken for a complete one.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyscallObservation {
    pub count: u64,
    pub first_seen_ms: u64,
}

impl Capture {
    pub fn record(&mut self, number: i64, elapsed_ms: u64) {
        let entry = self.counts.entry(number).or_insert(SyscallObservation {
            count: 0,
            first_seen_ms: elapsed_ms,
        });
        entry.count += 1;
        self.events += 1;
    }

    pub fn record_foreign(&mut self, audit_arch: u32) {
        *self.foreign_arch_counts.entry(audit_arch).or_insert(0) += 1;
        self.events += 1;
    }

    pub fn unique_syscalls(&self) -> usize {
        self.counts.len()
    }
}

/// The capture as written to `/run/crun-rs/<id>/syscalls.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CaptureFile {
    pub schema_version: u32,
    pub id: String,
    #[serde(default)]
    pub command: Vec<String>,
    pub arch: String,
    pub audit_arch: u32,
    pub runtime_version: String,
    pub started_at_unix: u64,
    pub duration_ms: u64,
    pub total_events: u64,
    pub processes_seen: u64,
    #[serde(default)]
    pub truncated: bool,
    /// Syscall name (or `unknown_<nr>`) to call count.
    pub syscalls: BTreeMap<String, u64>,
    /// Milliseconds after capture start when each syscall was first seen.
    /// Plotting unique syscalls against this shows whether a capture had
    /// stopped discovering new ones by the time it ended.
    #[serde(default)]
    pub first_seen_ms: BTreeMap<String, u64>,
    #[serde(default)]
    pub foreign_arch: BTreeMap<String, u64>,
}

impl CaptureFile {
    pub fn from_capture(id: &str, command: &[String], capture: &Capture) -> Self {
        let mut syscalls_map = BTreeMap::new();
        let mut first_seen = BTreeMap::new();

        for (number, observation) in &capture.counts {
            let name = syscalls::name(*number)
                .map(str::to_string)
                .unwrap_or_else(|| format!("unknown_{number}"));
            syscalls_map.insert(name.clone(), observation.count);
            first_seen.insert(name, observation.first_seen_ms);
        }

        Self {
            schema_version: CAPTURE_SCHEMA_VERSION,
            id: id.to_string(),
            command: command.to_vec(),
            arch: NATIVE_ARCH_NAME.to_string(),
            audit_arch: if capture.audit_arch == 0 {
                AUDIT_ARCH_NATIVE
            } else {
                capture.audit_arch
            },
            runtime_version: env!("CARGO_PKG_VERSION").to_string(),
            started_at_unix: capture.started_at_unix,
            duration_ms: capture.duration_ms,
            total_events: capture.events,
            processes_seen: capture.processes_seen,
            truncated: capture.truncated,
            syscalls: syscalls_map,
            first_seen_ms: first_seen,
            foreign_arch: capture
                .foreign_arch_counts
                .iter()
                .map(|(arch, count)| (format!("{arch:#010x}"), *count))
                .collect(),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read syscall capture: {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse syscall capture: {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create capture directory: {}", parent.display())
                })?;
            }
        }

        let content =
            serde_json::to_string_pretty(self).context("failed to serialize syscall capture")?;
        std::fs::write(path, format!("{content}\n"))
            .with_context(|| format!("failed to write syscall capture: {}", path.display()))
    }
}

/// Union of several captures of the same architecture.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergedCapture {
    pub audit_arch: u32,
    pub syscalls: BTreeMap<String, u64>,
    pub first_seen_ms: BTreeMap<String, u64>,
    pub foreign_arch: BTreeMap<String, u64>,
    pub total_events: u64,
    pub total_duration_ms: u64,
    pub sources: Vec<CaptureFile>,
}

/// Merges captures, refusing to mix architectures.
///
/// Syscall numbers differ per architecture, so merging an x86_64 capture with
/// an aarch64 one would silently produce a nonsense profile.
pub fn merge(captures: &[CaptureFile]) -> std::result::Result<MergedCapture, SeccompError> {
    let first = captures.first().ok_or(SeccompError::NoCaptures)?;
    let mut merged = MergedCapture {
        audit_arch: first.audit_arch,
        ..MergedCapture::default()
    };

    for capture in captures {
        if capture.audit_arch != merged.audit_arch {
            return Err(SeccompError::ArchMismatch {
                expected: merged.audit_arch,
                found: capture.audit_arch,
            });
        }

        for (name, count) in &capture.syscalls {
            *merged.syscalls.entry(name.clone()).or_insert(0) += count;
        }
        for (name, first_seen) in &capture.first_seen_ms {
            merged
                .first_seen_ms
                .entry(name.clone())
                .and_modify(|value| *value = (*value).min(*first_seen))
                .or_insert(*first_seen);
        }
        for (arch, count) in &capture.foreign_arch {
            *merged.foreign_arch.entry(arch.clone()).or_insert(0) += count;
        }

        merged.total_events += capture.total_events;
        merged.total_duration_ms += capture.duration_ms;
        merged.sources.push(capture.clone());
    }

    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture_file(id: &str, arch: u32, syscalls: &[(&str, u64, u64)]) -> CaptureFile {
        CaptureFile {
            schema_version: CAPTURE_SCHEMA_VERSION,
            id: id.to_string(),
            command: vec!["/bin/sh".to_string()],
            arch: NATIVE_ARCH_NAME.to_string(),
            audit_arch: arch,
            runtime_version: "0.1.0".to_string(),
            started_at_unix: 1_700_000_000,
            duration_ms: 100,
            total_events: syscalls.iter().map(|(_, count, _)| count).sum(),
            processes_seen: 1,
            truncated: false,
            syscalls: syscalls
                .iter()
                .map(|(name, count, _)| (name.to_string(), *count))
                .collect(),
            first_seen_ms: syscalls
                .iter()
                .map(|(name, _, first)| (name.to_string(), *first))
                .collect(),
            foreign_arch: BTreeMap::new(),
        }
    }

    #[test]
    fn records_counts_and_the_first_time_a_syscall_appears() {
        let mut capture = Capture::default();
        let read = syscalls::number("read").expect("read exists");

        capture.record(read, 5);
        capture.record(read, 40);

        assert_eq!(capture.unique_syscalls(), 1);
        assert_eq!(capture.counts[&read].count, 2);
        assert_eq!(capture.counts[&read].first_seen_ms, 5);
        assert_eq!(capture.events, 2);
    }

    #[test]
    fn names_syscall_numbers_this_architecture_does_not_define() {
        let mut capture = Capture::default();
        capture.record(999_999, 1);

        let file = CaptureFile::from_capture("demo", &[], &capture);

        assert!(file.syscalls.contains_key("unknown_999999"));
    }

    #[test]
    fn merges_counts_and_keeps_the_earliest_sighting() {
        let merged = merge(&[
            capture_file("a", AUDIT_ARCH_NATIVE, &[("read", 2, 30), ("write", 1, 40)]),
            capture_file("b", AUDIT_ARCH_NATIVE, &[("read", 5, 10)]),
        ])
        .expect("captures should merge");

        assert_eq!(merged.syscalls["read"], 7);
        assert_eq!(merged.syscalls["write"], 1);
        assert_eq!(merged.first_seen_ms["read"], 10);
        assert_eq!(merged.total_events, 8);
        assert_eq!(merged.sources.len(), 2);
    }

    #[test]
    fn refuses_to_merge_captures_from_different_architectures() {
        let error = merge(&[
            capture_file("a", 0xc000_003e, &[("read", 1, 0)]),
            capture_file("b", 0xc000_00b7, &[("read", 1, 0)]),
        ])
        .expect_err("mixed architectures should be rejected");

        assert!(matches!(error, SeccompError::ArchMismatch { .. }));
    }

    #[test]
    fn rejects_merging_nothing() {
        assert!(matches!(merge(&[]), Err(SeccompError::NoCaptures)));
    }

    #[test]
    fn writes_and_reads_a_capture_file() {
        let path =
            std::env::temp_dir().join(format!("crun-capture-test-{}.json", std::process::id()));
        let file = capture_file("demo", AUDIT_ARCH_NATIVE, &[("read", 3, 12)]);

        file.save(&path).expect("capture should save");
        let loaded = CaptureFile::load(&path).expect("capture should load");

        assert_eq!(loaded, file);
        let _ = std::fs::remove_file(&path);
    }
}
