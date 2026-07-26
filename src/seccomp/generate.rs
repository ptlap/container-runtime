//! Turns syscall captures into a profile.

use super::capture::{self, CaptureFile};
use super::compile::SeccompAction;
use super::profile::{
    build_profile, glibc_compat_set, mandatory_baseline, CrunMetadata, SeccompProfile, SourceRun,
    METADATA_SCHEMA_VERSION,
};
use super::{arch, syscalls};
use crate::error::SeccompError;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct GenerateOptions {
    pub workload: Option<String>,
    pub action: SeccompAction,
    /// Adds the syscalls a newer libc reaches for, so a profile survives a base
    /// image upgrade at the cost of a slightly wider surface.
    pub include_compat: bool,
    /// An existing profile to fold in, so profiles can be grown across runs.
    pub merge_into: Option<SeccompProfile>,
}

impl Default for GenerateOptions {
    fn default() -> Self {
        Self {
            workload: None,
            action: SeccompAction::Errno,
            include_compat: false,
            merge_into: None,
        }
    }
}

pub fn generate(
    captures: &[CaptureFile],
    options: GenerateOptions,
) -> std::result::Result<SeccompProfile, SeccompError> {
    let merged = capture::merge(captures)?;

    if merged.audit_arch != arch::AUDIT_ARCH_NATIVE {
        return Err(SeccompError::ArchMismatch {
            expected: arch::AUDIT_ARCH_NATIVE,
            found: merged.audit_arch,
        });
    }

    let mut counts: BTreeMap<String, u64> = merged.syscalls.clone();
    let mut source_runs: Vec<SourceRun> = merged
        .sources
        .iter()
        .map(|capture| SourceRun {
            container_id: capture.id.clone(),
            command: capture.command.clone(),
            started_at_unix: capture.started_at_unix,
            duration_ms: capture.duration_ms,
            events: capture.total_events,
            unique_syscalls: capture.syscalls.len(),
        })
        .collect();
    let mut total_events = merged.total_events;
    let mut capture_duration_ms = merged.total_duration_ms;

    if let Some(existing) = options.merge_into.as_ref() {
        if let Some(metadata) = existing.crun_metadata.as_ref() {
            for (name, count) in &metadata.syscall_counts {
                *counts.entry(name.clone()).or_insert(0) += count;
            }
            source_runs.extend(metadata.source_runs.iter().cloned());
            total_events += metadata.total_events;
            capture_duration_ms += metadata.capture_duration_ms;
        }

        for name in existing.allowed_names() {
            counts.entry(name).or_insert(0);
        }
    }

    // Names the capture reported that this architecture does not define, such
    // as unknown_<nr> placeholders from a foreign personality.
    let (_, unresolved) = syscalls::resolve_all(counts.keys());
    let observed: BTreeSet<String> = counts
        .keys()
        .filter(|name| syscalls::number(name).is_some())
        .cloned()
        .collect();

    let mut allowed = observed.clone();
    let mut baseline_added = 0usize;
    for name in mandatory_baseline() {
        if syscalls::number(name).is_some() && allowed.insert((*name).to_string()) {
            baseline_added += 1;
        }
    }

    if options.include_compat {
        for name in glibc_compat_set() {
            if syscalls::number(name).is_some() && allowed.insert((*name).to_string()) {
                baseline_added += 1;
            }
        }
    }

    let metadata = CrunMetadata {
        schema_version: METADATA_SCHEMA_VERSION,
        generator: "crun-rs".to_string(),
        runtime_version: env!("CARGO_PKG_VERSION").to_string(),
        workload: options.workload.clone(),
        arch: arch::NATIVE_ARCH_NAME.to_string(),
        audit_arch: merged.audit_arch,
        generated_at_unix: unix_timestamp(),
        observed_syscall_count: observed.len(),
        baseline_syscall_count: baseline_added,
        total_syscall_count: allowed.len(),
        capture_duration_ms,
        total_events,
        source_runs,
        unresolved,
        foreign_arch: merged.foreign_arch.clone(),
        syscall_counts: counts,
    };

    build_profile(
        &allowed,
        options.action.to_oci(),
        options.action.errno(),
        Some(metadata),
    )
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::capture::CAPTURE_SCHEMA_VERSION;

    fn capture(id: &str, syscalls: &[(&str, u64)]) -> CaptureFile {
        CaptureFile {
            schema_version: CAPTURE_SCHEMA_VERSION,
            id: id.to_string(),
            command: vec!["/bin/sh".to_string()],
            arch: arch::NATIVE_ARCH_NAME.to_string(),
            audit_arch: arch::AUDIT_ARCH_NATIVE,
            runtime_version: "0.1.0".to_string(),
            started_at_unix: 1_700_000_000,
            duration_ms: 250,
            total_events: syscalls.iter().map(|(_, count)| count).sum(),
            processes_seen: 1,
            truncated: false,
            syscalls: syscalls
                .iter()
                .map(|(name, count)| (name.to_string(), *count))
                .collect(),
            first_seen_ms: BTreeMap::new(),
            foreign_arch: BTreeMap::new(),
        }
    }

    #[test]
    fn allows_every_observed_syscall_plus_the_baseline() {
        let profile = generate(
            &[capture("demo", &[("read", 10), ("write", 4)])],
            GenerateOptions::default(),
        )
        .expect("profile should generate");

        let allowed = profile.allowed_names();
        assert!(allowed.contains("read"));
        assert!(allowed.contains("write"));
        for name in mandatory_baseline() {
            assert!(allowed.contains(*name), "baseline {name} is missing");
        }

        let metadata = profile
            .crun_metadata
            .clone()
            .expect("metadata should exist");
        assert_eq!(metadata.observed_syscall_count, 2);
        assert!(metadata.baseline_syscall_count > 0);
        assert_eq!(
            metadata.total_syscall_count,
            metadata.observed_syscall_count + metadata.baseline_syscall_count
        );
    }

    #[test]
    fn unions_syscalls_across_runs_and_sums_their_counts() {
        let profile = generate(
            &[
                capture("first", &[("read", 10)]),
                capture("second", &[("read", 5), ("openat", 2)]),
            ],
            GenerateOptions::default(),
        )
        .expect("profile should generate");

        let metadata = profile.crun_metadata.expect("metadata should exist");
        assert_eq!(metadata.syscall_counts["read"], 15);
        assert_eq!(metadata.syscall_counts["openat"], 2);
        assert_eq!(metadata.source_runs.len(), 2);
        assert_eq!(metadata.observed_syscall_count, 2);
    }

    #[test]
    fn folds_an_existing_profile_into_a_new_capture() {
        let first = generate(
            &[capture("first", &[("read", 3)])],
            GenerateOptions::default(),
        )
        .expect("first profile should generate");

        let second = generate(
            &[capture("second", &[("openat", 1)])],
            GenerateOptions {
                merge_into: Some(first),
                ..GenerateOptions::default()
            },
        )
        .expect("second profile should generate");

        let allowed = second.allowed_names();
        assert!(allowed.contains("read"));
        assert!(allowed.contains("openat"));

        let metadata = second.crun_metadata.expect("metadata should exist");
        assert_eq!(metadata.syscall_counts["read"], 3);
        assert_eq!(metadata.source_runs.len(), 2);
    }

    #[test]
    fn adds_the_compat_set_only_when_asked() {
        let without = generate(
            &[capture("demo", &[("read", 1)])],
            GenerateOptions::default(),
        )
        .expect("profile should generate");
        let with = generate(
            &[capture("demo", &[("read", 1)])],
            GenerateOptions {
                include_compat: true,
                ..GenerateOptions::default()
            },
        )
        .expect("profile should generate");

        assert!(!without.allowed_names().contains("statx"));
        assert!(with.allowed_names().contains("statx"));
    }

    #[test]
    fn reports_names_that_are_not_syscalls_on_this_architecture() {
        let profile = generate(
            &[capture("demo", &[("read", 1), ("unknown_999999", 2)])],
            GenerateOptions::default(),
        )
        .expect("profile should generate");

        assert!(!profile.allowed_names().contains("unknown_999999"));
        let metadata = profile.crun_metadata.expect("metadata should exist");
        assert_eq!(metadata.unresolved, vec!["unknown_999999".to_string()]);
    }

    #[test]
    fn records_the_workload_name_and_default_action() {
        let profile = generate(
            &[capture("demo", &[("read", 1)])],
            GenerateOptions {
                workload: Some("nginx".to_string()),
                action: SeccompAction::Kill,
                ..GenerateOptions::default()
            },
        )
        .expect("profile should generate");

        assert_eq!(
            profile.default_action(),
            oci_spec::runtime::LinuxSeccompAction::ScmpActKillProcess
        );
        assert_eq!(
            profile
                .crun_metadata
                .expect("metadata should exist")
                .workload
                .as_deref(),
            Some("nginx")
        );
    }
}
