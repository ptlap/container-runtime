//! Generated seccomp profiles.
//!
//! Profiles are written in the OCI `linux.seccomp` schema so a profile produced
//! here can be handed to any OCI runtime unchanged, with the provenance this
//! runtime records carried alongside it under `crunMetadata`. Consumers that do
//! not know the extra key ignore it.

use super::arch;
use super::syscalls;
use crate::error::SeccompError;
use anyhow::{Context, Result};
use oci_spec::runtime::{Arch, LinuxSeccomp, LinuxSeccompAction, LinuxSyscall};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const METADATA_SCHEMA_VERSION: u32 = 1;

/// Syscalls every generated profile allows, whether or not they were observed.
///
/// The vDSO answers `clock_gettime`, `gettimeofday`, `time`, `getcpu` and
/// `clock_getres` in user space on most builds, so those calls never enter the
/// kernel and a tracer never sees them; a profile learned on such a host would
/// break on a host or libc where they are issued for real. The rest cover paths
/// a short capture can miss entirely: returning from a signal handler, exiting,
/// and restarting an interrupted syscall.
pub fn mandatory_baseline() -> &'static [&'static str] {
    &[
        "clock_getres",
        "clock_gettime",
        "exit",
        "exit_group",
        "getcpu",
        "gettimeofday",
        "restart_syscall",
        "rt_sigreturn",
        "time",
    ]
}

/// Syscalls newer libc builds reach for on paths an older build did not use.
///
/// Opt-in, because including them trades a little attack surface for profiles
/// that survive a base-image upgrade.
pub fn glibc_compat_set() -> &'static [&'static str] {
    &[
        "clone3",
        "faccessat2",
        "getrandom",
        "newfstatat",
        "rseq",
        "statx",
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceRun {
    pub container_id: String,
    #[serde(default)]
    pub command: Vec<String>,
    pub started_at_unix: u64,
    pub duration_ms: u64,
    pub events: u64,
    pub unique_syscalls: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CrunMetadata {
    pub schema_version: u32,
    pub generator: String,
    pub runtime_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<String>,
    pub arch: String,
    pub audit_arch: u32,
    pub generated_at_unix: u64,
    pub observed_syscall_count: usize,
    pub baseline_syscall_count: usize,
    pub total_syscall_count: usize,
    pub capture_duration_ms: u64,
    pub total_events: u64,
    #[serde(default)]
    pub source_runs: Vec<SourceRun>,
    /// Names the capture reported that this architecture does not define.
    #[serde(default)]
    pub unresolved: Vec<String>,
    /// Non-native architectures seen during capture, by audit arch value.
    #[serde(default)]
    pub foreign_arch: BTreeMap<String, u64>,
    /// Observed call counts. Drives frequency ordered filter compilation.
    #[serde(default)]
    pub syscall_counts: BTreeMap<String, u64>,
}

/// An OCI seccomp profile plus the provenance this runtime records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SeccompProfile {
    #[serde(flatten)]
    pub seccomp: LinuxSeccomp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crun_metadata: Option<CrunMetadata>,
}

impl SeccompProfile {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read seccomp profile: {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse seccomp profile: {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create profile directory: {}", parent.display())
                })?;
            }
        }

        let content =
            serde_json::to_string_pretty(self).context("failed to serialize seccomp profile")?;
        std::fs::write(path, format!("{content}\n"))
            .with_context(|| format!("failed to write seccomp profile: {}", path.display()))
    }

    pub fn default_action(&self) -> LinuxSeccompAction {
        self.seccomp.default_action()
    }

    /// Every syscall name the profile allows.
    ///
    /// Docker's profile splits its allow list across several entries, some of
    /// which are gated on capabilities the container does not have; only
    /// unconditional `SCMP_ACT_ALLOW` entries count as allowed.
    /// Rejects OCI rule features this runtime cannot preserve in its allowlist BPF.
    pub fn validate_supported(&self) -> std::result::Result<(), SeccompError> {
        let Some(rules) = self.seccomp.syscalls() else {
            return Ok(());
        };

        for rule in rules {
            if rule.args().as_ref().is_some_and(|args| !args.is_empty()) {
                return Err(SeccompError::UnsupportedConditionalRule {
                    syscalls: rule.names().join(","),
                });
            }
        }

        Ok(())
    }

    pub fn allowed_names(&self) -> BTreeSet<String> {
        let Some(rules) = self.seccomp.syscalls() else {
            return BTreeSet::new();
        };

        rules
            .iter()
            .filter(|rule| rule.action() == LinuxSeccompAction::ScmpActAllow)
            .flat_map(|rule| rule.names().iter().cloned())
            .collect()
    }

    /// Allowed names that exist on the running architecture.
    ///
    /// Baseline profiles list names for architectures they do not target, so a
    /// raw count overstates how much surface they really expose.
    pub fn allowed_names_for_arch(&self) -> BTreeSet<String> {
        self.allowed_names()
            .into_iter()
            .filter(|name| syscalls::number(name).is_some())
            .collect()
    }
}

/// Builds an allowlist profile from a set of syscall names.
pub fn build_profile(
    names: &BTreeSet<String>,
    default_action: LinuxSeccompAction,
    default_errno: Option<u32>,
    metadata: Option<CrunMetadata>,
) -> std::result::Result<SeccompProfile, SeccompError> {
    let arch = arch::native_oci_arch()?;
    build_profile_for_arch(names, default_action, default_errno, metadata, arch)
}

pub fn build_profile_for_arch(
    names: &BTreeSet<String>,
    default_action: LinuxSeccompAction,
    default_errno: Option<u32>,
    metadata: Option<CrunMetadata>,
    arch: Arch,
) -> std::result::Result<SeccompProfile, SeccompError> {
    let mut seccomp = LinuxSeccomp::default();
    seccomp.set_default_action(default_action);
    seccomp.set_default_errno_ret(default_errno);
    seccomp.set_architectures(Some(vec![arch]));

    let mut rule = LinuxSyscall::default();
    rule.set_names(names.iter().cloned().collect());
    rule.set_action(LinuxSeccompAction::ScmpActAllow);
    seccomp.set_syscalls(Some(vec![rule]));

    Ok(SeccompProfile {
        seccomp,
        crun_metadata: metadata,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn sample_metadata() -> CrunMetadata {
        CrunMetadata {
            schema_version: METADATA_SCHEMA_VERSION,
            generator: "crun-rs".to_string(),
            runtime_version: "0.1.0".to_string(),
            workload: Some("nginx".to_string()),
            arch: "x86_64".to_string(),
            audit_arch: arch::AUDIT_ARCH_NATIVE,
            generated_at_unix: 1_700_000_000,
            observed_syscall_count: 2,
            baseline_syscall_count: 9,
            total_syscall_count: 11,
            capture_duration_ms: 1234,
            total_events: 5678,
            source_runs: vec![SourceRun {
                container_id: "demo".to_string(),
                command: vec!["/bin/sh".to_string()],
                started_at_unix: 1_700_000_000,
                duration_ms: 1234,
                events: 5678,
                unique_syscalls: 2,
            }],
            unresolved: vec![],
            foreign_arch: BTreeMap::new(),
            syscall_counts: BTreeMap::from([("read".to_string(), 42)]),
        }
    }

    #[test]
    fn emits_the_oci_seccomp_schema() {
        let profile = build_profile(
            &names(&["read", "write"]),
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            None,
        )
        .expect("profile should build");

        let json: serde_json::Value =
            serde_json::to_value(&profile).expect("profile should serialize");

        assert_eq!(json["defaultAction"], "SCMP_ACT_ERRNO");
        assert_eq!(json["defaultErrnoRet"], 1);
        assert_eq!(json["architectures"][0], "SCMP_ARCH_X86_64");
        assert_eq!(json["syscalls"][0]["action"], "SCMP_ACT_ALLOW");
        assert_eq!(json["syscalls"][0]["names"][0], "read");
        assert!(json.get("crunMetadata").is_none());
    }

    #[test]
    fn keeps_metadata_through_a_round_trip() {
        let profile = build_profile(
            &names(&["read"]),
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            Some(sample_metadata()),
        )
        .expect("profile should build");

        let encoded = serde_json::to_string(&profile).expect("profile should serialize");
        let decoded: SeccompProfile =
            serde_json::from_str(&encoded).expect("profile should deserialize");

        assert_eq!(decoded, profile);
        let metadata = decoded.crun_metadata.expect("metadata should survive");
        assert_eq!(metadata.workload.as_deref(), Some("nginx"));
        assert_eq!(metadata.syscall_counts.get("read"), Some(&42));
    }

    #[test]
    fn parses_a_profile_that_carries_no_metadata() {
        let decoded: SeccompProfile = serde_json::from_str(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "architectures": ["SCMP_ARCH_X86_64"],
                "syscalls": [{ "names": ["read", "write"], "action": "SCMP_ACT_ALLOW" }]
            }"#,
        )
        .expect("a plain OCI profile should parse");

        assert!(decoded.crun_metadata.is_none());
        assert_eq!(decoded.allowed_names().len(), 2);
    }

    #[test]
    fn rejects_conditional_rules_before_compilation() {
        let decoded: SeccompProfile = serde_json::from_str(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [{
                    "names": ["openat"],
                    "action": "SCMP_ACT_ALLOW",
                    "args": [{"index": 2, "value": 0, "op": "SCMP_CMP_EQ"}]
                }]
            }"#,
        )
        .expect("conditional profile should parse");

        assert!(matches!(
            decoded.validate_supported(),
            Err(SeccompError::UnsupportedConditionalRule { syscalls }) if syscalls == "openat"
        ));
    }

    #[test]
    fn counts_only_unconditionally_allowed_syscalls() {
        let decoded: SeccompProfile = serde_json::from_str(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    { "names": ["read", "write"], "action": "SCMP_ACT_ALLOW" },
                    { "names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38 },
                    { "names": ["ptrace"], "action": "SCMP_ACT_TRACE" }
                ]
            }"#,
        )
        .expect("profile should parse");

        let allowed = decoded.allowed_names();
        assert!(allowed.contains("read"));
        assert!(allowed.contains("write"));
        assert!(!allowed.contains("clone3"));
        assert!(!allowed.contains("ptrace"));
    }

    #[test]
    fn drops_names_this_architecture_does_not_define() {
        let decoded: SeccompProfile = serde_json::from_str(
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    { "names": ["read", "arm_sync_file_range", "definitely_not_a_syscall"],
                      "action": "SCMP_ACT_ALLOW" }
                ]
            }"#,
        )
        .expect("profile should parse");

        assert_eq!(decoded.allowed_names().len(), 3);
        assert_eq!(decoded.allowed_names_for_arch(), names(&["read"]));
    }

    #[test]
    fn baseline_names_all_exist_on_this_architecture() {
        for name in mandatory_baseline() {
            assert!(
                syscalls::number(name).is_some(),
                "baseline syscall {name} is not defined on this architecture"
            );
        }
    }

    #[test]
    fn writes_and_reads_a_profile_file() {
        let path =
            std::env::temp_dir().join(format!("crun-profile-test-{}.json", std::process::id()));
        let profile = build_profile(
            &names(&["read", "write"]),
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            Some(sample_metadata()),
        )
        .expect("profile should build");

        profile.save(&path).expect("profile should save");
        let loaded = SeccompProfile::load(&path).expect("profile should load");

        assert_eq!(loaded, profile);
        let _ = std::fs::remove_file(&path);
    }
}
