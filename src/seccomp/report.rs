//! Inspection and comparison reports for generated profiles.
//!
//! These are what the evaluation numbers come from: how much smaller a
//! generated profile is than the baseline it is measured against, and which
//! known vulnerabilities its blocked syscalls cut off.

use super::compile::{CompileOptions, SyscallOrder};
use super::profile::SeccompProfile;
use super::{arch, compile, syscalls};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProfileInspection {
    pub path: String,
    pub arch: String,
    pub default_action: String,
    pub allowed_count: usize,
    pub allowed_count_for_arch: usize,
    pub allowed: Vec<String>,
    /// Names the profile lists that this architecture does not define.
    pub unknown_for_arch: Vec<String>,
    pub instruction_count: usize,
    pub workload: Option<String>,
    pub generated_at_unix: Option<u64>,
    pub observed_syscall_count: Option<usize>,
    pub baseline_syscall_count: Option<usize>,
    pub total_events: Option<u64>,
    pub source_runs: usize,
}

pub fn inspect(path: &Path, profile: &SeccompProfile) -> Result<ProfileInspection> {
    let allowed = profile.allowed_names();
    let allowed_for_arch = profile.allowed_names_for_arch();
    let unknown = allowed
        .difference(&allowed_for_arch)
        .cloned()
        .collect::<Vec<_>>();

    let compiled = compile::compile(
        profile,
        CompileOptions {
            default_action: super::SeccompAction::Errno,
            order: SyscallOrder::ByNumber,
        },
    )?;

    let metadata = profile.crun_metadata.as_ref();

    Ok(ProfileInspection {
        path: path.display().to_string(),
        arch: arch::NATIVE_ARCH_NAME.to_string(),
        default_action: format!("{:?}", profile.default_action()),
        allowed_count: allowed.len(),
        allowed_count_for_arch: allowed_for_arch.len(),
        allowed: allowed.into_iter().collect(),
        unknown_for_arch: unknown,
        instruction_count: compiled.program.len(),
        workload: metadata.and_then(|value| value.workload.clone()),
        generated_at_unix: metadata.map(|value| value.generated_at_unix),
        observed_syscall_count: metadata.map(|value| value.observed_syscall_count),
        baseline_syscall_count: metadata.map(|value| value.baseline_syscall_count),
        total_events: metadata.map(|value| value.total_events),
        source_runs: metadata.map(|value| value.source_runs.len()).unwrap_or(0),
    })
}

/// One CVE and the syscalls that reach it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CveEntry {
    pub id: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub subsystem: String,
    /// Alternative routes to the same bug. Each route lists syscalls that are
    /// all required, so a CVE counts as blocked only when every route has at
    /// least one syscall denied.
    pub attack_paths: Vec<AttackPath>,
    #[serde(default = "default_true")]
    pub container_relevant: bool,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub references: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackPath {
    pub syscalls: Vec<String>,
    #[serde(default)]
    pub note: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CveMap {
    pub schema_version: u32,
    #[serde(default)]
    pub arch: String,
    pub entries: Vec<CveEntry>,
}

impl CveMap {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read CVE map: {}", path.display()))?;
        serde_json::from_str(&content)
            .with_context(|| format!("failed to parse CVE map: {}", path.display()))
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CveCoverage {
    pub total: usize,
    pub container_relevant: usize,
    pub mitigated_by_profile: usize,
    pub mitigated_by_baseline: usize,
    pub newly_mitigated: Vec<String>,
    pub still_reachable: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ComparisonReport {
    pub profile: String,
    pub baseline: Option<String>,
    pub arch: String,
    pub universe_count: usize,
    pub profile_allowed: usize,
    pub baseline_allowed: Option<usize>,
    /// 1 - profile/baseline, on syscalls that exist on this architecture.
    pub reduction_vs_baseline: Option<f64>,
    pub reduction_vs_universe: f64,
    /// Allowed by the baseline but not by the profile: surface removed.
    pub newly_blocked: Vec<String>,
    /// Allowed by the profile but not by the baseline: surface the baseline
    /// would have blocked, which is worth explaining rather than hiding.
    pub over_allowed: Vec<String>,
    pub cve: Option<CveCoverage>,
}

pub fn compare(
    profile_path: &Path,
    profile: &SeccompProfile,
    baseline: Option<(&Path, &SeccompProfile)>,
    cve_map: Option<&CveMap>,
) -> ComparisonReport {
    let universe_count = syscalls::table().len();
    let profile_allowed = profile.allowed_names_for_arch();

    let baseline_allowed = baseline.map(|(_, value)| value.allowed_names_for_arch());
    let reduction_vs_baseline = baseline_allowed.as_ref().and_then(|allowed| {
        (!allowed.is_empty()).then(|| 1.0 - (profile_allowed.len() as f64 / allowed.len() as f64))
    });

    let newly_blocked = baseline_allowed
        .as_ref()
        .map(|allowed| allowed.difference(&profile_allowed).cloned().collect())
        .unwrap_or_default();
    let over_allowed = baseline_allowed
        .as_ref()
        .map(|allowed| profile_allowed.difference(allowed).cloned().collect())
        .unwrap_or_default();

    let cve = cve_map.map(|map| {
        cve_coverage(
            map,
            &profile_allowed,
            baseline_allowed.as_ref().unwrap_or(&BTreeSet::new()),
        )
    });

    ComparisonReport {
        profile: profile_path.display().to_string(),
        baseline: baseline.map(|(path, _)| path.display().to_string()),
        arch: arch::NATIVE_ARCH_NAME.to_string(),
        universe_count,
        profile_allowed: profile_allowed.len(),
        baseline_allowed: baseline_allowed.as_ref().map(BTreeSet::len),
        reduction_vs_baseline,
        reduction_vs_universe: 1.0 - (profile_allowed.len() as f64 / universe_count as f64),
        newly_blocked,
        over_allowed,
        cve,
    }
}

/// A CVE is mitigated when every one of its attack paths has at least one
/// syscall the profile does not allow.
pub fn is_mitigated(entry: &CveEntry, allowed: &BTreeSet<String>) -> bool {
    if entry.attack_paths.is_empty() {
        return false;
    }

    entry.attack_paths.iter().all(|path| {
        path.syscalls
            .iter()
            .any(|syscall| !allowed.contains(syscall))
    })
}

fn cve_coverage(
    map: &CveMap,
    profile_allowed: &BTreeSet<String>,
    baseline_allowed: &BTreeSet<String>,
) -> CveCoverage {
    let relevant: Vec<&CveEntry> = map
        .entries
        .iter()
        .filter(|entry| entry.container_relevant)
        .collect();

    let mut newly_mitigated = Vec::new();
    let mut still_reachable = Vec::new();
    let mut mitigated_by_profile = 0;
    let mut mitigated_by_baseline = 0;

    for entry in &relevant {
        let by_profile = is_mitigated(entry, profile_allowed);
        let by_baseline = !baseline_allowed.is_empty() && is_mitigated(entry, baseline_allowed);

        if by_profile {
            mitigated_by_profile += 1;
        } else {
            still_reachable.push(entry.id.clone());
        }
        if by_baseline {
            mitigated_by_baseline += 1;
        }
        if by_profile && !by_baseline {
            newly_mitigated.push(entry.id.clone());
        }
    }

    CveCoverage {
        total: map.entries.len(),
        container_relevant: relevant.len(),
        mitigated_by_profile,
        mitigated_by_baseline,
        newly_mitigated,
        still_reachable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::profile::build_profile;
    use oci_spec::runtime::LinuxSeccompAction;

    fn names(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn profile_of(values: &[&str]) -> SeccompProfile {
        build_profile(
            &names(values),
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            None,
        )
        .expect("profile should build")
    }

    fn cve(id: &str, paths: &[&[&str]]) -> CveEntry {
        CveEntry {
            id: id.to_string(),
            title: String::new(),
            subsystem: String::new(),
            attack_paths: paths
                .iter()
                .map(|syscalls| AttackPath {
                    syscalls: syscalls.iter().map(|value| value.to_string()).collect(),
                    note: String::new(),
                })
                .collect(),
            container_relevant: true,
            confidence: "high".to_string(),
            references: BTreeMap::new(),
        }
    }

    #[test]
    fn computes_reduction_against_a_baseline() {
        let profile = profile_of(&["read", "write"]);
        let baseline = profile_of(&["read", "write", "openat", "mount"]);

        let report = compare(
            Path::new("profile.json"),
            &profile,
            Some((Path::new("baseline.json"), &baseline)),
            None,
        );

        assert_eq!(report.profile_allowed, 2);
        assert_eq!(report.baseline_allowed, Some(4));
        assert_eq!(report.reduction_vs_baseline, Some(0.5));
        assert_eq!(report.newly_blocked, vec!["mount", "openat"]);
        assert!(report.over_allowed.is_empty());
    }

    #[test]
    fn reports_syscalls_the_baseline_would_have_blocked() {
        let profile = profile_of(&["read", "ptrace"]);
        let baseline = profile_of(&["read"]);

        let report = compare(
            Path::new("profile.json"),
            &profile,
            Some((Path::new("baseline.json"), &baseline)),
            None,
        );

        assert_eq!(report.over_allowed, vec!["ptrace"]);
    }

    #[test]
    fn measures_reduction_against_the_whole_syscall_table_without_a_baseline() {
        let profile = profile_of(&["read"]);

        let report = compare(Path::new("profile.json"), &profile, None, None);

        assert_eq!(report.baseline_allowed, None);
        assert_eq!(report.reduction_vs_baseline, None);
        assert!(report.reduction_vs_universe > 0.99);
    }

    #[test]
    fn a_cve_is_blocked_only_when_every_path_is_cut() {
        let allowed = names(&["read", "write", "splice"]);

        // One path, and its only syscall is allowed.
        assert!(!is_mitigated(&cve("CVE-A", &[&["splice"]]), &allowed));
        // One path, syscall not allowed.
        assert!(is_mitigated(&cve("CVE-B", &[&["mount"]]), &allowed));
        // Two paths, one of them still open.
        assert!(!is_mitigated(
            &cve("CVE-C", &[&["mount"], &["splice"]]),
            &allowed
        ));
        // Two paths, both cut.
        assert!(is_mitigated(
            &cve("CVE-D", &[&["mount"], &["bpf"]]),
            &allowed
        ));
        // A path needs all of its syscalls, so denying one is enough.
        assert!(is_mitigated(
            &cve("CVE-E", &[&["splice", "mount"]]),
            &allowed
        ));
    }

    #[test]
    fn counts_cves_the_profile_blocks_that_the_baseline_does_not() {
        let profile = profile_of(&["read"]);
        let baseline = profile_of(&["read", "splice"]);
        let map = CveMap {
            schema_version: 1,
            arch: "x86_64".to_string(),
            entries: vec![
                cve("CVE-2022-0847", &[&["splice"]]),
                cve("CVE-2016-0728", &[&["keyctl"]]),
            ],
        };

        let report = compare(
            Path::new("profile.json"),
            &profile,
            Some((Path::new("baseline.json"), &baseline)),
            Some(&map),
        );

        let coverage = report.cve.expect("cve coverage should be present");
        assert_eq!(coverage.container_relevant, 2);
        assert_eq!(coverage.mitigated_by_profile, 2);
        assert_eq!(coverage.mitigated_by_baseline, 1);
        assert_eq!(coverage.newly_mitigated, vec!["CVE-2022-0847"]);
        assert!(coverage.still_reachable.is_empty());
    }

    #[test]
    fn ignores_entries_marked_as_not_container_relevant() {
        let profile = profile_of(&["read"]);
        let mut entry = cve("CVE-2019-5736", &[&["execve"]]);
        entry.container_relevant = false;
        let map = CveMap {
            schema_version: 1,
            arch: "x86_64".to_string(),
            entries: vec![entry],
        };

        let report = compare(Path::new("profile.json"), &profile, None, Some(&map));
        let coverage = report.cve.expect("cve coverage should be present");

        assert_eq!(coverage.total, 1);
        assert_eq!(coverage.container_relevant, 0);
        assert_eq!(coverage.mitigated_by_profile, 0);
    }

    #[test]
    fn inspection_reports_the_compiled_instruction_count() {
        let profile = profile_of(&["read", "write"]);

        let inspection =
            inspect(Path::new("profile.json"), &profile).expect("inspection should succeed");

        assert_eq!(inspection.allowed_count, 2);
        assert_eq!(inspection.allowed_count_for_arch, 2);
        assert!(inspection.instruction_count > 4);
        assert!(inspection.unknown_for_arch.is_empty());
    }
}
