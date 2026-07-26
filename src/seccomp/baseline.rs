//! Reads a Docker-format seccomp profile the way the Docker daemon does.
//!
//! Docker's profile is the baseline the generated profiles are measured
//! against, and it is not a plain allowlist: rules carry `includes` and
//! `excludes` filters on architecture and capabilities. A rule gated on
//! `CAP_SYS_ADMIN` does not apply to a container that was never granted it, so
//! counting every `SCMP_ACT_ALLOW` name would overstate what Docker actually
//! permits. These fields are a Docker extension rather than part of the OCI
//! schema, so they have to be read from the raw JSON.

use super::syscalls;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

/// Capabilities a Docker container is granted unless the operator changes them.
///
/// Rules gated on any of these do apply; rules gated on anything else do not.
pub fn docker_default_capabilities() -> &'static [&'static str] {
    &[
        "CAP_AUDIT_WRITE",
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_MKNOD",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT",
    ]
}

/// Architecture name Docker profiles use for the running target.
pub fn docker_arch_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "amd64"
    }

    #[cfg(target_arch = "aarch64")]
    {
        "arm64"
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "unsupported"
    }
}

#[derive(Debug, Clone)]
pub struct BaselineOptions {
    pub arch: String,
    pub capabilities: BTreeSet<String>,
}

impl Default for BaselineOptions {
    fn default() -> Self {
        Self {
            arch: docker_arch_name().to_string(),
            capabilities: docker_default_capabilities()
                .iter()
                .map(|value| value.to_string())
                .collect(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct RuleFilter {
    #[serde(default)]
    caps: Vec<String>,
    #[serde(default)]
    arches: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SyscallRule {
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    name: Option<String>,
    action: String,
    #[serde(default)]
    includes: Option<RuleFilter>,
    #[serde(default)]
    excludes: Option<RuleFilter>,
}

#[derive(Debug, Deserialize)]
struct DockerProfile {
    #[serde(default)]
    syscalls: Vec<SyscallRule>,
}

/// Names a Docker container with the given capabilities would be allowed to
/// call on this architecture.
pub fn allowed_names(path: &Path, options: &BaselineOptions) -> Result<BTreeSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read baseline profile: {}", path.display()))?;
    let profile: DockerProfile = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse baseline profile: {}", path.display()))?;

    let mut allowed = BTreeSet::new();
    for rule in &profile.syscalls {
        if rule.action != "SCMP_ACT_ALLOW" || !rule_applies(rule, options) {
            continue;
        }

        allowed.extend(rule.names.iter().cloned());
        if let Some(name) = rule.name.as_ref() {
            allowed.insert(name.clone());
        }
    }

    Ok(allowed)
}

/// The same set, restricted to syscalls this architecture actually defines.
///
/// The profile lists names for every architecture Docker supports, so a raw
/// count overstates the surface a container really has.
pub fn allowed_names_for_arch(path: &Path, options: &BaselineOptions) -> Result<BTreeSet<String>> {
    Ok(allowed_names(path, options)?
        .into_iter()
        .filter(|name| syscalls::number(name).is_some())
        .collect())
}

fn rule_applies(rule: &SyscallRule, options: &BaselineOptions) -> bool {
    if let Some(includes) = rule.includes.as_ref() {
        if !includes.arches.is_empty() && !includes.arches.contains(&options.arch) {
            return false;
        }
        // Docker requires every listed capability to be present.
        if includes
            .caps
            .iter()
            .any(|cap| !options.capabilities.contains(cap))
        {
            return false;
        }
    }

    if let Some(excludes) = rule.excludes.as_ref() {
        if !excludes.arches.is_empty() && excludes.arches.contains(&options.arch) {
            return false;
        }
        if !excludes.caps.is_empty()
            && excludes
                .caps
                .iter()
                .all(|cap| options.capabilities.contains(cap))
        {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_profile(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "crun-baseline-{name}-{}-{}.json",
            std::process::id(),
            name.len()
        ));
        std::fs::write(&path, content).expect("profile should write");
        path
    }

    #[test]
    fn skips_rules_gated_on_capabilities_the_container_does_not_have() {
        let path = write_profile(
            "caps",
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    { "names": ["read", "write"], "action": "SCMP_ACT_ALLOW" },
                    { "names": ["mount"], "action": "SCMP_ACT_ALLOW",
                      "includes": { "caps": ["CAP_SYS_ADMIN"] } },
                    { "names": ["chroot"], "action": "SCMP_ACT_ALLOW",
                      "includes": { "caps": ["CAP_SYS_CHROOT"] } }
                ]
            }"#,
        );

        let allowed = allowed_names(&path, &BaselineOptions::default()).expect("should parse");

        assert!(allowed.contains("read"));
        // Not in Docker's default capability set.
        assert!(!allowed.contains("mount"));
        // In Docker's default capability set, so the rule applies.
        assert!(allowed.contains("chroot"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn skips_rules_for_other_architectures() {
        let path = write_profile(
            "arches",
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    { "names": ["read"], "action": "SCMP_ACT_ALLOW" },
                    { "names": ["s390_pci_mmio_read"], "action": "SCMP_ACT_ALLOW",
                      "includes": { "arches": ["s390", "s390x"] } },
                    { "names": ["arch_prctl"], "action": "SCMP_ACT_ALLOW",
                      "includes": { "arches": ["amd64", "x32", "x86"] } }
                ]
            }"#,
        );

        let allowed = allowed_names(&path, &BaselineOptions::default()).expect("should parse");

        assert!(allowed.contains("read"));
        assert!(!allowed.contains("s390_pci_mmio_read"));
        #[cfg(target_arch = "x86_64")]
        assert!(allowed.contains("arch_prctl"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn honours_exclude_filters() {
        let path = write_profile(
            "excludes",
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    { "names": ["clone"], "action": "SCMP_ACT_ALLOW",
                      "excludes": { "caps": ["CAP_SYS_ADMIN"] } },
                    { "names": ["setuid"], "action": "SCMP_ACT_ALLOW",
                      "excludes": { "caps": ["CAP_SETUID"] } }
                ]
            }"#,
        );

        let allowed = allowed_names(&path, &BaselineOptions::default()).expect("should parse");

        // Excluded on a capability the container does not have, so it applies.
        assert!(allowed.contains("clone"));
        // Excluded on a capability the container does have, so it does not.
        assert!(!allowed.contains("setuid"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn ignores_rules_that_are_not_allow_rules() {
        let path = write_profile(
            "actions",
            r#"{
                "defaultAction": "SCMP_ACT_ERRNO",
                "syscalls": [
                    { "names": ["read"], "action": "SCMP_ACT_ALLOW" },
                    { "names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38 }
                ]
            }"#,
        );

        let allowed = allowed_names(&path, &BaselineOptions::default()).expect("should parse");

        assert!(allowed.contains("read"));
        assert!(!allowed.contains("clone3"));
        let _ = std::fs::remove_file(&path);
    }
}
