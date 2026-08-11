use crate::error::OciConfigError;
use anyhow::{Context, Result};
use nix::libc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct OciConfig {
    #[serde(default)]
    pub hostname: Option<String>,

    pub process: Process,
    pub root: Root,

    #[serde(default)]
    pub mounts: Vec<Mount>,

    #[serde(default)]
    pub healthcheck: Option<Healthcheck>,

    #[serde(default)]
    pub linux: Option<Linux>,

    #[serde(default)]
    pub crun: Option<CrunConfig>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BundleValidationReport {
    pub bundle: String,
    pub valid: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Process {
    pub args: Vec<String>,

    #[serde(default)]
    pub env: Vec<String>,

    #[serde(default)]
    pub cwd: Option<String>,

    #[serde(default)]
    pub user: Option<ProcessUser>,

    #[serde(default)]
    pub capabilities: Option<LinuxCapabilities>,

    #[serde(default)]
    pub rlimits: Vec<LinuxRlimit>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProcessUser {
    #[serde(default)]
    pub uid: u32,

    #[serde(default)]
    pub gid: u32,

    #[serde(default, rename = "additionalGids")]
    pub additional_gids: Vec<u32>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct LinuxCapabilities {
    #[serde(default)]
    pub bounding: Vec<String>,

    #[serde(default)]
    pub effective: Vec<String>,

    #[serde(default)]
    pub inheritable: Vec<String>,

    #[serde(default)]
    pub permitted: Vec<String>,

    #[serde(default)]
    pub ambient: Vec<String>,
}

impl LinuxCapabilities {
    pub fn is_empty(&self) -> bool {
        self.bounding.is_empty()
            && self.effective.is_empty()
            && self.inheritable.is_empty()
            && self.permitted.is_empty()
            && self.ambient.is_empty()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct LinuxRlimit {
    #[serde(rename = "type")]
    pub rlimit_type: String,

    pub hard: u64,
    pub soft: u64,
}

#[derive(Debug, Deserialize)]
pub struct Root {
    pub path: String,

    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Healthcheck {
    #[serde(default)]
    pub test: Vec<String>,

    #[serde(default)]
    pub interval: Option<String>,

    #[serde(default)]
    pub timeout: Option<String>,

    #[serde(default)]
    pub retries: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CrunConfig {
    #[serde(default)]
    pub profile: Option<String>,

    #[serde(default)]
    pub overlay: Option<CrunOverlay>,
}

#[derive(Debug, Deserialize)]
pub struct CrunOverlay {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default)]
    pub lowerdir: Option<String>,

    pub upperdir: String,
    pub workdir: String,
    pub mergeddir: String,
}

#[derive(Debug, Deserialize)]
pub struct Mount {
    pub destination: String,

    #[serde(default)]
    pub source: Option<String>,

    #[serde(rename = "type")]
    pub mount_type: String,

    #[serde(default)]
    pub options: Vec<String>,
}

impl Mount {
    /// A mount is a bind when it says so through its type or its options. OCI
    /// bundles use both spellings, and `none` with a `bind` option is what runc
    /// and umoci emit.
    pub fn is_bind(&self) -> bool {
        matches!(self.mount_type.as_str(), "bind" | "rbind" | "none")
            || self
                .options
                .iter()
                .any(|option| option == "bind" || option == "rbind")
    }
}

/// Filesystem types this runtime knows how to mount. Bundles produced by umoci
/// and runc declare `proc`, `sysfs`, `tmpfs`, `devpts` and `mqueue` entries.
pub fn is_supported_mount_type(mount_type: &str) -> bool {
    matches!(
        mount_type,
        "bind"
            | "rbind"
            | "none"
            | "proc"
            | "sysfs"
            | "tmpfs"
            | "devpts"
            | "mqueue"
            | "cgroup"
            | "cgroup2"
            | "ramfs"
    )
}

#[derive(Debug, Deserialize)]
pub struct Linux {
    #[serde(default)]
    pub namespaces: Vec<LinuxNamespace>,

    #[serde(default)]
    pub resources: Option<LinuxResources>,

    #[serde(default, rename = "maskedPaths")]
    pub masked_paths: Vec<String>,

    #[serde(default, rename = "readonlyPaths")]
    pub readonly_paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct LinuxNamespace {
    #[serde(rename = "type")]
    pub namespace_type: String,
}

#[derive(Debug, Deserialize)]
pub struct LinuxResources {
    #[serde(default)]
    pub memory: Option<LinuxMemory>,

    #[serde(default)]
    pub cpu: Option<LinuxCpu>,

    #[serde(default)]
    pub pids: Option<LinuxPids>,
}

#[derive(Debug, Deserialize)]
pub struct LinuxMemory {
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct LinuxCpu {
    #[serde(default)]
    pub quota: Option<i64>,

    #[serde(default)]
    pub period: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LinuxPids {
    #[serde(default)]
    pub limit: Option<i64>,
}

impl OciConfig {
    pub fn validate(&self) -> std::result::Result<(), OciConfigError> {
        if self.process.args.is_empty() {
            return Err(OciConfigError::EmptyProcessArgs);
        }

        if self
            .process
            .capabilities
            .as_ref()
            .is_some_and(|capabilities| !capabilities.is_empty())
        {
            return Err(OciConfigError::UnsupportedCapabilities);
        }

        if self.root.path.trim().is_empty() {
            return Err(OciConfigError::EmptyRootPath);
        }

        for mount in &self.mounts {
            if mount.destination.trim().is_empty() {
                return Err(OciConfigError::EmptyMountDestination);
            }
            if !is_supported_mount_type(&mount.mount_type) {
                return Err(OciConfigError::UnsupportedMountType {
                    mount_type: mount.mount_type.clone(),
                });
            }
            // Only bind mounts name a host path; filesystem mounts default
            // their source to the filesystem type.
            if mount.is_bind() && mount.source.as_deref().unwrap_or("").trim().is_empty() {
                return Err(OciConfigError::EmptyBindMountSource);
            }
        }

        if let Some(healthcheck) = &self.healthcheck {
            if healthcheck.test.is_empty() {
                return Err(OciConfigError::EmptyHealthcheckTest);
            }
        }

        for rlimit in &self.process.rlimits {
            if rlimit.soft > rlimit.hard {
                return Err(OciConfigError::RlimitSoftExceedsHard {
                    rlimit_type: rlimit.rlimit_type.clone(),
                });
            }
            if rlimit_resource(&rlimit.rlimit_type).is_none() {
                return Err(OciConfigError::UnsupportedRlimit {
                    rlimit_type: rlimit.rlimit_type.clone(),
                });
            }
        }

        if let Some(overlay) = self.crun.as_ref().and_then(|crun| crun.overlay.as_ref()) {
            if overlay.enabled {
                if overlay.upperdir.trim().is_empty() {
                    return Err(OciConfigError::EmptyOverlayPath { field: "upperdir" });
                }
                if overlay.workdir.trim().is_empty() {
                    return Err(OciConfigError::EmptyOverlayPath { field: "workdir" });
                }
                if overlay.mergeddir.trim().is_empty() {
                    return Err(OciConfigError::EmptyOverlayPath { field: "mergeddir" });
                }
            }
        }

        if let Some(profile) = self.crun.as_ref().and_then(|crun| crun.profile.as_deref()) {
            if !matches!(profile, "restricted" | "debug") {
                return Err(OciConfigError::UnsupportedCrunProfile {
                    profile: profile.to_string(),
                });
            }
        }

        if let Some(linux) = &self.linux {
            for namespace in &linux.namespaces {
                if !matches!(
                    namespace.namespace_type.as_str(),
                    "pid" | "mount" | "uts" | "ipc" | "network" | "user"
                ) {
                    return Err(OciConfigError::UnsupportedNamespace {
                        namespace_type: namespace.namespace_type.clone(),
                    });
                }
            }

            for path in linux.masked_paths.iter().chain(linux.readonly_paths.iter()) {
                validate_container_path(path)?;
            }
        }

        Ok(())
    }

    pub fn validation_warnings(&self) -> Vec<String> {
        Vec::new()
    }
}

pub fn rlimit_resource(name: &str) -> Option<libc::__rlimit_resource_t> {
    match name {
        "RLIMIT_AS" => Some(libc::RLIMIT_AS),
        "RLIMIT_CORE" => Some(libc::RLIMIT_CORE),
        "RLIMIT_CPU" => Some(libc::RLIMIT_CPU),
        "RLIMIT_FSIZE" => Some(libc::RLIMIT_FSIZE),
        "RLIMIT_NOFILE" => Some(libc::RLIMIT_NOFILE),
        "RLIMIT_NPROC" => Some(libc::RLIMIT_NPROC),
        "RLIMIT_STACK" => Some(libc::RLIMIT_STACK),
        _ => None,
    }
}

fn validate_container_path(path: &str) -> std::result::Result<(), OciConfigError> {
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(OciConfigError::LinuxPathNotAbsolute {
            path: path.display().to_string(),
        });
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::Prefix(_)
        )
    }) {
        return Err(OciConfigError::LinuxPathEscapesRoot {
            path: path.display().to_string(),
        });
    }
    Ok(())
}

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<OciConfig> {
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read config file: {}", path.as_ref().display()))?;

    let config: OciConfig =
        serde_json::from_str(&content).context("failed to parse OCI config.json")?;
    config.validate().context("invalid OCI config")?;

    Ok(config)
}

pub fn validate_bundle(bundle: &Path) -> Result<BundleValidationReport> {
    let config = load_config(bundle.join("config.json"))?;

    Ok(BundleValidationReport {
        bundle: bundle.display().to_string(),
        valid: true,
        warnings: config.validation_warnings(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn parse_config(input: &str) -> std::result::Result<OciConfig, OciConfigError> {
        let config: OciConfig = serde_json::from_str(input).expect("test JSON should parse");
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn parses_minimal_config() {
        let config = parse_config(
            r#"{
                "process": {
                    "args": ["/bin/sh"],
                    "env": ["PATH=/bin"],
                    "cwd": "/tmp"
                },
                "hostname": "demo",
                "root": {
                    "path": "rootfs",
                    "readonly": true
                },
                "healthcheck": {
                    "test": ["CMD", "/bin/sh", "-c", "true"],
                    "interval": "30s",
                    "timeout": "5s",
                    "retries": 3
                },
                "mounts": [
                    {
                        "destination": "/data",
                        "source": "/tmp/data",
                        "type": "bind",
                        "options": ["rbind", "ro"]
                    }
                ],
                "crun": {
                    "profile": "restricted",
                    "overlay": {
                        "enabled": true,
                        "upperdir": "../overlay/demo/upper",
                        "workdir": "../overlay/demo/work",
                        "mergeddir": "../overlay/demo/merged"
                    }
                }
            }"#,
        )
        .expect("valid config");

        assert_eq!(config.hostname.as_deref(), Some("demo"));
        assert_eq!(config.process.args, ["/bin/sh"]);
        assert_eq!(config.process.env, ["PATH=/bin"]);
        assert_eq!(config.process.cwd.as_deref(), Some("/tmp"));
        assert_eq!(config.root.path, "rootfs");
        assert!(config.root.readonly);
        let healthcheck = config
            .healthcheck
            .as_ref()
            .expect("healthcheck should parse");
        assert_eq!(
            healthcheck.test,
            ["CMD", "/bin/sh", "-c", "true"].map(str::to_string)
        );
        assert_eq!(healthcheck.interval.as_deref(), Some("30s"));
        assert_eq!(healthcheck.timeout.as_deref(), Some("5s"));
        assert_eq!(healthcheck.retries, Some(3));
        assert_eq!(config.mounts.len(), 1);
        assert_eq!(config.mounts[0].destination, "/data");
        assert_eq!(config.mounts[0].source.as_deref(), Some("/tmp/data"));
        assert_eq!(config.mounts[0].mount_type, "bind");
        let overlay = config
            .crun
            .as_ref()
            .and_then(|crun| crun.overlay.as_ref())
            .expect("overlay should parse");
        assert_eq!(
            config
                .crun
                .as_ref()
                .and_then(|crun| crun.profile.as_deref()),
            Some("restricted")
        );
        assert!(overlay.enabled);
        assert_eq!(overlay.upperdir, "../overlay/demo/upper");
        assert_eq!(overlay.workdir, "../overlay/demo/work");
        assert_eq!(overlay.mergeddir, "../overlay/demo/merged");
        assert!(config.linux.is_none());
    }

    #[test]
    fn rejects_empty_process_args() {
        let error = parse_config(
            r#"{
                "process": { "args": [] },
                "root": { "path": "rootfs" }
            }"#,
        )
        .expect_err("empty args should be rejected");

        assert!(matches!(error, OciConfigError::EmptyProcessArgs));
    }

    #[test]
    fn rejects_empty_root_path() {
        let error = parse_config(
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": " " }
            }"#,
        )
        .expect_err("empty root path should be rejected");

        assert!(matches!(error, OciConfigError::EmptyRootPath));
    }

    #[test]
    fn builds_bundle_validation_report_from_config() {
        let bundle = test_dir("builds_bundle_validation_report_from_config");
        fs::write(
            bundle.join("config.json"),
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": "rootfs" }
            }"#,
        )
        .expect("write config");

        let report = validate_bundle(&bundle).expect("bundle should validate");

        assert!(report.valid);
        assert_eq!(report.bundle, bundle.display().to_string());
        assert!(report.warnings.is_empty());

        fs::remove_dir_all(bundle).expect("cleanup test dir");
    }

    #[test]
    fn rejects_unsupported_mount_type() {
        let error = parse_config(
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": "rootfs" },
                "mounts": [
                    {
                        "destination": "/data",
                        "source": "/tmp/data",
                        "type": "nfs"
                    }
                ]
            }"#,
        )
        .expect_err("unsupported mount type should be rejected");

        assert!(matches!(
            error,
            OciConfigError::UnsupportedMountType { mount_type } if mount_type == "nfs"
        ));
    }

    #[test]
    fn accepts_filesystem_mounts_without_a_host_source() {
        let config = parse_config(
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": "rootfs" },
                "mounts": [
                    { "destination": "/proc", "type": "proc", "source": "proc" },
                    { "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
                      "options": ["nosuid", "strictatime", "mode=755", "size=65536k"] },
                    { "destination": "/dev/pts", "type": "devpts", "source": "devpts",
                      "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666"] },
                    { "destination": "/sys", "type": "sysfs", "source": "sysfs",
                      "options": ["nosuid", "noexec", "nodev", "ro"] }
                ]
            }"#,
        )
        .expect("an OCI bundle mount set should be accepted");

        assert_eq!(config.mounts.len(), 4);
        assert!(config.mounts.iter().all(|mount| !mount.is_bind()));
    }

    #[test]
    fn still_requires_a_source_for_bind_mounts() {
        let error = parse_config(
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": "rootfs" },
                "mounts": [
                    { "destination": "/data", "type": "bind", "options": ["rbind"] }
                ]
            }"#,
        )
        .expect_err("bind mount without a source should be rejected");

        assert!(matches!(error, OciConfigError::EmptyBindMountSource));
    }

    #[test]
    fn rejects_enabled_overlay_without_required_paths() {
        let error = parse_config(
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": "rootfs" },
                "crun": {
                    "overlay": {
                        "enabled": true,
                        "upperdir": "",
                        "workdir": "../overlay/work",
                        "mergeddir": "../overlay/merged"
                    }
                }
            }"#,
        )
        .expect_err("empty overlay paths should be rejected");

        assert!(matches!(
            error,
            OciConfigError::EmptyOverlayPath { field: "upperdir" }
        ));
    }

    #[test]
    fn parses_oci_user_capabilities_rlimits_and_paths() {
        let config: OciConfig = serde_json::from_str(
            r#"{
                "process": {
                    "args": ["/bin/sh"],
                    "user": {
                        "uid": 1000,
                        "gid": 1000,
                        "additionalGids": [10, 20]
                    },
                    "capabilities": {
                        "effective": ["CAP_NET_BIND_SERVICE"]
                    },
                    "rlimits": [
                        {
                            "type": "RLIMIT_NOFILE",
                            "soft": 64,
                            "hard": 128
                        }
                    ]
                },
                "root": { "path": "rootfs" },
                "linux": {
                    "maskedPaths": ["/proc/kcore"],
                    "readonlyPaths": ["/proc/sys"]
                }
            }"#,
        )
        .expect("OCI compatibility fields should parse");
        assert!(matches!(
            config.validate(),
            Err(OciConfigError::UnsupportedCapabilities)
        ));
        let user = config.process.user.as_ref().expect("user should parse");
        assert_eq!(user.uid, 1000);
        assert_eq!(user.gid, 1000);
        assert_eq!(user.additional_gids, [10, 20]);
        assert_eq!(config.process.rlimits[0].rlimit_type, "RLIMIT_NOFILE");
        assert_eq!(config.process.rlimits[0].soft, 64);
        assert_eq!(config.process.rlimits[0].hard, 128);
        assert_eq!(
            config
                .process
                .capabilities
                .as_ref()
                .expect("capabilities should parse")
                .effective,
            ["CAP_NET_BIND_SERVICE"]
        );
        assert_eq!(
            config
                .linux
                .as_ref()
                .expect("linux should parse")
                .masked_paths,
            ["/proc/kcore"]
        );
        assert!(config.validation_warnings().is_empty());
    }

    #[test]
    fn rejects_unsupported_namespace_types() {
        let error = parse_config(
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": "rootfs" },
                "linux": { "namespaces": [{"type": "time"}] }
            }"#,
        )
        .expect_err("unsupported namespace should be rejected");
        assert!(matches!(
            error,
            OciConfigError::UnsupportedNamespace { namespace_type } if namespace_type == "time"
        ));
    }

    #[test]
    fn rejects_bad_oci_compatibility_fields() {
        let rlimit_error = parse_config(
            r#"{
                "process": {
                    "args": ["/bin/sh"],
                    "rlimits": [
                        { "type": "RLIMIT_NOFILE", "soft": 128, "hard": 64 }
                    ]
                },
                "root": { "path": "rootfs" }
            }"#,
        )
        .expect_err("soft rlimit greater than hard should be rejected");
        assert!(matches!(
            rlimit_error,
            OciConfigError::RlimitSoftExceedsHard { rlimit_type } if rlimit_type == "RLIMIT_NOFILE"
        ));

        let path_error = parse_config(
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": "rootfs" },
                "linux": { "maskedPaths": ["proc/kcore"] }
            }"#,
        )
        .expect_err("relative masked path should be rejected");
        assert!(matches!(
            path_error,
            OciConfigError::LinuxPathNotAbsolute { path } if path == "proc/kcore"
        ));
    }

    #[test]
    fn rejects_unknown_crun_profile() {
        let error = parse_config(
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": "rootfs" },
                "crun": { "profile": "fast-but-unsafe" }
            }"#,
        )
        .expect_err("unknown profile should be rejected");

        assert!(matches!(
            error,
            OciConfigError::UnsupportedCrunProfile { profile } if profile == "fast-but-unsafe"
        ));
    }

    #[test]
    fn rejects_empty_healthcheck_test() {
        let error = parse_config(
            r#"{
                "process": { "args": ["/bin/sh"] },
                "root": { "path": "rootfs" },
                "healthcheck": { "test": [] }
            }"#,
        )
        .expect_err("empty healthcheck test should be rejected");

        assert!(matches!(error, OciConfigError::EmptyHealthcheckTest));
    }

    fn test_dir(name: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should be monotonic")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("crun-config-test-{name}-{suffix}"));
        fs::create_dir_all(&path).expect("create test dir");
        path
    }
}
