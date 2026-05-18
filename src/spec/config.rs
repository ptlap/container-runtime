use anyhow::{bail, Context, Result};
use serde::Deserialize;
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
    pub linux: Option<Linux>,
}

#[derive(Debug, Deserialize)]
pub struct Process {
    pub args: Vec<String>,

    #[serde(default)]
    pub env: Vec<String>,

    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Root {
    pub path: String,

    #[serde(default)]
    pub readonly: bool,
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

#[derive(Debug, Deserialize)]
pub struct Linux {
    #[serde(default)]
    pub namespaces: Vec<LinuxNamespace>,

    #[serde(default)]
    pub resources: Option<LinuxResources>,
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
    pub fn validate(&self) -> Result<()> {
        if self.process.args.is_empty() {
            bail!("process.args must not be empty");
        }

        if self.root.path.trim().is_empty() {
            bail!("root.path must not be empty");
        }

        for mount in &self.mounts {
            if mount.destination.trim().is_empty() {
                bail!("mount.destination must not be empty");
            }
            if mount.mount_type != "bind" {
                bail!("unsupported mount type: {}", mount.mount_type);
            }
            if mount.source.as_deref().unwrap_or("").trim().is_empty() {
                bail!("bind mount source must not be empty");
            }
        }

        Ok(())
    }
}

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<OciConfig> {
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read config file: {}", path.as_ref().display()))?;

    let config: OciConfig =
        serde_json::from_str(&content).context("failed to parse OCI config.json")?;
    config.validate().context("invalid OCI config")?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config(input: &str) -> Result<OciConfig> {
        let config: OciConfig = serde_json::from_str(input)?;
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
                "mounts": [
                    {
                        "destination": "/data",
                        "source": "/tmp/data",
                        "type": "bind",
                        "options": ["rbind", "ro"]
                    }
                ]
            }"#,
        )
        .expect("valid config");

        assert_eq!(config.hostname.as_deref(), Some("demo"));
        assert_eq!(config.process.args, ["/bin/sh"]);
        assert_eq!(config.process.env, ["PATH=/bin"]);
        assert_eq!(config.process.cwd.as_deref(), Some("/tmp"));
        assert_eq!(config.root.path, "rootfs");
        assert!(config.root.readonly);
        assert_eq!(config.mounts.len(), 1);
        assert_eq!(config.mounts[0].destination, "/data");
        assert_eq!(config.mounts[0].source.as_deref(), Some("/tmp/data"));
        assert_eq!(config.mounts[0].mount_type, "bind");
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

        assert!(error.to_string().contains("process.args"));
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

        assert!(error.to_string().contains("root.path"));
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
                        "type": "tmpfs"
                    }
                ]
            }"#,
        )
        .expect_err("unsupported mount type should be rejected");

        assert!(error.to_string().contains("unsupported mount type"));
    }
}
