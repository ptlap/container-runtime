use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct OciConfig {
    pub process: Process,
    pub root: Root,

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

impl OciConfig {
    pub fn validate(&self) -> Result<()> {
        if self.process.args.is_empty() {
            bail!("process.args must not be empty");
        }

        if self.root.path.trim().is_empty() {
            bail!("root.path must not be empty");
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
                "root": {
                    "path": "rootfs",
                    "readonly": true
                }
            }"#,
        )
        .expect("valid config");

        assert_eq!(config.process.args, ["/bin/sh"]);
        assert_eq!(config.process.env, ["PATH=/bin"]);
        assert_eq!(config.process.cwd.as_deref(), Some("/tmp"));
        assert_eq!(config.root.path, "rootfs");
        assert!(config.root.readonly);
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
}
