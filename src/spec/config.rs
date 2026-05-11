use anyhow::{Context, Result};
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

pub fn load_config<P: AsRef<Path>>(path: P) -> Result<OciConfig> {
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read config file: {}", path.as_ref().display()))?;

    let config: OciConfig =
        serde_json::from_str(&content).context("failed to parse OCI config.json")?;

    Ok(config)
}
