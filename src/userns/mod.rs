use anyhow::{Context, Result};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserNamespaceMap {
    pub host_uid: u32,
    pub host_gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserNamespaceMode {
    Host,
    Private(UserNamespaceMap),
}

impl UserNamespaceMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Private(_) => "private",
        }
    }

    pub fn is_private(self) -> bool {
        matches!(self, Self::Private(_))
    }
}

pub fn write_uid_gid_maps(child_pid: Pid, map: UserNamespaceMap) -> Result<()> {
    let proc_dir = PathBuf::from("/proc").join(child_pid.as_raw().to_string());

    fs::write(proc_dir.join("setgroups"), "deny\n")
        .with_context(|| format!("failed to write {}", proc_dir.join("setgroups").display()))?;
    fs::write(proc_dir.join("uid_map"), format!("0 {} 1\n", map.host_uid))
        .with_context(|| format!("failed to write {}", proc_dir.join("uid_map").display()))?;
    fs::write(proc_dir.join("gid_map"), format!("0 {} 1\n", map.host_gid))
        .with_context(|| format!("failed to write {}", proc_dir.join("gid_map").display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_user_namespace_modes_for_state() {
        assert_eq!(UserNamespaceMode::Host.as_str(), "host");
        assert_eq!(
            UserNamespaceMode::Private(UserNamespaceMap {
                host_uid: 1000,
                host_gid: 1000
            })
            .as_str(),
            "private"
        );
    }
}
