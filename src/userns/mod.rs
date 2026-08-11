use anyhow::{Context, Result};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::spec::config::ProcessUser;

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

pub fn validate_process_user(
    mode: UserNamespaceMode,
    process_user: Option<&ProcessUser>,
) -> Result<()> {
    let UserNamespaceMode::Private(_) = mode else {
        return Ok(());
    };

    let Some(user) = process_user else {
        return Ok(());
    };

    if user.uid != 0 || user.gid != 0 || !user.additional_gids.is_empty() {
        anyhow::bail!(
            "private user namespace only supports OCI uid=0, gid=0 and no additionalGids because the runtime maps container root only"
        );
    }

    Ok(())
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
    fn rejects_unmapped_private_process_credentials() {
        let user = ProcessUser {
            uid: 1000,
            gid: 0,
            additional_gids: vec![],
        };
        assert!(validate_process_user(
            UserNamespaceMode::Private(UserNamespaceMap {
                host_uid: 1000,
                host_gid: 1000
            }),
            Some(&user)
        )
        .is_err());
    }

    #[test]
    fn accepts_private_root_without_additional_groups() {
        let user = ProcessUser {
            uid: 0,
            gid: 0,
            additional_gids: vec![],
        };
        validate_process_user(
            UserNamespaceMode::Private(UserNamespaceMap {
                host_uid: 1000,
                host_gid: 1000,
            }),
            Some(&user),
        )
        .expect("root-only private user namespace should be supported");
    }

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
