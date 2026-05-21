use anyhow::Result;
use std::path::Path;

use crate::audit_log;
use crate::error::LifecycleError;
use crate::filesystem::resolve_rootfs;
use crate::modes::LogMode;
use crate::network::NetworkMode;
use crate::policy;
use crate::security::SecurityProfile;
use crate::spec::config::load_config;
use crate::state::{self, ContainerState, ContainerStatus, RuntimeMetadata};
use crate::userns::UserNamespaceMode;

#[derive(Debug, Clone, Copy)]
pub struct CreateOptions<'a> {
    pub id: &'a str,
    pub bundle: &'a Path,
    pub network_mode: NetworkMode,
    pub security_profile: SecurityProfile,
    pub log_mode: LogMode,
    pub userns_mode: UserNamespaceMode,
    pub tty: bool,
}

pub fn record_run_created(id: &str) -> Result<()> {
    ensure_container_absent(id)?;
    record_created_event(id)
}

pub fn create(options: CreateOptions<'_>) -> Result<ContainerState> {
    ensure_container_absent(options.id)?;

    let config = load_config(options.bundle.join("config.json"))?;
    let effective_policy = policy::resolve_effective_policy(
        config.crun.as_ref(),
        config
            .linux
            .as_ref()
            .and_then(|linux| linux.resources.as_ref()),
        options.security_profile,
        options.log_mode,
    )?;
    let rootfs_mode = resolve_rootfs(options.bundle, &config.root.path, config.crun.as_ref()).mode;

    let state = ContainerState::created(
        options.id,
        options.bundle,
        RuntimeMetadata {
            network_mode: options.network_mode.as_str(),
            security_profile: effective_policy.security_profile.as_str(),
            log_mode: effective_policy.log_mode.as_str(),
            userns_mode: options.userns_mode.as_str(),
            rootfs_mode: rootfs_mode.as_str(),
            policy_profile: effective_policy.profile.as_str(),
            tty: options.tty,
        },
    )?;
    state::save(&state)?;
    record_created_event(options.id)?;

    Ok(state)
}

pub fn load_created(id: &str) -> Result<ContainerState> {
    let state = state::load_current(id)?;
    if state.status != ContainerStatus::Created {
        return Err(LifecycleError::ContainerNotCreated { id: id.to_string() }.into());
    }

    Ok(state)
}

fn ensure_container_absent(id: &str) -> Result<()> {
    if state::exists(id)? {
        return Err(LifecycleError::ContainerAlreadyExists { id: id.to_string() }.into());
    }

    Ok(())
}

fn record_created_event(id: &str) -> Result<()> {
    audit_log::reset(id)?;
    audit_log::append_simple(id, "lifecycle", "created", Some("created"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_non_created_state_with_typed_error() {
        let error = LifecycleError::ContainerNotCreated {
            id: "demo".to_string(),
        };

        assert_eq!(error.to_string(), "container demo is not created");
    }
}
