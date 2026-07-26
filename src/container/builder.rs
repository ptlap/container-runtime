use crate::cgroup::CgroupConfig;
use crate::error::ContainerError;
use crate::filesystem::OverlayConfig;
use crate::network::NetworkMode;
use crate::seccomp::{Program, SeccompMode};
use crate::security::SecurityProfile;
use crate::spec::config::{LinuxRlimit, Mount, ProcessUser};
use crate::userns::UserNamespaceMode;
use nix::sched::CloneFlags;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ProcessExit {
    pub pid: i32,
    pub code: Option<i32>,
    pub signal: Option<String>,
    pub error: Option<String>,
    /// Syscalls observed while learning. Only set in learn mode.
    pub capture: Option<crate::seccomp::capture::Capture>,
}

pub struct ProcessConfig<'a> {
    pub id: &'a str,
    pub hostname: Option<&'a str>,
    pub args: &'a [String],
    pub env: &'a [String],
    pub cwd: Option<&'a str>,
    pub rootfs: &'a Path,
    pub overlay_config: Option<OverlayConfig>,
    pub readonly_rootfs: bool,
    pub mounts: &'a [Mount],
    pub process_user: Option<&'a ProcessUser>,
    pub rlimits: &'a [LinuxRlimit],
    pub masked_paths: &'a [String],
    pub readonly_paths: &'a [String],
    pub log_path: Option<&'a Path>,
    pub flags: CloneFlags,
    pub cgroup_config: Option<CgroupConfig>,
    pub network_mode: NetworkMode,
    pub security_profile: SecurityProfile,
    pub userns_mode: UserNamespaceMode,
    pub tty: bool,
    pub seccomp_mode: SeccompMode,
    /// Compiled in the parent before fork: the child cannot read the profile
    /// once it is inside the new rootfs.
    pub seccomp_program: Option<&'a Program>,
    pub seccomp_flags: u64,
}

impl<'a> ProcessConfig<'a> {
    pub fn builder() -> ProcessConfigBuilder<'a> {
        ProcessConfigBuilder::default()
    }
}

pub struct ProcessConfigBuilder<'a> {
    id: Option<&'a str>,
    hostname: Option<&'a str>,
    args: Option<&'a [String]>,
    env: Option<&'a [String]>,
    cwd: Option<&'a str>,
    rootfs: Option<&'a Path>,
    overlay_config: Option<OverlayConfig>,
    readonly_rootfs: bool,
    mounts: Option<&'a [Mount]>,
    process_user: Option<&'a ProcessUser>,
    rlimits: Option<&'a [LinuxRlimit]>,
    masked_paths: Option<&'a [String]>,
    readonly_paths: Option<&'a [String]>,
    log_path: Option<&'a Path>,
    flags: CloneFlags,
    cgroup_config: Option<CgroupConfig>,
    network_mode: Option<NetworkMode>,
    security_profile: Option<SecurityProfile>,
    userns_mode: Option<UserNamespaceMode>,
    tty: bool,
    seccomp_mode: SeccompMode,
    seccomp_program: Option<&'a Program>,
    seccomp_flags: u64,
}

impl Default for ProcessConfigBuilder<'_> {
    fn default() -> Self {
        Self {
            id: None,
            hostname: None,
            args: None,
            env: None,
            cwd: None,
            rootfs: None,
            overlay_config: None,
            readonly_rootfs: false,
            mounts: None,
            process_user: None,
            rlimits: None,
            masked_paths: None,
            readonly_paths: None,
            log_path: None,
            flags: CloneFlags::empty(),
            cgroup_config: None,
            network_mode: None,
            security_profile: None,
            userns_mode: None,
            tty: false,
            seccomp_mode: SeccompMode::Off,
            seccomp_program: None,
            seccomp_flags: 0,
        }
    }
}

impl<'a> ProcessConfigBuilder<'a> {
    pub fn id(mut self, id: &'a str) -> Self {
        self.id = Some(id);
        self
    }

    pub fn hostname(mut self, hostname: Option<&'a str>) -> Self {
        self.hostname = hostname;
        self
    }

    pub fn args(mut self, args: &'a [String]) -> Self {
        self.args = Some(args);
        self
    }

    pub fn env(mut self, env: &'a [String]) -> Self {
        self.env = Some(env);
        self
    }

    pub fn cwd(mut self, cwd: Option<&'a str>) -> Self {
        self.cwd = cwd;
        self
    }

    pub fn rootfs(mut self, rootfs: &'a Path) -> Self {
        self.rootfs = Some(rootfs);
        self
    }

    pub fn overlay_config(mut self, overlay_config: Option<OverlayConfig>) -> Self {
        self.overlay_config = overlay_config;
        self
    }

    pub fn readonly_rootfs(mut self, readonly_rootfs: bool) -> Self {
        self.readonly_rootfs = readonly_rootfs;
        self
    }

    pub fn mounts(mut self, mounts: &'a [Mount]) -> Self {
        self.mounts = Some(mounts);
        self
    }

    pub fn process_user(mut self, process_user: Option<&'a ProcessUser>) -> Self {
        self.process_user = process_user;
        self
    }

    pub fn rlimits(mut self, rlimits: &'a [LinuxRlimit]) -> Self {
        self.rlimits = Some(rlimits);
        self
    }

    pub fn masked_paths(mut self, masked_paths: &'a [String]) -> Self {
        self.masked_paths = Some(masked_paths);
        self
    }

    pub fn readonly_paths(mut self, readonly_paths: &'a [String]) -> Self {
        self.readonly_paths = Some(readonly_paths);
        self
    }

    pub fn log_path(mut self, log_path: Option<&'a Path>) -> Self {
        self.log_path = log_path;
        self
    }

    pub fn flags(mut self, flags: CloneFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn cgroup_config(mut self, cgroup_config: Option<CgroupConfig>) -> Self {
        self.cgroup_config = cgroup_config;
        self
    }

    pub fn network_mode(mut self, network_mode: NetworkMode) -> Self {
        self.network_mode = Some(network_mode);
        self
    }

    pub fn security_profile(mut self, security_profile: SecurityProfile) -> Self {
        self.security_profile = Some(security_profile);
        self
    }

    pub fn userns_mode(mut self, userns_mode: UserNamespaceMode) -> Self {
        self.userns_mode = Some(userns_mode);
        self
    }

    pub fn tty(mut self, tty: bool) -> Self {
        self.tty = tty;
        self
    }

    pub fn seccomp_mode(mut self, seccomp_mode: SeccompMode) -> Self {
        self.seccomp_mode = seccomp_mode;
        self
    }

    pub fn seccomp_program(mut self, seccomp_program: Option<&'a Program>) -> Self {
        self.seccomp_program = seccomp_program;
        self
    }

    pub fn seccomp_flags(mut self, seccomp_flags: u64) -> Self {
        self.seccomp_flags = seccomp_flags;
        self
    }

    pub fn build(self) -> std::result::Result<ProcessConfig<'a>, ContainerError> {
        let args = self
            .args
            .ok_or(ContainerError::MissingProcessConfigField { field: "args" })?;
        if args.is_empty() {
            return Err(ContainerError::EmptyProcessArgs);
        }

        Ok(ProcessConfig {
            id: self
                .id
                .ok_or(ContainerError::MissingProcessConfigField { field: "id" })?,
            hostname: self.hostname,
            args,
            env: self.env.unwrap_or(&[]),
            cwd: self.cwd,
            rootfs: self
                .rootfs
                .ok_or(ContainerError::MissingProcessConfigField { field: "rootfs" })?,
            overlay_config: self.overlay_config,
            readonly_rootfs: self.readonly_rootfs,
            mounts: self.mounts.unwrap_or(&[]),
            process_user: self.process_user,
            rlimits: self.rlimits.unwrap_or(&[]),
            masked_paths: self.masked_paths.unwrap_or(&[]),
            readonly_paths: self.readonly_paths.unwrap_or(&[]),
            log_path: self.log_path,
            flags: self.flags,
            cgroup_config: self.cgroup_config,
            network_mode: self.network_mode.unwrap_or(NetworkMode::None),
            security_profile: self.security_profile.unwrap_or(SecurityProfile::Default),
            userns_mode: self.userns_mode.unwrap_or(UserNamespaceMode::Host),
            tty: self.tty,
            seccomp_mode: self.seccomp_mode,
            seccomp_program: self.seccomp_program,
            seccomp_flags: self.seccomp_flags,
        })
    }
}

#[derive(Debug, Clone)]
pub struct StartedProcess {
    pub pid: i32,
    pub cgroup_path: Option<PathBuf>,
    pub network_subnet: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_config_builder_rejects_empty_process_args() {
        let args = Vec::new();
        let result = ProcessConfig::builder()
            .id("demo")
            .args(&args)
            .rootfs(Path::new("/tmp/rootfs"))
            .build();

        assert!(matches!(result, Err(ContainerError::EmptyProcessArgs)));
    }

    #[test]
    fn process_config_builder_reports_missing_required_field() {
        let args = vec!["/bin/sh".to_string()];
        let result = ProcessConfig::builder().id("demo").args(&args).build();

        assert!(matches!(
            result,
            Err(ContainerError::MissingProcessConfigField { field: "rootfs" })
        ));
    }

    #[test]
    fn process_config_builder_defaults_optional_runtime_settings() {
        let args = vec!["/bin/sh".to_string()];
        let config = ProcessConfig::builder()
            .id("demo")
            .args(&args)
            .rootfs(Path::new("/tmp/rootfs"))
            .build()
            .unwrap();

        assert_eq!(config.id, "demo");
        assert_eq!(config.env, &[] as &[String]);
        assert!(config.mounts.is_empty());
        assert_eq!(config.network_mode, NetworkMode::None);
        assert_eq!(config.security_profile, SecurityProfile::Default);
        assert_eq!(config.userns_mode, UserNamespaceMode::Host);
    }
}
