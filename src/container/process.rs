use super::builder::{ProcessConfig, ProcessExit, StartedProcess};
use super::log_helper::{redirect_stdio_to_log, start_log_helper, wait_for_log_helper};
use super::pty;
use crate::cgroup::Cgroup;
use crate::error::ContainerError;
use crate::filesystem::{apply_oci_linux_paths, setup_overlay_rootfs, setup_rootfs, OverlayConfig};
use crate::network::{
    allocate_bridge_network, cleanup_nat, cleanup_veth_host, release_bridge_network,
    setup_loopback, setup_nat, setup_veth_child, setup_veth_parent, BridgeNetwork, NetworkMode,
};
use crate::security::{self, SecurityProfile};
use crate::spec::config::{rlimit_resource, LinuxRlimit, Mount, ProcessUser};
use crate::userns::{write_uid_gid_maps, UserNamespaceMode};
use anyhow::{Context, Result};
use nix::fcntl::OFlag;
use nix::libc;
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, close, execvp, fork, pipe2, read, setsid, write, ForkResult};
use std::ffi::CString;
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use tracing::{error, warn};

struct ChildConfig<'a> {
    args: &'a [String],
    env: &'a [String],
    cwd: Option<&'a str>,
    hostname: Option<&'a str>,
    rootfs: &'a Path,
    overlay_config: Option<OverlayConfig>,
    readonly_rootfs: bool,
    mounts: &'a [Mount],
    process_user: Option<&'a ProcessUser>,
    rlimits: &'a [LinuxRlimit],
    masked_paths: &'a [String],
    readonly_paths: &'a [String],
    network_mode: NetworkMode,
    security_profile: SecurityProfile,
    userns_mode: UserNamespaceMode,
    child_flags: CloneFlags,
    is_rootless: bool,
}

impl<'a> ChildConfig<'a> {
    fn builder() -> ChildConfigBuilder<'a> {
        ChildConfigBuilder::default()
    }
}

struct ChildConfigBuilder<'a> {
    args: Option<&'a [String]>,
    env: Option<&'a [String]>,
    cwd: Option<&'a str>,
    hostname: Option<&'a str>,
    rootfs: Option<&'a Path>,
    overlay_config: Option<OverlayConfig>,
    readonly_rootfs: bool,
    mounts: Option<&'a [Mount]>,
    process_user: Option<&'a ProcessUser>,
    rlimits: Option<&'a [LinuxRlimit]>,
    masked_paths: Option<&'a [String]>,
    readonly_paths: Option<&'a [String]>,
    network_mode: Option<NetworkMode>,
    security_profile: Option<SecurityProfile>,
    userns_mode: Option<UserNamespaceMode>,
    child_flags: CloneFlags,
    is_rootless: bool,
}

impl Default for ChildConfigBuilder<'_> {
    fn default() -> Self {
        Self {
            args: None,
            env: None,
            cwd: None,
            hostname: None,
            rootfs: None,
            overlay_config: None,
            readonly_rootfs: false,
            mounts: None,
            process_user: None,
            rlimits: None,
            masked_paths: None,
            readonly_paths: None,
            network_mode: None,
            security_profile: None,
            userns_mode: None,
            child_flags: CloneFlags::empty(),
            is_rootless: false,
        }
    }
}

impl<'a> ChildConfigBuilder<'a> {
    fn args(mut self, args: &'a [String]) -> Self {
        self.args = Some(args);
        self
    }

    fn env(mut self, env: &'a [String]) -> Self {
        self.env = Some(env);
        self
    }

    fn cwd(mut self, cwd: Option<&'a str>) -> Self {
        self.cwd = cwd;
        self
    }

    fn hostname(mut self, hostname: Option<&'a str>) -> Self {
        self.hostname = hostname;
        self
    }

    fn rootfs(mut self, rootfs: &'a Path) -> Self {
        self.rootfs = Some(rootfs);
        self
    }

    fn overlay_config(mut self, overlay_config: Option<OverlayConfig>) -> Self {
        self.overlay_config = overlay_config;
        self
    }

    fn readonly_rootfs(mut self, readonly_rootfs: bool) -> Self {
        self.readonly_rootfs = readonly_rootfs;
        self
    }

    fn mounts(mut self, mounts: &'a [Mount]) -> Self {
        self.mounts = Some(mounts);
        self
    }

    fn process_user(mut self, process_user: Option<&'a ProcessUser>) -> Self {
        self.process_user = process_user;
        self
    }

    fn rlimits(mut self, rlimits: &'a [LinuxRlimit]) -> Self {
        self.rlimits = Some(rlimits);
        self
    }

    fn masked_paths(mut self, masked_paths: &'a [String]) -> Self {
        self.masked_paths = Some(masked_paths);
        self
    }

    fn readonly_paths(mut self, readonly_paths: &'a [String]) -> Self {
        self.readonly_paths = Some(readonly_paths);
        self
    }

    fn network_mode(mut self, network_mode: NetworkMode) -> Self {
        self.network_mode = Some(network_mode);
        self
    }

    fn security_profile(mut self, security_profile: SecurityProfile) -> Self {
        self.security_profile = Some(security_profile);
        self
    }

    fn userns_mode(mut self, userns_mode: UserNamespaceMode) -> Self {
        self.userns_mode = Some(userns_mode);
        self
    }

    fn child_flags(mut self, child_flags: CloneFlags) -> Self {
        self.child_flags = child_flags;
        self
    }

    fn rootless(mut self, is_rootless: bool) -> Self {
        self.is_rootless = is_rootless;
        self
    }

    fn build(self) -> std::result::Result<ChildConfig<'a>, ContainerError> {
        Ok(ChildConfig {
            args: self
                .args
                .ok_or(ContainerError::MissingProcessConfigField { field: "args" })?,
            env: self.env.unwrap_or(&[]),
            cwd: self.cwd,
            hostname: self.hostname,
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
            network_mode: self.network_mode.unwrap_or(NetworkMode::None),
            security_profile: self.security_profile.unwrap_or(SecurityProfile::Default),
            userns_mode: self.userns_mode.unwrap_or(UserNamespaceMode::Host),
            child_flags: self.child_flags,
            is_rootless: self.is_rootless,
        })
    }
}

struct ParentResources {
    container_id: String,
    cgroup: Option<Cgroup>,
    bridge_network: Option<BridgeNetwork>,
    release_bridge_allocation: bool,
}

impl ParentResources {
    fn new(container_id: &str) -> Self {
        Self {
            container_id: container_id.to_string(),
            cgroup: None,
            bridge_network: None,
            release_bridge_allocation: false,
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        if let Some(network) = self.bridge_network.take() {
            cleanup_nat(&network.subnet)
                .with_context(|| format!("failed to cleanup NAT for {}", network.subnet))?;
            if let Err(error) = cleanup_veth_host(&network.veth.host_name) {
                warn!("failed to cleanup veth {}: {error}", network.veth.host_name);
            }
        }

        if self.release_bridge_allocation {
            release_bridge_network(&self.container_id).with_context(|| {
                format!("failed to release bridge subnet for {}", self.container_id)
            })?;
            self.release_bridge_allocation = false;
        }

        if let Some(cgroup) = self.cgroup.take() {
            cgroup.delete()?;
        }

        Ok(())
    }

    fn cleanup_with_warnings(&mut self) {
        if let Err(error) = self.cleanup() {
            warn!("parent resource cleanup failed: {error}");
        }
    }
}

impl Drop for ParentResources {
    fn drop(&mut self) {
        self.cleanup_with_warnings();
    }
}

pub fn run_process(
    config: ProcessConfig<'_>,
    on_started: &mut dyn FnMut(StartedProcess) -> Result<()>,
) -> Result<ProcessExit> {
    if config.args.is_empty() {
        return Err(ContainerError::EmptyProcessArgs.into());
    }

    let network_mode = config.network_mode.to_effective();
    if network_mode != config.network_mode {
        warn!("bridge networking is not supported in rootless mode, falling back to none");
    }

    let (read_fd, write_fd) = cloexec_pipe().context("failed to create sync pipe")?;
    let (error_read_fd, error_write_fd) =
        cloexec_pipe().context("failed to create child error pipe")?;
    let (userns_ready_read_fd, userns_ready_write_fd) =
        cloexec_pipe().context("failed to create user namespace ready pipe")?;
    let (userns_mapped_read_fd, userns_mapped_write_fd) =
        cloexec_pipe().context("failed to create user namespace mapped pipe")?;
    let log_pipe = create_log_pipe(config.log_path)?;
    let (mut log_write_fd, log_helper) = start_log_helper(
        log_pipe,
        config.log_path,
        &[
            &read_fd,
            &write_fd,
            &error_read_fd,
            &error_write_fd,
            &userns_ready_read_fd,
            &userns_ready_write_fd,
            &userns_mapped_read_fd,
            &userns_mapped_write_fd,
        ],
    )?;

    let parent_flags = config.flags & CloneFlags::CLONE_NEWPID;

    let mut child_flags = config.flags;
    child_flags.remove(CloneFlags::CLONE_NEWPID);
    child_flags.remove(CloneFlags::CLONE_NEWUSER);

    if !parent_flags.is_empty() {
        unshare(parent_flags).context("failed to unshare parent namespaces")?;
    }

    let mut pty_manager = if config.tty {
        Some(pty::PtyManager::new().context("failed to allocate pty")?)
    } else {
        None
    };

    let mut _raw_guard = None;
    if let Some(pty) = pty_manager.as_ref() {
        _raw_guard = Some(pty::RawTerminalGuard::new().context("failed to set raw terminal mode")?);
        pty::register_sigwinch(pty.master.as_raw_fd());
    }

    let mut proxy_handles = None;
    if let Some(pty) = pty_manager.as_ref() {
        let master_clone = pty
            .master
            .try_clone()
            .context("failed to clone master fd")?;
        let mut inherited_fds = vec![
            &read_fd,
            &write_fd,
            &error_read_fd,
            &error_write_fd,
            &userns_ready_read_fd,
            &userns_ready_write_fd,
            &userns_mapped_read_fd,
            &userns_mapped_write_fd,
        ];
        if let Some(slave_fd) = pty.slave_ref() {
            inherited_fds.push(slave_fd);
        }
        proxy_handles = Some(
            pty::proxy_pty(master_clone, &inherited_fds).context("failed to start pty proxy")?,
        );
    }

    let process_exit = match unsafe { fork() }.context("failed to fork process")? {
        ForkResult::Child => {
            close(write_fd).ok();
            close(error_read_fd).ok();
            close(userns_ready_read_fd).ok();
            close(userns_mapped_write_fd).ok();

            if let Some(pty) = pty_manager.as_ref() {
                let slave_fd = pty.slave_fd().context(ContainerError::PtySlaveClosed)?;
                setsid().context("failed to setsid for container process")?;
                unsafe {
                    if libc::ioctl(slave_fd, libc::TIOCSCTTY, 0) == -1 {
                        return Err(ContainerError::FailedToSetControllingTerminal.into());
                    }
                    if libc::dup2(slave_fd, 0) == -1 {
                        return Err(ContainerError::FailedToDupSlaveToStdin.into());
                    }
                    if libc::dup2(slave_fd, 1) == -1 {
                        return Err(ContainerError::FailedToDupSlaveToStdout.into());
                    }
                    if libc::dup2(slave_fd, 2) == -1 {
                        return Err(ContainerError::FailedToDupSlaveToStderr.into());
                    }
                }
            } else if let Some(log_write_fd) = log_write_fd.take() {
                setsid().context("failed to setsid for container process")?;
                redirect_stdio_to_log(&log_write_fd)?;
                close(log_write_fd).ok();
            } else {
                setsid().context("failed to setsid for container process")?;
            }

            let is_root = nix::unistd::getuid().is_root();
            let child_config = ChildConfig::builder()
                .args(config.args)
                .env(config.env)
                .cwd(config.cwd)
                .hostname(config.hostname)
                .rootfs(config.rootfs)
                .overlay_config(config.overlay_config)
                .readonly_rootfs(config.readonly_rootfs)
                .mounts(config.mounts)
                .process_user(config.process_user)
                .rlimits(config.rlimits)
                .masked_paths(config.masked_paths)
                .readonly_paths(config.readonly_paths)
                .network_mode(network_mode)
                .security_profile(config.security_profile)
                .userns_mode(config.userns_mode)
                .child_flags(child_flags)
                .rootless(!is_root)
                .build()?;

            if let Err(error) = run_child(
                child_config,
                read_fd,
                userns_ready_write_fd,
                userns_mapped_read_fd,
            ) {
                error!("container error: {error}");
                write_child_error(&error_write_fd, &error).ok();
                close(error_write_fd).ok();
                std::process::exit(1);
            }

            unreachable!();
        }

        ForkResult::Parent { child } => {
            close(read_fd).ok();
            close(error_write_fd).ok();
            close(userns_ready_write_fd).ok();
            close(userns_mapped_read_fd).ok();
            if let Some(log_write_fd) = log_write_fd.take() {
                close(log_write_fd).ok();
            }
            if let Some(pty) = pty_manager.as_mut() {
                pty.close_slave();
            }
            let child_pid = child.as_raw();
            let mut resources = ParentResources::new(config.id);

            if let Some(cgroup_config) = config.cgroup_config {
                let cgroup = Cgroup::new(&format!("crun-{child_pid}"), &cgroup_config)?;
                resources.cgroup = Some(cgroup);
                resources
                    .cgroup
                    .as_ref()
                    .expect("cgroup was just created")
                    .add_process(child)?;
            }

            if network_mode == NetworkMode::Bridge {
                let network = allocate_bridge_network(config.id, child_pid)?;
                resources.bridge_network = Some(network);
                resources.release_bridge_allocation = true;
                let network = resources
                    .bridge_network
                    .as_ref()
                    .expect("bridge network was just created");
                setup_veth_parent(child, network)?;
                setup_nat(&network.subnet)?;
            }

            on_started(StartedProcess {
                pid: child_pid,
                cgroup_path: resources
                    .cgroup
                    .as_ref()
                    .map(|cgroup| cgroup.path().to_path_buf()),
                network_subnet: resources
                    .bridge_network
                    .as_ref()
                    .map(|network| network.subnet.clone()),
            })?;

            let signal = resources
                .bridge_network
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .context("failed to serialize bridge network config")?
                .unwrap_or_default();
            write(&write_fd, signal.as_bytes()).context("failed to signal child")?;
            close(write_fd).ok();

            if config.userns_mode.is_private() {
                wait_for_userns_ready(&userns_ready_read_fd)?;
            }
            close(userns_ready_read_fd).ok();

            if let UserNamespaceMode::Private(map) = config.userns_mode {
                write_uid_gid_maps(child, map)?;
                write(&userns_mapped_write_fd, b"1")
                    .context("failed to signal child that user namespace is mapped")?;
            }
            close(userns_mapped_write_fd).ok();

            let status = waitpid(child, None).context("failed to wait for child process")?;
            if config.tty {
                pty::unregister_sigwinch();
                if let Some(proxy) = proxy_handles.take() {
                    proxy.join();
                }
                drop(_raw_guard);
            }
            let child_error = read_child_error(error_read_fd)?;
            wait_for_log_helper(log_helper)?;

            match status {
                WaitStatus::Exited(_, code) => {
                    println!("container process exited with code: {code}");
                }
                WaitStatus::Signaled(_, signal, _) => {
                    println!("container process killed by signal: {signal:?}");
                }
                other => {
                    println!("container process ended with status: {other:?}");
                }
            }

            resources.cleanup()?;

            match status {
                WaitStatus::Exited(_, code) => ProcessExit {
                    pid: child_pid,
                    code: Some(code),
                    signal: None,
                    error: child_error,
                },
                WaitStatus::Signaled(_, signal, _) => ProcessExit {
                    pid: child_pid,
                    code: None,
                    signal: Some(format!("{signal:?}")),
                    error: child_error,
                },
                other => ProcessExit {
                    pid: child_pid,
                    code: None,
                    signal: Some(format!("{other:?}")),
                    error: child_error,
                },
            }
        }
    };

    Ok(process_exit)
}

fn create_log_pipe(log_path: Option<&Path>) -> Result<Option<(OwnedFd, OwnedFd)>> {
    let Some(path) = log_path else {
        return Ok(None);
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create log directory: {}", parent.display()))?;
    }

    Ok(Some(cloexec_pipe().context("failed to create log pipe")?))
}

fn cloexec_pipe() -> nix::Result<(OwnedFd, OwnedFd)> {
    pipe2(OFlag::O_CLOEXEC)
}

fn write_child_error(error_write_fd: &OwnedFd, error: &anyhow::Error) -> Result<()> {
    let message = error.to_string();
    write_all(error_write_fd, message.as_bytes()).context("failed to write child error")
}

fn write_all(fd: &OwnedFd, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let count = write(fd, bytes).context("failed to write fd")?;
        if count == 0 {
            return Err(ContainerError::WriteZeroBytes.into());
        }
        bytes = &bytes[count..];
    }

    Ok(())
}

fn read_child_error(error_read_fd: OwnedFd) -> Result<Option<String>> {
    let message = read_fd_to_string(error_read_fd).context("failed to read child error")?;
    let message = message.trim().to_string();

    if message.is_empty() {
        Ok(None)
    } else {
        Ok(Some(message))
    }
}

fn run_child(
    config: ChildConfig<'_>,
    read_fd: OwnedFd,
    userns_ready_write_fd: OwnedFd,
    userns_mapped_read_fd: OwnedFd,
) -> Result<()> {
    if config.is_rootless && config.userns_mode.is_private() {
        unshare(CloneFlags::CLONE_NEWUSER).context("failed to unshare user namespace")?;
        notify_userns_ready(&userns_ready_write_fd)?;
        wait_for_userns_mapped(&userns_mapped_read_fd)?;
    }

    if !config.child_flags.is_empty() {
        unshare(config.child_flags).context("failed to unshare child namespaces")?;
    }

    let signal = read_parent_signal(read_fd).context("failed to wait for parent signal")?;

    if config.child_flags.contains(CloneFlags::CLONE_NEWNET) {
        setup_loopback()?;
        if config.network_mode == NetworkMode::Bridge {
            let network: BridgeNetwork =
                serde_json::from_str(&signal).context("failed to parse bridge network config")?;
            setup_veth_child(&network)?;
        }
    }

    let command = CString::new(config.args[0].as_str()).context("invalid command")?;

    let c_args: Vec<CString> = config
        .args
        .iter()
        .map(|arg| CString::new(arg.as_str()).context("invalid process argument"))
        .collect::<Result<_>>()?;

    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .context("failed to make mounts private")?;

    let overlay_rootfs;
    let rootfs = if let Some(overlay_config) = config.overlay_config.as_ref() {
        overlay_rootfs = setup_overlay_rootfs(overlay_config)?;
        overlay_rootfs.as_path()
    } else {
        config.rootfs
    };

    setup_rootfs(rootfs, config.readonly_rootfs, config.mounts)?;
    apply_oci_linux_paths(config.masked_paths, config.readonly_paths)?;

    if let Some(hostname) = config.hostname {
        set_container_hostname(hostname)?;
    }

    if let Some(cwd) = config.cwd {
        chdir(cwd).with_context(|| format!("failed to chdir to process cwd: {cwd}"))?;
    }

    if !config.is_rootless && config.userns_mode.is_private() {
        unshare(CloneFlags::CLONE_NEWUSER).context("failed to unshare user namespace")?;
        notify_userns_ready(&userns_ready_write_fd)?;
        wait_for_userns_mapped(&userns_mapped_read_fd)?;
    }

    close(userns_ready_write_fd).ok();
    close(userns_mapped_read_fd).ok();

    apply_rlimits(config.rlimits)?;
    apply_process_user(config.process_user)?;

    security::apply(config.security_profile)?;

    for item in config.env {
        if let Some((key, value)) = item.split_once('=') {
            std::env::set_var(key, value);
        }
    }

    execvp(&command, &c_args).context("failed to exec process")?;

    unreachable!();
}

fn notify_userns_ready(write_fd: &OwnedFd) -> Result<()> {
    write_all(write_fd, b"1").context("failed to notify parent that user namespace is ready")
}

fn wait_for_userns_ready(read_fd: &OwnedFd) -> Result<()> {
    let mut buf = [0u8; 1];
    let count = read(read_fd, &mut buf).context("failed to wait for child user namespace")?;
    if count == 0 {
        return Err(ContainerError::ChildExitedBeforeUsernsReady.into());
    }

    Ok(())
}

fn wait_for_userns_mapped(read_fd: &OwnedFd) -> Result<()> {
    let mut buf = [0u8; 1];
    let count = read(read_fd, &mut buf).context("failed to wait for user namespace mapping")?;
    if count == 0 {
        return Err(ContainerError::ParentExitedBeforeUsernsMapped.into());
    }

    Ok(())
}

fn set_container_hostname(hostname: &str) -> Result<()> {
    let bytes = hostname.as_bytes();
    let result = unsafe { libc::sethostname(bytes.as_ptr().cast(), bytes.len()) };
    if result < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to set hostname: {hostname}"));
    }

    Ok(())
}

fn apply_rlimits(rlimits: &[LinuxRlimit]) -> Result<()> {
    for rlimit in rlimits {
        let resource = rlimit_resource(&rlimit.rlimit_type)
            .with_context(|| format!("unsupported rlimit type: {}", rlimit.rlimit_type))?;
        let limit = libc::rlimit {
            rlim_cur: rlimit.soft as libc::rlim_t,
            rlim_max: rlimit.hard as libc::rlim_t,
        };
        let result = unsafe { libc::setrlimit(resource, &limit) };
        if result < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("failed to set rlimit: {}", rlimit.rlimit_type));
        }
    }

    Ok(())
}

fn apply_process_user(user: Option<&ProcessUser>) -> Result<()> {
    let Some(user) = user else {
        return Ok(());
    };

    let groups = user
        .additional_gids
        .iter()
        .map(|gid| *gid as libc::gid_t)
        .collect::<Vec<_>>();
    let groups_ptr = if groups.is_empty() {
        std::ptr::null()
    } else {
        groups.as_ptr()
    };
    let setgroups_result = unsafe { libc::setgroups(groups.len(), groups_ptr) };
    if setgroups_result < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to set additional groups");
    }

    let setgid_result = unsafe { libc::setgid(user.gid as libc::gid_t) };
    if setgid_result < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to set gid: {}", user.gid));
    }

    let setuid_result = unsafe { libc::setuid(user.uid as libc::uid_t) };
    if setuid_result < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to set uid: {}", user.uid));
    }

    Ok(())
}

fn read_parent_signal(read_fd: OwnedFd) -> Result<String> {
    read_fd_to_string(read_fd).context("parent signal was not valid UTF-8")
}

fn read_fd_to_string(read_fd: OwnedFd) -> Result<String> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 64];

    loop {
        let count = read(&read_fd, &mut buf).context("failed to read parent signal")?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buf[..count]);
    }

    close(read_fd).ok();

    String::from_utf8(bytes).context("fd content was not valid UTF-8")
}
