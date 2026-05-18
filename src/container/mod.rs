use crate::cgroup::{Cgroup, CgroupConfig};
use crate::filesystem::setup_rootfs;
use crate::network::{
    allocate_bridge_network, cleanup_nat, cleanup_veth_host, release_bridge_network,
    setup_loopback, setup_nat, setup_veth_child, setup_veth_parent, BridgeNetwork, NetworkMode,
};
use crate::security::{self, SecurityProfile};
use crate::spec::config::Mount;
use anyhow::{bail, Context, Result};
use nix::libc;
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, close, execvp, fork, pipe, read, write, ForkResult};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ProcessExit {
    pub pid: i32,
    pub code: Option<i32>,
    pub signal: Option<String>,
    pub error: Option<String>,
}

pub struct ProcessConfig<'a> {
    pub id: &'a str,
    pub hostname: Option<&'a str>,
    pub args: &'a [String],
    pub env: &'a [String],
    pub cwd: Option<&'a str>,
    pub rootfs: &'a Path,
    pub readonly_rootfs: bool,
    pub mounts: &'a [Mount],
    pub log_path: Option<&'a Path>,
    pub flags: CloneFlags,
    pub cgroup_config: Option<CgroupConfig>,
    pub network_mode: NetworkMode,
    pub security_profile: SecurityProfile,
}

#[derive(Debug, Clone)]
pub struct StartedProcess {
    pub pid: i32,
    pub cgroup_path: Option<PathBuf>,
    pub network_subnet: Option<String>,
}

struct ChildConfig<'a> {
    args: &'a [String],
    env: &'a [String],
    cwd: Option<&'a str>,
    hostname: Option<&'a str>,
    rootfs: &'a Path,
    readonly_rootfs: bool,
    mounts: &'a [Mount],
    network_mode: NetworkMode,
    security_profile: SecurityProfile,
    child_flags: CloneFlags,
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
                eprintln!(
                    "warn: failed to cleanup veth {}: {error}",
                    network.veth.host_name
                );
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
            eprintln!("warn: parent resource cleanup failed: {error}");
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
        bail!("process args is empty");
    }

    let (read_fd, write_fd) = pipe().context("failed to create sync pipe")?;
    let (error_read_fd, error_write_fd) = pipe().context("failed to create child error pipe")?;
    let log_pipe = create_log_pipe(config.log_path)?;
    let (mut log_write_fd, log_helper) = start_log_helper(
        log_pipe,
        config.log_path,
        &[&read_fd, &write_fd, &error_read_fd, &error_write_fd],
    )?;

    let parent_flags = config.flags & CloneFlags::CLONE_NEWPID;

    let mut child_flags = config.flags;
    child_flags.remove(CloneFlags::CLONE_NEWPID);

    if !parent_flags.is_empty() {
        unshare(parent_flags).context("failed to unshare parent namespaces")?;
    }

    let process_exit = match unsafe { fork() }.context("failed to fork process")? {
        ForkResult::Child => {
            close(write_fd).ok();
            close(error_read_fd).ok();
            if let Some(log_write_fd) = log_write_fd.take() {
                redirect_stdio_to_log(&log_write_fd)?;
                close(log_write_fd).ok();
            }

            let child_config = ChildConfig {
                args: config.args,
                env: config.env,
                cwd: config.cwd,
                hostname: config.hostname,
                rootfs: config.rootfs,
                readonly_rootfs: config.readonly_rootfs,
                mounts: config.mounts,
                network_mode: config.network_mode,
                security_profile: config.security_profile,
                child_flags,
            };

            if let Err(error) = run_child(child_config, read_fd) {
                eprintln!("container error: {error}");
                write_child_error(&error_write_fd, &error).ok();
                close(error_write_fd).ok();
                std::process::exit(1);
            }

            unreachable!();
        }

        ForkResult::Parent { child } => {
            close(read_fd).ok();
            close(error_write_fd).ok();
            if let Some(log_write_fd) = log_write_fd.take() {
                close(log_write_fd).ok();
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

            if config.network_mode == NetworkMode::Bridge {
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

            let status = waitpid(child, None).context("failed to wait for child process")?;
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

    Ok(Some(pipe().context("failed to create log pipe")?))
}

fn redirect_stdio_to_log(log_write_fd: &OwnedFd) -> Result<()> {
    let fd = log_write_fd.as_raw_fd();
    duplicate_fd(fd, libc::STDOUT_FILENO).context("failed to redirect stdout to log pipe")?;
    duplicate_fd(fd, libc::STDERR_FILENO).context("failed to redirect stderr to log pipe")?;
    Ok(())
}

fn duplicate_fd(from: i32, to: i32) -> Result<()> {
    let result = unsafe { libc::dup2(from, to) };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("dup2 failed");
    }

    Ok(())
}

fn start_log_helper(
    log_pipe: Option<(OwnedFd, OwnedFd)>,
    log_path: Option<&Path>,
    inherited_control_fds: &[&OwnedFd],
) -> Result<(Option<OwnedFd>, Option<nix::unistd::Pid>)> {
    let Some((read_fd, write_fd)) = log_pipe else {
        return Ok((None, None));
    };
    let path = log_path
        .context("log path is required when log pipe exists")?
        .to_path_buf();

    match unsafe { fork() }.context("failed to fork log helper")? {
        ForkResult::Child => {
            for fd in inherited_control_fds {
                close_raw_fd(fd);
            }
            close(write_fd).ok();
            if let Err(error) = pump_logs(read_fd, path) {
                eprintln!("log helper error: {error}");
                std::process::exit(1);
            }
            std::process::exit(0);
        }
        ForkResult::Parent { child } => {
            close(read_fd).ok();
            Ok((Some(write_fd), Some(child)))
        }
    }
}

fn close_raw_fd(fd: &OwnedFd) {
    unsafe {
        libc::close(fd.as_raw_fd());
    }
}

fn pump_logs(read_fd: OwnedFd, log_path: PathBuf) -> Result<()> {
    let mut log_file = File::create(&log_path)
        .with_context(|| format!("failed to create container log: {}", log_path.display()))?;
    let mut stdout = io::stdout().lock();
    let mut buf = [0u8; 8192];

    loop {
        let count = read(&read_fd, &mut buf).context("failed to read container log pipe")?;
        if count == 0 {
            break;
        }
        stdout
            .write_all(&buf[..count])
            .context("failed to write container output to stdout")?;
        stdout.flush().context("failed to flush stdout")?;
        log_file
            .write_all(&buf[..count])
            .context("failed to write container log")?;
        log_file.flush().context("failed to flush container log")?;
    }

    close(read_fd).ok();
    Ok(())
}

fn wait_for_log_helper(log_helper: Option<nix::unistd::Pid>) -> Result<()> {
    let Some(log_helper) = log_helper else {
        return Ok(());
    };

    match waitpid(log_helper, None).context("failed to wait for log helper")? {
        WaitStatus::Exited(_, 0) => Ok(()),
        WaitStatus::Exited(_, code) => bail!("log helper exited with code: {code}"),
        WaitStatus::Signaled(_, signal, _) => bail!("log helper killed by signal: {signal:?}"),
        other => bail!("log helper ended with status: {other:?}"),
    }
}

fn write_child_error(error_write_fd: &OwnedFd, error: &anyhow::Error) -> Result<()> {
    let message = error.to_string();
    write_all(error_write_fd, message.as_bytes()).context("failed to write child error")
}

fn write_all(fd: &OwnedFd, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        let count = write(fd, bytes).context("failed to write fd")?;
        if count == 0 {
            bail!("failed to write fd: wrote zero bytes");
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

fn run_child(config: ChildConfig<'_>, read_fd: OwnedFd) -> Result<()> {
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

    setup_rootfs(config.rootfs, config.readonly_rootfs, config.mounts)?;

    if let Some(hostname) = config.hostname {
        set_container_hostname(hostname)?;
    }

    if let Some(cwd) = config.cwd {
        chdir(cwd).with_context(|| format!("failed to chdir to process cwd: {cwd}"))?;
    }

    security::apply(config.security_profile)?;

    for item in config.env {
        if let Some((key, value)) = item.split_once('=') {
            std::env::set_var(key, value);
        }
    }

    execvp(&command, &c_args).context("failed to exec process")?;

    unreachable!();
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
