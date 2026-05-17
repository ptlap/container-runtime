use crate::cgroup::{Cgroup, CgroupConfig};
use crate::filesystem::setup_rootfs;
use crate::network::{
    cleanup_nat, cleanup_veth_host, setup_loopback, setup_nat, setup_veth_child, setup_veth_parent,
    BridgeNetwork, NetworkMode,
};
use crate::security::{self, SecurityProfile};
use anyhow::{bail, Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, close, execvp, fork, pipe, read, write, ForkResult};
use std::ffi::CString;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ProcessExit {
    pub pid: i32,
    pub code: Option<i32>,
    pub signal: Option<String>,
    pub error: Option<String>,
}

pub struct ProcessConfig<'a> {
    pub args: &'a [String],
    pub env: &'a [String],
    pub cwd: Option<&'a str>,
    pub rootfs: &'a Path,
    pub readonly_rootfs: bool,
    pub flags: CloneFlags,
    pub cgroup_config: Option<CgroupConfig>,
    pub network_mode: NetworkMode,
    pub security_profile: SecurityProfile,
}

#[derive(Debug, Clone)]
pub struct StartedProcess {
    pub pid: i32,
    pub cgroup_path: Option<PathBuf>,
}

struct ChildConfig<'a> {
    args: &'a [String],
    env: &'a [String],
    cwd: Option<&'a str>,
    rootfs: &'a Path,
    readonly_rootfs: bool,
    network_mode: NetworkMode,
    security_profile: SecurityProfile,
    child_flags: CloneFlags,
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

            let child_config = ChildConfig {
                args: config.args,
                env: config.env,
                cwd: config.cwd,
                rootfs: config.rootfs,
                readonly_rootfs: config.readonly_rootfs,
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
            let child_pid = child.as_raw();

            let cgroup = if let Some(cgroup_config) = config.cgroup_config {
                let cgroup = Cgroup::new(&format!("crun-{child_pid}"), &cgroup_config)?;
                cgroup.add_process(child)?;
                Some(cgroup)
            } else {
                None
            };

            let bridge_network = if config.network_mode == NetworkMode::Bridge {
                let network = BridgeNetwork::for_pid(child_pid);
                setup_veth_parent(child, &network)?;
                setup_nat(&network.subnet)?;
                Some(network)
            } else {
                None
            };

            on_started(StartedProcess {
                pid: child_pid,
                cgroup_path: cgroup.as_ref().map(|cgroup| cgroup.path().to_path_buf()),
            })?;

            let signal = bridge_network
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .context("failed to serialize bridge network config")?
                .unwrap_or_default();
            write(&write_fd, signal.as_bytes()).context("failed to signal child")?;
            close(write_fd).ok();

            let status = waitpid(child, None).context("failed to wait for child process")?;
            let child_error = read_child_error(error_read_fd)?;

            if config.network_mode == NetworkMode::Bridge {
                if let Some(network) = &bridge_network {
                    cleanup_nat(&network.subnet)?;
                    cleanup_veth_host(&network.veth.host_name).ok();
                }
            }

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

            if let Some(cgroup) = cgroup {
                cgroup.delete()?;
            }

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

    setup_rootfs(config.rootfs, config.readonly_rootfs)?;

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
