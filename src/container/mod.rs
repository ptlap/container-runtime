use crate::cgroup::{Cgroup, CgroupConfig};
use crate::filesystem::setup_rootfs;
use crate::network::{
    cleanup_nat, cleanup_veth_host, setup_loopback, setup_nat, setup_veth_child, setup_veth_parent,
    NetworkMode, VethPair,
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

    let parent_flags = config.flags & CloneFlags::CLONE_NEWPID;

    let mut child_flags = config.flags;
    child_flags.remove(CloneFlags::CLONE_NEWPID);

    if !parent_flags.is_empty() {
        unshare(parent_flags).context("failed to unshare parent namespaces")?;
    }

    let process_exit = match unsafe { fork() }.context("failed to fork process")? {
        ForkResult::Child => {
            close(write_fd).ok();

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
                std::process::exit(1);
            }

            unreachable!();
        }

        ForkResult::Parent { child } => {
            close(read_fd).ok();
            let child_pid = child.as_raw();

            let cgroup = if let Some(cgroup_config) = config.cgroup_config {
                let cgroup = Cgroup::new(&format!("crun-{child_pid}"), &cgroup_config)?;
                cgroup.add_process(child)?;
                Some(cgroup)
            } else {
                None
            };

            let veth = if config.network_mode == NetworkMode::Bridge {
                let veth = VethPair::for_pid(child_pid);
                setup_veth_parent(child, &veth)?;
                setup_nat()?;
                Some(veth)
            } else {
                None
            };

            on_started(StartedProcess {
                pid: child_pid,
                cgroup_path: cgroup.as_ref().map(|cgroup| cgroup.path().to_path_buf()),
            })?;

            let peer_name = veth
                .as_ref()
                .map(|veth| veth.peer_name.as_str())
                .unwrap_or("");
            write(&write_fd, peer_name.as_bytes()).context("failed to signal child")?;
            close(write_fd).ok();

            let status = waitpid(child, None).context("failed to wait for child process")?;

            if config.network_mode == NetworkMode::Bridge {
                cleanup_nat()?;
                if let Some(veth) = &veth {
                    cleanup_veth_host(&veth.host_name).ok();
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
                },
                WaitStatus::Signaled(_, signal, _) => ProcessExit {
                    pid: child_pid,
                    code: None,
                    signal: Some(format!("{signal:?}")),
                },
                other => ProcessExit {
                    pid: child_pid,
                    code: None,
                    signal: Some(format!("{other:?}")),
                },
            }
        }
    };

    Ok(process_exit)
}

fn run_child(config: ChildConfig<'_>, read_fd: OwnedFd) -> Result<()> {
    if !config.child_flags.is_empty() {
        unshare(config.child_flags).context("failed to unshare child namespaces")?;
    }
    let peer_name = read_parent_signal(read_fd).context("failed to wait for parent signal")?;

    if config.child_flags.contains(CloneFlags::CLONE_NEWNET) {
        setup_loopback()?;
        if config.network_mode == NetworkMode::Bridge {
            setup_veth_child(&peer_name)?;
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

    String::from_utf8(bytes).context("parent signal was not valid UTF-8")
}
