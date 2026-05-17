use crate::cgroup::{Cgroup, CgroupConfig};
use crate::filesystem::setup_rootfs;
use crate::network::{cleanup_nat, setup_loopback, setup_nat, setup_veth_child, setup_veth_parent};
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
}

#[derive(Debug, Clone)]
pub struct StartedProcess {
    pub pid: i32,
    pub cgroup_path: Option<PathBuf>,
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

            if let Err(error) = run_child(
                config.args,
                config.env,
                config.cwd,
                config.rootfs,
                config.readonly_rootfs,
                read_fd,
                child_flags,
            ) {
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

            if child_flags.contains(CloneFlags::CLONE_NEWNET) {
                setup_veth_parent(child)?;
                setup_nat()?;
            }

            on_started(StartedProcess {
                pid: child_pid,
                cgroup_path: cgroup.as_ref().map(|cgroup| cgroup.path().to_path_buf()),
            })?;

            write(&write_fd, &[1u8]).context("failed to signal child")?;
            close(write_fd).ok();

            let status = waitpid(child, None).context("failed to wait for child process")?;

            if child_flags.contains(CloneFlags::CLONE_NEWNET) {
                cleanup_nat()?;
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

fn run_child(
    args: &[String],
    env: &[String],
    cwd: Option<&str>,
    rootfs: &Path,
    readonly_rootfs: bool,
    read_fd: OwnedFd,
    child_flags: CloneFlags,
) -> Result<()> {
    if !child_flags.is_empty() {
        unshare(child_flags).context("failed to unshare child namespaces")?;
    }
    let mut buf = [0u8; 1];
    read(&read_fd, &mut buf).context("failed to wait for parent signal")?;
    close(read_fd).ok();

    if child_flags.contains(CloneFlags::CLONE_NEWNET) {
        setup_loopback()?;
        setup_veth_child()?;
    }

    let command = CString::new(args[0].as_str()).context("invalid command")?;

    let c_args: Vec<CString> = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).context("invalid process argument"))
        .collect::<Result<_>>()?;

    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .context("failed to make mounts private")?;

    setup_rootfs(rootfs, readonly_rootfs)?;

    if let Some(cwd) = cwd {
        chdir(cwd).with_context(|| format!("failed to chdir to process cwd: {cwd}"))?;
    }

    for item in env {
        if let Some((key, value)) = item.split_once('=') {
            std::env::set_var(key, value);
        }
    }

    execvp(&command, &c_args).context("failed to exec process")?;

    unreachable!();
}
