use crate::cgroup::{Cgroup, CgroupConfig};
use crate::filesystem::setup_rootfs;
use crate::network::setup_loopback;
use anyhow::{bail, Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{close, execvp, fork, pipe, read, write, ForkResult};
use std::ffi::CString;
use std::os::fd::OwnedFd;
use std::path::Path;

pub fn run_process(
    args: &[String],
    env: &[String],
    rootfs: &Path,
    flags: CloneFlags,
    cgroup_config: Option<CgroupConfig>,
) -> Result<()> {
    if args.is_empty() {
        bail!("process args is empty");
    }

    let (read_fd, write_fd) = pipe().context("failed to create sync pipe")?;

    // Parent chỉ giữ PID namespace
    let parent_flags = flags & CloneFlags::CLONE_NEWPID;

    // Child nhận phần còn lại
    let mut child_flags = flags;
    child_flags.remove(CloneFlags::CLONE_NEWPID);

    if !parent_flags.is_empty() {
        unshare(parent_flags).context("failed to unshare parent namespaces")?;
    }

    match unsafe { fork() }.context("failed to fork process")? {
        ForkResult::Child => {
            close(write_fd).ok();

            if let Err(error) = run_child(args, env, rootfs, read_fd, child_flags) {
                eprintln!("container error: {error}");
                std::process::exit(1);
            }

            unreachable!();
        }

        ForkResult::Parent { child } => {
            close(read_fd).ok();

            let cgroup = if let Some(config) = cgroup_config {
                let cgroup = Cgroup::new(&format!("crun-{}", child.as_raw()), &config)?;

                cgroup.add_process(child)?;

                Some(cgroup)
            } else {
                None
            };

            // TODO: setup veth pair ở đây

            write(&write_fd, &[1u8]).context("failed to signal child")?;

            close(write_fd).ok();

            let status = waitpid(child, None).context("failed to wait for child process")?;

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
        }
    }

    Ok(())
}
fn run_child(
    args: &[String],
    env: &[String],
    rootfs: &Path,
    read_fd: OwnedFd,
    child_flags: CloneFlags,
) -> Result<()> {
    if !child_flags.is_empty() {
        unshare(child_flags)
            .context("failed to unshare child namespaces")?;
    }

    if child_flags.contains(CloneFlags::CLONE_NEWNET) {
        setup_loopback()?;
    }

    let mut buf = [0u8; 1];

    read(&read_fd, &mut buf)
        .context("failed to wait for parent signal")?;

    close(read_fd).ok();

    let command =
        CString::new(args[0].as_str()).context("invalid command")?;

    let c_args: Vec<CString> = args
        .iter()
        .map(|arg| {
            CString::new(arg.as_str())
                .context("invalid process argument")
        })
        .collect::<Result<_>>()?;

    mount::<str, str, str, str>(
        None,
        "/",
        None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None,
    )
    .context("failed to make mounts private")?;

    setup_rootfs(rootfs)?;

    for item in env {
        if let Some((key, value)) = item.split_once('=') {
            std::env::set_var(key, value);
        }
    }

    execvp(&command, &c_args)
        .context("failed to exec process")?;

    unreachable!();
}
) -> Result<()> {
    if !child_flags.is_empty() {
        unshare(child_flags).context("failed to unshare child namespaces")?;
    }

    if child_flags.contains(CloneFlags::CLONE_NEWET) {
        setup_loopback()?;
    }
}

    let mut buf = [0u8; 1];

    read(&read_fd, &mut buf).context("failed to wait for parent signal")?;

    close(read_fd).ok();

    let command = CString::new(args[0].as_str()).context("invalid command")?;

    let c_args: Vec<CString> = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).context("invalid process argument"))
        .collect::<Result<_>>()?;

    mount::<str, str, str, str>(None, "/", None, MsFlags::MS_REC | MsFlags::MS_PRIVATE, None)
        .context("failed to make mounts private")?;

    setup_rootfs(rootfs)?;

    for item in env {
        if let Some((key, value)) = item.split_once('=') {
            std::env::set_var(key, value);
        }
    }

    execvp(&command, &c_args).context("failed to exec process")?;

    unreachable!();
}
