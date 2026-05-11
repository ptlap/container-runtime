use crate::filesystem::setup_rootfs;
use anyhow::{bail, Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult};
use std::ffi::CString;
use std::path::Path;

pub fn run_process(
    args: &[String],
    env: &[String],
    rootfs: &Path,
    flags: CloneFlags,
) -> Result<()> {
    if args.is_empty() {
        bail!("process args is empty");
    }

    unshare(flags).context("failed to unshare namespaces")?;

    match unsafe { fork() }.context("failed to fork process")? {
        ForkResult::Child => {
            if let Err(error) = run_child(args, env, rootfs) {
                eprintln!("container error: {error}");
                std::process::exit(1);
            }

            unreachable!();
        }

        ForkResult::Parent { child } => {
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
        }
    }

    Ok(())
}

fn run_child(args: &[String], env: &[String], rootfs: &Path) -> Result<()> {
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
