use anyhow::{bail, Context, Result};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult};
use std::ffi::CString;

pub fn run_process(args: &[String], flags: CloneFlags) -> Result<()> {
    if args.is_empty() {
        bail!("process args is empty");
    }

    unshare(flags).context("failed to unshare namespaces")?;

    match unsafe { fork() }.context("failed to fork process")? {
        ForkResult::Child => {
            let command = CString::new(args[0].as_str()).context("invalid command")?;

            let c_args: Vec<CString> = args
                .iter()
                .map(|arg| CString::new(arg.as_str()).context("invalid process argument"))
                .collect::<Result<_>>()?;

            mount::<str, str, str, str>(
                None,
                "/",
                None,
                MsFlags::MS_REC | MsFlags::MS_PRIVATE,
                None,
            )
            .context("failed to make mounts private")?;

            mount(
                Some("proc"),
                "/proc",
                Some("proc"),
                MsFlags::empty(),
                None::<&str>,
            )
            .context("failed to mount proc")?;

            execvp(&command, &c_args).context("failed to exec process")?;

            unreachable!();
        }

        ForkResult::Parent { child } => {
            let status = waitpid(child, None).context("failed to wait for child process")?;

            match status {
                WaitStatus::Exited(_, code) => {
                    println!("container process exited with code: {}", code);
                }
                WaitStatus::Signaled(_, signal, _) => {
                    println!("container process killed by signal: {:?}", signal);
                }
                other => {
                    println!("container process ended with status: {:?}", other);
                }
            }
        }
    }

    Ok(())
}
