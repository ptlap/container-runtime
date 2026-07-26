use crate::error::ContainerError;
use anyhow::{Context, Result};
use nix::libc;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{close, fork, read, ForkResult};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use tracing::error;

pub fn redirect_stdio_to_log(log_write_fd: &OwnedFd) -> Result<()> {
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

pub fn start_log_helper(
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
                error!("log helper error: {error}");
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

pub fn wait_for_log_helper(log_helper: Option<nix::unistd::Pid>) -> Result<()> {
    wait_for_log_helper_status(log_helper, None)
}

/// Checks the log helper's exit status, waiting for it only when nobody else
/// has. The seccomp tracer waits on every child of the runtime, so it reaps the
/// log helper too and hands the status back here.
pub fn wait_for_log_helper_status(
    log_helper: Option<nix::unistd::Pid>,
    already_reaped: Option<WaitStatus>,
) -> Result<()> {
    let Some(log_helper) = log_helper else {
        return Ok(());
    };

    let status = match already_reaped {
        Some(status) => status,
        None => waitpid(log_helper, None).context("failed to wait for log helper")?,
    };

    match status {
        WaitStatus::Exited(_, 0) => Ok(()),
        WaitStatus::Exited(_, code) => Err(ContainerError::LogHelperExited { code }.into()),
        WaitStatus::Signaled(_, signal, _) => Err(ContainerError::LogHelperKilled {
            signal: format!("{signal:?}"),
        }
        .into()),
        other => Err(ContainerError::LogHelperStatus {
            status: format!("{other:?}"),
        }
        .into()),
    }
}
