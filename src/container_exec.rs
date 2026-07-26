use crate::container::env::replace_environment;
use crate::container::pty::{
    proxy_pty, register_sigwinch, unregister_sigwinch, PtyManager, RawTerminalGuard,
};
use crate::error::ContainerError;
use crate::fd::set_cloexec;
use crate::seccomp::Program;
use anyhow::{Context, Result};
use libc;
use nix::sched::{setns, CloneFlags};
use nix::sys::prctl;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execvp, fork, setsid, ForkResult, Pid};
use std::ffi::CString;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::path::Path;
use tracing::{error, warn};

const NAMESPACES: [(&str, CloneFlags); 6] = [
    ("user", CloneFlags::CLONE_NEWUSER),
    ("mnt", CloneFlags::CLONE_NEWNS),
    ("uts", CloneFlags::CLONE_NEWUTS),
    ("ipc", CloneFlags::CLONE_NEWIPC),
    ("net", CloneFlags::CLONE_NEWNET),
    ("pid", CloneFlags::CLONE_NEWPID),
];

#[derive(Debug, Clone)]
pub struct ExecConfig<'a> {
    pub target_pid: i32,
    pub args: &'a [String],
    pub env: &'a [String],
    pub cwd: Option<&'a str>,
    pub cgroup_path: Option<&'a str>,
    pub tty: bool,
    /// The container's own filter, compiled by the caller.
    ///
    /// seccomp is not inherited through `setns`, so a process that joins the
    /// container's namespaces starts unfiltered unless it installs the filter
    /// itself.
    pub seccomp_program: Option<&'a Program>,
    pub seccomp_flags: u64,
}

#[derive(Debug, Clone)]
pub struct ExecExit {
    pub code: Option<i32>,
    pub signal: Option<String>,
}

pub fn exec_in_container(config: ExecConfig<'_>) -> Result<ExecExit> {
    if config.args.is_empty() {
        return Err(ContainerError::EmptyExecArgs.into());
    }

    let mut pty_manager = if config.tty {
        Some(PtyManager::new().context("failed to allocate pty for exec")?)
    } else {
        None
    };

    let mut _raw_guard = None;
    if let Some(pty) = pty_manager.as_ref() {
        _raw_guard = Some(RawTerminalGuard::new().context("failed to set raw terminal mode")?);
        register_sigwinch(pty.master.as_raw_fd());
    }

    let mut proxy_handles = None;
    if let Some(pty) = pty_manager.as_ref() {
        let master_clone = pty
            .master
            .try_clone()
            .context("failed to clone master fd")?;
        let mut inherited_fds = Vec::new();
        if let Some(slave_fd) = pty.slave_ref() {
            inherited_fds.push(slave_fd);
        }
        proxy_handles =
            Some(proxy_pty(master_clone, &inherited_fds).context("failed to start pty proxy")?);
    }

    match unsafe { fork() }.context("failed to fork exec namespace helper")? {
        ForkResult::Child => {
            if let Some(pty) = pty_manager.as_ref() {
                // Drop master in child helper
                drop(pty.master.try_clone());
            }

            if let Err(error) = run_namespace_helper(config, pty_manager) {
                error!("exec error: {error}");
                std::process::exit(1);
            }

            unreachable!();
        }
        ForkResult::Parent { child } => {
            if let Some(pty) = pty_manager.as_mut() {
                pty.close_slave();
            }

            if let Some(cgroup_path) = config.cgroup_path {
                if let Err(error) = add_to_cgroup(cgroup_path, child) {
                    warn!("could not add exec helper to container cgroup: {error}");
                }
            }

            let exit = wait_for_exec_child(child);

            if config.tty {
                unregister_sigwinch();
                if let Some(proxy) = proxy_handles.take() {
                    proxy.join();
                }
                drop(_raw_guard);
            }

            exit
        }
    }
}

fn run_namespace_helper(config: ExecConfig<'_>, pty_manager: Option<PtyManager>) -> Result<()> {
    join_namespaces(config.target_pid)?;

    match unsafe { fork() }.context("failed to fork exec process")? {
        ForkResult::Child => {
            if let Some(pty) = pty_manager.as_ref() {
                let slave_fd = pty.slave_fd().context(ContainerError::PtySlaveClosed)?;
                setsid().context("failed to setsid for exec process")?;
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
            }
            exec_command(
                config.args,
                config.env,
                config.cwd,
                config.seccomp_program,
                config.seccomp_flags,
            )?;
            unreachable!();
        }
        ForkResult::Parent { child } => {
            let exit = wait_for_exec_child(child)?;
            match (exit.code, exit.signal) {
                (Some(code), _) => std::process::exit(code),
                (None, Some(signal)) => {
                    warn!("exec process killed by signal: {signal}");
                    std::process::exit(128);
                }
                (None, None) => std::process::exit(1),
            }
        }
    }
}

fn is_same_namespace(ns_name: &str, target_pid: i32) -> bool {
    let self_path = format!("/proc/self/ns/{ns_name}");
    let target_path = format!("/proc/{target_pid}/ns/{ns_name}");

    if let (Ok(self_meta), Ok(target_meta)) = (fs::metadata(&self_path), fs::metadata(&target_path))
    {
        use std::os::unix::fs::MetadataExt;
        self_meta.ino() == target_meta.ino()
    } else {
        false
    }
}

fn join_namespaces(target_pid: i32) -> Result<()> {
    let mut namespace_files = Vec::new();
    for (namespace, flag) in NAMESPACES {
        if namespace == "user" && is_same_namespace("user", target_pid) {
            continue;
        }
        let path = format!("/proc/{target_pid}/ns/{namespace}");
        let file =
            File::open(&path).with_context(|| format!("failed to open namespace: {path}"))?;
        set_cloexec(&file).with_context(|| format!("failed to mark namespace CLOEXEC: {path}"))?;
        namespace_files.push((path, file, flag));
    }

    for (path, file, flag) in namespace_files {
        setns(&file, flag).with_context(|| format!("failed to join namespace: {path}"))?;
    }

    Ok(())
}

fn exec_command(
    args: &[String],
    env: &[String],
    cwd: Option<&str>,
    seccomp_program: Option<&Program>,
    seccomp_flags: u64,
) -> Result<()> {
    let cwd = cwd.unwrap_or("/");
    chdir(cwd).with_context(|| format!("failed to chdir to container cwd: {cwd}"))?;

    replace_environment(env)?;

    let command = CString::new(args[0].as_str()).context("invalid exec command")?;
    let c_args = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).context("invalid exec argument"))
        .collect::<Result<Vec<_>>>()?;

    if let Some(program) = seccomp_program {
        // Installing a filter needs no_new_privs or CAP_SYS_ADMIN, and the
        // exec'd process should be no more privileged than the container.
        prctl::set_no_new_privs().context("failed to enable no_new_privs for exec")?;
        program
            .install(seccomp_flags)
            .context("failed to install the seccomp filter for exec")?;
    }

    execvp(&command, &c_args).context("failed to exec command")?;

    unreachable!();
}

fn wait_for_exec_child(pid: Pid) -> Result<ExecExit> {
    let status = waitpid(pid, None).context("failed to wait for exec process")?;

    let exit = match status {
        WaitStatus::Exited(_, code) => ExecExit {
            code: Some(code),
            signal: None,
        },
        WaitStatus::Signaled(_, signal, _) => ExecExit {
            code: None,
            signal: Some(format!("{signal:?}")),
        },
        other => ExecExit {
            code: None,
            signal: Some(format!("{other:?}")),
        },
    };

    Ok(exit)
}

pub fn add_to_cgroup(cgroup_path: &str, pid: Pid) -> Result<()> {
    let path = Path::new(cgroup_path);
    if path.exists() {
        fs::write(path.join("cgroup.procs"), pid.as_raw().to_string())
            .context("failed to add exec helper to cgroup")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_exec_args_with_typed_error() {
        let config = ExecConfig {
            target_pid: 1,
            args: &[],
            env: &[],
            cwd: None,
            cgroup_path: None,
            tty: false,
            seccomp_program: None,
            seccomp_flags: 0,
        };

        let error = exec_in_container(config).expect_err("empty exec args should be rejected");
        let container_error = error
            .downcast_ref::<ContainerError>()
            .expect("error should be typed");

        assert!(matches!(container_error, ContainerError::EmptyExecArgs));
    }
}
