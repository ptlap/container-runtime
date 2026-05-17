use anyhow::{bail, Context, Result};
use nix::sched::{setns, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execvp, fork, ForkResult, Pid};
use std::ffi::CString;
use std::fs::{self, File};
use std::path::Path;

const NAMESPACES: [(&str, CloneFlags); 5] = [
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
}

#[derive(Debug, Clone)]
pub struct ExecExit {
    pub code: Option<i32>,
    pub signal: Option<String>,
}

pub fn exec_in_container(config: ExecConfig<'_>) -> Result<ExecExit> {
    if config.args.is_empty() {
        bail!("exec args is empty");
    }

    match unsafe { fork() }.context("failed to fork exec namespace helper")? {
        ForkResult::Child => {
            if let Err(error) = run_namespace_helper(config) {
                eprintln!("exec error: {error}");
                std::process::exit(1);
            }

            unreachable!();
        }
        ForkResult::Parent { child } => {
            if let Some(cgroup_path) = config.cgroup_path {
                if let Err(error) = add_to_cgroup(cgroup_path, child) {
                    eprintln!("warn: could not add exec helper to container cgroup: {error}");
                }
            }

            wait_for_exec_child(child)
        }
    }
}

fn run_namespace_helper(config: ExecConfig<'_>) -> Result<()> {
    join_namespaces(config.target_pid)?;

    match unsafe { fork() }.context("failed to fork exec process")? {
        ForkResult::Child => {
            exec_command(config.args, config.env, config.cwd)?;
            unreachable!();
        }
        ForkResult::Parent { child } => {
            let exit = wait_for_exec_child(child)?;
            match (exit.code, exit.signal) {
                (Some(code), _) => std::process::exit(code),
                (None, Some(signal)) => {
                    eprintln!("exec process killed by signal: {signal}");
                    std::process::exit(128);
                }
                (None, None) => std::process::exit(1),
            }
        }
    }
}

fn join_namespaces(target_pid: i32) -> Result<()> {
    let mut namespace_files = Vec::new();
    for (namespace, flag) in NAMESPACES {
        let path = format!("/proc/{target_pid}/ns/{namespace}");
        let file =
            File::open(&path).with_context(|| format!("failed to open namespace: {path}"))?;
        namespace_files.push((path, file, flag));
    }

    for (path, file, flag) in namespace_files {
        setns(&file, flag).with_context(|| format!("failed to join namespace: {path}"))?;
    }

    Ok(())
}

fn exec_command(args: &[String], env: &[String], cwd: Option<&str>) -> Result<()> {
    let cwd = cwd.unwrap_or("/");
    chdir(cwd).with_context(|| format!("failed to chdir to container cwd: {cwd}"))?;

    for item in env {
        if let Some((key, value)) = item.split_once('=') {
            std::env::set_var(key, value);
        }
    }

    let command = CString::new(args[0].as_str()).context("invalid exec command")?;
    let c_args = args
        .iter()
        .map(|arg| CString::new(arg.as_str()).context("invalid exec argument"))
        .collect::<Result<Vec<_>>>()?;

    execvp(&command, &c_args).context("failed to exec command")?;

    unreachable!();
}

fn add_to_cgroup(cgroup_path: &str, pid: Pid) -> Result<()> {
    let procs_path = Path::new(cgroup_path).join("cgroup.procs");
    fs::write(&procs_path, pid.as_raw().to_string()).with_context(|| {
        format!(
            "failed to add exec process to cgroup: {}",
            procs_path.display()
        )
    })
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
