use crate::state::{self, ContainerStatus};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

const MAX_PROCESS_TREE_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct TraceOptions {
    pub strace: bool,
    pub strace_duration: Duration,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TraceReport {
    pub id: String,
    pub pid: i32,
    pub runtime_status: String,
    pub proc_status: BTreeMap<String, String>,
    pub process_tree: ProcessNode,
    pub strace: StraceReport,
    pub ebpf: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProcessNode {
    pub pid: i32,
    pub command: String,
    pub children: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StraceReport {
    pub available: bool,
    pub requested: bool,
    pub duration_ms: Option<u64>,
    pub summary: Option<String>,
    pub error: Option<String>,
}

pub fn trace(id: &str, options: TraceOptions) -> Result<TraceReport> {
    let container_state = state::load_current(id)?;
    if container_state.status != ContainerStatus::Running {
        bail!("container {id} is not running");
    }

    let pid = container_state
        .pid
        .context("running container state has no pid")?;
    let proc_status = read_proc_status(pid)?;
    let process_tree = collect_process_tree(pid)?;
    let strace_available = command_available("strace");
    let strace = collect_strace(pid, strace_available, options)?;

    Ok(TraceReport {
        id: id.to_string(),
        pid,
        runtime_status: "running".to_string(),
        proc_status,
        process_tree,
        strace,
        ebpf: "not enabled; eBPF remains an optional research extension".to_string(),
    })
}

fn collect_process_tree(pid: i32) -> Result<ProcessNode> {
    let mut visited = BTreeSet::new();
    collect_process_node(pid, 0, &mut visited)
}

fn collect_process_node(
    pid: i32,
    depth: usize,
    visited: &mut BTreeSet<i32>,
) -> Result<ProcessNode> {
    if !visited.insert(pid) {
        let command = match read_command(pid) {
            Ok(command) => command,
            Err(_) => "<cycle>".to_string(),
        };
        return Ok(ProcessNode {
            pid,
            command,
            children: Vec::new(),
        });
    }

    let mut children = Vec::new();
    if depth < MAX_PROCESS_TREE_DEPTH {
        for child_pid in read_child_pids(pid)? {
            if let Ok(child) = collect_process_node(child_pid, depth + 1, visited) {
                children.push(child);
            }
        }
    }

    Ok(ProcessNode {
        pid,
        command: read_command(pid)?,
        children,
    })
}

fn read_proc_status(pid: i32) -> Result<BTreeMap<String, String>> {
    let path = proc_pid_path(pid, "status");
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read proc status: {}", path.display()))?;
    Ok(parse_proc_status(&content))
}

fn parse_proc_status(content: &str) -> BTreeMap<String, String> {
    let mut status = BTreeMap::new();
    for line in content.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        status.insert(key.to_string(), value.trim().to_string());
    }
    status
}

fn read_command(pid: i32) -> Result<String> {
    let cmdline_path = proc_pid_path(pid, "cmdline");
    if let Ok(cmdline) = fs::read(&cmdline_path) {
        let command = parse_cmdline(&cmdline);
        if !command.is_empty() {
            return Ok(command);
        }
    }

    let comm_path = proc_pid_path(pid, "comm");
    fs::read_to_string(&comm_path)
        .map(|value| value.trim().to_string())
        .with_context(|| format!("failed to read process command: {}", comm_path.display()))
}

fn parse_cmdline(cmdline: &[u8]) -> String {
    cmdline
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_child_pids(pid: i32) -> Result<Vec<i32>> {
    let path = proc_pid_path(pid, &format!("task/{pid}/children"));
    let content = fs::read_to_string(&path)
        .with_context(|| format!("failed to read process children: {}", path.display()))?;
    let mut children = Vec::new();
    for value in content.split_whitespace() {
        if let Ok(pid) = value.parse::<i32>() {
            children.push(pid);
        }
    }
    Ok(children)
}

fn collect_strace(pid: i32, available: bool, options: TraceOptions) -> Result<StraceReport> {
    if !options.strace {
        return Ok(StraceReport {
            available,
            requested: false,
            duration_ms: None,
            summary: None,
            error: None,
        });
    }

    let duration_ms = u64::try_from(options.strace_duration.as_millis()).unwrap_or(u64::MAX);
    if !available {
        return Ok(StraceReport {
            available,
            requested: true,
            duration_ms: Some(duration_ms),
            summary: None,
            error: Some("strace is not installed or not executable".to_string()),
        });
    }

    let mut child = Command::new("strace")
        .arg("-f")
        .arg("-p")
        .arg(pid.to_string())
        .arg("-c")
        .arg("-qq")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to start strace")?;

    thread::sleep(options.strace_duration);
    let _ = child.kill();
    let output = child
        .wait_with_output()
        .context("failed to collect strace output")?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    Ok(StraceReport {
        available,
        requested: true,
        duration_ms: Some(duration_ms),
        summary: (!stderr.is_empty()).then_some(stderr),
        error: (!output.status.success()).then(|| format!("strace exited with {}", output.status)),
    })
}

fn command_available(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn proc_pid_path(pid: i32, child: &str) -> std::path::PathBuf {
    std::path::Path::new("/proc")
        .join(pid.to_string())
        .join(child)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_status_fields() {
        let status = parse_proc_status(
            r#"Name:	sh
State:	S (sleeping)
Pid:	42
NoNewPrivs:	1
"#,
        );

        assert_eq!(status.get("Name").map(String::as_str), Some("sh"));
        assert_eq!(
            status.get("State").map(String::as_str),
            Some("S (sleeping)")
        );
        assert_eq!(status.get("NoNewPrivs").map(String::as_str), Some("1"));
    }

    #[test]
    fn parses_nul_separated_cmdline() {
        let command = parse_cmdline(b"/bin/sh\0-c\0sleep 10\0");

        assert_eq!(command, "/bin/sh -c sleep 10");
    }

    #[test]
    fn reports_unrequested_strace_without_running_external_command() {
        let report = collect_strace(
            1,
            false,
            TraceOptions {
                strace: false,
                strace_duration: Duration::from_millis(10),
            },
        )
        .expect("strace report should build");

        assert!(!report.available);
        assert!(!report.requested);
        assert_eq!(report.duration_ms, None);
    }
}
