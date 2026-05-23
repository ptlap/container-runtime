use crate::audit_log::{self, AuditEvent as RuntimeEvent};
use crate::doctor;
use crate::health::{self, HealthResult};
use crate::inspect_security;
use crate::lifecycle;
use crate::modes::LogMode;
use crate::rootfs_diff;
use crate::state;
use crate::trace::{ProcessNode, TraceReport};
use anyhow::{bail, Context, Result};
use std::fs;
use std::io;
use std::path::Path;
use std::thread;
use std::time::Duration;

pub fn process_exit_status(code: Option<i32>, signal: Option<&str>) -> i32 {
    match (code, signal) {
        (Some(code), _) if (0..=255).contains(&code) => code,
        (Some(code), _) if code < 0 => 1,
        (Some(_), _) => 255,
        (None, Some(_)) => 128,
        (None, None) => 1,
    }
}

pub fn should_capture_logs(log_mode: LogMode, stdin_is_terminal: bool) -> bool {
    match log_mode {
        LogMode::Auto => !stdin_is_terminal,
        LogMode::On => true,
        LogMode::Off => false,
    }
}

pub fn print_trace_report(report: &TraceReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!("id: {}", report.id);
    println!("pid: {}", report.pid);
    println!("runtime_status: {}", report.runtime_status);
    if let Some(name) = report.proc_status.get("Name") {
        println!("process_name: {name}");
    }
    if let Some(state) = report.proc_status.get("State") {
        println!("process_state: {state}");
    }
    if let Some(nnp) = report.proc_status.get("NoNewPrivs") {
        println!("no_new_privs: {nnp}");
    }
    println!("process_tree:");
    print_process_node(&report.process_tree, 0);
    println!("strace_available: {}", report.strace.available);
    println!("strace_requested: {}", report.strace.requested);
    if let Some(duration_ms) = report.strace.duration_ms {
        println!("strace_duration_ms: {duration_ms}");
    }
    if let Some(summary) = report.strace.summary.as_deref() {
        println!("strace_summary:");
        println!("{summary}");
    }
    if let Some(error) = report.strace.error.as_deref() {
        println!("strace_error: {error}");
    }
    println!("ebpf: {}", report.ebpf);

    Ok(())
}

fn print_process_node(node: &ProcessNode, depth: usize) {
    let indent = "  ".repeat(depth);
    println!("{indent}- {} {}", node.pid, node.command);
    for child in &node.children {
        print_process_node(child, depth + 1);
    }
}

pub fn run_healthcheck(id: &str, json: bool, watch: bool, interval_ms: u64) -> Result<()> {
    health::run(id, watch, Duration::from_millis(interval_ms), |result| {
        print_health_result(&result, json)
    })
}

fn print_health_result(result: &HealthResult, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("id: {}", result.id);
        println!("status: {}", result.status);
        println!("checked_at_unix: {}", result.checked_at_unix);
        println!("attempts: {}", result.attempts);
        println!("command: {:?}", result.command);
        if let Some(code) = result.exit_code {
            println!("exit_code: {code}");
        }
        if let Some(signal) = result.signal.as_deref() {
            println!("signal: {signal}");
        }
    }

    Ok(())
}

pub fn list_containers(json: bool) -> Result<()> {
    let states = state::list()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&states)?);
        return Ok(());
    }

    println!(
        "{:<24} {:<10} {:<8} {:<8} {:<11} {:<8} {:<8} {:<10} {:<10} BUNDLE",
        "ID", "STATUS", "PID", "NET", "SECURITY", "USERNS", "ROOTFS", "PROFILE", "HEALTH"
    );
    for state in states {
        println!(
            "{:<24} {:<10} {:<8} {:<8} {:<11} {:<8} {:<8} {:<10} {:<10} {}",
            state.id,
            format!("{:?}", state.status).to_lowercase(),
            state.pid.map_or("-".to_string(), |pid| pid.to_string()),
            state.network_mode,
            state.security_profile,
            state.userns_mode,
            state.rootfs_mode,
            state.policy_profile,
            state
                .health
                .as_ref()
                .map(|health| health.status.as_str())
                .unwrap_or("-"),
            state.bundle
        );
    }

    Ok(())
}

pub fn show_logs(id: &str, follow: bool) -> Result<()> {
    if follow {
        let log_path = lifecycle::log_path(id)?;
        follow_logs(&log_path)?;
    } else {
        print!("{}", lifecycle::read_logs(id)?);
    }

    Ok(())
}

fn follow_logs(log_path: &Path) -> Result<()> {
    let mut position = 0usize;

    loop {
        if let Ok(content) = fs::read_to_string(log_path) {
            if content.len() > position {
                print!("{}", &content[position..]);
                position = content.len();
            }
        }

        io::Write::flush(&mut io::stdout()).context("failed to flush stdout")?;
        thread::sleep(Duration::from_millis(250));
    }
}

pub fn run_doctor(fix: bool, json: bool) -> Result<()> {
    let report = doctor::run(fix)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    if report.issues.is_empty() {
        println!("doctor: ok");
        return Ok(());
    }

    for issue in &report.issues {
        let fixed = if issue.fixed { "fixed" } else { "unfixed" };
        let id = issue.id.as_deref().unwrap_or("-");
        let path = issue.path.as_deref().unwrap_or("-");
        println!(
            "{} id={} path={} status={} message={}",
            issue.kind, id, path, fixed, issue.message
        );
    }

    if !report.is_clean() {
        bail!("doctor found unfixed issues");
    }

    Ok(())
}

pub fn inspect_security_command(id: &str, json: bool) -> Result<()> {
    let inspection = inspect_security::inspect(id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&inspection)?);
        return Ok(());
    }

    println!("id: {}", inspection.id);
    println!("pid: {}", inspection.pid);
    println!("security_profile: {}", inspection.security_profile);
    println!("userns_mode: {}", inspection.userns_mode);
    println!("rootfs_mode: {}", inspection.rootfs_mode);
    println!("readonly_rootfs: {}", inspection.readonly_rootfs);
    println!("mount_count: {}", inspection.mount_count);
    if let Some(value) = inspection.no_new_privs {
        println!("no_new_privs: {value}");
    }
    if let Some(mode) = inspection.seccomp.mode {
        println!("seccomp_mode: {mode}");
    }
    if let Some(filters) = inspection.seccomp.filters {
        println!("seccomp_filters: {filters}");
    }
    if let Some(value) = inspection.capabilities.effective.as_deref() {
        println!("cap_effective: {value}");
    }
    if let Some(value) = inspection.capabilities.permitted.as_deref() {
        println!("cap_permitted: {value}");
    }
    if let Some(value) = inspection.resources.memory_limit.as_deref() {
        println!("memory_limit: {value}");
    }
    if let Some(value) = inspection.resources.pids_limit.as_deref() {
        println!("pids_limit: {value}");
    }
    if let Some(value) = inspection.resources.cpu_quota {
        println!("cpu_quota: {value}");
    }
    if let Some(value) = inspection.resources.cpu_period {
        println!("cpu_period: {value}");
    }
    for warning in &inspection.warnings {
        println!("warning: {warning}");
    }

    Ok(())
}

pub fn diff_rootfs(id: &str, json: bool) -> Result<()> {
    let report = rootfs_diff::diff_container(id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("id: {}", report.id);
    println!("lowerdir: {}", report.lowerdir);
    println!("upperdir: {}", report.upperdir);
    if report.entries.is_empty() {
        println!("no changes");
        return Ok(());
    }

    for entry in &report.entries {
        println!("{} {}", entry.kind.as_label(), entry.path);
    }

    Ok(())
}

pub fn validate_bundle(bundle: &Path, json: bool) -> Result<()> {
    let report = crate::spec::config::validate_bundle(bundle)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("valid: {}", report.valid);
    println!("bundle: {}", report.bundle);
    for warning in &report.warnings {
        println!("warning: {warning}");
    }

    Ok(())
}

pub fn stream_events(
    id: &str,
    json: bool,
    history: bool,
    snapshot: bool,
    once: bool,
    interval_ms: u64,
) -> Result<()> {
    if history {
        return show_event_history(id, json);
    }

    crate::events::stream_counter_events(
        id,
        snapshot,
        once,
        Duration::from_millis(interval_ms),
        |event| print_event(event, json, true),
    )
}

fn print_event(event: RuntimeEvent, json: bool, audit: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(&event)?);
    } else if let Some(status) = event.status.as_deref() {
        println!(
            "{} {} {} status={}",
            event.timestamp_unix, event.source, event.name, status
        );
    } else if let Some(fields) = event.fields.as_ref() {
        let fields = fields
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<_>>()
            .join(" ");
        println!(
            "{} {} {} {}",
            event.timestamp_unix, event.source, event.name, fields
        );
    } else {
        println!(
            "{} {} {} value={} delta={}",
            event.timestamp_unix,
            event.source,
            event.name,
            event.value.unwrap_or(0),
            event.delta.unwrap_or(0)
        );
    }

    if audit {
        audit_log::append(&event)?;
    }

    Ok(())
}

fn show_event_history(id: &str, json: bool) -> Result<()> {
    for event in audit_log::read_history(id)? {
        print_event(event, json, false)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_process_exit_code_to_cli_status() {
        assert_eq!(process_exit_status(Some(0), None), 0);
        assert_eq!(process_exit_status(Some(42), None), 42);
    }

    #[test]
    fn clamps_process_exit_code_to_shell_range() {
        assert_eq!(process_exit_status(Some(300), None), 255);
        assert_eq!(process_exit_status(Some(-1), None), 1);
    }

    #[test]
    fn maps_signal_and_missing_status_to_nonzero_cli_status() {
        assert_eq!(process_exit_status(None, Some("SIGKILL")), 128);
        assert_eq!(process_exit_status(None, None), 1);
    }

    #[test]
    fn decides_log_capture_from_mode_and_terminal_state() {
        assert!(!should_capture_logs(LogMode::Auto, true));
        assert!(should_capture_logs(LogMode::Auto, false));
        assert!(should_capture_logs(LogMode::On, true));
        assert!(should_capture_logs(LogMode::On, false));
        assert!(!should_capture_logs(LogMode::Off, true));
        assert!(!should_capture_logs(LogMode::Off, false));
    }
}
