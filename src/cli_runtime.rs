use crate::audit_log::{self, AuditEvent as RuntimeEvent};
use crate::cgroup::read_container_stats;
use crate::checkpoint::{self, CheckpointOptions, RestoreOptions};
use crate::doctor;
use crate::error::SeccompError;
use crate::health::{self, HealthResult};
use crate::image;
use crate::inspect_security;
use crate::lifecycle;
use crate::modes::LogMode;
use crate::rootfs_diff;
use crate::seccomp::baseline;
use crate::seccomp::capture::CaptureFile;
use crate::seccomp::profile::SeccompProfile;
use crate::seccomp::{
    compile, generate, report, syscalls, CompileOptions, SeccompAction, SyscallOrder,
};
use crate::state;
use crate::trace::{ProcessNode, TraceOptions, TraceReport};
use anyhow::{bail, Context, Result};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
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

pub fn show_state(id: &str, json: bool) -> Result<()> {
    let state = state::load_current(id)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&state)?);
    } else {
        println!("id: {}", state.id);
        println!("status: {:?}", state.status);
        println!(
            "pid: {}",
            state.pid.map_or("-".to_string(), |pid| pid.to_string())
        );
        println!("bundle: {}", state.bundle);
        println!(
            "cgroup_path: {}",
            state.cgroup_path.as_deref().unwrap_or("-")
        );
        println!("network_mode: {}", state.network_mode);
        if let Some(subnet) = state.network_subnet {
            println!("network_subnet: {subnet}");
        }
        if let Some(log_path) = state.log_path {
            println!("log_path: {log_path}");
        }
        println!("log_mode: {}", state.log_mode);
        println!("security_profile: {}", state.security_profile);
        println!("userns_mode: {}", state.userns_mode);
        println!("rootfs_mode: {}", state.rootfs_mode);
        println!("policy_profile: {}", state.policy_profile);
        if let Some(health) = state.health.as_ref() {
            println!("health_status: {}", health.status);
            println!("health_checked_at_unix: {}", health.checked_at_unix);
        }
        println!("created_at_unix: {}", state.created_at_unix);
        println!("updated_at_unix: {}", state.updated_at_unix);
        if let Some(code) = state.exit_code {
            println!("exit_code: {code}");
        }
        if let Some(signal) = state.signal {
            println!("signal: {signal}");
        }
    }

    Ok(())
}

pub fn show_stats(id: &str, json: bool) -> Result<()> {
    let stats = read_container_stats(id)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        println!("id: {id}");
        println!("cgroup_path: {}", stats.path);
        if let Some(value) = stats.memory_current {
            println!("memory_current: {value}");
        }
        if let Some(value) = stats.memory_max {
            println!("memory_max: {value}");
        }
        if let Some(value) = stats.cpu_usage_usec {
            println!("cpu_usage_usec: {value}");
        }
        if let Some(value) = stats.cpu_user_usec {
            println!("cpu_user_usec: {value}");
        }
        if let Some(value) = stats.cpu_system_usec {
            println!("cpu_system_usec: {value}");
        }
        if let Some(value) = stats.pids_current {
            println!("pids_current: {value}");
        }
        if let Some(value) = stats.pids_max {
            println!("pids_max: {value}");
        }
        if let Some(value) = stats.cpu.nr_periods {
            println!("cpu_nr_periods: {value}");
        }
        if let Some(value) = stats.cpu.nr_throttled {
            println!("cpu_nr_throttled: {value}");
        }
        if let Some(value) = stats.cpu.throttled_usec {
            println!("cpu_throttled_usec: {value}");
        }
        for (event, value) in &stats.memory.events {
            println!("memory_event_{event}: {value}");
        }
        for (event, value) in &stats.pids.events {
            println!("pids_event_{event}: {value}");
        }
        if let Some(value) = stats.memory.pressure.as_deref() {
            println!("memory_pressure: {value}");
        }
        if let Some(value) = stats.cpu.pressure.as_deref() {
            println!("cpu_pressure: {value}");
        }
        for device in &stats.io {
            println!(
                "io_device {}: rbytes={} wbytes={} rios={} wios={} dbytes={} dios={}",
                device.device,
                device.rbytes.unwrap_or(0),
                device.wbytes.unwrap_or(0),
                device.rios.unwrap_or(0),
                device.wios.unwrap_or(0),
                device.dbytes.unwrap_or(0),
                device.dios.unwrap_or(0)
            );
        }
    }

    Ok(())
}

pub fn checkpoint_container(id: &str, json: bool, images_dir: Option<PathBuf>) -> Result<()> {
    let report = checkpoint::checkpoint(id, CheckpointOptions { images_dir })?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("experimental: {}", report.experimental);
    println!("id: {}", report.id);
    println!("pid: {}", report.pid);
    println!("images_dir: {}", report.images_dir);
    println!("criu_available: {}", report.criu.available);
    if let Some(version) = report.criu.version.as_deref() {
        println!("criu_version: {version}");
    }
    println!("command: {}", report.command.join(" "));

    Ok(())
}

pub fn restore_container(id: &str, json: bool, images_dir: Option<PathBuf>) -> Result<()> {
    let report = checkpoint::restore(id, RestoreOptions { images_dir })?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("experimental: {}", report.experimental);
    println!("id: {}", report.id);
    println!("images_dir: {}", report.images_dir);
    println!("criu_available: {}", report.criu.available);
    if let Some(version) = report.criu.version.as_deref() {
        println!("criu_version: {version}");
    }
    println!("command: {}", report.command.join(" "));

    Ok(())
}

pub fn import_image(rootfs_tar: &Path, name: &str) -> Result<()> {
    let image = image::import(rootfs_tar, name)?;
    println!("imported image: {}", image.name);
    println!("path: {}", image.path);
    println!("rootfs: {}", image.rootfs);
    Ok(())
}

pub fn list_images(json: bool) -> Result<()> {
    let images = image::list()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&images)?);
        return Ok(());
    }

    println!("{:<24} {:<48} ROOTFS", "NAME", "PATH");
    for image in images {
        println!("{:<24} {:<48} {}", image.name, image.path, image.rootfs);
    }

    Ok(())
}

pub fn trace_container(id: &str, json: bool, strace: bool, duration_ms: u64) -> Result<()> {
    if duration_ms == 0 {
        bail!("trace duration must be greater than zero");
    }

    let report = crate::trace::trace(
        id,
        TraceOptions {
            strace,
            strace_duration: Duration::from_millis(duration_ms),
        },
    )?;
    print_trace_report(&report, json)
}

/// Inputs for `crun seccomp generate`.
#[derive(Debug, Clone)]
pub struct SeccompGenerateRequest<'a> {
    pub capture_paths: &'a [PathBuf],
    pub container_ids: &'a [String],
    pub output: &'a Path,
    pub workload: Option<&'a str>,
    pub action: SeccompAction,
    pub include_compat: bool,
    pub merge_into: Option<&'a Path>,
    pub json: bool,
}

pub fn seccomp_generate(request: SeccompGenerateRequest<'_>) -> Result<()> {
    let SeccompGenerateRequest {
        capture_paths,
        container_ids,
        output,
        workload,
        action,
        include_compat,
        merge_into,
        json,
    } = request;

    let mut captures = Vec::new();
    for id in container_ids {
        captures.push(CaptureFile::load(&state::capture_path(id)?)?);
    }
    for path in capture_paths {
        captures.push(CaptureFile::load(path)?);
    }

    if captures.is_empty() {
        return Err(SeccompError::NoCaptures.into());
    }

    let merge_into = merge_into.map(SeccompProfile::load).transpose()?;
    let profile = generate::generate(
        &captures,
        generate::GenerateOptions {
            workload: workload.map(str::to_string),
            action,
            include_compat,
            merge_into,
        },
    )?;
    profile.save(output)?;

    let report = report::inspect(output, &profile)?;
    print_profile_inspection(&report, json)
}

pub fn seccomp_inspect(path: &Path, json: bool) -> Result<()> {
    let profile = SeccompProfile::load(path)?;
    let report = report::inspect(path, &profile)?;
    print_profile_inspection(&report, json)
}

pub fn seccomp_compare(
    path: &Path,
    baseline: Option<&Path>,
    cve_map: Option<&Path>,
    json: bool,
) -> Result<()> {
    let profile = SeccompProfile::load(path)?;
    // Read through the Docker-aware loader: baseline profiles gate rules on
    // capabilities and architecture, and counting every allow rule would
    // overstate what the baseline really permits.
    let baseline_options = baseline::BaselineOptions::default();
    let baseline = baseline
        .map(|path| {
            baseline::allowed_names_for_arch(path, &baseline_options).map(|allowed| {
                report::Baseline {
                    path: path.display().to_string(),
                    allowed,
                }
            })
        })
        .transpose()?;
    let cve_map = cve_map.map(report::CveMap::load).transpose()?;

    let report = report::compare(path, &profile, baseline.as_ref(), cve_map.as_ref());

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("profile: {}", report.profile);
    if let Some(baseline) = &report.baseline {
        println!("baseline: {baseline}");
    }
    println!("arch: {}", report.arch);
    println!("syscalls_on_arch: {}", report.universe_count);
    println!("profile_allowed: {}", report.profile_allowed);
    if let Some(count) = report.baseline_allowed {
        println!("baseline_allowed: {count}");
    }
    if let Some(reduction) = report.reduction_vs_baseline {
        println!("reduction_vs_baseline: {:.4}", reduction);
    }
    println!("reduction_vs_arch: {:.4}", report.reduction_vs_universe);
    println!("newly_blocked: {}", report.newly_blocked.len());
    println!("over_allowed: {}", report.over_allowed.len());

    if let Some(cve) = &report.cve {
        println!("cve_total: {}", cve.total);
        println!("cve_container_relevant: {}", cve.container_relevant);
        println!("cve_blocked_by_profile: {}", cve.mitigated_by_profile);
        println!("cve_blocked_by_baseline: {}", cve.mitigated_by_baseline);
        println!("cve_newly_blocked: {}", cve.newly_mitigated.len());
    }

    Ok(())
}

pub fn seccomp_compile(
    path: &Path,
    action: SeccompAction,
    order: SyscallOrder,
    json: bool,
) -> Result<()> {
    let profile = SeccompProfile::load(path)?;
    let compiled = compile::compile(
        &profile,
        CompileOptions {
            default_action: action,
            order,
        },
    )?;

    if json {
        let report = serde_json::json!({
            "profile": path.display().to_string(),
            "default_action": action.as_str(),
            "order": order.as_str(),
            "allowed_count": compiled.allowed.len(),
            "instruction_count": compiled.program.len(),
            "unresolved": compiled.unresolved,
            "allowed": compiled
                .allowed
                .iter()
                .map(|number| syscalls::name(*number).unwrap_or("unknown"))
                .collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("profile: {}", path.display());
    println!("default_action: {}", action.as_str());
    println!("order: {}", order.as_str());
    println!("allowed_count: {}", compiled.allowed.len());
    println!("instruction_count: {}", compiled.program.len());
    for name in &compiled.unresolved {
        println!("warning: unknown syscall for this architecture: {name}");
    }

    Ok(())
}

fn print_profile_inspection(report: &report::ProfileInspection, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    println!("profile: {}", report.path);
    println!("arch: {}", report.arch);
    println!("default_action: {}", report.default_action);
    println!("allowed_count: {}", report.allowed_count);
    println!("allowed_count_for_arch: {}", report.allowed_count_for_arch);
    println!("instruction_count: {}", report.instruction_count);
    if let Some(workload) = &report.workload {
        println!("workload: {workload}");
    }
    if let Some(count) = report.observed_syscall_count {
        println!("observed_syscalls: {count}");
    }
    if let Some(count) = report.baseline_syscall_count {
        println!("baseline_syscalls: {count}");
    }
    if let Some(events) = report.total_events {
        println!("captured_events: {events}");
    }
    println!("source_runs: {}", report.source_runs);
    for name in &report.unknown_for_arch {
        println!("warning: unknown syscall for this architecture: {name}");
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
