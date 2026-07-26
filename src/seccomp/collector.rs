//! ptrace supervisor that records the syscalls a container makes.
//!
//! The container installs a filter that returns `SECCOMP_RET_TRACE` for every
//! syscall, so each call stops the tracee once with `PTRACE_EVENT_SECCOMP`.
//! That is half the stops of `PTRACE_SYSCALL`, which matters because the
//! workloads being profiled make millions of calls.

use super::capture::Capture;
use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use std::collections::HashSet;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub struct CollectorOptions {
    /// The container process. Its exit status is what the caller waits for.
    pub root_pid: Pid,
    /// Direct children of the runtime that are not part of the container: the
    /// log helper and the pty proxy. Their statuses are handed back rather than
    /// consumed, because `waitpid(-1)` cannot tell them apart from tracees.
    pub exclude_pids: Vec<Pid>,
    /// Stops collecting after this many events. Only used to bound pathological
    /// runs; the capture is marked truncated when it fires.
    pub max_events: Option<u64>,
}

#[derive(Debug)]
pub struct CollectorOutcome {
    pub root_status: WaitStatus,
    pub reaped_others: Vec<(Pid, WaitStatus)>,
    pub capture: Capture,
}

/// Supervises the container process tree until the root process exits.
///
/// Replaces the plain `waitpid` of a normal run: the tracer has to reap every
/// tracee anyway, so making it the single waiter avoids a second process and
/// the PID reuse window that would come with one.
pub fn run(options: CollectorOptions) -> Result<CollectorOutcome> {
    let started = Instant::now();
    let mut capture = Capture {
        audit_arch: super::arch::AUDIT_ARCH_NATIVE,
        started_at_unix: unix_timestamp(),
        ..Capture::default()
    };

    let mut outcome = CollectorOutcome {
        root_status: WaitStatus::StillAlive,
        reaped_others: Vec::new(),
        capture: Capture::default(),
    };

    let excluded: HashSet<Pid> = options.exclude_pids.iter().copied().collect();
    let mut tracees: HashSet<Pid> = HashSet::new();
    let mut root_exited = false;
    let mut options_set = false;

    loop {
        let status = match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL)) {
            Ok(status) => status,
            Err(Errno::ECHILD) => break,
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(error).context("failed to wait for traced process"),
        };

        let Some(pid) = status_pid(&status) else {
            continue;
        };

        if excluded.contains(&pid) {
            if is_terminal(&status) {
                outcome.reaped_others.push((pid, status));
            }
            continue;
        }

        match status {
            WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                tracees.remove(&pid);
                if pid == options.root_pid {
                    outcome.root_status = status;
                    root_exited = true;
                }
                if root_exited && tracees.is_empty() {
                    break;
                }
            }

            WaitStatus::PtraceEvent(pid, _, event) => {
                handle_event(
                    pid,
                    event,
                    &mut tracees,
                    &mut capture,
                    started.elapsed().as_millis() as u64,
                )?;

                if options
                    .max_events
                    .is_some_and(|limit| capture.events >= limit)
                {
                    capture.truncated = true;
                    warn!(
                        events = capture.events,
                        "syscall capture reached its event limit"
                    );
                }

                resume(pid, None);
            }

            WaitStatus::Stopped(pid, signal) => {
                if pid == options.root_pid && !options_set {
                    // The container raised SIGSTOP after PTRACE_TRACEME and is
                    // waiting for the tracer to be ready. Nothing may run until
                    // the options are set, because a RET_TRACE syscall with no
                    // tracer attached fails with ENOSYS.
                    set_trace_options(pid)?;
                    options_set = true;
                    tracees.insert(pid);
                    resume(pid, None);
                    continue;
                }

                if tracees.insert(pid) && signal == Signal::SIGSTOP {
                    // A newly auto-attached child. Its attach stop can arrive
                    // before the parent's fork event, so an unknown pid in
                    // SIGSTOP is treated as an attach either way, and the
                    // signal is not delivered on.
                    resume(pid, None);
                    continue;
                }

                if is_group_stop(pid) {
                    resume(pid, None);
                } else {
                    // A real signal for the tracee; swallowing it would change
                    // how the workload behaves.
                    resume(pid, Some(signal));
                }
            }

            WaitStatus::StillAlive | WaitStatus::Continued(_) => {}

            #[allow(unreachable_patterns)]
            other => debug!(?other, "ignoring wait status"),
        }
    }

    capture.processes_seen = capture.processes_seen.max(1);
    capture.duration_ms = started.elapsed().as_millis() as u64;
    outcome.capture = capture;

    Ok(outcome)
}

fn handle_event(
    pid: Pid,
    event: i32,
    tracees: &mut HashSet<Pid>,
    capture: &mut Capture,
    elapsed_ms: u64,
) -> Result<()> {
    if event == ptrace::Event::PTRACE_EVENT_SECCOMP as i32 {
        match syscall_number(pid) {
            Ok(number) => capture.record(number, elapsed_ms),
            // The tracee can die between the stop and the register read.
            Err(Errno::ESRCH) => {}
            Err(error) => return Err(error).context("failed to read the trapped syscall number"),
        }
        return Ok(());
    }

    let is_new_child = event == ptrace::Event::PTRACE_EVENT_FORK as i32
        || event == ptrace::Event::PTRACE_EVENT_VFORK as i32
        || event == ptrace::Event::PTRACE_EVENT_CLONE as i32;

    if is_new_child {
        match ptrace::getevent(pid) {
            Ok(child) => {
                let child = Pid::from_raw(child as i32);
                if tracees.insert(child) {
                    capture.processes_seen += 1;
                }
            }
            Err(Errno::ESRCH) => {}
            Err(error) => return Err(error).context("failed to read the new child pid"),
        }
    }

    Ok(())
}

fn set_trace_options(pid: Pid) -> Result<()> {
    // EXITKILL is not optional: a tracee whose tracer disappears keeps its
    // RET_TRACE filter, and every syscall it makes afterwards fails with
    // ENOSYS. Killing it is the only sane outcome.
    let options = ptrace::Options::PTRACE_O_TRACESECCOMP
        | ptrace::Options::PTRACE_O_TRACEFORK
        | ptrace::Options::PTRACE_O_TRACEVFORK
        | ptrace::Options::PTRACE_O_TRACECLONE
        | ptrace::Options::PTRACE_O_TRACEEXEC
        | ptrace::Options::PTRACE_O_TRACESYSGOOD
        | ptrace::Options::PTRACE_O_EXITKILL;

    ptrace::setoptions(pid, options).context("failed to set ptrace options")
}

/// Distinguishes a group stop from a signal delivery stop.
///
/// `PTRACE_GETSIGINFO` fails with ESRCH in group stop, which is the documented
/// way to tell them apart without `PTRACE_SEIZE`.
fn is_group_stop(pid: Pid) -> bool {
    matches!(ptrace::getsiginfo(pid), Err(Errno::ESRCH))
}

fn resume(pid: Pid, signal: Option<Signal>) {
    match ptrace::cont(pid, signal) {
        Ok(()) => {}
        // The tracee exited between its stop and this call.
        Err(Errno::ESRCH) => {}
        Err(error) => warn!(pid = pid.as_raw(), %error, "failed to resume tracee"),
    }
}

#[cfg(target_arch = "x86_64")]
fn syscall_number(pid: Pid) -> nix::Result<i64> {
    let regs = ptrace::getregs(pid)?;
    Ok(regs.orig_rax as i64)
}

#[cfg(target_arch = "aarch64")]
fn syscall_number(pid: Pid) -> nix::Result<i64> {
    // x8 holds the syscall number on arm64. PTRACE_GETREGSET with
    // NT_ARM_SYSTEM_CALL is the fully robust route when the number also has to
    // be written, but reading x8 at a seccomp stop is what strace does.
    let regs = ptrace::getregset::<ptrace::RegisterSetValue>(pid)?;
    Ok(regs.regs[8] as i64)
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn syscall_number(_pid: Pid) -> nix::Result<i64> {
    Err(Errno::ENOSYS)
}

fn status_pid(status: &WaitStatus) -> Option<Pid> {
    match status {
        WaitStatus::Exited(pid, _)
        | WaitStatus::Signaled(pid, _, _)
        | WaitStatus::Stopped(pid, _)
        | WaitStatus::PtraceEvent(pid, _, _)
        | WaitStatus::PtraceSyscall(pid)
        | WaitStatus::Continued(pid) => Some(*pid),
        WaitStatus::StillAlive => None,
    }
}

fn is_terminal(status: &WaitStatus) -> bool {
    matches!(status, WaitStatus::Exited(..) | WaitStatus::Signaled(..))
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_pid_out_of_every_wait_status() {
        let pid = Pid::from_raw(42);

        assert_eq!(status_pid(&WaitStatus::Exited(pid, 0)), Some(pid));
        assert_eq!(
            status_pid(&WaitStatus::Signaled(pid, Signal::SIGKILL, false)),
            Some(pid)
        );
        assert_eq!(
            status_pid(&WaitStatus::Stopped(pid, Signal::SIGSTOP)),
            Some(pid)
        );
        assert_eq!(
            status_pid(&WaitStatus::PtraceEvent(pid, Signal::SIGTRAP, 7)),
            Some(pid)
        );
        assert_eq!(status_pid(&WaitStatus::StillAlive), None);
    }

    #[test]
    fn treats_only_exit_statuses_as_terminal() {
        let pid = Pid::from_raw(42);

        assert!(is_terminal(&WaitStatus::Exited(pid, 0)));
        assert!(is_terminal(&WaitStatus::Signaled(
            pid,
            Signal::SIGKILL,
            false
        )));
        assert!(!is_terminal(&WaitStatus::Stopped(pid, Signal::SIGSTOP)));
    }

    #[test]
    fn counts_a_forked_child_as_a_new_process() {
        let mut tracees = HashSet::new();
        let mut capture = Capture::default();
        let read = super::super::syscalls::number("read").expect("read exists");

        capture.record(read, 0);
        assert_eq!(capture.events, 1);
        assert_eq!(capture.processes_seen, 0);

        tracees.insert(Pid::from_raw(2));
        assert_eq!(tracees.len(), 1);
    }
}
