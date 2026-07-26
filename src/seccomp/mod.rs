//! Seccomp filter construction, syscall tables and profile handling.
//!
//! The runtime builds three kinds of filter:
//!
//! * the fixed denylist behind `--security default`,
//! * a trace-everything filter used while learning a workload's syscall set,
//! * an allowlist compiled from a generated profile.

pub mod arch;
pub mod baseline;
pub mod bpf;
pub mod capture;
pub mod collector;
pub mod compile;
pub mod generate;
pub mod profile;
pub mod report;
pub mod syscalls;

#[cfg(target_arch = "aarch64")]
mod syscalls_aarch64;
#[cfg(target_arch = "x86_64")]
mod syscalls_x86_64;

pub use arch::{AUDIT_ARCH_NATIVE, NATIVE_ARCH_NAME};
pub use bpf::{FilterBuilder, Program};
pub use compile::{CompileOptions, CompiledProfile, SeccompAction, SyscallOrder};

use crate::error::SeccompError;
use nix::libc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeccompMode {
    /// No extra filter beyond whatever `--security` installs.
    Off,
    /// Trace every syscall and record what the workload uses.
    Learn,
    /// Install an allowlist compiled from a profile.
    Enforce,
}

impl SeccompMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Learn => "learn",
            Self::Enforce => "enforce",
        }
    }
}

/// What the forked child installs. Carries borrowed data only, so it can cross
/// `fork` without owning an allocation.
#[derive(Debug, Clone, Copy)]
pub enum SeccompPlan<'a> {
    None,
    /// Return `SECCOMP_RET_TRACE` for everything. Requires a tracer to already
    /// be attached, otherwise every syscall fails with ENOSYS.
    Learn,
    Enforce {
        program: &'a Program,
        flags: u64,
    },
}

impl SeccompPlan<'_> {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn is_learn(&self) -> bool {
        matches!(self, Self::Learn)
    }
}

/// Filter used while learning. Foreign architectures are traced rather than
/// denied so the capture can report that they occurred at all.
pub fn learn_filter() -> std::result::Result<Program, SeccompError> {
    arch::ensure_supported()?;

    FilterBuilder::new()
        .load_arch()
        .ret(libc::SECCOMP_RET_TRACE)
        .build()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeccompOptions {
    pub mode: SeccompMode,
    pub profile_path: Option<PathBuf>,
    pub capture_path: Option<PathBuf>,
    pub action: SeccompAction,
    pub order: SyscallOrder,
    /// Adds `SECCOMP_FILTER_FLAG_LOG` so denied calls are recorded by the audit
    /// subsystem even when the filter is enforcing.
    pub log: bool,
}

impl Default for SeccompOptions {
    fn default() -> Self {
        Self {
            mode: SeccompMode::Off,
            profile_path: None,
            capture_path: None,
            action: SeccompAction::Errno,
            order: SyscallOrder::ByFrequency,
            log: false,
        }
    }
}

impl SeccompOptions {
    pub fn filter_flags(&self) -> u64 {
        if self.log {
            libc::SECCOMP_FILTER_FLAG_LOG
        } else {
            0
        }
    }
}

/// Validates the flag combination and fills in defaults.
pub fn resolve_options(
    mode: SeccompMode,
    profile_path: Option<PathBuf>,
    capture_path: Option<PathBuf>,
    action: SeccompAction,
    order: SyscallOrder,
    log: bool,
    default_capture_path: &Path,
) -> std::result::Result<SeccompOptions, SeccompError> {
    match mode {
        SeccompMode::Enforce if profile_path.is_none() => {
            return Err(SeccompError::MissingProfilePath)
        }
        SeccompMode::Off | SeccompMode::Learn if profile_path.is_some() => {
            return Err(SeccompError::ProfileWithoutEnforce)
        }
        _ => {}
    }

    if mode != SeccompMode::Learn && capture_path.is_some() {
        return Err(SeccompError::CaptureWithoutLearn);
    }

    let capture_path = match mode {
        SeccompMode::Learn => {
            Some(capture_path.unwrap_or_else(|| default_capture_path.to_path_buf()))
        }
        _ => None,
    };

    Ok(SeccompOptions {
        mode,
        profile_path,
        capture_path,
        action,
        order,
        log,
    })
}

/// Loads and compiles the profile in the parent, before `fork`.
///
/// The child installs its filter after `pivot_root`, when the host path of the
/// profile no longer resolves, so the compiled program has to exist before the
/// container is created. Doing it here also means a bad profile fails before
/// any cgroup or network resource is allocated.
pub fn prepare(options: &SeccompOptions) -> anyhow::Result<Option<CompiledProfile>> {
    let SeccompMode::Enforce = options.mode else {
        return Ok(None);
    };

    let path = options
        .profile_path
        .as_deref()
        .ok_or(SeccompError::MissingProfilePath)?;
    let profile = profile::SeccompProfile::load(path)?;
    let compiled = compile::compile(
        &profile,
        CompileOptions {
            default_action: options.action,
            order: options.order,
        },
    )?;

    Ok(Some(compiled))
}

pub fn parse_mode(value: &str) -> std::result::Result<SeccompMode, SeccompError> {
    match value {
        "off" => Ok(SeccompMode::Off),
        "learn" => Ok(SeccompMode::Learn),
        "enforce" => Ok(SeccompMode::Enforce),
        value => Err(SeccompError::InvalidMode {
            value: value.to_string(),
        }),
    }
}

pub fn parse_action(value: &str) -> std::result::Result<SeccompAction, SeccompError> {
    match value {
        "errno" => Ok(SeccompAction::Errno),
        "enosys" => Ok(SeccompAction::Enosys),
        "kill" => Ok(SeccompAction::Kill),
        "log" => Ok(SeccompAction::Log),
        value => Err(SeccompError::InvalidAction {
            value: value.to_string(),
        }),
    }
}

pub fn parse_order(value: &str) -> std::result::Result<SyscallOrder, SeccompError> {
    match value {
        "as-listed" => Ok(SyscallOrder::AsListed),
        "by-number" => Ok(SyscallOrder::ByNumber),
        "by-frequency" => Ok(SyscallOrder::ByFrequency),
        value => Err(SeccompError::InvalidOrder {
            value: value.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_capture() -> PathBuf {
        PathBuf::from("/run/crun-rs/demo/syscalls.json")
    }

    #[test]
    fn learn_filter_traces_every_syscall() {
        let program = learn_filter().expect("learn filter should build");
        let insns = program.as_slice();

        assert_eq!(insns.len(), 2);
        assert_eq!(insns[1].k, libc::SECCOMP_RET_TRACE);
    }

    #[test]
    fn enforce_requires_a_profile_path() {
        let error = resolve_options(
            SeccompMode::Enforce,
            None,
            None,
            SeccompAction::Errno,
            SyscallOrder::ByFrequency,
            false,
            &default_capture(),
        )
        .expect_err("enforce without a profile should be rejected");

        assert!(matches!(error, SeccompError::MissingProfilePath));
    }

    #[test]
    fn a_profile_path_without_enforce_is_rejected() {
        let error = resolve_options(
            SeccompMode::Learn,
            Some(PathBuf::from("/tmp/profile.json")),
            None,
            SeccompAction::Errno,
            SyscallOrder::ByFrequency,
            false,
            &default_capture(),
        )
        .expect_err("a profile path outside enforce should be rejected");

        assert!(matches!(error, SeccompError::ProfileWithoutEnforce));
    }

    #[test]
    fn learn_defaults_the_capture_path_to_the_state_directory() {
        let options = resolve_options(
            SeccompMode::Learn,
            None,
            None,
            SeccompAction::Errno,
            SyscallOrder::ByFrequency,
            false,
            &default_capture(),
        )
        .expect("learn should resolve");

        assert_eq!(options.capture_path, Some(default_capture()));
    }

    #[test]
    fn a_capture_path_without_learn_is_rejected() {
        let error = resolve_options(
            SeccompMode::Off,
            None,
            Some(PathBuf::from("/tmp/capture.json")),
            SeccompAction::Errno,
            SyscallOrder::ByFrequency,
            false,
            &default_capture(),
        )
        .expect_err("a capture path outside learn should be rejected");

        assert!(matches!(error, SeccompError::CaptureWithoutLearn));
    }

    #[test]
    fn only_the_log_flag_sets_a_filter_flag() {
        let mut options = SeccompOptions::default();
        assert_eq!(options.filter_flags(), 0);

        options.log = true;
        assert_eq!(options.filter_flags(), libc::SECCOMP_FILTER_FLAG_LOG);
    }

    #[test]
    fn parses_modes_actions_and_orders_from_strings() {
        assert_eq!(parse_mode("learn").expect("valid"), SeccompMode::Learn);
        assert_eq!(parse_action("kill").expect("valid"), SeccompAction::Kill);
        assert_eq!(
            parse_order("by-number").expect("valid"),
            SyscallOrder::ByNumber
        );
        assert!(parse_mode("nope").is_err());
        assert!(parse_action("nope").is_err());
        assert!(parse_order("nope").is_err());
    }

    #[test]
    fn round_trips_every_mode_through_its_string() {
        for mode in [SeccompMode::Off, SeccompMode::Learn, SeccompMode::Enforce] {
            assert_eq!(parse_mode(mode.as_str()).expect("valid"), mode);
        }
    }

    #[test]
    fn round_trips_every_action_through_its_string() {
        for action in [
            SeccompAction::Errno,
            SeccompAction::Enosys,
            SeccompAction::Kill,
            SeccompAction::Log,
        ] {
            assert_eq!(parse_action(action.as_str()).expect("valid"), action);
        }
    }
}
