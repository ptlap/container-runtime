//! Compiles a profile into an installable seccomp program.

use super::arch::{self, AUDIT_ARCH_NATIVE};
use super::bpf::{FilterBuilder, Program};
use super::profile::SeccompProfile;
use super::syscalls;
use crate::error::SeccompError;
use nix::libc;
use oci_spec::runtime::LinuxSeccompAction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SeccompAction {
    /// Fail the call with EPERM. Matches Docker's default and degrades rather
    /// than killing when a learned profile turns out to be incomplete.
    Errno,
    /// Fail the call with ENOSYS, which libc reads as "this kernel is older
    /// than I thought" and answers with its own fallback path.
    Enosys,
    /// Kill the whole process, so a violation is unambiguous.
    Kill,
    /// Allow the call but record it. Turns a profile into a dry run.
    Log,
}

impl SeccompAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Errno => "errno",
            Self::Enosys => "enosys",
            Self::Kill => "kill",
            Self::Log => "log",
        }
    }

    pub fn to_bpf_ret(self) -> u32 {
        match self {
            Self::Errno => libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            Self::Enosys => libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
            Self::Kill => libc::SECCOMP_RET_KILL_PROCESS,
            Self::Log => libc::SECCOMP_RET_LOG,
        }
    }

    pub fn to_oci(self) -> LinuxSeccompAction {
        match self {
            Self::Errno | Self::Enosys => LinuxSeccompAction::ScmpActErrno,
            Self::Kill => LinuxSeccompAction::ScmpActKillProcess,
            Self::Log => LinuxSeccompAction::ScmpActLog,
        }
    }

    pub fn errno(self) -> Option<u32> {
        match self {
            Self::Errno => Some(libc::EPERM as u32),
            Self::Enosys => Some(libc::ENOSYS as u32),
            Self::Kill | Self::Log => None,
        }
    }
}

/// Order of the comparison chain.
///
/// A linear classic BPF chain runs up to two instructions per allowed syscall,
/// so the order decides how much work an average call does. Learn mode records
/// call counts, which lets the hot syscalls be compared first; a profile
/// written by hand has no counts and falls back to numeric order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallOrder {
    AsListed,
    ByNumber,
    ByFrequency,
}

impl SyscallOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AsListed => "as-listed",
            Self::ByNumber => "by-number",
            Self::ByFrequency => "by-frequency",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CompileOptions {
    pub default_action: SeccompAction,
    pub order: SyscallOrder,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            default_action: SeccompAction::Errno,
            order: SyscallOrder::ByFrequency,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledProfile {
    pub program: Program,
    /// Allowed syscall numbers in the order they are compared.
    pub allowed: Vec<i64>,
    /// Profile names this architecture does not define.
    pub unresolved: Vec<String>,
    pub default_action: SeccompAction,
}

pub fn compile(
    profile: &SeccompProfile,
    options: CompileOptions,
) -> std::result::Result<CompiledProfile, SeccompError> {
    arch::ensure_supported()?;
    profile.validate_supported()?;

    let names = profile.allowed_names();
    let (mut allowed, unresolved) = syscalls::resolve_all(&names);
    order_syscalls(&mut allowed, profile, options.order);

    let program = build_allowlist(&allowed, options.default_action)?;

    Ok(CompiledProfile {
        program,
        allowed,
        unresolved,
        default_action: options.default_action,
    })
}

fn order_syscalls(allowed: &mut [i64], profile: &SeccompProfile, order: SyscallOrder) {
    match order {
        SyscallOrder::AsListed | SyscallOrder::ByNumber => {}
        SyscallOrder::ByFrequency => {
            let Some(counts) = profile
                .crun_metadata
                .as_ref()
                .map(|metadata| &metadata.syscall_counts)
                .filter(|counts| !counts.is_empty())
            else {
                return;
            };

            // Descending by observed count, then by number so the result is
            // stable for syscalls that were never seen.
            allowed.sort_by(|left, right| {
                let left_count = syscalls::name(*left)
                    .and_then(|name| counts.get(name))
                    .copied()
                    .unwrap_or(0);
                let right_count = syscalls::name(*right)
                    .and_then(|name| counts.get(name))
                    .copied()
                    .unwrap_or(0);
                right_count.cmp(&left_count).then(left.cmp(right))
            });
        }
    }
}

/// Builds the allowlist program.
///
/// ```text
/// load  seccomp_data.arch
/// jne   native      -> default action     (foreign architectures are denied)
/// load  seccomp_data.nr
/// jge   x32 bit     -> default action     (x86_64 only)
/// jeq   nr          -> allow              (repeated per allowed syscall)
/// ret   default action
/// ```
pub fn build_allowlist(
    allowed: &[i64],
    default_action: SeccompAction,
) -> std::result::Result<Program, SeccompError> {
    arch::ensure_supported()?;

    let deny = default_action.to_bpf_ret();
    let mut builder = FilterBuilder::new()
        .load_arch()
        .jne_then_ret(AUDIT_ARCH_NATIVE, deny)
        .load_syscall_nr();

    // The x32 ABI reuses x86_64 numbers with a high bit set, so a chain that
    // only compares low numbers would let x32 callers through.
    #[cfg(target_arch = "x86_64")]
    {
        builder = builder.jge_then_ret(arch::X32_SYSCALL_BIT, deny);
    }

    for syscall in allowed {
        let number = u32::try_from(*syscall)
            .map_err(|_| SeccompError::InvalidSyscallNumber { number: *syscall })?;
        builder = builder.jeq_then_ret(number, libc::SECCOMP_RET_ALLOW);
    }

    builder.ret(deny).build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seccomp::profile::{build_profile, CrunMetadata, METADATA_SCHEMA_VERSION};
    use std::collections::{BTreeMap, BTreeSet};

    fn names(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    fn metadata_with_counts(counts: &[(&str, u64)]) -> CrunMetadata {
        CrunMetadata {
            schema_version: METADATA_SCHEMA_VERSION,
            generator: "crun-rs".to_string(),
            runtime_version: "0.1.0".to_string(),
            workload: None,
            arch: arch::NATIVE_ARCH_NAME.to_string(),
            audit_arch: AUDIT_ARCH_NATIVE,
            generated_at_unix: 0,
            observed_syscall_count: counts.len(),
            baseline_syscall_count: 0,
            total_syscall_count: counts.len(),
            capture_duration_ms: 0,
            total_events: 0,
            source_runs: Vec::new(),
            unresolved: Vec::new(),
            foreign_arch: BTreeMap::new(),
            syscall_counts: counts
                .iter()
                .map(|(name, count)| (name.to_string(), *count))
                .collect(),
        }
    }

    #[test]
    fn compiles_an_allowlist_that_denies_everything_else() {
        let profile = build_profile(
            &names(&["read", "write"]),
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            None,
        )
        .expect("profile should build");

        let compiled =
            compile(&profile, CompileOptions::default()).expect("profile should compile");
        let insns = compiled.program.as_slice();

        assert_eq!(compiled.allowed.len(), 2);
        assert!(compiled.unresolved.is_empty());
        assert_eq!(
            insns[insns.len() - 1].k,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
        assert!(insns.iter().any(|insn| insn.k == libc::SECCOMP_RET_ALLOW));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn guards_against_the_x32_abi() {
        let program = build_allowlist(&[0], SeccompAction::Errno).expect("program should build");

        assert!(program
            .as_slice()
            .iter()
            .any(|insn| insn.k == arch::X32_SYSCALL_BIT));
    }

    #[test]
    fn compares_the_most_frequent_syscall_first() {
        let profile = build_profile(
            &names(&["read", "write", "futex"]),
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            Some(metadata_with_counts(&[
                ("read", 10),
                ("write", 5),
                ("futex", 900),
            ])),
        )
        .expect("profile should build");

        let compiled = compile(
            &profile,
            CompileOptions {
                default_action: SeccompAction::Errno,
                order: SyscallOrder::ByFrequency,
            },
        )
        .expect("profile should compile");

        assert_eq!(compiled.allowed.first().copied(), syscalls::number("futex"));
        assert_eq!(compiled.allowed.last().copied(), syscalls::number("write"));
    }

    /// Position in the chain is what frequency ordering buys: the emitted
    /// program is a prologue plus two instructions per candidate, so a syscall
    /// compared at position n costs prologue + 2n + 1 instructions on every
    /// call. This asserts the hot syscall really does land at the front.
    #[test]
    fn frequency_ordering_shortens_the_path_for_hot_syscalls() {
        let mut names = BTreeSet::new();
        for entry in syscalls::table().iter().take(120) {
            names.insert(entry.name.to_string());
        }
        names.insert("epoll_pwait".to_string());

        let hot = syscalls::number("epoll_pwait").expect("epoll_pwait exists");
        let profile = build_profile(
            &names,
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            Some(metadata_with_counts(&[("epoll_pwait", 100_000)])),
        )
        .expect("profile should build");

        let by_number = compile(
            &profile,
            CompileOptions {
                default_action: SeccompAction::Errno,
                order: SyscallOrder::ByNumber,
            },
        )
        .expect("profile should compile");
        let by_frequency = compile(
            &profile,
            CompileOptions {
                default_action: SeccompAction::Errno,
                order: SyscallOrder::ByFrequency,
            },
        )
        .expect("profile should compile");

        let position = |compiled: &CompiledProfile| {
            compiled
                .allowed
                .iter()
                .position(|value| *value == hot)
                .expect("the hot syscall is allowed")
        };

        assert_eq!(position(&by_frequency), 0);
        assert!(
            position(&by_number) > 20,
            "numeric order should leave the hot syscall deep in the chain"
        );
        // Same program length either way; only the order changes.
        assert_eq!(by_number.program.len(), by_frequency.program.len());
    }

    #[test]
    fn keeps_numeric_order_without_frequency_data() {
        let profile = build_profile(
            &names(&["write", "read"]),
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            None,
        )
        .expect("profile should build");

        let compiled = compile(
            &profile,
            CompileOptions {
                default_action: SeccompAction::Errno,
                order: SyscallOrder::ByNumber,
            },
        )
        .expect("profile should compile");

        let mut sorted = compiled.allowed.clone();
        sorted.sort_unstable();
        assert_eq!(compiled.allowed, sorted);
    }

    #[test]
    fn reports_names_the_architecture_does_not_define() {
        let profile = build_profile(
            &names(&["read", "definitely_not_a_syscall"]),
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            None,
        )
        .expect("profile should build");

        let compiled =
            compile(&profile, CompileOptions::default()).expect("profile should compile");

        assert_eq!(compiled.allowed.len(), 1);
        assert_eq!(compiled.unresolved, vec!["definitely_not_a_syscall"]);
    }

    #[test]
    fn compiles_an_empty_allowlist_into_a_deny_everything_filter() {
        let profile = build_profile(
            &BTreeSet::new(),
            LinuxSeccompAction::ScmpActErrno,
            Some(1),
            None,
        )
        .expect("profile should build");

        let compiled =
            compile(&profile, CompileOptions::default()).expect("profile should compile");

        assert!(compiled.allowed.is_empty());
        assert!(!compiled
            .program
            .as_slice()
            .iter()
            .any(|insn| insn.k == libc::SECCOMP_RET_ALLOW));
    }

    #[test]
    fn maps_actions_onto_kernel_return_values() {
        assert_eq!(
            SeccompAction::Errno.to_bpf_ret(),
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
        );
        assert_eq!(
            SeccompAction::Enosys.to_bpf_ret(),
            libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
        assert_eq!(
            SeccompAction::Kill.to_bpf_ret(),
            libc::SECCOMP_RET_KILL_PROCESS
        );
        assert_eq!(SeccompAction::Log.to_bpf_ret(), libc::SECCOMP_RET_LOG);
        assert_eq!(
            SeccompAction::Kill.to_oci(),
            LinuxSeccompAction::ScmpActKillProcess
        );
    }
}
