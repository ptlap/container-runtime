//! Seccomp filter construction, syscall tables and profile handling.
//!
//! The runtime builds three kinds of filter:
//!
//! * the fixed denylist behind `--security default`,
//! * a trace-everything filter used while learning a workload's syscall set,
//! * an allowlist compiled from a generated profile.

pub mod arch;
pub mod bpf;
pub mod compile;
pub mod profile;
pub mod syscalls;

#[cfg(target_arch = "aarch64")]
mod syscalls_aarch64;
#[cfg(target_arch = "x86_64")]
mod syscalls_x86_64;

pub use arch::{AUDIT_ARCH_NATIVE, NATIVE_ARCH_NAME};
pub use bpf::{FilterBuilder, Program};
