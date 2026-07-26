use crate::seccomp::arch::{self, AUDIT_ARCH_NATIVE};
use crate::seccomp::bpf::{FilterBuilder, Program};
use crate::seccomp::{self, SeccompPlan};
use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::libc;
use nix::sys::prctl;
use nix::sys::ptrace;
use nix::sys::signal::{raise, Signal};
use serde::{Deserialize, Serialize};

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAPABILITY_U32S: usize = 2;

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    Default,
    Unconfined,
}

impl SecurityProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Unconfined => "unconfined",
        }
    }
}

/// Applies the security profile and any seccomp plan, in the child, just before
/// `execvp`.
///
/// Installing a seccomp filter needs `no_new_privs` or `CAP_SYS_ADMIN`, so it is
/// enabled whenever a plan is active rather than only for the default profile;
/// otherwise `--security unconfined --seccomp enforce` would depend on the
/// runtime happening to run as root.
pub fn apply(profile: SecurityProfile, plan: SeccompPlan<'_>) -> Result<()> {
    if profile == SecurityProfile::Default || !plan.is_none() {
        prctl::set_no_new_privs().context("failed to enable no_new_privs")?;
    }

    if profile == SecurityProfile::Default {
        drop_capabilities().context("failed to drop capabilities for default security profile")?;
        install_seccomp_filter()
            .context("failed to install seccomp filter for default security profile")?;
    }

    match plan {
        SeccompPlan::None => Ok(()),
        SeccompPlan::Learn => {
            // The tracer has to be attached and its options set before the
            // trace filter goes in: a SECCOMP_RET_TRACE syscall with no tracer
            // fails with ENOSYS, which would break the calls this function
            // still has to make before exec.
            ptrace::traceme().context("failed to enable tracing for seccomp learn mode")?;
            raise(Signal::SIGSTOP).context("failed to stop for the seccomp tracer")?;

            seccomp::learn_filter()?
                .install(0)
                .context("failed to install the seccomp trace filter")
        }
        SeccompPlan::Enforce { program, flags } => program
            .install(flags)
            .context("failed to install the seccomp allowlist"),
    }
}

fn drop_capabilities() -> Result<()> {
    let mut header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = empty_capability_data();

    let result = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapUserHeader,
            data.as_ptr(),
        )
    };

    Errno::result(result).map(drop).context("capset failed")
}

fn empty_capability_data() -> [CapUserData; CAPABILITY_U32S] {
    [CapUserData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; CAPABILITY_U32S]
}

fn install_seccomp_filter() -> Result<()> {
    seccomp_denylist_filter()?.install(0)
}

/// Denies a fixed set of host-impacting syscalls and lets everything else
/// through. This is the historical `--security default` behaviour; the
/// generated allowlists live in [`crate::seccomp`].
fn seccomp_denylist_filter() -> Result<Program> {
    arch::ensure_supported()?;

    let deny = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    let mut builder = FilterBuilder::new()
        .load_arch()
        .jne_then_ret(AUDIT_ARCH_NATIVE, deny)
        .load_syscall_nr();

    for syscall in denied_syscalls() {
        builder = builder.jeq_then_ret(*syscall as u32, deny);
    }

    Ok(builder.ret(libc::SECCOMP_RET_ALLOW).build()?)
}

fn denied_syscalls() -> &'static [libc::c_long] {
    &[
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_reboot,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
        libc::SYS_ptrace,
        libc::SYS_bpf,
        libc::SYS_keyctl,
        libc::SYS_open_by_handle_at,
        libc::SYS_unshare,
        libc::SYS_setns,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_security_profiles_for_state() {
        assert_eq!(SecurityProfile::Default.as_str(), "default");
        assert_eq!(SecurityProfile::Unconfined.as_str(), "unconfined");
    }

    #[test]
    fn empty_capability_data_clears_all_sets() {
        let data = empty_capability_data();

        assert_eq!(data.len(), 2);
        assert!(data
            .iter()
            .all(|item| item.effective == 0 && item.permitted == 0 && item.inheritable == 0));
    }

    #[test]
    fn seccomp_filter_denies_expected_syscalls_and_allows_rest() {
        let program = seccomp_denylist_filter().expect("denylist should build");
        let filter = program.as_slice();

        assert_eq!(
            filter.first().map(|item| item.k),
            Some(crate::seccomp::bpf::SECCOMP_DATA_ARCH_OFFSET)
        );
        assert_eq!(
            filter.last().map(|item| item.k),
            Some(libc::SECCOMP_RET_ALLOW)
        );
        assert!(filter
            .windows(2)
            .any(|items| items[0].k == libc::SYS_mount as u32
                && items[1].k == (libc::SECCOMP_RET_ERRNO | libc::EPERM as u32)));
    }

    #[test]
    fn denylist_rejects_foreign_architectures_before_reading_the_syscall() {
        let program = seccomp_denylist_filter().expect("denylist should build");
        let filter = program.as_slice();

        assert_eq!(filter[1].k, AUDIT_ARCH_NATIVE);
        assert_eq!(filter[1].jt, 1, "a native arch must skip the reject");
        assert_eq!(
            filter[2].k,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            "a foreign arch must be rejected"
        );
    }

    #[test]
    fn denylist_covers_every_denied_syscall() {
        let program = seccomp_denylist_filter().expect("denylist should build");
        let filter = program.as_slice();

        for syscall in denied_syscalls() {
            assert!(
                filter.iter().any(|item| item.k == *syscall as u32),
                "syscall {syscall} is missing from the denylist filter"
            );
        }
    }
}
