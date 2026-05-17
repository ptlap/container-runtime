use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::libc;
use nix::sys::prctl;
use serde::{Deserialize, Serialize};

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const CAPABILITY_U32S: usize = 2;
const SECCOMP_DATA_NR_OFFSET: u32 = 0;

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

pub fn apply(profile: SecurityProfile) -> Result<()> {
    match profile {
        SecurityProfile::Default => {
            prctl::set_no_new_privs()
                .context("failed to enable no_new_privs for default security profile")?;
            drop_capabilities()
                .context("failed to drop capabilities for default security profile")?;
            install_seccomp_filter()
                .context("failed to install seccomp filter for default security profile")
        }
        SecurityProfile::Unconfined => Ok(()),
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
    let mut filter = seccomp_denylist_filter();
    let mut program = libc::sock_fprog {
        len: filter
            .len()
            .try_into()
            .context("seccomp filter has too many instructions")?,
        filter: filter.as_mut_ptr(),
    };

    let result = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &mut program as *mut libc::sock_fprog,
        )
    };

    Errno::result(result)
        .map(drop)
        .context("prctl seccomp failed")
}

fn seccomp_denylist_filter() -> Vec<libc::sock_filter> {
    let mut filter = Vec::new();
    filter.push(bpf_stmt(
        libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
        SECCOMP_DATA_NR_OFFSET,
    ));

    for syscall in denied_syscalls() {
        filter.push(bpf_jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            *syscall as u32,
            0,
            1,
        ));
        filter.push(bpf_stmt(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
    }

    filter.push(bpf_stmt(
        libc::BPF_RET | libc::BPF_K,
        libc::SECCOMP_RET_ALLOW,
    ));
    filter
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

fn bpf_stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
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
        let filter = seccomp_denylist_filter();

        assert_eq!(
            filter.first().map(|item| item.k),
            Some(SECCOMP_DATA_NR_OFFSET)
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
}
