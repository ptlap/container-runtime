use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::libc;
use nix::sys::prctl;
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

pub fn apply(profile: SecurityProfile) -> Result<()> {
    match profile {
        SecurityProfile::Default => {
            prctl::set_no_new_privs()
                .context("failed to enable no_new_privs for default security profile")?;
            drop_capabilities().context("failed to drop capabilities for default security profile")
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
}
