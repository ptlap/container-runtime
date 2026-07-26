//! Architecture identifiers shared by filter construction and syscall tables.

use crate::error::SeccompError;
use oci_spec::runtime::Arch;

/// `AUDIT_ARCH_*` value the kernel reports in `seccomp_data.arch` for natively
/// compiled binaries. The values come from the OCI spec crate so the filter and
/// the emitted profile can never disagree about what an architecture is.
#[cfg(target_arch = "x86_64")]
pub const AUDIT_ARCH_NATIVE: u32 = Arch::ScmpArchX86_64 as u32;

#[cfg(target_arch = "aarch64")]
pub const AUDIT_ARCH_NATIVE: u32 = Arch::ScmpArchAarch64 as u32;

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const AUDIT_ARCH_NATIVE: u32 = 0;

/// The x32 ABI reuses x86_64 syscall numbers with this bit set. A filter that
/// only compares low numbers would let x32 callers through, so it is rejected
/// explicitly.
#[cfg(target_arch = "x86_64")]
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[cfg(target_arch = "x86_64")]
pub const NATIVE_ARCH_NAME: &str = "x86_64";

#[cfg(target_arch = "aarch64")]
pub const NATIVE_ARCH_NAME: &str = "aarch64";

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const NATIVE_ARCH_NAME: &str = "unsupported";

pub fn native_oci_arch() -> std::result::Result<Arch, SeccompError> {
    #[cfg(target_arch = "x86_64")]
    {
        Ok(Arch::ScmpArchX86_64)
    }

    #[cfg(target_arch = "aarch64")]
    {
        Ok(Arch::ScmpArchAarch64)
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(SeccompError::UnsupportedArchitecture)
    }
}

pub fn ensure_supported() -> std::result::Result<(), SeccompError> {
    if AUDIT_ARCH_NATIVE == 0 {
        return Err(SeccompError::UnsupportedArchitecture);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_audit_arch_matches_the_oci_architecture() {
        ensure_supported().expect("the test host must be a supported architecture");
        let arch = native_oci_arch().expect("native arch should resolve");

        assert_eq!(arch as u32, AUDIT_ARCH_NATIVE);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn uses_the_documented_x86_64_audit_value() {
        assert_eq!(AUDIT_ARCH_NATIVE, 0xc000_003e);
        assert_eq!(NATIVE_ARCH_NAME, "x86_64");
    }
}
