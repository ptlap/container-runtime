//! Classic BPF primitives for building seccomp filter programs.
//!
//! The runtime builds its filters by hand rather than through libseccomp, so
//! this module owns every raw `sock_filter` detail and the rest of the codebase
//! works with [`FilterBuilder`] and [`Program`].

use crate::error::SeccompError;
use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::libc;

/// Kernel limit on the number of instructions in one filter (`BPF_MAXINSNS`).
pub const MAX_BPF_INSNS: usize = 4096;

/// Offset of `seccomp_data.nr`.
pub const SECCOMP_DATA_NR_OFFSET: u32 = 0;
/// Offset of `seccomp_data.arch`.
pub const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;

pub fn stmt(code: u32, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

pub fn jump(code: u32, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

#[derive(Debug, Default)]
pub struct FilterBuilder {
    insns: Vec<libc::sock_filter>,
}

impl FilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads `seccomp_data.arch` into the accumulator.
    pub fn load_arch(mut self) -> Self {
        self.insns.push(stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            SECCOMP_DATA_ARCH_OFFSET,
        ));
        self
    }

    /// Loads `seccomp_data.nr` into the accumulator.
    pub fn load_syscall_nr(mut self) -> Self {
        self.insns.push(stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            SECCOMP_DATA_NR_OFFSET,
        ));
        self
    }

    pub fn ret(mut self, action: u32) -> Self {
        self.insns.push(stmt(libc::BPF_RET | libc::BPF_K, action));
        self
    }

    /// `accumulator == k` returns `action`, otherwise execution falls through.
    ///
    /// The return instruction is emitted inline so the jump offsets stay at 0
    /// and 1 no matter how long the chain grows. That is what keeps an
    /// allowlist of arbitrary length within the `u8` range of `jt`/`jf`.
    pub fn jeq_then_ret(mut self, k: u32, action: u32) -> Self {
        self.insns
            .push(jump(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, k, 0, 1));
        self.ret(action)
    }

    /// `accumulator != k` returns `action`, otherwise execution falls through.
    pub fn jne_then_ret(mut self, k: u32, action: u32) -> Self {
        self.insns
            .push(jump(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, k, 1, 0));
        self.ret(action)
    }

    /// `accumulator >= k` returns `action`, otherwise execution falls through.
    pub fn jge_then_ret(mut self, k: u32, action: u32) -> Self {
        self.insns
            .push(jump(libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K, k, 0, 1));
        self.ret(action)
    }

    pub fn len(&self) -> usize {
        self.insns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    pub fn build(self) -> std::result::Result<Program, SeccompError> {
        let program = Program { insns: self.insns };
        program.validate()?;
        Ok(program)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    insns: Vec<libc::sock_filter>,
}

impl Program {
    pub fn len(&self) -> usize {
        self.insns.len()
    }

    pub fn is_empty(&self) -> bool {
        self.insns.is_empty()
    }

    pub fn as_slice(&self) -> &[libc::sock_filter] {
        &self.insns
    }

    /// Rejects programs the kernel would refuse, so failures surface in the
    /// parent before the container is forked rather than inside the child.
    pub fn validate(&self) -> std::result::Result<(), SeccompError> {
        if self.insns.is_empty() {
            return Err(SeccompError::EmptyProgram);
        }

        if self.insns.len() > MAX_BPF_INSNS {
            return Err(SeccompError::ProgramTooLong {
                length: self.insns.len(),
                limit: MAX_BPF_INSNS,
            });
        }

        let last = self.insns[self.insns.len() - 1];
        if u32::from(last.code) & (libc::BPF_RET | libc::BPF_K) != (libc::BPF_RET | libc::BPF_K) {
            return Err(SeccompError::ProgramDoesNotEndInReturn);
        }

        for (index, insn) in self.insns.iter().enumerate() {
            let class = u32::from(insn.code) & 0x07;
            if class != libc::BPF_JMP {
                continue;
            }
            for offset in [insn.jt, insn.jf] {
                let target = index + 1 + usize::from(offset);
                if target >= self.insns.len() {
                    return Err(SeccompError::JumpOutOfRange { index, target });
                }
            }
        }

        Ok(())
    }

    /// Installs the filter on the calling thread.
    ///
    /// `seccomp(2)` is used rather than `prctl(PR_SET_SECCOMP)` because only it
    /// accepts flags, and `SECCOMP_FILTER_FLAG_LOG` is what makes a dry run of
    /// a generated profile possible. Kernels without the syscall fall back to
    /// `prctl`, which is equivalent when no flags are requested.
    pub fn install(&self, flags: u64) -> Result<()> {
        let mut insns = self.insns.clone();
        let mut program = libc::sock_fprog {
            len: insns
                .len()
                .try_into()
                .map_err(|_| SeccompError::ProgramTooLong {
                    length: insns.len(),
                    limit: MAX_BPF_INSNS,
                })?,
            filter: insns.as_mut_ptr(),
        };

        let result = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                flags,
                &program as *const libc::sock_fprog,
            )
        };

        if result == 0 {
            return Ok(());
        }

        let errno = Errno::last();
        if flags == 0 && matches!(errno, Errno::ENOSYS | Errno::EINVAL) {
            let result = unsafe {
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &mut program as *mut libc::sock_fprog,
                )
            };
            return Errno::result(result)
                .map(drop)
                .context("prctl seccomp failed");
        }

        Err(errno).context("seccomp filter install failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_the_expected_instruction_sequence() {
        let program = FilterBuilder::new()
            .load_arch()
            .jne_then_ret(0xc000_003e, libc::SECCOMP_RET_KILL_PROCESS)
            .load_syscall_nr()
            .jeq_then_ret(0, libc::SECCOMP_RET_ALLOW)
            .ret(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32)
            .build()
            .expect("program should build");

        // load arch, arch compare, arch reject, load nr, syscall compare,
        // syscall allow, default reject.
        assert_eq!(program.len(), 7);
        let insns = program.as_slice();
        assert_eq!(insns[0].k, SECCOMP_DATA_ARCH_OFFSET);
        assert_eq!(insns[1].k, 0xc000_003e);
        assert_eq!(insns[2].k, libc::SECCOMP_RET_KILL_PROCESS);
        assert_eq!(insns[3].k, SECCOMP_DATA_NR_OFFSET);
        assert_eq!(insns[4].k, 0);
        assert_eq!(insns[5].k, libc::SECCOMP_RET_ALLOW);
        assert_eq!(insns[6].k, libc::SECCOMP_RET_ERRNO | libc::EPERM as u32);
    }

    #[test]
    fn keeps_jump_offsets_within_one_for_long_chains() {
        let mut builder = FilterBuilder::new().load_arch().load_syscall_nr();
        for syscall in 0..2000 {
            builder = builder.jeq_then_ret(syscall, libc::SECCOMP_RET_ALLOW);
        }
        let program = builder
            .ret(libc::SECCOMP_RET_ERRNO | libc::EPERM as u32)
            .build()
            .expect("a 2000 syscall allowlist should build");

        assert_eq!(program.len(), 2 + 2 * 2000 + 1);
        assert!(program
            .as_slice()
            .iter()
            .all(|insn| insn.jt <= 1 && insn.jf <= 1));
    }

    #[test]
    fn rejects_programs_over_the_instruction_limit() {
        let mut builder = FilterBuilder::new().load_arch().load_syscall_nr();
        for syscall in 0..3000 {
            builder = builder.jeq_then_ret(syscall, libc::SECCOMP_RET_ALLOW);
        }
        let error = builder
            .ret(libc::SECCOMP_RET_ALLOW)
            .build()
            .expect_err("an oversized program should be rejected");

        assert!(matches!(error, SeccompError::ProgramTooLong { .. }));
    }

    #[test]
    fn rejects_a_program_that_does_not_end_in_a_return() {
        let error = FilterBuilder::new()
            .load_arch()
            .build()
            .expect_err("a program without a return should be rejected");

        assert!(matches!(error, SeccompError::ProgramDoesNotEndInReturn));
    }

    #[test]
    fn rejects_an_empty_program() {
        let error = FilterBuilder::new()
            .build()
            .expect_err("an empty program should be rejected");

        assert!(matches!(error, SeccompError::EmptyProgram));
    }

    #[test]
    fn rejects_a_jump_past_the_end_of_the_program() {
        let program = Program {
            insns: vec![
                jump(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, 0, 9, 0),
                stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
            ],
        };

        assert!(matches!(
            program.validate(),
            Err(SeccompError::JumpOutOfRange { .. })
        ));
    }
}
