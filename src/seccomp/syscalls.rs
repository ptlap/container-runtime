//! Syscall name and number lookup for the running architecture.

use super::arch::NATIVE_ARCH_NAME;

#[cfg(target_arch = "x86_64")]
use super::syscalls_x86_64 as table_data;

#[cfg(target_arch = "aarch64")]
use super::syscalls_aarch64 as table_data;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallEntry {
    pub name: &'static str,
    pub number: i64,
}

/// All syscalls this architecture defines, sorted by name.
pub fn table() -> &'static [SyscallEntry] {
    table_data::TABLE
}

/// All syscalls this architecture defines, sorted by number.
pub fn table_by_number() -> &'static [SyscallEntry] {
    table_data::BY_NUMBER
}

pub fn number(name: &str) -> Option<i64> {
    table()
        .binary_search_by(|entry| entry.name.cmp(name))
        .ok()
        .map(|index| table()[index].number)
}

pub fn name(number: i64) -> Option<&'static str> {
    table_by_number()
        .binary_search_by(|entry| entry.number.cmp(&number))
        .ok()
        .map(|index| table_by_number()[index].name)
}

pub fn arch_name() -> &'static str {
    NATIVE_ARCH_NAME
}

/// Resolves profile syscall names, reporting the ones this architecture does
/// not know so the caller can surface them rather than silently dropping them.
pub fn resolve_all<I, S>(names: I) -> (Vec<i64>, Vec<String>)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut resolved = Vec::new();
    let mut unresolved = Vec::new();

    for item in names {
        let item = item.as_ref();
        match number(item) {
            Some(value) => resolved.push(value),
            None => unresolved.push(item.to_string()),
        }
    }

    resolved.sort_unstable();
    resolved.dedup();
    unresolved.sort();
    unresolved.dedup();

    (resolved, unresolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::libc;

    #[test]
    fn table_is_sorted_by_name_without_duplicates() {
        let entries = table();
        assert!(!entries.is_empty());

        for pair in entries.windows(2) {
            assert!(
                pair[0].name < pair[1].name,
                "{} is not before {}",
                pair[0].name,
                pair[1].name
            );
        }
    }

    #[test]
    fn table_by_number_is_sorted_without_duplicates() {
        for pair in table_by_number().windows(2) {
            assert!(
                pair[0].number < pair[1].number,
                "{} is not before {}",
                pair[0].number,
                pair[1].number
            );
        }
    }

    #[test]
    fn resolves_every_entry_back_to_its_own_name() {
        for entry in table() {
            assert_eq!(number(entry.name), Some(entry.number), "{}", entry.name);
            assert_eq!(name(entry.number), Some(entry.name), "{}", entry.name);
        }
    }

    #[test]
    fn numbers_match_libc_for_common_syscalls() {
        let expected: &[(&str, i64)] = &[
            ("read", libc::SYS_read),
            ("write", libc::SYS_write),
            ("close", libc::SYS_close),
            ("openat", libc::SYS_openat),
            ("mmap", libc::SYS_mmap),
            ("mprotect", libc::SYS_mprotect),
            ("munmap", libc::SYS_munmap),
            ("brk", libc::SYS_brk),
            ("rt_sigaction", libc::SYS_rt_sigaction),
            ("rt_sigprocmask", libc::SYS_rt_sigprocmask),
            ("rt_sigreturn", libc::SYS_rt_sigreturn),
            ("ioctl", libc::SYS_ioctl),
            ("clone", libc::SYS_clone),
            ("execve", libc::SYS_execve),
            ("exit", libc::SYS_exit),
            ("exit_group", libc::SYS_exit_group),
            ("wait4", libc::SYS_wait4),
            ("kill", libc::SYS_kill),
            ("futex", libc::SYS_futex),
            ("getpid", libc::SYS_getpid),
            ("getuid", libc::SYS_getuid),
            ("setuid", libc::SYS_setuid),
            ("setgid", libc::SYS_setgid),
            ("socket", libc::SYS_socket),
            ("connect", libc::SYS_connect),
            ("bind", libc::SYS_bind),
            ("listen", libc::SYS_listen),
            ("accept4", libc::SYS_accept4),
            ("sendto", libc::SYS_sendto),
            ("recvfrom", libc::SYS_recvfrom),
            ("setsockopt", libc::SYS_setsockopt),
            ("epoll_create1", libc::SYS_epoll_create1),
            ("epoll_ctl", libc::SYS_epoll_ctl),
            ("epoll_pwait", libc::SYS_epoll_pwait),
            ("nanosleep", libc::SYS_nanosleep),
            ("clock_gettime", libc::SYS_clock_gettime),
            ("getrandom", libc::SYS_getrandom),
            ("statx", libc::SYS_statx),
            ("mount", libc::SYS_mount),
            ("ptrace", libc::SYS_ptrace),
            ("seccomp", libc::SYS_seccomp),
            ("splice", libc::SYS_splice),
            ("keyctl", libc::SYS_keyctl),
            ("bpf", libc::SYS_bpf),
            ("unshare", libc::SYS_unshare),
            ("setns", libc::SYS_setns),
        ];

        for (syscall, value) in expected {
            assert_eq!(
                number(syscall),
                Some(*value),
                "generated table disagrees with libc for {syscall}"
            );
        }
    }

    #[test]
    fn reports_names_this_architecture_does_not_define() {
        let (resolved, unresolved) = resolve_all(["read", "write", "definitely_not_a_syscall"]);

        assert_eq!(resolved.len(), 2);
        assert_eq!(unresolved, vec!["definitely_not_a_syscall".to_string()]);
    }

    #[test]
    fn deduplicates_and_sorts_resolved_numbers() {
        let (resolved, _) = resolve_all(["write", "read", "read"]);

        assert_eq!(
            resolved,
            vec![
                number("read").expect("read exists"),
                number("write").expect("write exists"),
            ]
        );
    }
}
