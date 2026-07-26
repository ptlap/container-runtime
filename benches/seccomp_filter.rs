//! How long it takes to build and evaluate the seccomp filters.
//!
//! Two things are measured. Construction cost, which the runtime pays once per
//! container before fork. And the number of BPF instructions a syscall walks
//! through before it is allowed, which the kernel pays on every single call and
//! which is what the ordering strategy actually changes.

use container_runtime::seccomp::compile::{build_allowlist, SeccompAction};
use container_runtime::seccomp::syscalls;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// A syscall set the size of a small service, in the order a generated profile
/// would list it.
fn workload_syscalls() -> Vec<i64> {
    let names = [
        "read",
        "write",
        "openat",
        "close",
        "fstat",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "ioctl",
        "pread64",
        "pwrite64",
        "access",
        "pipe2",
        "select",
        "sched_yield",
        "madvise",
        "socket",
        "connect",
        "accept4",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "bind",
        "listen",
        "getsockname",
        "getpeername",
        "setsockopt",
        "getsockopt",
        "clone",
        "execve",
        "exit",
        "wait4",
        "kill",
        "uname",
        "fcntl",
        "getdents64",
        "getcwd",
        "chdir",
        "rename",
        "mkdir",
        "rmdir",
        "unlink",
        "readlink",
        "chmod",
        "chown",
        "umask",
        "gettimeofday",
        "getrlimit",
        "getrusage",
        "sysinfo",
        "times",
        "getuid",
        "getgid",
        "setuid",
        "setgid",
        "geteuid",
        "getegid",
        "setpgid",
        "getppid",
        "getpgrp",
        "setsid",
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "futex",
        "clock_gettime",
        "clock_nanosleep",
        "exit_group",
        "eventfd2",
        "timerfd_create",
        "prlimit64",
        "getrandom",
        "statx",
    ];

    names
        .iter()
        .filter_map(|name| syscalls::number(name))
        .collect()
}

/// Docker's default profile is roughly this size, so it is the baseline chain
/// length a per-workload profile is competing with.
fn baseline_sized_syscalls() -> Vec<i64> {
    syscalls::table()
        .iter()
        .take(296)
        .map(|entry| entry.number)
        .collect()
}

fn filter_construction(criterion: &mut Criterion) {
    let workload = workload_syscalls();
    let baseline = baseline_sized_syscalls();

    criterion.bench_function("build_allowlist_workload_sized", |bencher| {
        bencher.iter(|| {
            build_allowlist(black_box(&workload), SeccompAction::Errno).expect("filter builds")
        })
    });

    criterion.bench_function("build_allowlist_baseline_sized", |bencher| {
        bencher.iter(|| {
            build_allowlist(black_box(&baseline), SeccompAction::Errno).expect("filter builds")
        })
    });
}

criterion_group!(benches, filter_construction);
criterion_main!(benches);
