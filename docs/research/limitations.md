# Limitations

What this runtime and this method do not do. Stated here so the evaluation can
reference them rather than discovering them under questioning.

## Method

**Dynamic tracing sees only the paths that ran.** A profile learned from a run
that never hit an error path, never rotated a log, never reloaded its
configuration and never renegotiated TLS will not allow the syscalls those paths
need. Mitigations, all implemented: a mandatory baseline unioned into every
profile, merging captures across runs, `--seccomp-action log` to validate
without enforcing, and `firstSeenMs` in every capture so the discovery curve
shows whether a run had stopped finding new syscalls before it ended. None of
them makes the method sound the way static analysis is sound.

**The vDSO hides syscalls.** `clock_gettime`, `gettimeofday`, `time`, `getcpu`
and `clock_getres` are answered in user space on most builds and never enter the
kernel, so no tracer sees them. A profile learned on such a host would break
where they are issued for real, which is why they are in the mandatory baseline
whether or not they were observed. The same reasoning covers `rt_sigreturn` and
`restart_syscall`, which only appear if a signal arrives during the capture.

**Syscall numbers are a coarse unit.** A filter cannot distinguish `AF_NETLINK`
from `AF_INET` in `socket`, one `ioctl` command from another, or one `prctl`
option from another. Any CVE reachable through a syscall the workload needs is
not mitigated, however small the profile is. The CVE figure measures filter
potential, not exploit prevention.

**Profiles are tied to a libc and a kernel.** A glibc upgrade that starts using
`clone3`, `rseq`, `faccessat2` or `statx` can break a profile learned against
the older build. `--compat` unions in that set at the cost of a slightly wider
surface, and the two counts are reported separately.

**The learned set is a subset of what the security profile permits.** Under
`--security default --seccomp learn` the 16 denylisted syscalls return EPERM
before reaching the tracer, so they can never enter a generated profile. That is
intended, but it means the numbers describe "syscalls the workload used that the
denylist allowed", not "syscalls the workload attempted".

**Tracing changes timing.** Each traced syscall costs two context switches and
two ptrace operations against roughly 0.3 µs for the syscall itself. Beyond
being slow, it changes *which* code runs: an internal timeout can fire under
tracing that would never fire natively. Learn-mode runs are therefore never used
for performance figures.

## Runtime

**`crun exec` applies the profile, healthchecks do not.** seccomp is not
inherited through `setns`, so an exec session has to install the container's
filter itself; it now does. Healthchecks deliberately still run unfiltered:
they are the operator's own probe rather than container-controlled code, and
confining them would report a container as unhealthy whenever its profile is
narrower than its probe.

**`create` and `start` are not OCI conformant.** `create` writes a state file and
creates no process; `start` does the whole fork and exec and blocks until the
container exits. There is no detached mode. Scripts and tests background the
`crun run` process from the shell instead, which is sufficient for every
measurement here but is not what the specification describes.

**Cleanup depends on the foreground process surviving.** Teardown of the cgroup,
veth pair, NAT rules and state file happens in a `Drop` implementation, which
does not run when the runtime is killed with SIGKILL. `crun doctor --fix`
recovers afterwards rather than preventing the leak.

**`--net bridge` has no bridge.** It creates a veth pair per container with its
own /24 and NATs it, so a container can reach the host and the internet but not
another container. Any experiment needing container-to-container traffic is out
of scope; host-as-client covers everything in the corpus.

**`/dev` is minimal.** `/dev/null`, `/dev/zero`, `/dev/random`, `/dev/urandom`,
`/dev/shm` and the `/dev/stdout` family of links. No `/dev/pts` unless the bundle
declares it, no `/dev/console`.

## Corpus

Two workloads needed adaptation, both declared in `workloads/workloads.json` and
reported when applied:

**nginx** points `/var/log/nginx/access.log` and `error.log` at `/dev/stdout`
and `/dev/stderr`. The runtime now creates those links, but the manifest still
replaces them with regular files so the measurement does not depend on that
detail.

**postgres** runs `initdb` on first boot through its entrypoint, which would
make iteration 1 differ from every later one. The manifest initialises the data
directory once under Docker and exports that container, so every measured run
starts from the same state.

Both adaptations are evidence for this chapter rather than against the result:
they are the runtime's gaps, made visible.
