# Threat model

What the generated profiles are meant to stop, and what they are not.

## Attacker

An attacker who has achieved arbitrary code execution **inside** the container:
through an application vulnerability, a malicious dependency, or a compromised
image. They run as whatever user the workload runs as, inside its namespaces,
under its cgroup limits.

This is the interesting position because everything before it is somebody else's
problem, and everything after it is the kernel's attack surface.

## Goal

Reach the host: escape the namespaces, gain privileges the container was not
given, or corrupt kernel memory. Every route runs through a syscall.

## What the security layers do

The runtime has two independent security layers. The selected base profile is
applied when the container process is prepared and is reapplied to namespace-
joining `crun exec` sessions. Under `denylist`, it enables `no_new_privs`, removes
capabilities, and denies a fixed set of host-impacting syscalls. Under
`unconfined`, this base hardening is intentionally skipped.

A generated profile is an optional second layer. It denies the syscalls the
workload never used when `--seccomp enforce` is selected, and the same generated
filter is installed for `crun exec` enforcement. Healthchecks deliberately do not
install this generated allowlist: they are operator-supplied probes, not the
captured workload. They still receive the selected base profile, so omitting the
allowlist does not make a `denylist` healthcheck unrestricted.

An exploit needing a denied syscall fails at the boundary rather than in the
kernel, regardless of whether the underlying bug is present, exploitable, or
even known. That is the property being measured: not "this CVE is patched" but
"this route does not exist for this container".

## What it does not do

**Anything reachable through a syscall the workload needs.** nginx reads and
writes files and sockets, so a bug in `read`, `write`, `sendmsg` or `epoll_wait`
is fully reachable under nginx's own profile. Minimality bounds the surface; it
does not eliminate it.

**Argument-level attacks.** The filter compares syscall numbers only. A workload
that legitimately calls `socket` can still open `AF_NETLINK`; one that calls
`ioctl` can issue any command. Argument filtering exists in seccomp for
scalar arguments and could narrow some of these, but is not implemented here.

**Anything below the syscall interface.** Speculative execution, DMA, firmware,
and hypervisor bugs are all out of scope.

**The runtime itself.** A bug in `crun` that lets a container influence what the
runtime does before the filter is installed is not covered by the filter. The
memfd self-exec in `selfexec.rs` addresses one specific instance of this class,
where a container overwrites the runtime binary through `/proc/self/exe`.

**The generated allowlist does not cover healthcheck probes.** They are not a
fully confined execution context under the optional generated profile, but the
base `denylist` security layer still applies. `crun exec` sessions get the
container's generated filter when enforcement is enabled.

## Trust boundaries

| Component | Trusted |
|---|---|
| The kernel | yes, and it is what the profile protects |
| The runtime before fork | yes |
| The bundle configuration | yes, it comes from the operator |
| The image filesystem | no |
| The workload process | no, this is the attacker |
| A generated profile | as data, yes; it is produced by the operator's own run |

## Assumption about profile generation

The learn run is assumed to be benign. A profile learned from an already
compromised workload would allow whatever the attacker used, so profiles must be
generated from a trusted run of a trusted image, in the same way a golden image
is built before it is deployed.
