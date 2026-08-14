# Related work

Where automatic syscall policy generation stands, and what this runtime adds.

## The problem

Docker's default seccomp profile allows 296 of the 363 syscalls that exist on
x86_64 for a container with default capabilities. That number is a compromise:
one profile has to run every image anyone might start, so it can only exclude
what is dangerous for everybody. A single workload uses a small fraction of it.
The gap between what a profile permits and what a workload needs is attack
surface that costs nothing to remove, if you can work out what to remove.

## Prior work

**Confine** (Ghavamnia et al., RAID 2020) analyses a container image statically:
it identifies the binaries the image can run, builds a call graph over their
libraries, and derives the syscalls reachable from them. Sound in the sense that
it over-approximates, so it does not break workloads. The over-approximation is
also its cost: indirect calls and `dlopen` force conservative assumptions, and
the resulting profile is larger than what the workload actually uses.

**sysfilter** (DeMarinis et al., RAID 2020) works on binaries rather than
images, extracting the syscall set from an ELF and its dependencies through
static analysis of the call graph. The same trade-off, at a different level: no
false denials by construction, but everything reachable is allowed whether or
not it is ever called.

**Chestnut** (Canella et al., 2021) combines compiler-assisted extraction with a
binary analysis fallback and adds a runtime enforcement layer. It narrows the
set further by using source information where it exists, which is not always.

**DockerSlim** minimises the image rather than the syscall set, using dynamic
observation to strip files that are never touched. Same instinct, applied to the
filesystem; it produces a seccomp profile as a side effect, but the profile is
not the object of the analysis.

## Where this sits

The distinguishing property here is not that tracing is used to derive a
profile. It is **where** the tracing lives: inside the runtime, on the same code
path that later enforces the profile.

That has three consequences the prior work does not have:

1. **No separate tooling step.** `minicrun run --seccomp learn` and `minicrun run
   --seccomp enforce` are the same command with one flag changed, against the
   same bundle, with the same namespace, cgroup and rootfs setup. Nothing about
   the observed run differs from the enforced run except the filter.

2. **Call frequencies, not just call sets.** Because the runtime counts what it
   observes, the generated profile carries per-syscall counts, and the filter
   compiler orders its comparison chain by them. A linear classic BPF chain
   executes up to two instructions per allowed syscall, so putting `read`,
   `write`, `futex` and `epoll_wait` first measurably shortens the average path.
   libseccomp cannot do this: it has no frequency data to sort by.

3. **The runtime can report on itself.** `minicrun inspect-security` shows the mode,
   the profile and how many syscalls it allows; `minicrun seccomp compare` measures
   a profile against Docker's and against a CVE dataset from inside the same
   tool that produced it.

The honest counterpoint, which belongs in the limitations chapter rather than
hidden: dynamic tracing observes only the paths that were exercised. Static
analysis over-approximates and never breaks a workload; this approach
under-approximates and can. That is why every generated profile unions in a
mandatory baseline, why profiles are merged across runs, and why
`--seccomp-action log` exists to validate a profile without enforcing it.

## Comparison

| | Confine | sysfilter | Chestnut | DockerSlim | This work |
|---|---|---|---|---|---|
| Analysis | static, image | static, binary | compiler + binary | dynamic, files | dynamic, syscalls |
| Lives in the runtime | no | no | no | no | **yes** |
| Breaks workloads | no | no | no | rarely | possible, mitigated |
| Uses call frequency | no | no | no | no | **yes** |
| Output | seccomp profile | seccomp profile | seccomp + enforcement | slim image | OCI profile |
| Needs the workload to run | no | no | partly | yes | yes |

## References

The citations above are to the published papers; check each against its
proceedings entry before quoting a claim in the thesis. This file records the
positioning argument, not a substitute for reading them.
