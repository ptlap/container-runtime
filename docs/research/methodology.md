# Methodology

How every number in the evaluation is defined and produced. The formulas here
are what `crun seccomp compare` computes and what `scripts/experiment.sh`
records.

## Definitions

Let `U` be the set of syscalls the running architecture defines. The runtime
reads it from its generated table, which is derived from libc and committed:
**363 on x86_64**.

`A_P` is the set of syscalls profile `P` allows, intersected with `U`. The
intersection matters: baseline profiles list names for every architecture their
author supports, so counting raw names overstates the surface a container on
this machine really has.

Four profiles are compared:

| Symbol | Profile | `|A_P|` on x86_64 |
|---|---|---|
| `A_none` | No filter | 363 |
| `A_crun` | `--security default`, the runtime's 16-syscall denylist | 347 |
| `A_docker` | Docker's default profile, default capabilities | **296** |
| `A_gen(w)` | Generated for workload `w` | measured |

`A_docker` is not simply every `SCMP_ACT_ALLOW` name. Docker's rules carry
`includes` and `excludes` filters on architecture and capabilities, which are a
Docker extension rather than part of the OCI schema. A rule gated on
`CAP_SYS_ADMIN` does not apply to a container that was never granted it. Read
naively the profile appears to allow 441 names; read the way Docker reads it,
for a container with Docker's default capability set on x86_64, it allows 296.
The larger number would flatter every reduction figure measured against it.

## Attack surface

```
Reduction_docker(w)   = 1 - |A_gen(w)| / |A_docker|      <- headline figure
Reduction_universe(w) = 1 - |A_gen(w)| / |U|
Reduction_crun(w)     = 1 - |A_gen(w)| / |A_crun|
NewlyBlocked(w)       = A_docker \ A_gen(w)
OverAllowed(w)        = A_gen(w) \ A_docker
```

`OverAllowed` should normally be empty. When it is not, the workload uses
something Docker's profile denies, and that is a finding to report rather than
smooth over.

## CVE coverage

Each CVE in `data/cve-syscall-map.json` carries one or more `attack_paths`. The
structure is a disjunction of conjunctions: every syscall inside one path is
required for that route, and a CVE counts as blocked only when **every** path
has at least one denied syscall.

```
Mitigated(P)      = { c : for every path p in c, some s in p is not in A_P }
CVECoverage(w)    = |Mitigated(A_gen(w))| / |container-relevant CVEs|
NewlyMitigated(w) = Mitigated(A_gen(w)) \ Mitigated(A_docker)
```

Counting a CVE as blocked when *any* route is closed is the usual mistake and
inflates the result, because most of these bugs have more than one route.

Two things this metric does not claim. It measures **filter potential**, not
exploit prevention: a syscall-number filter cannot distinguish socket families,
`ioctl` commands or `prctl` options, so a CVE reachable through a syscall the
workload legitimately needs is not mitigated no matter how small the profile is.
And Docker's profile already denies most classic escape entry points (`bpf`,
`keyctl`, `mount`, `unshare`, `setns`, `io_uring_*`, `perf_event_open`,
`userfaultfd`, the module calls), so the CVE win over Docker is much smaller
than the syscall-count win. That gap is expected and should be stated before a
reviewer finds it: the contribution is automation and per-workload minimality,
not the discovery that `bpf` is dangerous.

## False denial

Three checks, all of which must pass for a run to count as functional:

1. **Startup** — the container reaches `running` and its readiness probe passes
   within the timeout.
2. **Functional** — the workload's smoke command exits 0 with the expected output.
3. **Steady** — no `Operation not permitted` or `Bad system call` markers in the
   container log, and under `--seccomp-action kill` the exit signal is not
   `SIGSYS`.

```
false_denial_rate = failing workload-arms / total workload-arms
```

Reported per workload as well as overall, because one hard workload failing is a
different result from every workload degrading.

## Overhead

Learn-mode and enforce-mode overhead answer different questions and are never
averaged together.

**Learn** is a one-off offline cost. Reported as absolute wall time and as a
ratio to the unconfined run. It is expected to be large: every syscall stops the
tracee twice through the scheduler.

**Enforce** is the steady-state cost. Reported as the median difference in
`time_to_ready_ms` against `--security unconfined` and `--security default`.

The startup metric in `scripts/benchmark.sh` cannot be used for this. It stops
when the runtime records the container as running, and that happens in the
parent before it releases the child, which then unshares namespaces, pivots
root, applies limits and installs the filter. Any seccomp cost lands after the
timestamp. `scripts/experiment.sh` measures time to readiness and whole-run time
instead.

## Statistics

30 measured iterations after 3 discarded warmups, per arm per workload.

Reported as **median with p25, p75, p95, min, max and n**. Startup latency is
right skewed with a hard floor: a mean is dragged by the tail and a standard
deviation asserts a symmetry the data does not have. Mean and standard deviation
are still recorded in the JSON so the older benchmark summary shape stays a
strict subset.

## Noise control

- `--net none` for the headline arms: no veth, no NAT, no allocation lock
  contention across hundreds of container starts.
- Arms interleaved per iteration rather than run in blocks, so thermal and
  frequency drift is shared instead of biasing whichever ran first.
- `--log on` always, so container output goes to its own file and never mixes
  with runtime diagnostics, which go to stderr.
- Unique container ids per iteration, `crun doctor --fix` between arms.
- Warmups discarded rather than caches dropped. Dropping caches measures the
  disk, not the filter.
- Kernel, CPU, core count, load average, image digests, git commit and the
  runtime binary's sha256 recorded with every result.

## Reproducing

```bash
sudo scripts/reproduce.sh --tag $(date +%F)   # full run
sudo scripts/reproduce.sh --quick             # a few minutes, for validation
```
