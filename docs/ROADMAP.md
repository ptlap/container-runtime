# Container Runtime Roadmap

This roadmap is the single planning file for the project. Use it as the Codex
goal source: pick one goal, implement it, run the pass criteria, commit, then
move to the next goal.

## Current Baseline

- [x] Container lifecycle: `run`, `create`, `start`, `state`, `ps`, `delete`.
- [x] Process control: `exec`, TTY, `kill`, `stop`, exit-code propagation.
- [x] Isolation: namespaces, cgroup v2, `pivot_root`, bind mounts, overlay rootfs.
- [x] Networking: `none`, `host`, `bridge`, subnet allocation, stale lock recovery.
- [x] Security: no-new-privs, capability drop, seccomp, user namespace, memfd self-exec.
- [x] Observability: logs, stats, events, healthcheck, persisted health state.
- [x] Seccomp: syscall capture through ptrace, profile generation, allowlist enforcement.
- [ ] Evaluation: attack surface reduction, CVE coverage, false denial and overhead measurement.

## Global Pass Criteria

Run after every code goal:

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features
cargo build --release
```

Root-required runtime tests must be run manually by the user when Codex cannot
run them:

```bash
sudo target/release/crun ps
sudo target/release/crun run --net none --security unconfined smoke examples/bundle
sudo target/release/crun delete smoke
```

## Goal 1: Root-Required Integration Test Harness

Objective: create repeatable root-only tests without making normal CI require
root.

- [x] Add `tests/integration/root_runtime.rs`.
- [x] Mark tests `#[ignore]` or skip clearly when not root.
- [x] Cover run/state/delete, stats, logs, health, events, bind mount, and TTY.
- [x] Add `scripts/e2e.sh` for one-command local validation.

Pass:

```bash
cargo test
sudo cargo test --test root_runtime -- --ignored --nocapture
sudo scripts/e2e.sh
```

## Goal 2: `crun doctor`

Objective: add operational recovery checks for stale runtime resources.

- [x] Add `crun doctor`.
- [x] Add `crun doctor --fix`.
- [x] Detect stale running state with dead PID.
- [x] Detect orphan cgroups under `/sys/fs/cgroup/container-runtime`.
- [x] Detect stale bridge network allocations.
- [x] Detect orphan `vethh*` links where possible.

Pass:

```bash
sudo target/release/crun doctor
sudo target/release/crun doctor --fix
sudo target/release/crun ps
```

## Goal 3: `crun inspect-security`

Objective: make security posture visible and demo-friendly.

- [x] Add `crun inspect-security <id> [--json]`.
- [x] Report `NoNewPrivs`, seccomp mode, capabilities, userns mode.
- [x] Report readonly rootfs, mount mode, memory limit, pids limit, CPU limit.
- [x] Return warnings for weak posture: host userns, unconfined security, no limits.

Pass:

```bash
sudo target/release/crun run --net none --security default sec-demo examples/bundle
sudo target/release/crun inspect-security sec-demo --json
sudo target/release/crun delete sec-demo
```

## Goal 4: Overlay Rootfs Diff

Objective: show what changed inside an overlay-backed container.

- [x] Add `crun diff <id>`.
- [x] Read overlay `upperdir` from state or config.
- [x] Classify created, modified, and deleted whiteout entries.
- [x] Support text and JSON output.

Pass:

```bash
sudo target/release/crun run --net none diff-demo <overlay-bundle>
# inside container: touch /new-file; rm /some-file; exit
sudo target/release/crun diff diff-demo --json
sudo target/release/crun delete diff-demo
```

## Goal 5: Runtime Audit Log

Objective: persist lifecycle and runtime events for later inspection.

- [x] Write `/run/crun-rs/<id>/runtime.log`.
- [x] Log `created`, `started`, `exec`, `health`, `event`, `stopped`, `deleted`.
- [x] Add `crun events <id> --history`.
- [x] Use JSON lines internally for stable parsing.

Pass:

```bash
sudo target/release/crun create audit-demo examples/bundle
sudo target/release/crun start audit-demo
sudo target/release/crun events audit-demo --history --json
sudo target/release/crun delete audit-demo
```

## Goal 6: Health Watch Mode

Objective: turn healthcheck into a platform-like loop.

- [x] Add `crun health <id> --watch --interval-ms 1000`.
- [x] Keep updating health state until the container stops.
- [x] Honor `retries`.
- [x] Emit health events into runtime audit log when Goal 5 exists.

Pass:

```bash
sudo target/release/crun run --net none --security unconfined health-demo /tmp/crun-health-bundle
sudo target/release/crun health health-demo --watch --interval-ms 500
sudo target/release/crun state health-demo --json
sudo target/release/crun delete health-demo
```

## Goal 7: OCI Compatibility Layer

Objective: support a clearer and larger OCI subset.

- [x] Add `crun validate <bundle>`.
- [x] Support `process.user`.
- [x] Support `process.capabilities`.
- [x] Support `process.rlimits`.
- [x] Support `linux.maskedPaths` and `linux.readonlyPaths`.
- [x] Document unsupported fields through validation warnings.

Pass:

```bash
target/release/crun validate examples/bundle
target/release/crun validate /tmp/bad-bundle
sudo target/release/crun run --net none oci-demo examples/bundle
sudo target/release/crun delete oci-demo
```

## Goal 8: Resource Policy Profiles

Objective: provide secure defaults as named profiles.

- [x] Add `crun.profile` in config.
- [x] Implement `restricted`.
- [x] Implement `debug`.
- [x] Merge profile defaults with explicit config values predictably.
- [x] Expose chosen profile in state.

Pass:

```bash
sudo target/release/crun run --net none restricted-demo <restricted-bundle>
sudo target/release/crun inspect-security restricted-demo --json
sudo target/release/crun delete restricted-demo
```

## Goal 9: Image Import Minimal

Objective: move from rootfs-only input to minimal local image storage.

- [x] Add `crun image import <rootfs.tar> <name>`.
- [x] Store under `/var/lib/crun-rs/images/<name>/rootfs`.
- [x] Add `crun image list`.
- [x] Add `crun run-image <name> <id>`.
- [x] Keep registry/pull out of scope.

Pass:

```bash
sudo target/release/crun image import alpine-rootfs.tar alpine
sudo target/release/crun image list
sudo target/release/crun run-image alpine image-demo
sudo target/release/crun delete image-demo
```

## Goal 10: Trace Mode

Objective: expose kernel/process behavior during runtime operations.

- [x] Add `crun trace <id>`.
- [x] Start with process tree and `/proc/<pid>/status`.
- [x] Add optional `strace` integration if installed.
- [x] Keep eBPF as optional research extension.

Pass:

```bash
sudo target/release/crun trace demo --json
```

## Goal 11: Checkpoint/Restore Research Mode

Objective: optional academic extension using CRIU.

- [x] Detect `criu` availability.
- [x] Add `crun checkpoint <id>`.
- [x] Add `crun restore <id>`.
- [x] Mark experimental in CLI output.

Pass:

```bash
criu --version
sudo target/release/crun checkpoint ckpt-demo
sudo target/release/crun restore ckpt-demo
```

## Goal 12: Benchmark Suite Polish

Objective: produce repeatable performance evidence.

- [x] Add JSON output to `scripts/benchmark.sh`.
- [x] Measure startup `--net none`.
- [x] Measure startup `--net bridge`.
- [x] Measure `exec` latency.
- [x] Measure memory footprint where possible.

Pass:

```bash
sudo scripts/benchmark.sh --iterations 30 --net none --security default --json
sudo scripts/benchmark.sh --iterations 30 --net bridge --security default --json
```

## Goal 13: Reproducible Bundle Bootstrap

Objective: make a fresh clone able to run every test, script and benchmark
without any untracked local state.

- [x] Narrow `.gitignore` from bare `rootfs/` and `bundle/` to the extracted
      filesystems only.
- [x] Track `examples/bundle/config.json`.
- [x] Implement `scripts/setup-rootfs.sh` with an Alpine version and sha256
      pinned in `scripts/rootfs.lock`.
- [x] Add `--check-only` so a script can assert the bundle is present.
- [x] Document the bootstrap step in the README.

Pass:

```bash
rm -rf examples/bundle/rootfs
sudo scripts/setup-rootfs.sh
scripts/setup-rootfs.sh --check-only
sudo scripts/e2e.sh
git status --short
```

## Goal 14: Deterministic Container Environment

Objective: stop the host environment and runtime chatter from contaminating
container behaviour and machine-readable output.

- [x] Clear the inherited environment before `execvp` in `container/process.rs`.
- [x] Clear it on the `crun exec` path in `container_exec.rs` as well.
- [x] Route library-level `println!` and `eprintln!` through `tracing`, on stderr.
- [x] Add a root test asserting the container environment equals the bundle's.

Pass:

```bash
cargo clippy --all-targets --all-features
FOO=leak sudo -E target/release/crun run --log on envtest examples/bundle
sudo target/release/crun logs envtest | grep -c FOO   # expects 0
sudo target/release/crun delete envtest
```

## Goal 15: Concurrent-Safe State Writes

Objective: keep runtime state readable and correct when hundreds of containers
and concurrent readers touch it during an experiment.

- [x] Write state through a temporary file plus fsync and rename.
- [x] Hold an exclusive `flock` across read-modify-write.
- [x] Stop `refresh_liveness` writing outside the lock.
- [x] Add a concurrency unit test with parallel writers and readers.

Pass:

```bash
cargo test state
sudo scripts/benchmark.sh --iterations 30 --net none --security default --json
```

## Goal 16: OCI Filesystem Mounts

Objective: run bundles produced by standard OCI tooling.

- [x] Dispatch `mounts[]` by type: bind, proc, sysfs, tmpfs, devpts, mqueue, cgroup.
- [x] Parse mount options into flags, propagation and filesystem data.
- [x] Let the bundle's declarations win over the built-in `/proc` and `/dev` setup.
- [x] Add `/dev/shm`, which PostgreSQL needs, and the `/dev/stdout` family of links.
- [x] Accept filesystem mounts in config validation without a host source.

Pass:

```bash
cargo test filesystem
cargo test spec::config
sudo target/release/crun run --net none mounts-demo examples/bundle
sudo target/release/crun delete mounts-demo
```

## Goal 17: Seccomp Filter and Profile Infrastructure

Objective: build the filter, table and profile machinery the rest of the work
sits on.

- [x] Extract the BPF primitives into `src/seccomp/bpf.rs` with validation.
- [x] Generate committed syscall tables for x86_64 and aarch64.
- [x] Emit profiles in the OCI `linux.seccomp` schema with `crunMetadata`.
- [x] Compile allowlists, guarding foreign architectures and the x32 ABI.
- [x] Order the comparison chain by observed frequency.
- [x] Keep the existing denylist behaviour behind `--security default`.

Pass:

```bash
cargo test seccomp
target/release/crun seccomp compile <profile> --json
```

## Goal 18: Learn and Enforce Modes

Objective: capture what a workload really uses, and run it under nothing else.

- [x] Add `--seccomp off|learn|enforce` with profile, output, action and order flags.
- [x] Trace with `PTRACE_O_TRACESECCOMP` and follow forks, vforks, clones and threads.
- [x] Hand the log helper and pty proxy statuses back from the tracer.
- [x] Write captures to `/run/crun-rs/<id>/syscalls.json`.
- [x] Add `crun seccomp generate|inspect|compare|compile`.
- [x] Record the mode, profile and action in state so `crun start` reproduces them.

Pass:

```bash
sudo cargo test --test root_runtime -- --ignored --nocapture
sudo target/release/crun run --seccomp learn --seccomp-out /tmp/x.json demo examples/bundle
sudo target/release/crun seccomp generate --capture /tmp/x.json -o /tmp/x.seccomp.json
sudo target/release/crun run --seccomp enforce --seccomp-profile /tmp/x.seccomp.json demo2 examples/bundle
```

## Goal 19: Evaluation Data and Harness

Objective: produce every number the thesis reports.

- [x] Vendor Docker's default profile with its licence and provenance.
- [x] Read it the way Docker does, honouring capability and architecture gates.
- [x] Curate `data/cve-syscall-map.json` with disjunctive attack paths.
- [x] Validate the dataset with `scripts/check-cve-map.py`.
- [x] Build digest-pinned workload bundles with `scripts/build-workloads.sh`.
- [x] Measure the arms with `scripts/experiment.sh`.
- [ ] Run the full corpus and commit the results.

Pass:

```bash
scripts/check-cve-map.py
sudo scripts/build-workloads.sh --workload all
sudo scripts/experiment.sh --workload busybox --arm all --repeat 5 --tag smoke
jq '.comparison.reduction_vs_baseline' docs/benchmark/data/smoke/busybox.json
```

## Goal 20: Thesis Reproducibility Package

Objective: regenerate every table with one command.

- [x] Add `scripts/reproduce.sh` with `--tag` and `--quick`.
- [x] Add `scripts/render-tables.py` producing Markdown and CSV.
- [x] Write the methodology, threat model, related work and limitations notes.
- [ ] Commit the final raw results, profiles and tables.

Pass:

```bash
sudo scripts/reproduce.sh --quick
ls docs/benchmark/results-*.md
```

## Goal 21: Extensions

Objective: the work that deepens the evaluation once the core numbers exist.

- [ ] Compare a binary-search filter against the linear chain.
- [ ] Add an eBPF capture backend behind a feature flag and compare its overhead.
- [x] Apply the container's filter to `crun exec`.
- [ ] Give `create` and `start` OCI semantics with a detached container process.
- [ ] Rename `--net bridge`, which is really per-container veth plus NAT.

Pass:

```bash
cargo test
sudo scripts/experiment.sh --workload all --arm all --repeat 30 --tag final
```

## Recommended Execution Order

1. Root-required integration test harness.
2. `crun doctor`.
3. `crun inspect-security`.
4. Overlay `crun diff`.
5. Runtime audit log.
6. Health watch mode.
7. OCI compatibility layer.
8. Resource policy profiles.
9. Image import minimal.
10. Trace mode.
11. Checkpoint/restore research mode.
12. Benchmark suite polish.
13. Reproducible bundle bootstrap.
14. Deterministic container environment.
15. Concurrent-safe state writes.
16. OCI filesystem mounts.
17. Seccomp filter and profile infrastructure.
18. Learn and enforce modes.
19. Evaluation data and harness.
20. Thesis reproducibility package.
21. Extensions.

## Codex Goal Template

Use this with a Codex goal:

```text
Implement Goal N from docs/ROADMAP.md. Keep the change scoped to that goal.
After implementation, run cargo fmt --check, cargo test, cargo clippy
--all-targets --all-features, and cargo build --release. If root-required
commands cannot run in the sandbox, list them at the end under Commands for
user to run. Commit the code changes locally; do not push.
```
