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

- [ ] Detect `criu` availability.
- [ ] Add `crun checkpoint <id>`.
- [ ] Add `crun restore <id>`.
- [ ] Mark experimental in CLI output.

Pass:

```bash
criu --version
sudo target/release/crun checkpoint ckpt-demo
sudo target/release/crun restore ckpt-demo
```

## Goal 12: Benchmark Suite Polish

Objective: produce repeatable performance evidence.

- [ ] Add JSON output to `scripts/benchmark.sh`.
- [ ] Measure startup `--net none`.
- [ ] Measure startup `--net bridge`.
- [ ] Measure `exec` latency.
- [ ] Measure memory footprint where possible.

Pass:

```bash
sudo scripts/benchmark.sh --iterations 30 --net none --security default --json
sudo scripts/benchmark.sh --iterations 30 --net bridge --security default --json
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

## Codex Goal Template

Use this with a Codex goal:

```text
Implement Goal N from docs/ROADMAP.md. Keep the change scoped to that goal.
After implementation, run cargo fmt --check, cargo test, cargo clippy
--all-targets --all-features, and cargo build --release. If root-required
commands cannot run in the sandbox, list them at the end under Commands for
user to run. Commit the code changes locally; do not push.
```
