# container-runtime

A minimal Linux container runtime written in Rust for studying how containers are
built from kernel primitives: namespaces, cgroups v2, rootfs isolation, and
process execution.

This project is an educational mini-runtime, not a Docker replacement and not a
production-ready OCI runtime.

## Features

- Parse a small OCI-like `config.json` subset.
- Isolate PID, mount, UTS, IPC, and network namespaces.
- Switch rootfs with `pivot_root`.
- Apply cgroups v2 memory and CPU limits.
- Inspect cgroup stats while a container is running.
- Support network modes: `bridge`, `none`, and `host`.
- Support security profiles: `denylist` (legacy CLI alias: `default`) and `unconfined`.
- Store runtime state under `/run/crun-rs/<id>/state.json`.

## Requirements

- Linux host with cgroups v2.
- Root privileges for namespace, mount, cgroup, and network operations.
- `ip` from iproute2.
- `iptables` for bridge-mode NAT.

## Build

```bash
cargo build --release
cargo test
cargo clippy --all-targets --all-features
```

## Example bundle

The example root filesystem is not tracked in git. Build it once after cloning,
before running the root tests, `scripts/e2e.sh`, or `scripts/benchmark.sh`:

```bash
sudo scripts/setup-rootfs.sh
scripts/setup-rootfs.sh --check-only
```

The tarball is pinned by version and sha256 in `scripts/rootfs.lock`, so every
machine builds the same rootfs. Run as root so ownership and device nodes are
restored.

## Benchmark

```bash
sudo scripts/benchmark.sh --iterations 30 --net none --security denylist
```

The benchmark script creates a temporary bundle that runs `/bin/sh -c "exit 0"`,
records startup latency to CSV and prints min/avg/max latency. Use `--net
bridge` to include veth and NAT setup overhead.

## Run

```bash
sudo target/release/crun run --net bridge --security denylist demo examples/bundle
```

Lifecycle form:

```bash
sudo target/release/crun create --net bridge --security denylist demo examples/bundle
sudo target/release/crun state demo --json
sudo target/release/crun start demo
```

Useful commands from another terminal:

```bash
sudo target/release/crun state demo --json
sudo target/release/crun stats demo --json
sudo target/release/crun stop demo --timeout 10
sudo target/release/crun kill demo --signal SIGTERM
sudo target/release/crun delete demo
```

Network modes:

- `bridge`: isolated network namespace with veth, `eth0`, and NAT.
- `none`: isolated network namespace with loopback only.
- `host`: host network namespace, no `CLONE_NEWNET`.

Security profiles:

- `denylist` (the legacy CLI spelling `default` is accepted): enables Linux
  `no_new_privs` and clears effective, permitted, and inheritable capabilities
  before `exec`. It also installs a small seccomp denylist for host-impacting
  syscalls such as `mount`, `ptrace`, `bpf`, `keyctl`, module loading, and reboot
  operations.
- `unconfined`: skips runtime security hardening for debugging.

## Seccomp profile generation

The runtime can watch a workload, record the syscalls it actually makes, and
turn that into a minimal allowlist:

```bash
# Observe. Every syscall traps to a tracer; nothing is denied.
sudo target/release/crun run --seccomp learn --seccomp-out /tmp/demo.trace.json \
  demo examples/bundle

# Generate an OCI linux.seccomp profile from one or more captures.
sudo target/release/crun seccomp generate --capture /tmp/demo.trace.json \
  -o /tmp/demo.seccomp.json --name demo

# Enforce it.
sudo target/release/crun run --seccomp enforce --seccomp-profile /tmp/demo.seccomp.json \
  demo2 examples/bundle

# Measure it against Docker's default profile and a CVE dataset.
target/release/crun seccomp compare /tmp/demo.seccomp.json \
  --baseline third_party/moby-profiles/seccomp/default.json \
  --cve-map data/cve-syscall-map.json --json
```

`--seccomp-action` chooses what happens to a denied syscall: `errno` (default,
matching Docker), `enosys` (so libc takes its fallback path), `kill`, or `log`,
which allows the call but records it, turning a profile into a dry run.

Generated profiles use the OCI `linux.seccomp` schema, so they can be handed to
runc or youki unchanged. Provenance travels alongside under `crunMetadata`.

### Healthcheck security boundary

Healthchecks run through the same namespace-joining execution path as `crun
exec`, but they intentionally do not install the generated seccomp allowlist.
The container's base security profile is still applied: under `denylist`,
`no_new_privs`, capability removal, and the fixed host-impacting syscall denylist
remain active; under `unconfined`, that base hardening is intentionally absent.
This separation prevents an operator-supplied probe from being marked unhealthy
only because its syscall set was not present in the workload capture. It does not
make healthchecks a trusted or unrestricted execution context under `denylist`.

Evaluation methodology is in `docs/research/methodology.md`; the whole pipeline
reruns with `sudo scripts/reproduce.sh --quick`.

## Current Limits

- OCI support is partial: `create` writes state without creating a process, and
  `start` blocks until the container exits, so there is no detached mode.
- Healthcheck probes do not install the generated seccomp allowlist, by design;
  they still receive the container's base security profile, while `crun exec`
  installs the generated profile when enforcement is enabled.
- Learn mode observes only the paths a run exercised, so a generated profile can
  miss syscalls a rarer path needs. See `docs/research/limitations.md`.
- `--net bridge` creates a veth pair and NAT per container rather than a shared
  bridge, so containers cannot reach each other.
- The runtime expects an unpacked rootfs; use `scripts/build-workloads.sh` with
  skopeo and umoci to produce bundles from images.
