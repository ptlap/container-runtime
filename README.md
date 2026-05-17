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
- Support security profiles: `default` and `unconfined`.
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

## Run

```bash
sudo target/release/crun run --net bridge --security default demo examples/bundle
```

Lifecycle form:

```bash
sudo target/release/crun create --net bridge --security default demo examples/bundle
sudo target/release/crun state demo --json
sudo target/release/crun start demo
```

Useful commands from another terminal:

```bash
sudo target/release/crun state demo --json
sudo target/release/crun stats demo --json
sudo target/release/crun delete demo
```

Network modes:

- `bridge`: isolated network namespace with veth, `eth0`, and NAT.
- `none`: isolated network namespace with loopback only.
- `host`: host network namespace, no `CLONE_NEWNET`.

Security profiles:

- `default`: enables Linux `no_new_privs` and clears effective, permitted, and
  inheritable capabilities before `exec`. It also installs a small seccomp
  denylist for host-impacting syscalls such as `mount`, `ptrace`, `bpf`,
  `keyctl`, module loading, and reboot operations.
- `unconfined`: skips runtime security hardening for debugging.

## Current Limits

- OCI support is partial.
- Seccomp is a small denylist, not a complete production allowlist.
- User namespace UID/GID mapping is not implemented.
- Bridge mode still uses a fixed `10.0.0.0/24` subnet.
- The runtime expects an existing unpacked rootfs; it does not pull images.
