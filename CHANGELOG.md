# Changelog

All notable changes to this project will be documented in this file.

## 0.1.0 - 2026-08-14

Initial public release of minicrun, an educational Linux container-runtime
prototype written in Rust.

### Highlights

- OCI-like bundle execution with Linux namespace, mount, cgroup v2, and network
  isolation.
- Container lifecycle, state, stats, logs, health, exec, checkpoint, and
  diagnostic commands.
- Fixed denylist security profile plus seccomp learn, generate, enforce,
  inspect, compile, and comparison workflows.
- Reproducible example rootfs, benchmark harness, workload corpus, and
  root-required integration tests.
- Hardened cleanup and recovery for cgroups, mounts, veth devices, NAT rules,
  overlay state, and stale processes.

This release is intended for education and research. It is not production-ready
and must not be used as a security boundary for untrusted workloads.
