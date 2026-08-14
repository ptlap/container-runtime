# Contributing to minicrun

Thank you for helping improve minicrun. This project is an educational Linux
container-runtime prototype and is not production-ready.

## Development setup

You need a Linux host with cgroups v2 and a Rust toolchain matching
`rust-toolchain.toml`. Build the reproducible example rootfs before running the
root integration suite:

```bash
sudo scripts/setup-rootfs.sh
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
```

Tests that exercise namespaces, mounts, cgroups, or networking require root:

```bash
sudo -E cargo test --test root_runtime -- --ignored --nocapture --test-threads=1
```

## Submitting changes

1. Open an issue before undertaking a broad behavioral change.
2. Keep each pull request focused and add tests for changed behavior.
3. Run formatting, tests, Clippy, and a release build before submitting.
4. Explain host-impacting behavior and cleanup paths in the pull request.
5. Do not include generated rootfs contents, credentials, or host state.

Use clear, imperative commit messages such as `fix: clean up failed mounts`.
Root-required tests belong under `tests/integration/` and must be marked
`#[ignore]` or skip clearly when not run as root.

## Reporting security issues

Do not open a public issue for a suspected vulnerability. Follow
[SECURITY.md](SECURITY.md) instead.
