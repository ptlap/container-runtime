## Summary

Describe the problem and the focused change that solves it.

## Runtime behavior

Describe user-visible behavior, compatibility considerations, and any effects on
namespaces, mounts, cgroups, networking, state, or cleanup.

## Validation

- [ ] `cargo fmt --check`
- [ ] `cargo test`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo build --release`
- [ ] Root/manual checks completed or documented as not applicable

## Host impact

List resources created on the host and how success, failure, and interruption
paths clean them up.
