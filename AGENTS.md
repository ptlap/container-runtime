# Repository Guidelines

## Project Structure & Module Organization

This is a Rust container-runtime prototype. Core source lives in `src/`:
`main.rs` defines the `crun` CLI, `lib.rs` exports modules, and submodules cover
container orchestration, cgroups, filesystem setup, namespaces, networking, and
OCI-like config parsing. Example runtime input is in `examples/bundle/`. Project
notes and planning live in `docs/`, especially `docs/BLUEPRINT.md`. Scripts for
rootfs setup and benchmarking belong in `scripts/`. Tests are split under
`tests/unit/` and `tests/integration/`; benchmarks live in `benches/`.

## Build, Test, and Development Commands

- `cargo build`: compile the debug binary and library.
- `cargo build --release`: build the optimized `target/release/crun` binary.
- `cargo test`: run unit, integration, and doc tests.
- `cargo fmt --check`: verify Rust formatting.
- `cargo clippy --lib --bin crun --all-features`: lint the main library and CLI.
- `cargo clippy --all-targets --all-features`: full lint pass; keep this green
  once benchmarks are implemented.
- `sudo target/release/crun run examples/bundle`: run the example bundle. Most
  namespace, mount, cgroup, and network operations require root.

If a required Rust command cannot run inside the agent sandbox, list it at the
end of the chat under `Commands for user to run` and ask the user to paste the
output back. Do this for root-only runtime checks, host-network/cgroup tests, or
any command blocked by sandbox permissions.

## Coding Style & Naming Conventions

Use Rust 2021 defaults and `rustfmt` formatting. Prefer small, focused modules
and explicit names such as `setup_rootfs`, `namespace_flags`, and `CgroupConfig`.
Use `anyhow::Result` at application boundaries with `.context()` or
`.with_context()` for syscall and filesystem failures. Avoid `unwrap()` and
`expect()` in runtime paths. Keep host resources owned and cleaned up explicitly:
cgroups, veth devices, iptables rules, temporary mounts, and state files.

## Testing Guidelines

Add unit tests for logic that does not require root: config parsing, namespace
flag mapping, cgroup validation, state path generation, stats parsing, and
network name generation. Put root-required end-to-end checks in integration tests
and skip clearly when not run as root. Name tests by behavior, for example
`parses_memory_limit_from_config` or `rejects_empty_process_args`.

## Commit & Pull Request Guidelines

History uses short conventional-style messages, for example `feat: setup veth
networking` and `fix: clean up NAT rules after container exit`. Keep commits
scoped and imperative. Pull requests should include a concise summary, changed
runtime behavior, test results, and any root-only/manual verification performed.
Link related issues when available and call out host-impacting changes such as
networking, cgroups, mounts, or cleanup behavior.

After completing code changes, create a local commit so the user can test and
roll back if needed. Do not push; the user will push only after tests pass.
Do not commit or push Markdown-only documentation files unless the user
explicitly asks for it. Do not add generated Markdown files to `.gitignore`.

## Security & Configuration Tips

Do not describe this project as production-ready. Changes touching namespaces,
mounts, cgroups, iptables, or `/proc/sys` can affect the host; document cleanup
paths and failure behavior. Keep Docker/image-management features outside the
runtime core unless explicitly scoped as scripts or examples.

## Codex Code Fit Rules

When implementing roadmap goals:

- Match the existing Rust style: small structs/enums, explicit conversion impls, and `anyhow::Result`.
- Keep CLI parsing in `src/main.rs`; move reusable behavior into existing modules.
- Do not duplicate runtime logic in tests or scripts.
- Use existing state helpers from `src/state/mod.rs`.
- Use existing network helpers from `src/network/mod.rs`.
- Use existing runtime/container helpers from `src/container/mod.rs`.
- For host resources, always define cleanup behavior: cgroups, veth, NAT, mounts, state files.
- Root-required tests must live under `tests/integration/` and be `#[ignore]` or self-skip when not root.
- Tests should call the `crun` binary like a user would.
- Avoid broad refactors while implementing a single roadmap goal.
- Avoid `unwrap()` and `expect()` in runtime code; they are acceptable only in tests.
