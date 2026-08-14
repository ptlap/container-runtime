# Provenance

| Field | Value |
|---|---|
| Source | https://github.com/moby/profiles |
| File | `seccomp/default.json` |
| Retrieved | 2026-07-26 from the `main` branch |
| sha256 | `536529b665dd0972c37bfb569f5d4ac8a53592e7b00752bc39ff063ca9864c74` |
| Size | 13470 bytes |
| Licence | Apache-2.0, see `LICENSE` |

The file is vendored unmodified. Docker's default seccomp profile used to live in
`moby/moby` under `profiles/seccomp/default.json` and now has its own repository,
which `moby/moby` vendors back in.

## What it allows

The profile is not a plain allow list: rules carry `includes` and `excludes`
filters on architecture and capabilities, which are a Docker extension rather
than part of the OCI schema. A rule gated on `CAP_SYS_ADMIN` does not apply to a
container that was never granted it.

Counted with `minicrun seccomp compare`, which models Docker's default capability
set, on x86_64:

| Measure | Count |
|---|---|
| Syscalls defined on x86_64 (the runtime's table) | 363 |
| `SCMP_ACT_ALLOW` names listed anywhere in the profile | 441 |
| Allowed for a default container on x86_64 | **296** |

The 296 figure is the one to compare generated profiles against. The raw 441
counts names for architectures this host does not have, and counting every
allow rule regardless of its capability gate overstates the real surface.
