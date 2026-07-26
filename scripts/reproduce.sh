#!/usr/bin/env bash
# Regenerate every evaluation table from a clean checkout.
#
# This is the single command an examiner should need. --quick runs a reduced
# version in a few minutes so the pipeline can be validated without waiting for
# the full corpus.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="$(date +%F)"
QUICK=0
SKIP_BUILD=0
SKIP_WORKLOADS=0

usage() {
    cat <<'EOF'
Usage: scripts/reproduce.sh [options]

  --tag NAME          Result tag (default: today's date)
  --quick             busybox and redis only, 5 iterations
  --skip-build        Assume target/release/crun is current
  --skip-workloads    Assume workloads/ is already built
  -h, --help          Show this help

Requires root, plus skopeo and umoci for the workload bundles.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --tag) TAG="$2"; shift 2 ;;
        --quick) QUICK=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --skip-workloads) SKIP_WORKLOADS=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

step() {
    echo
    echo "=== $* ==="
}

[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 2; }

step "checking dependencies"
missing=0
for tool in jq python3 cargo; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing: $tool" >&2; missing=1; }
done
if [ "$SKIP_WORKLOADS" -eq 0 ]; then
    for tool in skopeo umoci; do
        command -v "$tool" >/dev/null 2>&1 || { echo "missing: $tool (needed to build workload bundles)" >&2; missing=1; }
    done
fi
[ "$missing" -eq 0 ] || exit 2
echo "ok"

if [ "$SKIP_BUILD" -eq 0 ]; then
    step "building the runtime"
    cargo build --release --manifest-path "$REPO_ROOT/Cargo.toml"
fi

step "checking the example bundle"
"$REPO_ROOT/scripts/setup-rootfs.sh" --check-only || "$REPO_ROOT/scripts/setup-rootfs.sh"

step "validating the CVE dataset"
"$REPO_ROOT/scripts/check-cve-map.py"

if [ "$SKIP_WORKLOADS" -eq 0 ]; then
    step "building workload bundles"
    if [ "$QUICK" -eq 1 ]; then
        "$REPO_ROOT/scripts/build-workloads.sh" --workload busybox
        "$REPO_ROOT/scripts/build-workloads.sh" --workload redis
    else
        "$REPO_ROOT/scripts/build-workloads.sh" --workload all
    fi
    "$REPO_ROOT/scripts/build-workloads.sh" --verify || true
fi

step "running the experiment (tag $TAG)"
if [ "$QUICK" -eq 1 ]; then
    "$REPO_ROOT/scripts/experiment.sh" --workload busybox --arm all --repeat 5 --warmup 1 --tag "$TAG" --keep-going
    "$REPO_ROOT/scripts/experiment.sh" --workload redis --arm all --repeat 5 --warmup 1 --tag "$TAG" --keep-going
else
    "$REPO_ROOT/scripts/experiment.sh" --workload all --arm all --repeat 30 --tag "$TAG" --keep-going
fi

step "rendering tables"
"$REPO_ROOT/scripts/render-tables.py" --tag "$TAG"

step "artifact to chapter mapping"
cat <<EOF
docs/research/related-work.md          chapter 2, related work
docs/research/threat-model.md          chapter 3, design
docs/research/methodology.md           chapter 3, metric definitions
src/seccomp/                           chapter 4, implementation
docs/benchmark/results-$TAG.md         chapter 5, evaluation tables
docs/benchmark/data/$TAG/tables/*.csv  chapter 5, source data
docs/research/limitations.md           chapter 6, limitations and future work
EOF
