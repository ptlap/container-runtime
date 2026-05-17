#!/usr/bin/env bash
set -euo pipefail

runtime="./target/release/crun"
bundle="./examples/bundle"
iterations=30
net="none"
security="default"
output=""
prefix="bench"

usage() {
  cat <<'USAGE'
Usage: scripts/benchmark.sh [options]

Options:
  --runtime PATH       Runtime binary to execute (default: ./target/release/crun)
  --bundle PATH        Bundle with rootfs/config.json (default: ./examples/bundle)
  --iterations N       Number of runs (default: 30)
  --net MODE           Network mode: none, bridge, host (default: none)
  --security PROFILE   Security profile: default, unconfined (default: default)
  --output PATH        CSV output path (default: /tmp/crun-benchmark-<timestamp>.csv)
  --prefix NAME        Container id prefix (default: bench)
  -h, --help           Show this help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --runtime)
      runtime="$2"
      shift 2
      ;;
    --bundle)
      bundle="$2"
      shift 2
      ;;
    --iterations)
      iterations="$2"
      shift 2
      ;;
    --net)
      net="$2"
      shift 2
      ;;
    --security)
      security="$2"
      shift 2
      ;;
    --output)
      output="$2"
      shift 2
      ;;
    --prefix)
      prefix="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! "$iterations" =~ ^[0-9]+$ ]] || [[ "$iterations" -lt 1 ]]; then
  echo "--iterations must be a positive integer" >&2
  exit 2
fi

if [[ ! -x "$runtime" ]]; then
  echo "runtime is not executable: $runtime" >&2
  echo "build it first with: cargo build --release" >&2
  exit 2
fi

rootfs="$(realpath "$bundle/rootfs")"
if [[ ! -d "$rootfs" ]]; then
  echo "rootfs not found: $rootfs" >&2
  exit 2
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "benchmark must run as root because the runtime uses namespaces, mounts, and cgroups" >&2
  exit 2
fi

if [[ -z "$output" ]]; then
  output="/tmp/crun-benchmark-$(date +%Y%m%d-%H%M%S).csv"
fi

tmp_bundle="$(mktemp -d /tmp/crun-bench-bundle.XXXXXX)"
cleanup() {
  rm -rf "$tmp_bundle"
}
trap cleanup EXIT

ln -s "$rootfs" "$tmp_bundle/rootfs"
cat > "$tmp_bundle/config.json" <<'JSON'
{
  "ociVersion": "1.0.2",
  "process": {
    "args": ["/bin/sh", "-c", "exit 0"],
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    ],
    "cwd": "/"
  },
  "root": {
    "path": "rootfs",
    "readonly": false
  },
  "linux": {
    "namespaces": [
      { "type": "pid" },
      { "type": "mount" },
      { "type": "uts" },
      { "type": "ipc" },
      { "type": "network" }
    ],
    "resources": {
      "memory": { "limit": 268435456 },
      "cpu": { "quota": 50000, "period": 100000 }
    }
  }
}
JSON

echo "iteration,duration_ms,status" > "$output"

total=0
min=""
max=0
ok=0
failed=0

for i in $(seq 1 "$iterations"); do
  id="${prefix}-${net}-${security}-${i}-$$"
  start_ns="$(date +%s%N)"

  set +e
  "$runtime" run --net "$net" --security "$security" "$id" "$tmp_bundle" >/dev/null 2>&1
  status=$?
  set -e

  end_ns="$(date +%s%N)"
  duration_ms=$(( (end_ns - start_ns) / 1000000 ))
  echo "$i,$duration_ms,$status" >> "$output"

  "$runtime" delete "$id" >/dev/null 2>&1 || true

  if [[ "$status" -eq 0 ]]; then
    ok=$((ok + 1))
    total=$((total + duration_ms))
    if [[ -z "$min" || "$duration_ms" -lt "$min" ]]; then
      min="$duration_ms"
    fi
    if [[ "$duration_ms" -gt "$max" ]]; then
      max="$duration_ms"
    fi
  else
    failed=$((failed + 1))
  fi
done

if [[ "$ok" -gt 0 ]]; then
  avg=$((total / ok))
else
  avg=0
  min=0
fi

cat <<SUMMARY
runtime: $runtime
bundle: $tmp_bundle
iterations: $iterations
network: $net
security: $security
successful: $ok
failed: $failed
min_ms: $min
avg_ms: $avg
max_ms: $max
csv: $output
SUMMARY

if [[ "$failed" -gt 0 ]]; then
  exit 1
fi
