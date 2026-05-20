#!/usr/bin/env bash
set -euo pipefail

runtime="./target/release/crun"
bundle="./examples/bundle"
iterations=30
net="none"
security="default"
output=""
prefix="bench"
json=false

usage() {
  cat <<'USAGE'
Usage: scripts/benchmark.sh [options]

Options:
  --runtime PATH       Runtime binary to execute (default: ./target/release/crun)
  --bundle PATH        Bundle with rootfs/config.json (default: ./examples/bundle)
  --iterations N       Number of runs (default: 30)
  --net MODE           Network mode: none, bridge, host (default: none)
  --security PROFILE   Security profile: default, unconfined (default: default)
  --json               Write JSON output instead of CSV
  --output PATH        Output path (default: /tmp/crun-benchmark-<timestamp>.<csv|json>)
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
    --json)
      json=true
      shift
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

case "$net" in
  none|bridge|host) ;;
  *)
    echo "--net must be one of: none, bridge, host" >&2
    exit 2
    ;;
esac

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

timestamp="$(date +%Y%m%d-%H%M%S)"
if [[ -z "$output" ]]; then
  if [[ "$json" == true ]]; then
    output="/tmp/crun-benchmark-${timestamp}.json"
  else
    output="/tmp/crun-benchmark-${timestamp}.csv"
  fi
fi

tmp_bundle="$(mktemp -d /tmp/crun-bench-bundle.XXXXXX)"
results_tmp="$(mktemp /tmp/crun-bench-results.XXXXXX)"
cleanup() {
  rm -rf "$tmp_bundle"
  rm -f "$results_tmp"
}
trap cleanup EXIT

ln -s "$rootfs" "$tmp_bundle/rootfs"
cat > "$tmp_bundle/config.json" <<'JSON'
{
  "ociVersion": "1.0.2",
  "process": {
    "args": ["/bin/sh", "-c", "sleep 300"],
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

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  printf '%s' "$value"
}

now_ns() {
  date +%s%N
}

rss_kb() {
  local pid="$1"
  awk '/^VmRSS:/ { print $2; found=1 } END { if (!found) print 0 }' "/proc/${pid}/status" 2>/dev/null || printf '0\n'
}

state_json() {
  "$runtime" state "$1" --json 2>/dev/null
}

state_pid() {
  sed -n 's/.*"pid": \([0-9][0-9]*\).*/\1/p' | head -n 1
}

wait_for_running() {
  local id="$1"
  local deadline_ns=$(( $(now_ns) + 10000000000 ))

  while [[ "$(now_ns)" -lt "$deadline_ns" ]]; do
    if state_json "$id" | grep -q '"status": "running"'; then
      return 0
    fi
    sleep 0.05
  done

  return 1
}

append_result() {
  local iteration="$1"
  local startup_ms="$2"
  local exec_ms="$3"
  local runtime_rss="$4"
  local container_rss="$5"
  local status="$6"

  if [[ "$json" == true ]]; then
    local sep=""
    if [[ -s "$results_tmp" ]]; then
      sep=","
    fi
    printf '%s{"iteration":%s,"startup_ms":%s,"exec_ms":%s,"runtime_rss_kb":%s,"container_rss_kb":%s,"status":%s}\n' \
      "$sep" "$iteration" "$startup_ms" "$exec_ms" "$runtime_rss" "$container_rss" "$status" >> "$results_tmp"
  else
    echo "$iteration,$startup_ms,$exec_ms,$runtime_rss,$container_rss,$status" >> "$output"
  fi
}

if [[ "$json" != true ]]; then
  echo "iteration,startup_ms,exec_ms,runtime_rss_kb,container_rss_kb,status" > "$output"
fi

startup_total=0
startup_min=""
startup_max=0
exec_total=0
exec_min=""
exec_max=0
runtime_rss_total=0
container_rss_total=0
ok=0
failed=0

for i in $(seq 1 "$iterations"); do
  id="${prefix}-${net}-${security}-${i}-$$"
  run_pid=""
  startup_ms=0
  exec_ms=0
  runtime_rss=0
  container_rss=0
  status=1

  start_ns="$(now_ns)"
  "$runtime" run --net "$net" --security "$security" "$id" "$tmp_bundle" >/dev/null 2>&1 &
  run_pid=$!

  if wait_for_running "$id"; then
    running_ns="$(now_ns)"
    startup_ms=$(( (running_ns - start_ns) / 1000000 ))
    runtime_rss="$(rss_kb "$run_pid")"
    container_pid="$(state_json "$id" | state_pid || true)"
    if [[ -n "$container_pid" ]]; then
      container_rss="$(rss_kb "$container_pid")"
    fi

    exec_start_ns="$(now_ns)"
    set +e
    "$runtime" exec "$id" /bin/true >/dev/null 2>&1
    status=$?
    set -e
    exec_end_ns="$(now_ns)"
    exec_ms=$(( (exec_end_ns - exec_start_ns) / 1000000 ))
  fi

  "$runtime" stop "$id" >/dev/null 2>&1 || true
  if [[ -n "$run_pid" ]]; then
    wait "$run_pid" >/dev/null 2>&1 || true
  fi
  "$runtime" delete "$id" >/dev/null 2>&1 || true

  append_result "$i" "$startup_ms" "$exec_ms" "$runtime_rss" "$container_rss" "$status"

  if [[ "$status" -eq 0 ]]; then
    ok=$((ok + 1))
    startup_total=$((startup_total + startup_ms))
    exec_total=$((exec_total + exec_ms))
    runtime_rss_total=$((runtime_rss_total + runtime_rss))
    container_rss_total=$((container_rss_total + container_rss))
    if [[ -z "$startup_min" || "$startup_ms" -lt "$startup_min" ]]; then
      startup_min="$startup_ms"
    fi
    if [[ "$startup_ms" -gt "$startup_max" ]]; then
      startup_max="$startup_ms"
    fi
    if [[ -z "$exec_min" || "$exec_ms" -lt "$exec_min" ]]; then
      exec_min="$exec_ms"
    fi
    if [[ "$exec_ms" -gt "$exec_max" ]]; then
      exec_max="$exec_ms"
    fi
  else
    failed=$((failed + 1))
  fi
done

if [[ "$ok" -gt 0 ]]; then
  startup_avg=$((startup_total / ok))
  exec_avg=$((exec_total / ok))
  runtime_rss_avg=$((runtime_rss_total / ok))
  container_rss_avg=$((container_rss_total / ok))
else
  startup_avg=0
  startup_min=0
  exec_avg=0
  exec_min=0
  runtime_rss_avg=0
  container_rss_avg=0
fi

if [[ "$json" == true ]]; then
  {
    printf '{\n'
    printf '  "runtime": "%s",\n' "$(json_escape "$runtime")"
    printf '  "bundle": "%s",\n' "$(json_escape "$tmp_bundle")"
    printf '  "iterations": %s,\n' "$iterations"
    printf '  "network": "%s",\n' "$(json_escape "$net")"
    printf '  "security": "%s",\n' "$(json_escape "$security")"
    printf '  "successful": %s,\n' "$ok"
    printf '  "failed": %s,\n' "$failed"
    printf '  "summary": {\n'
    printf '    "startup_min_ms": %s,\n' "$startup_min"
    printf '    "startup_avg_ms": %s,\n' "$startup_avg"
    printf '    "startup_max_ms": %s,\n' "$startup_max"
    printf '    "exec_min_ms": %s,\n' "$exec_min"
    printf '    "exec_avg_ms": %s,\n' "$exec_avg"
    printf '    "exec_max_ms": %s,\n' "$exec_max"
    printf '    "runtime_rss_avg_kb": %s,\n' "$runtime_rss_avg"
    printf '    "container_rss_avg_kb": %s\n' "$container_rss_avg"
    printf '  },\n'
    printf '  "results": [\n'
    sed 's/^/    /' "$results_tmp"
    printf '  ]\n'
    printf '}\n'
  } > "$output"
fi

cat <<SUMMARY
runtime: $runtime
bundle: $tmp_bundle
iterations: $iterations
network: $net
security: $security
successful: $ok
failed: $failed
startup_min_ms: $startup_min
startup_avg_ms: $startup_avg
startup_max_ms: $startup_max
exec_min_ms: $exec_min
exec_avg_ms: $exec_avg
exec_max_ms: $exec_max
runtime_rss_avg_kb: $runtime_rss_avg
container_rss_avg_kb: $container_rss_avg
output: $output
SUMMARY

if [[ "$failed" -gt 0 ]]; then
  exit 1
fi
