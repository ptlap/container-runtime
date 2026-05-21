#!/usr/bin/env bash
set -euo pipefail

runtime="${RUNTIME:-./target/release/crun}"
rootfs="$(realpath examples/bundle/rootfs)"
tmp_root="$(mktemp -d /tmp/crun-e2e.XXXXXX)"

cleanup_ids=()
cleanup() {
  for id in "${cleanup_ids[@]}"; do
    "$runtime" stop "$id" --timeout 1 >/dev/null 2>&1 || true
    "$runtime" delete "$id" >/dev/null 2>&1 || true
  done
  rm -rf "$tmp_root"
}
trap cleanup EXIT

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "scripts/e2e.sh must run as root" >&2
    exit 2
  fi
}

require_runtime() {
  if [[ ! -x "$runtime" ]]; then
    echo "runtime is not executable: $runtime" >&2
    echo "build it first with: cargo build --release" >&2
    exit 2
  fi
}

write_bundle() {
  local bundle="$1"
  local args_json="$2"
  local extra="${3:-}"
  mkdir -p "$bundle"
  ln -s "$rootfs" "$bundle/rootfs"
  cat > "$bundle/config.json" <<JSON
{
  "ociVersion": "1.0.2",
  "process": {
    "args": $args_json,
    "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "cwd": "/"
  },
  "root": { "path": "rootfs", "readonly": false },
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
      "pids": { "limit": 64 }
    }
  }${extra}
}
JSON
}

wait_running() {
  local id="$1"
  for _ in $(seq 1 50); do
    if "$runtime" state "$id" --json 2>/dev/null | grep -q '"status": "running"'; then
      return 0
    fi
    sleep 0.1
  done
  echo "container did not become running: $id" >&2
  return 1
}

require_root
require_runtime

smoke_id="e2e-smoke-$$"
cleanup_ids+=("$smoke_id")
smoke_bundle="$tmp_root/smoke"
write_bundle "$smoke_bundle" '["/bin/sh", "-c", "exit 0"]'
"$runtime" run --net none --security unconfined "$smoke_id" "$smoke_bundle" >/dev/null
"$runtime" state "$smoke_id" --json | grep -q '"status": "stopped"'
"$runtime" delete "$smoke_id" >/dev/null

observe_id="e2e-observe-$$"
cleanup_ids+=("$observe_id")
observe_bundle="$tmp_root/observe"
write_bundle "$observe_bundle" '["/bin/sh", "-c", "echo log-ok; sleep 60"]' ',
  "healthcheck": { "test": ["CMD", "/bin/sh", "-c", "test -f /etc/resolv.conf"], "retries": 1 }'
"$runtime" run --net none --security unconfined --log on "$observe_id" "$observe_bundle" >/tmp/crun-e2e-run.log 2>&1 &
runner_pid=$!
wait_running "$observe_id"
"$runtime" stats "$observe_id" --json | grep -q '"memory"'
"$runtime" events "$observe_id" --snapshot --once --json | grep -q '"name":"snapshot"'
"$runtime" health "$observe_id" --json | grep -q '"status": "healthy"'
"$runtime" stop "$observe_id" --timeout 1 >/dev/null
wait "$runner_pid" || true
"$runtime" logs "$observe_id" | grep -q 'log-ok'
"$runtime" delete "$observe_id" >/dev/null

mount_id="e2e-mount-$$"
cleanup_ids+=("$mount_id")
shared="$tmp_root/shared"
mkdir -p "$shared"
echo mounted-ok > "$shared/message.txt"
mount_bundle="$tmp_root/mount"
write_bundle "$mount_bundle" \
  '["/bin/sh", "-c", "cat /data/message.txt && ! sh -c '\''echo fail > /data/new.txt'\''"]' \
  ',
  "mounts": [{
    "destination": "/data",
    "source": "'"$shared"'",
    "type": "bind",
    "options": ["rbind", "ro"]
  }]'
mount_output="$tmp_root/mount.out"
"$runtime" run --net none --security unconfined "$mount_id" "$mount_bundle" >"$mount_output" 2>&1
grep -q 'mounted-ok' "$mount_output"
"$runtime" delete "$mount_id" >/dev/null

if [[ -t 0 && -t 1 ]] && command -v script >/dev/null 2>&1; then
  tty_id="e2e-tty-$$"
  cleanup_ids+=("$tty_id")
  tty_bundle="$tmp_root/tty"
  write_bundle "$tty_bundle" '["/bin/sh", "-c", "echo tty-ok"]'
  script -qfec "$runtime run -t --net none --security unconfined $tty_id $tty_bundle" /tmp/crun-e2e-tty.out
  grep -q 'tty-ok' /tmp/crun-e2e-tty.out
  "$runtime" delete "$tty_id" >/dev/null
else
  echo "skip tty e2e: no interactive tty or script(1) unavailable"
fi

echo "e2e ok"
