#!/usr/bin/env bash
# Run the seccomp evaluation and write the numbers the thesis reports.
#
# scripts/benchmark.sh is left alone: its startup metric stops at the moment the
# runtime records the container as running, which happens in the parent before
# the child sets up its namespaces and installs any seccomp filter, so it cannot
# see enforce mode overhead at all. This script measures time to readiness and
# a whole-run figure instead.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/common.sh
. "$REPO_ROOT/scripts/lib/common.sh"

RUNTIME="$REPO_ROOT/target/release/minicrun"
MANIFEST="$REPO_ROOT/workloads/workloads.json"
BUNDLE_DIR="$REPO_ROOT/workloads"
BASELINE="$REPO_ROOT/third_party/moby-profiles/seccomp/default.json"
CVE_MAP="$REPO_ROOT/data/cve-syscall-map.json"
OUT_DIR="$REPO_ROOT/docs/benchmark/data"
WORKLOAD="all"
ARMS="all"
REPEAT=30
WARMUP=3
NET=""
SECCOMP_ACTION="errno"
TIMEOUT_MS=15000
TAG="$(date +%F-%H%M%S)"
KEEP_GOING=0
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: scripts/experiment.sh [options]

  --workload NAME|all   Workload from workloads/workloads.json (default: all)
  --arm NAME|all        unconfined | minicrun-denylist | learn | enforce | all
  --repeat N            Measured iterations per arm (default: 30)
  --warmup K            Discarded iterations per arm (default: 3)
  --net none|bridge     Override the manifest network mode
  --seccomp-action A    errno | kill, for the enforce arm (default: errno)
  --timeout-ms MS       Readiness timeout (default: 15000)
  --tag NAME            Output subdirectory (default: date +%F-%H%M%S)
  --out DIR             Output root (default: docs/benchmark/data)
  --profile-dir DIR     Where generated profiles are written
  --keep-going          Continue after a failed arm
  --dry-run             Print the plan and exit
  -h, --help            Show this help

Arms are interleaved per iteration rather than run in blocks, so thermal and
frequency drift is shared across them instead of biasing whichever ran first.
EOF
}

PROFILE_DIR=""

while [ $# -gt 0 ]; do
    case "$1" in
        --workload) WORKLOAD="$2"; shift 2 ;;
        --arm) ARMS="$2"; shift 2 ;;
        --repeat) REPEAT="$2"; shift 2 ;;
        --warmup) WARMUP="$2"; shift 2 ;;
        --net) NET="$2"; shift 2 ;;
        --seccomp-action) SECCOMP_ACTION="$2"; shift 2 ;;
        --timeout-ms) TIMEOUT_MS="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        --profile-dir) PROFILE_DIR="$2"; shift 2 ;;
        --keep-going) KEEP_GOING=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

RESULT_DIR="$OUT_DIR/$TAG"
PROFILE_DIR="${PROFILE_DIR:-$RESULT_DIR/profiles}"

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: missing required command: $1" >&2; exit 2; }
}

require jq
[ -x "$RUNTIME" ] || { echo "error: build the runtime first: cargo build --release" >&2; exit 2; }
[ -f "$MANIFEST" ] || { echo "error: missing manifest: $MANIFEST" >&2; exit 2; }

workload_names() {
    if [ "$WORKLOAD" = "all" ]; then
        jq -r '.workloads[].name' "$MANIFEST"
    else
        jq -r --arg name "$WORKLOAD" '.workloads[] | select(.name == $name) | .name' "$MANIFEST"
    fi
}

workload_json() {
    jq --arg name "$1" '.workloads[] | select(.name == $name)' "$MANIFEST"
}

arm_list() {
    if [ "$ARMS" = "all" ]; then
        echo "unconfined minicrun-denylist learn enforce"
    else
        echo "$ARMS" | tr ',' ' '
    fi
}

cleanup_container() {
    local id="$1"
    "$RUNTIME" stop "$id" --timeout 2 >/dev/null 2>&1 || true
    "$RUNTIME" delete "$id" >/dev/null 2>&1 || true
}

# Runs one container and reports: ready_ms total_ms rss_kb ready functional
run_once() {
    local workload="$1" arm="$2" iteration="$3" bundle="$4" net="$5" spec="$6"
    local id="exp-${workload}-${arm}-${iteration}-$$"
    local -a extra=()

    case "$arm" in
        unconfined) extra=(--security unconfined) ;;
        minicrun-denylist) extra=(--security denylist) ;;
        learn)
            extra=(--security unconfined --seccomp learn
                   --seccomp-out "$RESULT_DIR/captures/${workload}-${iteration}.json")
            ;;
        enforce)
            extra=(--security unconfined --seccomp enforce
                   --seccomp-profile "$PROFILE_DIR/${workload}.json"
                   --seccomp-action "$SECCOMP_ACTION")
            ;;
        *) echo "error: unknown arm: $arm" >&2; return 2 ;;
    esac

    local start_ns ready_ms total_ms rss=0 ready=false functional=false
    start_ns="$(now_ns)"

    "$RUNTIME" run --net "$net" --log on "${extra[@]}" "$id" "$bundle" \
        >"$RESULT_DIR/logs/${workload}-${arm}-${iteration}.out" 2>&1 &
    local runner_pid=$!

    if wait_for_running "$RUNTIME" "$id" "$TIMEOUT_MS" >/dev/null; then
        local container_pid
        container_pid="$(state_pid "$RUNTIME" "$id")"
        [ -n "$container_pid" ] && rss="$(rss_kb "$container_pid")"

        if check_ready "$id" "$spec"; then
            ready=true
            ready_ms="$(ms_since "$start_ns")"
            if check_smoke "$id" "$spec"; then
                functional=true
            fi
        fi
    fi

    ready_ms="${ready_ms:-0}"
    cleanup_container "$id"
    wait "$runner_pid" 2>/dev/null || true
    total_ms="$(ms_since "$start_ns")"

    echo "$ready_ms $total_ms $rss $ready $functional"
}

check_ready() {
    local id="$1" spec="$2"
    local ready_log ready_expect
    ready_log="$(jq -r '.ready_log // empty' <<<"$spec")"
    ready_expect="$(jq -r '.ready_expect // empty' <<<"$spec")"

    local deadline=$((SECONDS + TIMEOUT_MS / 1000 + 1))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if [ -n "$ready_log" ]; then
            if "$RUNTIME" logs "$id" 2>/dev/null | grep -q -- "$ready_log"; then
                return 0
            fi
        elif jq -e '.ready_exec' >/dev/null <<<"$spec"; then
            local output
            output="$(jq -r '.ready_exec[]' <<<"$spec" | xargs -d '\n' "$RUNTIME" exec "$id" 2>/dev/null || true)"
            if [ -z "$ready_expect" ] || grep -qF -- "$ready_expect" <<<"$output"; then
                [ -n "$output" ] && return 0
            fi
        else
            return 0
        fi
        sleep 0.2
    done

    return 1
}

check_smoke() {
    local id="$1" spec="$2"
    jq -e '.smoke' >/dev/null <<<"$spec" || return 0

    local expect output
    expect="$(jq -r '.smoke_expect // empty' <<<"$spec")"
    output="$(jq -r '.smoke[]' <<<"$spec" | xargs -d '\n' "$RUNTIME" exec "$id" 2>/dev/null || true)"

    [ -z "$expect" ] || grep -qF -- "$expect" <<<"$output"
}

if [ "$DRY_RUN" -eq 1 ]; then
    echo "tag: $TAG"
    echo "workloads: $(workload_names | tr '\n' ' ')"
    echo "arms: $(arm_list)"
    echo "repeat: $REPEAT (warmup $WARMUP)"
    echo "results: $RESULT_DIR"
    exit 0
fi

# Checked after --dry-run so the plan can be reviewed without privileges.
[ "$(id -u)" -eq 0 ] || { echo "error: must run as root" >&2; exit 2; }

mkdir -p "$RESULT_DIR/logs" "$RESULT_DIR/captures" "$PROFILE_DIR"

cat >"$RESULT_DIR/environment.json" <<EOF
{
  "kernel": "$(uname -r)",
  "arch": "$(uname -m)",
  "cores": $(nproc),
  "loadavg_start": $(awk '{print $1}' /proc/loadavg),
  "crun_sha256": "$(sha256sum "$RUNTIME" | awk '{print $1}')",
  "git_commit": "$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)",
  "started_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

status=0
for workload in $(workload_names); do
    spec="$(workload_json "$workload")"
    bundle="$BUNDLE_DIR/$workload"
    net="${NET:-$(jq -r '.net // "none"' <<<"$spec")}"

    if [ ! -f "$bundle/config.json" ]; then
        echo "skipping $workload: no bundle at $bundle (run scripts/build-workloads.sh)"
        [ "$KEEP_GOING" -eq 1 ] || status=1
        continue
    fi

    echo "== $workload (net=$net) =="
    declare -A ready_samples total_samples rss_samples ready_ok functional_ok
    for arm in $(arm_list); do
        ready_samples[$arm]=""
        total_samples[$arm]=""
        rss_samples[$arm]=""
        ready_ok[$arm]=0
        functional_ok[$arm]=0
    done

    # The enforce arm needs a profile, so learn once up front when it is missing.
    if [[ " $(arm_list) " == *" enforce "* ]] && [ ! -f "$PROFILE_DIR/$workload.json" ]; then
        echo "-- learning a profile for $workload"
        for round in 1 2 3; do
            run_once "$workload" learn "seed$round" "$bundle" "$net" "$spec" >/dev/null || true
        done
        capture_args=()
        for capture in "$RESULT_DIR/captures/${workload}-seed"*.json; do
            [ -f "$capture" ] && capture_args+=(--capture "$capture")
        done
        if [ "${#capture_args[@]}" -gt 0 ]; then
            "$RUNTIME" seccomp generate "${capture_args[@]}" \
                -o "$PROFILE_DIR/$workload.json" --name "$workload" >/dev/null
        else
            echo "warning: no captures produced for $workload; skipping the enforce arm" >&2
        fi
    fi

    for iteration in $(seq 1 $((WARMUP + REPEAT))); do
        for arm in $(arm_list); do
            if [ "$arm" = "enforce" ] && [ ! -f "$PROFILE_DIR/$workload.json" ]; then
                continue
            fi

            read -r ready_ms total_ms rss ready functional < <(
                run_once "$workload" "$arm" "$iteration" "$bundle" "$net" "$spec"
            )

            [ "$iteration" -le "$WARMUP" ] && continue

            ready_samples[$arm]+="$ready_ms"$'\n'
            total_samples[$arm]+="$total_ms"$'\n'
            rss_samples[$arm]+="$rss"$'\n'
            [ "$ready" = true ] && ready_ok[$arm]=$(( ${ready_ok[$arm]} + 1 ))
            [ "$functional" = true ] && functional_ok[$arm]=$(( ${functional_ok[$arm]} + 1 ))
        done
    done

    arms_json="{}"
    for arm in $(arm_list); do
        [ -n "${ready_samples[$arm]}" ] || continue
        ready_summary="$(printf '%s' "${ready_samples[$arm]}" | grep -v '^$' | summarize_json)"
        total_summary="$(printf '%s' "${total_samples[$arm]}" | grep -v '^$' | summarize_json)"
        rss_summary="$(printf '%s' "${rss_samples[$arm]}" | grep -v '^$' | summarize_json)"
        arms_json="$(jq --arg arm "$arm" \
            --argjson ready "$ready_summary" \
            --argjson total "$total_summary" \
            --argjson rss "$rss_summary" \
            --argjson ready_ok "${ready_ok[$arm]}" \
            --argjson functional_ok "${functional_ok[$arm]}" \
            --argjson repeat "$REPEAT" \
            '.[$arm] = {time_to_ready_ms: $ready, total_run_ms: $total, container_rss_kb: $rss,
                        ready_ok: $ready_ok, functional_ok: $functional_ok,
                        false_denial_rate: (1 - ($functional_ok / $repeat))}' \
            <<<"$arms_json")"
    done

    comparison="{}"
    if [ -f "$PROFILE_DIR/$workload.json" ]; then
        comparison="$("$RUNTIME" seccomp compare "$PROFILE_DIR/$workload.json" \
            --baseline "$BASELINE" --cve-map "$CVE_MAP" --json)"
    fi

    jq -n \
        --arg tag "$TAG" \
        --arg workload "$workload" \
        --arg image "$(jq -r '.image' <<<"$spec")" \
        --arg digest "$(jq -r '.digest // ""' <<<"$spec")" \
        --argjson environment "$(cat "$RESULT_DIR/environment.json")" \
        --argjson config "{\"net\":\"$net\",\"repeat\":$REPEAT,\"warmup\":$WARMUP,\"seccomp_action\":\"$SECCOMP_ACTION\",\"timeout_ms\":$TIMEOUT_MS}" \
        --argjson arms "$arms_json" \
        --argjson comparison "$comparison" \
        '{schema_version: 1, tag: $tag, workload: $workload, image: $image, digest: $digest,
          environment: $environment, config: $config, arms: $arms, comparison: $comparison}' \
        >"$RESULT_DIR/$workload.json"

    echo "wrote $RESULT_DIR/$workload.json"
done

echo "results: $RESULT_DIR"
exit "$status"
