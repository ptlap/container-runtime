# Shared helpers for the benchmark and experiment scripts.
# shellcheck shell=bash

now_ns() {
    date +%s%N
}

ms_since() {
    local start_ns="$1"
    echo $(((($(now_ns) - start_ns)) / 1000000))
}

rss_kb() {
    local pid="$1"
    [ -r "/proc/$pid/status" ] || { echo 0; return; }
    awk '/^VmRSS:/ {print $2; exit}' "/proc/$pid/status" 2>/dev/null || echo 0
}

state_field() {
    local runtime="$1" id="$2" field="$3"
    "$runtime" state "$id" --json 2>/dev/null | jq -r ".$field // empty"
}

state_pid() {
    state_field "$1" "$2" pid
}

# Waits until the runtime reports the container as running.
wait_for_running() {
    local runtime="$1" id="$2" timeout_ms="${3:-15000}"
    local start_ns deadline_ns
    start_ns="$(now_ns)"
    deadline_ns=$((start_ns + timeout_ms * 1000000))

    while [ "$(now_ns)" -lt "$deadline_ns" ]; do
        if [ "$(state_field "$runtime" "$id" status)" = "running" ]; then
            ms_since "$start_ns"
            return 0
        fi
        sleep 0.02
    done

    return 1
}

# min, p25, median, p75, max, mean, n as a JSON object, values on stdin.
#
# Startup latency is right skewed and has a hard floor, so a mean plus standard
# deviation asserts a symmetry the data does not have. The mean is kept only so
# the older benchmark summary shape stays a subset of this one.
summarize_json() {
    sort -n | awk '
        { values[NR] = $1; total += $1 }
        END {
            if (NR == 0) { print "{\"n\":0}"; exit }
            n = NR
            median_idx = int(0.5 * (n - 1)) + 1
            p25_idx = int(0.25 * (n - 1)) + 1
            p75_idx = int(0.75 * (n - 1)) + 1
            p95_idx = int(0.95 * (n - 1)) + 1
            mean = total / n
            variance = 0
            for (i = 1; i <= n; i++) variance += (values[i] - mean) ^ 2
            stddev = (n > 1) ? sqrt(variance / (n - 1)) : 0
            printf "{\"n\":%d,\"min\":%d,\"p25\":%d,\"median\":%d,\"p75\":%d,\"p95\":%d,\"max\":%d,\"mean\":%.2f,\"stddev\":%.2f}",
                n, values[1], values[p25_idx], values[median_idx], values[p75_idx], values[p95_idx], values[n], mean, stddev
        }
    '
}
