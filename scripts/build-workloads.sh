#!/usr/bin/env bash
# Build OCI bundles for the evaluation workloads.
#
# skopeo copies the image by digest and umoci unpacks it into a real OCI bundle,
# so process.args, env, cwd and user come from the image configuration rather
# than being written by hand. Hand written startup arguments are the easiest way
# to get the syscall numbers wrong, because startup is where the syscall set is
# widest.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$REPO_ROOT/workloads/workloads.json"
OUT_DIR="$REPO_ROOT/workloads"
OCI_DIR="/var/lib/crun-rs/oci"
WORKLOAD="all"
FORCE=0
LIST=0
VERIFY=0
UPDATE_DIGEST=""

usage() {
    cat <<'EOF'
Usage: scripts/build-workloads.sh [options]

  --workload NAME|all     Workload to build (default: all)
  --manifest PATH         Workload manifest (default: workloads/workloads.json)
  --out DIR               Bundle output directory (default: workloads)
  --oci-dir DIR           Where skopeo stores OCI layouts (default: /var/lib/crun-rs/oci)
  --force                 Rebuild even when the bundle already exists
  --list                  Print workloads and their pinned digests, then exit
  --verify                Check bundles against their provenance, then exit
  --update-digest NAME    Resolve NAME's current digest into the manifest, then exit
  -h, --help              Show this help

Requires skopeo and umoci. Run as root so umoci can restore ownership.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --workload) WORKLOAD="$2"; shift 2 ;;
        --manifest) MANIFEST="$2"; shift 2 ;;
        --out) OUT_DIR="$2"; shift 2 ;;
        --oci-dir) OCI_DIR="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --list) LIST=1; shift ;;
        --verify) VERIFY=1; shift ;;
        --update-digest) UPDATE_DIGEST="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: missing required command: $1" >&2; exit 2; }
}

require jq
[ -f "$MANIFEST" ] || { echo "error: missing manifest: $MANIFEST" >&2; exit 2; }

workload_names() {
    if [ "$WORKLOAD" = "all" ]; then
        jq -r '.workloads[].name' "$MANIFEST"
    else
        jq -r --arg name "$WORKLOAD" '.workloads[] | select(.name == $name) | .name' "$MANIFEST"
    fi
}

workload_field() {
    jq -r --arg name "$1" --arg field "$2" \
        '.workloads[] | select(.name == $name) | .[$field] // empty' "$MANIFEST"
}

if [ "$LIST" -eq 1 ]; then
    printf '%-12s %-46s %s\n' NAME IMAGE DIGEST
    jq -r '.workloads[] | [.name, .image, (.digest // "-")] | @tsv' "$MANIFEST" \
        | while IFS=$'\t' read -r name image digest; do
            printf '%-12s %-46s %s\n' "$name" "$image" "${digest:--}"
        done
    exit 0
fi

if [ -n "$UPDATE_DIGEST" ]; then
    require skopeo
    image="$(workload_field "$UPDATE_DIGEST" image)"
    [ -n "$image" ] || { echo "error: unknown workload: $UPDATE_DIGEST" >&2; exit 2; }
    echo "resolving $image"
    digest="$(skopeo inspect "docker://$image" | jq -r '.Digest')"
    [ -n "$digest" ] || { echo "error: could not resolve a digest" >&2; exit 1; }
    tmp="$(mktemp)"
    jq --arg name "$UPDATE_DIGEST" --arg digest "$digest" \
        '(.workloads[] | select(.name == $name) | .digest) = $digest' "$MANIFEST" >"$tmp"
    mv "$tmp" "$MANIFEST"
    echo "$UPDATE_DIGEST pinned to $digest"
    exit 0
fi

if [ "$VERIFY" -eq 1 ]; then
    status=0
    for name in $(workload_names); do
        bundle="$OUT_DIR/$name"
        if [ ! -f "$bundle/config.json" ] || [ ! -d "$bundle/rootfs" ]; then
            echo "missing: $bundle"
            status=1
            continue
        fi
        recorded="$(jq -r '.digest // empty' "$bundle/provenance.json" 2>/dev/null || true)"
        expected="$(workload_field "$name" digest)"
        if [ -n "$expected" ] && [ "$recorded" != "$expected" ]; then
            echo "digest drift: $name built from ${recorded:-unknown}, manifest pins $expected"
            status=1
            continue
        fi
        echo "ok: $name"
    done
    exit "$status"
fi

require skopeo
require umoci
[ "$(id -u)" -eq 0 ] || echo "warning: not running as root; umoci cannot restore ownership" >&2

mkdir -p "$OCI_DIR" "$OUT_DIR"

for name in $(workload_names); do
    image="$(workload_field "$name" image)"
    digest="$(workload_field "$name" digest)"
    [ -n "$image" ] || { echo "error: unknown workload: $WORKLOAD" >&2; exit 2; }

    bundle="$OUT_DIR/$name"
    if [ -d "$bundle/rootfs" ] && [ "$FORCE" -eq 0 ]; then
        echo "$name: already built (use --force to rebuild)"
        continue
    fi

    if [ -z "$digest" ]; then
        echo "error: $name has no pinned digest; run --update-digest $name first" >&2
        exit 1
    fi

    reference="${image%%:*}"
    reference="${image%@*}"
    reference="${reference%%:*}@$digest"

    echo "== $name =="
    echo "copying docker://$reference"
    rm -rf "${OCI_DIR:?}/$name"
    skopeo copy "docker://$reference" "oci:$OCI_DIR/$name:latest"

    echo "unpacking into $bundle"
    rm -rf "$bundle/rootfs" "$bundle/config.json" "$bundle/umoci.json"
    umoci unpack --image "$OCI_DIR/$name:latest" "$bundle"

    args_override="$(workload_field "$name" args_override)"
    if [ -n "$args_override" ]; then
        tmp="$(mktemp)"
        jq --argjson args "$args_override" '.process.args = $args' "$bundle/config.json" >"$tmp"
        mv "$tmp" "$bundle/config.json"
    fi

    user_override="$(workload_field "$name" user_override)"
    if [ -n "$user_override" ]; then
        tmp="$(mktemp)"
        jq --argjson user "$user_override" \
            '.process.user.uid = $user.uid | .process.user.gid = $user.gid' \
            "$bundle/config.json" >"$tmp"
        mv "$tmp" "$bundle/config.json"
    fi

    # Declared adaptations, recorded rather than applied silently: each one is a
    # gap in this runtime and belongs in the limitations chapter.
    jq -c '.rootfs_fixups[]? // empty' <(jq --arg name "$name" '.workloads[] | select(.name == $name)' "$MANIFEST") \
        | while read -r fixup; do
            kind="$(jq -r '.kind' <<<"$fixup")"
            case "$kind" in
                replace_symlink_with_file)
                    for path in $(jq -r '.paths[]' <<<"$fixup"); do
                        target="$bundle/rootfs${path}"
                        if [ -L "$target" ]; then
                            rm -f "$target"
                            mkdir -p "$(dirname "$target")"
                            : >"$target"
                            echo "fixup: replaced symlink $path with a regular file"
                        fi
                    done
                    ;;
                *)
                    echo "warning: unknown fixup kind: $kind" >&2
                    ;;
            esac
        done

    cat >"$bundle/provenance.json" <<EOF
{
  "name": "$name",
  "image": "$image",
  "digest": "$digest",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "skopeo": "$(skopeo --version | head -1)",
  "umoci": "$(umoci --version 2>&1 | head -1)",
  "host_kernel": "$(uname -r)"
}
EOF

    if [ -x "$REPO_ROOT/target/release/minicrun" ]; then
        "$REPO_ROOT/target/release/minicrun" validate "$bundle" || {
            echo "error: generated bundle failed validation: $bundle" >&2
            exit 1
        }
    fi

    echo "$name: ready at $bundle"
done
