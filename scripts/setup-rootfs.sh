#!/usr/bin/env bash
# Build the example bundle root filesystem that the tests, e2e script and
# benchmark all depend on.
#
# The extracted rootfs is deliberately not tracked by git, so a fresh clone has
# to run this script once before any root test can pass.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_FILE="$REPO_ROOT/scripts/rootfs.lock"
DEST="$REPO_ROOT/examples/bundle"
FORCE=0
CHECK_ONLY=0
UPDATE_LOCK=0
VERSION=""

usage() {
    cat <<'EOF'
Usage: scripts/setup-rootfs.sh [options]

  --dest PATH      Bundle directory to populate (default: examples/bundle)
  --version VER    Alpine version to fetch (default: from scripts/rootfs.lock)
  --force          Re-extract even when the rootfs already exists
  --check-only     Verify the bundle is usable, then exit
  --update-lock    Fetch the upstream checksum and rewrite scripts/rootfs.lock
  -h, --help       Show this help

The tarball is verified against the sha256 pinned in scripts/rootfs.lock, so
every machine builds a byte-identical rootfs. Use --update-lock when moving to
a new Alpine release; commit the resulting lock file.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dest) DEST="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --force) FORCE=1; shift ;;
        --check-only) CHECK_ONLY=1; shift ;;
        --update-lock) UPDATE_LOCK=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ ! -f "$LOCK_FILE" ]; then
    echo "error: missing lock file: $LOCK_FILE" >&2
    exit 2
fi

# shellcheck disable=SC1090
. "$LOCK_FILE"
VERSION="${VERSION:-$alpine_version}"
ARCH="$alpine_arch"
MIRROR="$alpine_mirror"
SERIES="v${VERSION%.*}"
TARBALL="alpine-minirootfs-${VERSION}-${ARCH}.tar.gz"
URL="$MIRROR/$SERIES/releases/$ARCH/$TARBALL"
ROOTFS="$DEST/rootfs"

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "error: missing required command: $1" >&2; exit 2; }
}

check_bundle() {
    [ -f "$DEST/config.json" ] || { echo "missing: $DEST/config.json" >&2; return 1; }
    [ -x "$ROOTFS/bin/busybox" ] || { echo "missing: $ROOTFS/bin/busybox" >&2; return 1; }
    # /bin/sh is an absolute symlink to /bin/busybox, which only resolves inside
    # the container, so test the link itself rather than its target.
    [ -e "$ROOTFS/bin/sh" ] || [ -L "$ROOTFS/bin/sh" ] || {
        echo "missing: $ROOTFS/bin/sh" >&2
        return 1
    }
    return 0
}

if [ "$CHECK_ONLY" -eq 1 ]; then
    if check_bundle; then
        echo "bundle ok: $DEST"
        exit 0
    fi
    echo "bundle incomplete; run scripts/setup-rootfs.sh" >&2
    exit 1
fi

require curl
require sha256sum
require tar

if [ "$UPDATE_LOCK" -eq 1 ]; then
    echo "fetching upstream checksum for $TARBALL"
    checksum="$(curl -fsSL "$URL.sha256" | awk '{print $1}')"
    [ -n "$checksum" ] || { echo "error: could not read upstream checksum" >&2; exit 1; }
    cat >"$LOCK_FILE" <<EOF
# Pinned base root filesystem for examples/bundle.
# Regenerate the checksum with: scripts/setup-rootfs.sh --update-lock --version <v>
alpine_version=$VERSION
alpine_arch=$ARCH
alpine_sha256=$checksum
alpine_mirror=$MIRROR
EOF
    echo "updated $LOCK_FILE"
    alpine_sha256="$checksum"
fi

if [ -d "$ROOTFS" ] && [ "$FORCE" -eq 0 ]; then
    if check_bundle; then
        echo "bundle already present: $DEST (use --force to rebuild)"
        exit 0
    fi
    echo "bundle present but incomplete; rebuilding"
fi

WORK_DIR="$(mktemp -d /tmp/crun-rootfs.XXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "downloading $URL"
curl -fsSL "$URL" -o "$WORK_DIR/$TARBALL"

if ! echo "$alpine_sha256  $WORK_DIR/$TARBALL" | sha256sum -c - >/dev/null; then
    echo "error: checksum mismatch for $TARBALL" >&2
    echo "expected $alpine_sha256" >&2
    echo "actual   $(sha256sum "$WORK_DIR/$TARBALL" | awk '{print $1}')" >&2
    exit 1
fi
echo "checksum ok"

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"
# Extraction needs root to restore ownership and device nodes.
if [ "$(id -u)" -eq 0 ]; then
    tar -xzf "$WORK_DIR/$TARBALL" -C "$ROOTFS"
else
    echo "note: not running as root; extracting without ownership restore"
    tar -xzf "$WORK_DIR/$TARBALL" -C "$ROOTFS" --no-same-owner
fi

if [ ! -f "$DEST/config.json" ]; then
    echo "error: missing $DEST/config.json (it is tracked in git)" >&2
    exit 1
fi

check_bundle
echo "bundle ready: $DEST (alpine $VERSION $ARCH)"
