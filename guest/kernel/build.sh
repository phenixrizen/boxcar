#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
#
# Builds the boxcar guest kernel: the pinned Linux tarball, Firecracker's base
# config, and boxcar.fragment on top. `cargo xtask kernel` runs this inside the
# boxcar-kernel-builder image with /src (guest/kernel, read-only), /out
# (target/guest) and /cache (target/kernel-cache) mounted; `--native` runs it
# on the host. The locations and job count can be overridden:
#
#   BOXCAR_KERNEL_SRC    directory with VERSION, base/ and boxcar.fragment (/src)
#   BOXCAR_KERNEL_OUT    where vmlinux, vmlinux.debug, kernel.config and
#                        System.map are written (/out)
#   BOXCAR_KERNEL_CACHE  the tarball and the extracted, built tree (/cache)
#   BOXCAR_KERNEL_JOBS   make -j (nproc)
set -euo pipefail

SRC=${BOXCAR_KERNEL_SRC:-/src}
OUT=${BOXCAR_KERNEL_OUT:-/out}
CACHE=${BOXCAR_KERNEL_CACHE:-/cache}
JOBS=${BOXCAR_KERNEL_JOBS:-$(nproc)}

# KERNEL_VERSION, KERNEL_SHA256 and FIRECRACKER_COMMIT.
# shellcheck source=VERSION
. "$SRC/VERSION"
: "${KERNEL_VERSION:?missing from VERSION}" "${KERNEL_SHA256:?missing from VERSION}"

# The kernel embeds whoami@hostname in its version string. The container runs
# as a bare uid with no passwd entry, where whoami fails.
export KBUILD_BUILD_USER=${KBUILD_BUILD_USER:-boxcar}
export KBUILD_BUILD_HOST=${KBUILD_BUILD_HOST:-boxcar-kernel-builder}

fail() {
    echo "kernel: $*" >&2
    exit 1
}

# verify_fragment CONFIG FRAGMENT: every fragment line must hold in CONFIG.
# CONFIG_X=y and CONFIG_X="..." need that exact line. CONFIG_X=n needs
# "# CONFIG_X is not set", or no CONFIG_X= line at all. A line of any other
# shape can never be applied and counts as missing. Mirrors verify_fragment in
# xtask/src/kernel.rs.
verify_fragment() {
    local config=$1 fragment=$2 total=0 missing=0 line sym ok
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        case $line in '' | '#'*) continue ;; esac
        total=$((total + 1))
        ok=0
        if [[ $line =~ ^(CONFIG_[A-Za-z0-9_]+)=n$ ]]; then
            sym=${BASH_REMATCH[1]}
            if grep -qxF -- "# $sym is not set" "$config" || ! grep -q -- "^$sym=" "$config"; then
                ok=1
            fi
        elif [[ $line =~ ^CONFIG_[A-Za-z0-9_]+=.+$ ]]; then
            if grep -qxF -- "$line" "$config"; then
                ok=1
            fi
        fi
        if [ "$ok" -eq 0 ]; then
            echo "fragment: missing from .config: $line"
            missing=$((missing + 1))
        fi
    done <"$fragment"
    if [ "$missing" -ne 0 ]; then
        echo "fragment: $missing of $total lines not applied"
        return 1
    fi
    echo "fragment: all $total applied"
}

# has_btf FILE: readelf -S lists a section named exactly .BTF (not .BTF_ids
# or a symbol that merely mentions it). The listing goes through a variable
# because grep -q closing the pipe early would trip pipefail.
has_btf() {
    local sections
    sections=$(readelf -S "$1")
    grep -Eq '\] \.BTF +' <<<"$sections"
}

tarball=$CACHE/linux-$KERNEL_VERSION.tar.xz
tree=$CACHE/linux-$KERNEL_VERSION
url=https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_VERSION%%.*}.x/linux-$KERNEL_VERSION.tar.xz

mkdir -p "$CACHE" "$OUT"

if [ ! -f "$tarball" ]; then
    echo "kernel: downloading $url"
    rm -f "$tarball.part"
    curl --fail --silent --show-error --location --retry 3 --output "$tarball.part" "$url"
    mv "$tarball.part" "$tarball"
fi
if ! echo "$KERNEL_SHA256  $tarball" | sha256sum --check --status; then
    rm -f "$tarball"
    fail "sha256 of linux-$KERNEL_VERSION.tar.xz does not match KERNEL_SHA256 ($KERNEL_SHA256); removed it from the cache"
fi
echo "kernel: linux-$KERNEL_VERSION.tar.xz sha256 ok"

# Extract to a scratch directory and rename, so an interrupted extraction never
# leaves a half-populated tree that looks complete.
if [ ! -f "$tree/Makefile" ]; then
    echo "kernel: extracting into $tree"
    rm -rf "$tree" "$tree.tmp"
    mkdir "$tree.tmp"
    tar -xf "$tarball" -C "$tree.tmp" --strip-components=1
    mv "$tree.tmp" "$tree"
fi

cd "$tree"
cp "$SRC/base/microvm-kernel-ci-x86_64-6.18.config" .config
scripts/kconfig/merge_config.sh -m .config "$SRC/boxcar.fragment"
make olddefconfig
verify_fragment .config "$SRC/boxcar.fragment" || fail "fragment not applied; see the lines above"

make -j"$JOBS" vmlinux
has_btf vmlinux || fail "vmlinux has no .BTF section (is pahole >= 1.22 installed?)"

objcopy --only-keep-debug vmlinux "$OUT/vmlinux.debug"
objcopy --strip-debug vmlinux "$OUT/vmlinux"
has_btf "$OUT/vmlinux" || fail ".BTF did not survive objcopy --strip-debug"

cp .config "$OUT/kernel.config"
cp System.map "$OUT/System.map"
echo "kernel: linux-$KERNEL_VERSION built into $OUT"
