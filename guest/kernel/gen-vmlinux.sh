#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
#
# Generates the sensor's kernel type bindings from the built kernel's BTF.
# `cargo xtask gen-vmlinux` runs this inside the boxcar-kernel-builder image
# with /out (target/guest, holding vmlinux) mounted; it reads /out/vmlinux and
# writes /out/vmlinux.h (bpftool's C dump), /out/vmlinux.rs.body (bindgen's
# output, without a header) and /out/vmlinux.tools (the tool versions, one a
# line). The allowlisted types are the ones the eBPF programs read; bindgen
# brings in what they refer to.
#
#   BOXCAR_KERNEL_OUT   where vmlinux is, and the outputs go (/out)
set -euo pipefail

OUT=${BOXCAR_KERNEL_OUT:-/out}

fail() {
    echo "gen-vmlinux: $*" >&2
    exit 1
}

[ -f "$OUT/vmlinux" ] || fail "$OUT/vmlinux is missing: build the kernel first"
command -v bpftool >/dev/null || fail "bpftool is not installed"
command -v bindgen >/dev/null || fail "bindgen is not installed"

allowlist=(
    task_struct linux_binprm mm_struct sock sock_common socket
    sockaddr sockaddr_in sockaddr_in6 file path dentry qstr
    kernel_siginfo cred pt_regs
)
args=()
for t in "${allowlist[@]}"; do
    args+=(--allowlist-type "$t")
done

bpftool btf dump file "$OUT/vmlinux" format c >"$OUT/vmlinux.h"
grep -q 'struct task_struct {' "$OUT/vmlinux.h" || fail "the BTF dump has no task_struct"

bindgen "$OUT/vmlinux.h" \
    --use-core \
    --ctypes-prefix core::ffi \
    --no-layout-tests \
    --no-prepend-enum-name \
    --default-enum-style moduleconsts \
    --with-derive-default \
    "${args[@]}" \
    >"$OUT/vmlinux.rs.body"
grep -q 'pub struct task_struct ' "$OUT/vmlinux.rs.body" || fail "bindgen produced no task_struct"

{
    bpftool version | head -n1
    bindgen --version
} >"$OUT/vmlinux.tools"
echo "gen-vmlinux: $(wc -l <"$OUT/vmlinux.rs.body") lines of bindings"
