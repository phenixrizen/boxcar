# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
#
# Builder image for the boxcar guest kernel. `cargo xtask kernel` builds it and
# runs build.sh inside. The base image is pinned by digest; keep it equal to
# DEBIAN_IMAGE in VERSION.
FROM debian:trixie@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c

ENV DEBIAN_FRONTEND=noninteractive

# bpftool and bindgen generate the sensor's kernel type bindings from the
# built kernel's BTF (`cargo xtask gen-vmlinux`); their versions are named in
# the generated file's header.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        build-essential flex bison bc libelf-dev libssl-dev dwarves \
        python3 xz-utils cpio kmod rsync ca-certificates curl \
        bpftool bindgen \
 && rm -rf /var/lib/apt/lists/*

# CONFIG_DEBUG_INFO_BTF needs pahole 1.22 or newer. Fail the image build, not
# the kernel build an hour later, if the distribution ever ships an older one.
RUN v="$(pahole --version | sed 's/^v//')" \
 && echo "pahole $v" \
 && [ "$(printf '%s\n1.22\n' "$v" | sort -V | head -n1)" = "1.22" ]
