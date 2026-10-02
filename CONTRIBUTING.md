# Contributing to boxcar

## Ground rules

- Every commit is signed off (`git commit -s`) and by doing so you agree to
  [CLA.md](CLA.md). Commit subjects are `area: summary` in the imperative.
- Every new source file starts with
  `// SPDX-License-Identifier: Apache-2.0` and
  `// Copyright 2026 The boxcar Authors`. A file ported from another project
  keeps that project's header above ours, names its source repository and
  commit, and gets an entry in [NOTICE](NOTICE).
- No git dependencies and no `[patch]` sections in `Cargo.toml`. Everything
  comes from crates.io at the pinned versions in the workspace manifest.
- Commands are argv arrays. Never build a shell string from user input.
- Every control-socket message and every audit record type has a size limit
  and a test.
- Tests that need `/dev/kvm` are gated behind `--features kvm-tests` and skip
  cleanly when the device or the guest artifacts are missing.

## Checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo nextest run --workspace
cargo deny check
cargo xtask schema && git diff --exit-code proto/   # the schemas are current
cargo xtask test-kvm m1          # needs /dev/kvm and target/guest/*
```

`cargo xtask schema` writes `proto/schema/{control-v1,audit-v1,guest-v1}.json`
and `proto/testdata/control-v1.jsonl` from the types in `boxcar-proto`; a
change to a message or record type is committed with them. The protocols
are described in [docs/control-protocol.md](docs/control-protocol.md) and
[docs/audit-events.md](docs/audit-events.md).

## KVM on the dev machine

```bash
sudo modprobe kvm_amd            # or kvm_intel
sudo setfacl -m "u:$(id -un):rw" /dev/kvm
cargo run -p boxcar -- doctor
cargo xtask test-kvm m1          # the KVM-gated tests, once the artifacts below are built
```

`cargo xtask test-kvm m1` runs the gated tests of `boxcar-vmm` and `boxcar`,
which boot real VMs: one at a time, with their output shown, and with
`BOXCAR_TEST_KERNEL`, `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` set to
the artifacts in `target/guest`. Without `/dev/kvm` or an artifact it says
what is missing and exits 0.

## Guest artifacts

```bash
cargo xtask kernel               # builds target/guest/vmlinux in Docker
cargo xtask initramfs            # builds target/guest/initramfs.cpio
cargo xtask rootfs alpine        # unpacks target/guest/rootfs-alpine/
```
