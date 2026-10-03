# The eBPF programs' licence

boxcar is Apache-2.0. One part of the tree is not: the guest sensor's eBPF
programs, `crates/boxcar-sensor-ebpf`, are licensed `MIT OR GPL-2.0`, and
the object they build to declares `Dual MIT/GPL` in its `license` section.
This page says why, and what it does and does not touch.

## Why

The kernel gates some of its BPF helpers and attachment points on the
program's licence: a program may call the GPL-only helpers (`bpf_d_path`,
which resolves a file to its path, among them) and attach to LSM hooks only
when its `license` section names a GPL-compatible licence. The sensor needs
both: `file_open` is an LSM hook, `bpf_d_path` is how it names the file,
`socket_connect`, `bpf` and `task_kill` are LSM hooks. `Dual MIT/GPL` is the
string the kernel's own documentation gives for dual-licensed programs, and
what aya's template uses.

The programs also read the kernel's own structures (`task_struct`,
`linux_binprm`, `sock`, ...) through `src/vmlinux.rs`, Rust bindings that
`cargo xtask gen-vmlinux` generates from the guest kernel's BTF with
`bpftool` and `bindgen` inside the kernel build image. Those bindings
describe the Linux kernel's types and carry its licence, `GPL-2.0`, in their
header, with the kernel version and the blake3 of the BTF they came from.

## What it touches

- The eBPF crate is **not** a member of the Cargo workspace (it is in
  `[workspace] exclude`), has its own `Cargo.lock`, and builds only for
  `bpfel-unknown-none` on the pinned nightly, through `boxcar-sensor`'s
  `build.rs` or by hand in its directory.
- Its output, the eBPF object, is embedded in `boxcar-sensor`, the
  userspace sensor that runs **inside the guest**, as bytes that are handed
  to the guest kernel. It is data to the Rust program that carries it, in
  the way a kernel module is data to the tool that loads it; `boxcar-sensor`
  itself is Apache-2.0.
- Nothing from the eBPF crate or the bindings is compiled into, linked
  into, or run by a host binary. `boxcar`, `boxcar-vmm` and the other host
  crates do not depend on it. `boxcar-sensor-common`, the `no_std` event
  structs both sides share, is Apache-2.0 and has no kernel types in it.

## For contributors

A change to the eBPF crate is a contribution under the DCO like any other,
under `MIT OR GPL-2.0` for that crate. `cargo xtask gen-vmlinux` regenerates
the bindings; do not edit them. `cargo xtask check-vmlinux` fails when the
kernel's BTF is not the one the bindings came from, and `cargo xtask kernel`
runs that check once a kernel is built.
