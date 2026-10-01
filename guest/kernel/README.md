# boxcar guest kernel

boxcar boots its own Linux 6.18 guest on KVM through Firecracker's legacy boot
path: an MP table, virtio-mmio devices declared on the kernel command line, no
ACPI and no PCI. The kernel is the pinned upstream tarball built from
Firecracker's CI microVM config with `boxcar.fragment` applied on top.

```
cargo xtask kernel              # build in Docker (needs only Docker)
cargo xtask kernel --jobs 16    # limit make parallelism (default: all CPUs)
cargo xtask kernel --native     # build on this host, no container
```

Outputs, in `target/guest/`:

| File | Contents |
| --- | --- |
| `vmlinux` | uncompressed kernel, debug info stripped, `.BTF` kept |
| `vmlinux.debug` | the debug info, for symbolizing and debuggers |
| `kernel.config` | the final `.config` |
| `System.map` | symbol map |

`cargo xtask kernel` finishes by printing the blake3 of `vmlinux`.

## Files

| File | Purpose |
| --- | --- |
| `VERSION` | `KERNEL_VERSION`, `KERNEL_SHA256` (of the tarball, from `sha256sums.asc` on kernel.org), `FIRECRACKER_COMMIT`, and `DEBIAN_IMAGE` |
| `base/microvm-kernel-ci-x86_64-6.18.config` | Firecracker's config, copied verbatim from `resources/guest_configs/` at `FIRECRACKER_COMMIT` (Apache-2.0; see `NOTICE`) |
| `boxcar.fragment` | the options boxcar changes; every line is checked against the final `.config` |
| `Dockerfile` | the builder image, `debian:trixie` pinned by digest, with pahole 1.22 or newer |
| `build.sh` | the build, run inside the image (or on the host with `--native`) |

## How the build works

Docker mode builds the image, then runs it as the invoking user, so
everything under `target/` is owned by you, with three bind mounts:
`guest/kernel` at `/src` (read-only), `target/guest` at `/out` and
`target/kernel-cache` at `/cache`. `HOME` is `/cache`, because the kernel build
writes `.cache` files.

`build.sh` then:

1. downloads `linux-$KERNEL_VERSION.tar.xz` into `/cache` if it is missing and
   checks its sha256 against `KERNEL_SHA256` (a mismatch deletes the file and
   fails);
2. extracts it into `/cache/linux-$KERNEL_VERSION`;
3. copies the base config to `.config`, merges `boxcar.fragment` with
   `scripts/kconfig/merge_config.sh -m`, and runs `make olddefconfig`;
4. checks every fragment line against the resulting `.config` and stops with
   the list of misses if any is not there, or prints `fragment: all N applied`;
5. runs `make vmlinux`, checks `.BTF` is present, splits the debug info into
   `vmlinux.debug`, strips `vmlinux`, and checks `.BTF` survived the strip.

A fragment line `CONFIG_X=y` or `CONFIG_X="..."` must appear exactly in the
final `.config`. `CONFIG_X=n` passes when `# CONFIG_X is not set` is there, or
when `CONFIG_X` does not appear at all. `cargo xtask kernel` runs the same
check again in Rust on `target/guest/kernel.config` after the build.

The extracted tree lives in the cache and is built in place, so a second run
reuses the tarball and the object files and only rebuilds what changed. Delete
`target/kernel-cache` to start from scratch.

`--native` runs `build.sh` directly after checking that `pahole` is 1.22 or
newer (`CONFIG_DEBUG_INFO_BTF` needs it) and that the libelf headers are
installed; otherwise it stops and points at the Docker build.

## Dependency lines in the fragment

Merging the fragment into Firecracker's config needed none: every line took
effect as written. The one place this depends on Kconfig rather than on a line
is the debug-info choice. The base config has `CONFIG_DEBUG_INFO_NONE=y`, and
`CONFIG_DEBUG_INFO_DWARF5=y` from the fragment displaces it inside that choice
(the final `.config` has `CONFIG_DEBUG_INFO=y` and
`# CONFIG_DEBUG_INFO_NONE is not set`). `CONFIG_EXPERT=y`, which
`CONFIG_IO_URING=n` needs to be settable, is already in the fragment.

If a future kernel or base config needs a line to make an option stick, add it
to `boxcar.fragment` and list it here with the reason. Never drop a fragment
line to get the build through.

## Updating

- **Kernel**: set `KERNEL_VERSION` to the newest 6.18.y from
  <https://www.kernel.org/releases.json> and `KERNEL_SHA256` to its line in
  <https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc>.
- **Base config**: copy `resources/guest_configs/microvm-kernel-ci-x86_64-6.18.config`
  from Firecracker at a commit you name in `FIRECRACKER_COMMIT`, and update the
  commit in `NOTICE`.
- **Builder image**: `docker pull debian:trixie`, then
  `docker inspect --format '{{index .RepoDigests 0}}' debian:trixie`. Put the
  digest in both the `Dockerfile` `FROM` line and `DEBIAN_IMAGE`.
