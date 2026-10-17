# Running a session from an image (M5 Task 3, #25)

Branch `issue-25`, from `main` at 42f48f9. The M5 plan is `docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`, section 3 (*Running from an image*) and section 6, Task 3; Task 2 (`docs/plans/oci-image-cache.md`, PR #42) built the cache this task boots from. Subject: `run: boot a session from an image`. The plan is reviewed before the code.

## 1. Where it sits

| File | What |
| --- | --- |
| `crates/boxcar/src/cli.rs` | `--image REF`, `--pull missing\|always\|never`, `--cache-dir DIR` on `run` |
| `crates/boxcar/src/cmd/run.rs` | the image's place in the run: pull, copy, boot paths, defaults, `vmm.start.image` |
| `crates/boxcar/src/oci/session.rs` | new: the per-session copy of a cached tree, and the boot paths made in it |
| `crates/boxcar/src/oci/defaults.rs` | new: what the session runs, from the command line, the image and boxcar's defaults |
| `crates/boxcar/src/oci/pull.rs`, `client.rs` | `ensure(store, reference, mode)`: the `--pull` modes; loopback registries over plain HTTP |
| `crates/boxcar/src/cmd/image.rs` | `default_cache_dir`, the roots and the Docker config shared with `run` |
| `crates/boxcar/src/cmd/doctor.rs` | the cache line |
| `crates/boxcar-vmm/src/vmm.rs` | `VmConfig::image`, into `vmm.start` |
| `crates/boxcar-proto/src/audit/payloads.rs`, `proto/schema/audit-v1.json`, `docs/audit-events.md` | `VmmStart::image: Option<ImageRef>` |
| `crates/boxcar/tests/run_args.rs` | the flags' relations, refused before a session exists |
| `crates/boxcar/tests/kvm_m5.rs`, `xtask/src/test_kvm.rs` | the gated M5 suite and `cargo xtask test-kvm m5` |

Dependencies: none new. The copy uses `libc` (`ioctl(FICLONE)`, `copy_file_range`, the `*at` calls) as `unpack.rs` does; the gated test builds its image with `tar`, `flate2` and `boxcar-testreg`, all already dev-dependencies.

## 2. The pieces

### The command line (`cli.rs`)

`--image REF` names an image as `boxcar image pull` does (`alpine` is `docker.io/library/alpine:latest`). It conflicts with `--rootfs` and `--no-fs`; `--rootfs` becomes required unless `--no-fs` or `--image` is given. `--pull missing|always|never` (default `missing`) and `--cache-dir DIR` (default `$XDG_CACHE_HOME/boxcar`, else `$HOME/.cache/boxcar`, as `image`'s) need `--image`. With `--image` the session has shares, so the network and vsock defaults, the sensor and the gate are as with `--rootfs`.

A reference that does not parse is a usage error (exit 2), refused with the other usage errors before anything exists. A pull that fails, or `--pull never` finding no image, exits 1 before the session exists, naming `boxcar image pull REF` in the second case.

### Finding or pulling the image (`pull.rs`: `ensure`)

Before the audit log opens, under the store's shared lock, which the run then holds through the copy (so `rm` and `prune`, which take it exclusive, wait, and the image cannot go between being found and being copied):

- `missing`: a reference with a digest is looked for as `images/<hex>`; one with a tag through its ref. Found: nothing is fetched. Not found: the pull, as `boxcar image pull` does it, with the same progress lines on stderr.
- `always`: the pull. An unchanged tag fetches the manifest and nothing else (Task 2's `existed`); a moved tag pulls the new image.
- `never`: found as for `missing`, else exit 1.

The pull's own shared lock nests inside the run's (two shared `flock`s from one process on two descriptors). The result is the manifest digest, its `image.json` (the layers, the defaults) and the tree's directory.

### The copy (`session.rs`: `copy_tree`)

The cached tree `images/<hex>/rootfs` is copied into the session directory as `rootfs`, after the audit writer has opened that directory and before the VM is built, so the guest's root share is the session's own and the cache is never opened for writing by a run. The copy is of the whole tree, with the unpacker's care: the source is walked with directory descriptors, `readdir` and `fstatat(AT_SYMLINK_NOFOLLOW)`, so no path is resolved and no link is followed on either side; names are acted on with `*at` calls; and the walk descends by name and ascends through `..`, holding three descriptors a side whatever the depth (a tree can be as deep as the pull allowed).

Per entry, by kind:

- Directory: `mkdirat` 0o700, then its children; its own mode set at the end, deepest first, through an `O_PATH` descriptor, so a `0o555` or `0o000` directory gets its children first.
- Regular file: opened `O_RDONLY|O_NOFOLLOW`; the copy created `O_WRONLY|O_CREAT|O_EXCL` 0o600. `ioctl(FICLONE)` first: a reflink shares extents and not an inode, so a later write in the copy touches nothing in the cache. When it is refused (`EOPNOTSUPP`, `EXDEV`, `EINVAL`: another filesystem, or one without reflinks) the data goes through `copy_file_range` in a loop, and through `read`/`write` when that is refused too. Then `fchmod` to the cached mode, setuid and setgid bits included where the host allows them. The first file of a hardlink group (`nlink > 1`) is copied and its path remembered by `(dev, ino)`; the others are `linkat`ed to it within the copy, so a group stays a group in the copy and never reaches the cache.
- Symlink: `readlinkat` and `symlinkat`, the target as it is, however dangling or absolute: it is the guest's to resolve.
- Anything else (the unpacker makes none): skipped and counted; the count is said on stderr when it is not zero.

Times are not copied (decision). The copy is bounded by the cache, which the pull bounded. A copy that fails (no space, a descriptor limit, an I/O error) is removed whole and the run exits 1, as a run whose VM cannot be built does today; no `vmm.start` is recorded. The copy stays with the session afterwards, as the default workspace does (decision).

### The boot paths (`session.rs`: `prepare_boot_paths`)

Init writes to the root share at boot, and a policy that refuses writes there (Task 5's `agent-isolate-strict`) must not stand between init and its setup, so the host makes in the copy what init would, before the guest boots, mirroring init exactly:

- The mount points `dev`, `proc`, `sys` (init moves the early mounts onto them) and `run` (init mounts a tmpfs there), each `mkdir` 0o755 when missing; `tmp` (1777) and `workspace` (0o755) the unpacker already made.
- `/etc/resolv.conf`, when the session has a network (`--net`): followed as init's resolver follows it (each component in turn, a link's target put in its place against the link's directory, at most 40 links, never above `/`). Where it leads exists: nothing. It leads under `/run`: nothing (init's tmpfs). Elsewhere and missing: an empty file, mode 0o644, when its directory exists; when the directory is missing nothing is made, and init fails the boot as it does today with `--rootfs`. A path init refuses (a loop, `..` above `/`) is left to init too.
- `/etc/ssl/certs/ca-certificates.crt`, when the session inspects (`inspect` is set): followed the same way; an empty file 0o644 where it leads when missing and its directory exists, as init's trust plan would `Touch` it before binding the bundle over it. Without an `inspect` rule init touches nothing here, and neither does the host.
- The session's working directory (below), `mkdir -p` 0o755 when missing, as Docker makes `WorkingDir`.

`follow` is the resolver's algorithm written again on the host side (decision: `boxcar-init` is the guest's binary crate, built for musl without a library target); its tests are the resolver's cases.

### What the session runs (`defaults.rs`)

From the image's `image.json` defaults, bounded first: `env`, `entrypoint`, `cmd` and `working_dir` together at most 32 KiB of text, every `env` entry `NAME=VALUE` with a non-empty name, `working_dir` empty or absolute; an image past these is refused (exit 1, before the session exists) with a fixed sentence, none of its text repeated.

- `argv`: the command given on the command line; else `Entrypoint` followed by `Cmd`; else boxcar's `DEFAULT_ARGV` (`/bin/sh -l`). A given command replaces both, as the M5 plan rules (not Docker's `Entrypoint` prefixing).
- `env`: boxcar's defaults (`PATH`, `HOME`, `TERM`, `LANG`), then the image's `Env` in its order, then `--env`: a later name wins in the guest, so the image's `PATH` overrides the default and the user's overrides the image's.
- `cwd`: `WorkingDir` when set, else `/workspace`; `HOME` stays boxcar's unless the image's `Env` sets it.
- `User` is ignored (the M5 plan's decision: the session runs as the host user).

### `vmm.start.image`

`VmmStart` gains `image: Option<ImageRef>`, omitted when there is none and read as none when absent: `ImageRef { reference: String, manifest_digest: String, config_digest: String }`, the reference as given on the command line (normalized: `docker.io/library/alpine:3.22`), the digests as `sha256:<hex>`. `VmConfig` carries it; the VMM records it. The schema is regenerated and `docs/audit-events.md` says the field. The record stays well under its limit (a reference is at most 255 bytes; the test pins the largest).

### `boxcar doctor`

A line `image cache: <dir>` whose status is *missing* with the hint `boxcar image pull REF makes it` when the default cache does not exist, and otherwise *ok* saying how many images and tags it holds and whether a copy into the default audit directory would reflink (`FICLONE` of a small probe file written under a dot name in the cache's root into the audit directory, both removed; `copy` when it is refused, `unknown` when either directory is missing).

### Loopback registries (`client.rs`)

A registry on `localhost` or `127.0.0.0/8` is spoken to over plain HTTP, as Docker treats insecure-by-default local registries (decision). Everything else about the client holds: challenges honoured only from the registry's own origin, credentials only to it, bodies and deadlines bounded. The gated M5 suite needs it, and so does anyone with a `localhost:5000` registry; Task 2's test-only `insecure_loopback` becomes this rule.

### The gated suite and `xtask`

`cargo xtask test-kvm m5` runs everything `m4` runs plus `crates/boxcar/tests/kvm_m5.rs`. The suite starts a `boxcar-testreg` registry on the loopback and builds its image at test time: layer 1 is the Alpine tree `BOXCAR_TEST_ROOTFS` names, tarred by the test; layer 2 carries `/tmp/boxcar-test-1.0-r0.apk`, an APKv2 package built by the test (its control and data streams gzip'd and concatenated, `datahash` computed, installed with `--allow-untrusted`), whose one file prints a marker, and `/etc/motd`; the config's `Env` sets `BOXCAR_IMAGE_TEST=1`, `WorkingDir` is `/srv/app` (absent in the image), `Entrypoint` is `/bin/sh -c` and `Cmd` prints `from-image`.

## 3. Events and the orders they come in

- **P1.** `--pull missing`, an empty cache: lock shared, pull (the registry sees the manifest, the config and both layers), copy, boot paths, defaults, boot. A second run: lock, found, no request to the registry, copy, boot; stderr has no `layer` line.
- **P2.** `--pull always` on an unchanged tag: one manifest request, nothing else fetched. On a moved tag: the new image pulled and copied; the old stays until `prune`.
- **P3.** `--pull never` on an empty cache: exit 1 naming `boxcar image pull`; no session directory, no cache entry.
- **P4.** `prune` or `rm` started while a run holds the shared lock: it waits until the copy is done, then removes what nothing names; the running session's copy is its own and unaffected.
- **P5.** Two runs of one image at once: both hold the lock shared, both copy, each into its own session directory; a third run arriving as one of them pulls waits on the pull's staging only as Task 2 orders it.
- **P6.** The copy fails midway (no space, a descriptor limit, an I/O error): the partial copy is removed, the audit log closes with no records, the run exits 1 with the reason; the cache is as it was.
- **P7.** The guest writes, removes and `chmod`s everywhere it can, `/workspace` and `/tmp` included, and installs a package: the cached tree's hashes, modes, links and names are the same after the session; the copy differs.
- **P8.** An image without `/dev`, `/proc`, `/sys`, `/run`, `/etc/resolv.conf` or its `WorkingDir`: the host makes them, init's steps find them, the boot proceeds. An image with `/etc/resolv.conf` a link into `/run`: nothing made, init binds over the tmpfs path as today.
- **P9.** An image whose config has an `Env` entry without `=`, a relative `WorkingDir` or 40 KiB of defaults: refused before the session exists, exit 1, the text not repeated.
- **P10.** The session copy is made on another filesystem than the cache, or on one without reflinks: the data is copied; the result is the same tree.
- **P11.** A hostile cache? None: the cache is the user's own directory, written by Task 2's unpacker. The copy still follows no link and resolves no path, so a tree altered by hand cannot send the copy outside the cache or the session directory.

## 4. Invariants

- **I1.** A run opens nothing in the cache for writing: only the lock file for `flock`, and the tree for reading.
- **I2.** When the VM is built, the session's root share is a complete copy; otherwise the run has exited 1 and the copy is gone.
- **I3.** The copy equals the cached tree in names, kinds, data, modes (setuid, setgid and sticky included), symlink targets and hardlink groups, plus the boot paths added, which touch nothing that exists.
- **I4.** No inode of the copy is an inode of the cache (a reflink shares extents, not inodes); writing in the copy changes nothing in the cache.
- **I5.** The image is found and copied under one shared lock, so it cannot be removed between the two.
- **I6.** What the session runs comes from the command line first, the image second, boxcar's defaults last, in `argv`, `env` and `cwd` alike.
- **I7.** `vmm.start.image` names the manifest whose tree was copied and its config.
- **I8.** Nothing an image says (its config's text, its paths) reaches an error message or a log line; failures are fixed sentences.

## 5. Out of scope

Ownership in the guest (#32), an overlay instead of a copy (#31), credential helpers (#35), the image's `User`, `Volumes`, `ExposedPorts`, `Healthcheck`, `Labels` and `StopSignal`, images for other platforms (Task 2 resolves indexes to `linux/amd64`), the policy files and their enforcement (Tasks 4 and 5), the docs beyond `docs/audit-events.md` and the command's help (Task 8), and reclaiming session copies.

## 6. Tests

Every test is written before its code and fails on the stub.

- `oci::session` (unit, temporary directories): a tree with files, `0o555` and `0o000` directories, a setuid file, a sticky directory, absolute, relative and dangling symlinks and one to `/etc/passwd`, a hardlink pair and nesting, copied: the listing of the copy equals the source's (kind, mode, size, data, link target), the pair shares an inode in the copy and none with the source, no inode is shared with the source, the source's listing is unchanged; a write in the copy leaves the source's bytes as they were; a tree 2,500 deep copies (and a binary-level test copies one under `ulimit -n 64`); the fallback path forced by a test hook that refuses `FICLONE` gives the same tree; a failure midway (a destination made read-only) leaves nothing behind. Boot paths: each path made when missing and left when present (bytes compared); `resolv.conf` as a link into `/run` left alone, as a link to a missing directory left alone, as a link to an existing file left alone, as a loop left alone; the trust file made only with `inspect` and only where its directory exists; the working directory made with its parents.
- `oci::defaults`: `argv`, `env` and `cwd` for each combination of command line, image and defaults; the bounds and the malformed entries refused with fixed text; the largest accepted image.
- `oci::pull::ensure` against `boxcar-testreg`: each `--pull` mode by tag and by digest, the requests the registry saw, `never` on an empty cache; a loopback registry over HTTP and a non-loopback host refusing HTTP.
- `tests/run_args.rs`: `--image` with `--rootfs` and with `--no-fs` refused; `--pull` and `--cache-dir` without `--image` refused; a bad reference exits 2 and leaves no session directory; `--pull never` on an empty cache exits 1 and leaves no session directory.
- `boxcar-proto`: `vmm.start` with and without `image` (absent reads as none); the largest `image` within the record's limit; the schema and golden lines regenerated.
- `cmd::doctor`: the cache line missing, present with counts, reflink or copy.
- `tests/kvm_m5.rs` (gated): from the test-registry image, a run with no command prints `from-image`; a run with a command installs the package from the local layer (`apk add --allow-untrusted --no-network`, with `--repositories-file /dev/null` if the index fetch gets in the way), runs it, prints `pwd` as `/srv/app` and `BOXCAR_IMAGE_TEST` as `1`; `vmm.start.image` names the reference and both digests and `shares[0].host_root` is under the session directory; a session that writes, removes and `chmod`s everywhere leaves the cached tree's hash (every path's kind, mode, size, content and link target, hardlink groups) unchanged while the copy's differs; a second run fetches nothing; `--pull never` without the image exits 1 before a session exists.

## 7. Decisions (to the M5 plan's section 8 when the task ships)

- **The copy goes into the session directory as `rootfs` and stays with the session**, as the default workspace does: it is the filesystem the audited session ran on, and reclaiming sessions is one decision for copies and workspaces alike.
- **Times are not copied.** Package managers and builds do not depend on the cached tree's times, and the copy is a fresh filesystem for the session.
- **The copy descends by name and ascends through `..`**, three descriptors a side at any depth, as Task 2's deletion does; a tree is as deep as the pull allowed.
- **A given command replaces `Entrypoint` and `Cmd` both**, as the M5 plan rules; boxcar's command is an argv, not Docker's arguments to an entrypoint.
- **The resolver's `follow` is written again on the host side**: `boxcar-init` is the guest's binary, built for musl with no library target, and the thirty lines are pinned by the same cases on both sides.
- **Loopback registries are plain HTTP**, as Docker's insecure-by-default rule for `localhost` and `127.0.0.0/8`; the gated suite and local development registries need it, and the client's other rules hold unchanged.
- **The image's defaults are bounded at 32 KiB**: the session's config travels as one line of the guest channel (64 KiB), and an image is untrusted input.
- **`--cache-dir` on `run`**, with `image`'s default, so tests and the test box point the cache anywhere.
- **The copy is made after the audit log opens**, into the session directory the writer made; a failed copy leaves a log with no records and exits 1, as a VM that cannot be built does today.
- **`doctor` probes reflinks** from the cache into the audit directory, since that is the copy the run makes, and says `copy` when they are not there: the difference is the cost of a session's start, not its correctness.
