# Running a session from an image (M5 Task 3, #25)

Branch `issue-25`, from `main` at 42f48f9. The M5 plan is `docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`, section 3 (*Running from an image*) and section 6, Task 3; Task 2 (`docs/plans/oci-image-cache.md`, PR #42) built the cache this task boots from, and this task amends two of its rules (the modes a cached tree stores, and index digests as references). Subject: `run: boot a session from an image`. The plan is reviewed before the code.

## 1. Where it sits

| File | What |
| --- | --- |
| `crates/boxcar/src/cli.rs` | `--image REF`, `--pull missing\|always\|never`, `--cache-dir DIR` on `run` |
| `crates/boxcar/src/cmd/run.rs` | the image's place in the run: find or pull, copy, boot paths, defaults, `vmm.start.image` |
| `crates/boxcar/src/oci/session.rs` | new: the per-session copy of a cached tree, the boot paths made in it, the modes set last |
| `crates/boxcar/src/oci/defaults.rs` | new: what the session runs, from the command line, the image and boxcar's defaults |
| `crates/boxcar/src/oci/pull.rs`, `client.rs` | `ensure(store, reference, mode)`: the `--pull` modes; index digests recorded; loopback registries over plain HTTP |
| `crates/boxcar/src/oci/unpack.rs`, `store.rs` | Task 2 amended: readable stored modes and `image.json`'s `modes`; `_indexes` entries beside `_tags` |
| `crates/boxcar/src/cmd/image.rs` | `default_cache_dir`, the roots and the Docker config shared with `run`; `ls` shows index entries |
| `crates/boxcar/src/cmd/doctor.rs` | the cache line |
| `crates/boxcar-vmm/src/vmm.rs` | `VmConfig::image`, into `vmm.start` |
| `crates/boxcar-proto/src/audit/payloads.rs`, `proto/schema/audit-v1.json`, `docs/audit-events.md` | `VmmStart::image: Option<ImageRef>` |
| `crates/boxcar/tests/run_args.rs` | the flags' relations, refused before a session exists |
| `crates/boxcar/tests/kvm_m5.rs`, `xtask/src/test_kvm.rs` | the gated M5 suite and `cargo xtask test-kvm m5` |

Dependencies: none new. The copy uses `libc` (`ioctl(FICLONE)`, `copy_file_range`, the `*at` calls) as `unpack.rs` does; the gated test builds its image with `tar`, `flate2` and `boxcar-testreg`, all already dev-dependencies. The guest (`boxcar-init`, the sensor, the kernel) is unchanged.

## 2. The pieces

### The command line (`cli.rs`)

`--image REF` names an image as `boxcar image pull` does (`alpine` is `docker.io/library/alpine:latest`). It conflicts with `--rootfs` and `--no-fs`; `--rootfs` becomes required unless `--no-fs` or `--image` is given. `--pull missing|always|never` (default `missing`) and `--cache-dir DIR` (default `$XDG_CACHE_HOME/boxcar`, else `$HOME/.cache/boxcar`, as `image`'s) need `--image`. `--image` needs the vsock session, as `--stdin` does: the image's environment and working directory travel in the session's config over the control channel, and the console session carries only the command, so `--image` with `--no-vsock` is a usage error (exit 2). With `--image` the session has shares, so the network and vsock defaults, the sensor and the gate are as with `--rootfs`.

A reference that does not parse is a usage error (exit 2), refused with the other usage errors before anything exists. A pull that fails, or `--pull never` finding no image, exits 1 before the session exists, naming `boxcar image pull REF` in the second case.

### Finding or pulling the image (`pull.rs`: `ensure`)

Before the audit log opens, under the store's shared lock, which the run then holds through the copy (so `rm` and `prune`, which take it exclusive, wait, and the image cannot go between being found and being copied):

- `missing`: found in the cache, nothing is fetched; else the pull, as `boxcar image pull` does it, with the same progress lines on stderr.
- `always`: the pull. An unchanged tag fetches the manifest and nothing else (Task 2's `existed`); a moved tag pulls the new image.
- `never`: found, else exit 1.

*Found* means: a reference with a tag, through its ref under `_tags`; a reference with a digest, as `images/<hex>` when the digest is a manifest's, or through `refs/<registry>/<repository>/_indexes/<hex>` when it is an index's. A digest can name an index (`debian:trixie-slim@sha256:…` does), and Task 2 keeps only the `linux/amd64` manifest's image, so the pull now also records, whenever it resolved an index, an index entry: a file under `_indexes` named by the index's digest and holding the manifest's, written and synced as a tag ref is, at its final name only once whole. An index entry is a lookup mapping, not a reference: only tags keep an image from `prune`, as Task 2 rules (an image pulled by digest alone is pruned, index or manifest), so a tag that moves from index A to index B leaves A's entry pointing at an image that `prune` then removes, and the entry goes with the image, as its tags do. An entry whose image is gone is as good as absent: the next pull overwrites it. `Store::list` reports entries apart from refs (`boxcar image ls` shows `<registry>/<repository>@sha256:<index>` with its manifest after the tags), and `boxcar image rm REF@sha256:<digest>` removes the image the digest names, through its entry when it is an index's, with its tags and entries. `_indexes`, like `_tags`, is a name no repository path component can have.

The pull's own shared lock nests inside the run's (two shared `flock`s from one process on two descriptors). The result is the manifest digest, its `image.json` (the layers, the defaults, the modes below) and the tree's directory.

### What the cache stores (`unpack.rs`, `store.rs`: Task 2 amended)

An unprivileged owner cannot read a `0o000` file or list a `0o000` directory of their own, and the copy must read every entry without touching the cache (another run may be copying the same tree). So the cached tree stores *readable* modes: a regular file gets its mode with owner read forced on (`mode | 0o400`), a directory its mode with owner read, write and search forced on (`mode | 0o700`), and `image.json` gains `modes`, the paths whose true mode differs from the stored one with that true mode (`[[path, mode], …]`, in the unpacker's metadata budget, absent and empty in older caches). Nothing else about the tree changes; `boxcar image` has no other reader of modes. The copy gives the session the true modes (below). A tree cached by an earlier boxcar can hold an unreadable entry; a copy that meets one fails with a fixed sentence saying to `boxcar image rm` the image and pull it again, and exits 1.

### The copy (`session.rs`: `copy_tree`, `prepare_boot_paths`, `set_modes`)

The cached tree `images/<hex>/rootfs` is copied into the session directory as `rootfs`, after the audit writer has opened that directory and before the VM is built, so the guest's root share is the session's own and the cache is never opened for writing by a run. The copy is of the whole tree, with the unpacker's care: the source is walked with directory descriptors, `readdir` and `fstatat(AT_SYMLINK_NOFOLLOW)`, so no path is resolved and no link is followed on either side; names are acted on with `*at` calls; and the walk descends by name and ascends through `..`, holding three descriptors a side whatever the depth (a tree can be as deep as the pull allowed).

Per entry, by kind:

- Directory: `mkdirat` 0o700; its children; its mode comes last (below).
- Regular file: opened `O_RDONLY|O_NOFOLLOW` (readable: the cache stores it so); the copy created `O_WRONLY|O_CREAT|O_EXCL` 0o600. `ioctl(FICLONE)` first: a reflink shares extents and not an inode, so a later write in the copy touches nothing in the cache. When it is refused (`EOPNOTSUPP`, `EXDEV`, `EINVAL`: another filesystem, or one without reflinks) the data goes through `copy_file_range` in a loop, and through `read`/`write` when that is refused too. Then `fchmod` to the stored mode, setuid and setgid bits included where the host allows them. The first file of a hardlink group (`nlink > 1`) is copied and its path remembered by `(dev, ino)`; the others are `linkat`ed to it within the copy, so a group stays a group in the copy and never reaches the cache.
- Symlink: `readlinkat` and `symlinkat`, the target as it is, however dangling or absolute: it is the guest's to resolve.
- Anything else (the unpacker makes none): skipped and counted; the count is said on stderr when it is not zero.

Then, while every directory of the copy is still 0o700, the boot paths (below). Then the modes, deepest first, through `O_PATH|O_NOFOLLOW` descriptors of the name in its parent (the parent resolved in the copy's root with `openat2(RESOLVE_IN_ROOT)`): every directory's stored mode, and every `modes` entry's true mode in place of its stored one, files included. A `0o555` `/etc` is writable until `resolv.conf` is in it; a `0o000` directory gets its children, their modes and the boot paths first. Nothing that restricts the owner is set before the copy and its preparation are complete.

Times are not copied (decision). The copy is bounded by the cache, which the pull bounded. A copy that fails (no space, a descriptor limit, an I/O error, an unreadable entry from an older cache) is removed whole and the run exits 1, as a run whose VM cannot be built does today; no `vmm.start` is recorded. The copy stays with the session afterwards, as the default workspace does (decision).

### The boot paths (`session.rs`: `prepare_boot_paths`)

Init writes to the root share at boot, and a policy that refuses writes there (Task 5's `agent-isolate-strict`) must not stand between init and its setup, so the host makes in the copy what init would, before the guest boots, mirroring init exactly and in an order where what is made first is there for what is decided next:

1. The mount points `dev`, `proc`, `sys` (init moves the early mounts onto them) and `run` (init mounts a tmpfs there), each `mkdir -p` 0o755 where it leads once the image's links are followed, when missing; `tmp` (1777) and `workspace` (0o755) the unpacker already made.
2. The session's working directory (below), `mkdir -p` 0o755, in the filesystem the guest will see there. The guest's view is the copy with init's mounts applied where init applies them: `mount(2)` follows a link at a mount point, so the workspace share lands where the image's `/workspace` leads once its links are followed (`/srv` for `/workspace -> srv`), and the tmpfs and the kernel filesystems where `/run`, `/dev`, `/proc` and `/sys` lead; those resolved places are the view's boundaries. A path is followed as init's resolver follows one (below), component by component, a link's target put in its place; at or beneath the workspace's boundary the components are looked up, and links followed, in the workspace's host directory (the one `--workspace` names, or the session's new one), since that is what the guest sees there; at or beneath a kernel filesystem's boundary nothing of the image is seen, so the rest is taken as written; a `..` that leaves a boundary resumes the lookups. Leading under the workspace's boundary (`/app/project` with `/app -> /workspace`; `/workspace/build` with `/workspace -> srv`): made in the workspace's host directory, and the session's `cwd` stays the path as written, which the guest resolves the same way. Leading under a kernel filesystem's boundary (`/var/run/app` with `/var/run -> /run`): refused before the session exists (exit 1, a fixed sentence). A path init would refuse (a loop, `..` above `/`), or an image whose `/workspace` leads to nothing or to a file (the mount would fail): refused the same way. Anywhere else: made in the copy, parents included.
3. `/etc/resolv.conf`, when the session has a network (`--net`): followed as init's resolver follows it (each component in turn, a link's target put in its place against the link's directory, at most 40 links, never above `/`). Where it leads exists: nothing. It leads under `/run`: nothing (init's tmpfs). Elsewhere and missing: an empty file, mode 0o644, when its directory exists; when the directory is missing nothing is made, and init fails the boot as it does today with `--rootfs`. A path init refuses (a loop, `..` above `/`) is left to init too. The working directory is made before this step, so a target beneath it finds its directory and init has nothing left to touch.
4. `/etc/ssl/certs/ca-certificates.crt`, when the session inspects (`inspect` is set): followed the same way; an empty file 0o644 where it leads when missing and its directory exists, as init's trust plan would `Touch` it before binding the bundle over it. Without an `inspect` rule init touches nothing here, and neither does the host.

`follow` is the resolver's algorithm written again on the host side (decision: `boxcar-init` is the guest's binary crate, built for musl without a library target); its tests are the resolver's cases.

### What the session runs (`defaults.rs`)

From the image's `image.json` defaults, bounded first: `env`, `entrypoint`, `cmd` and `working_dir` together at most 32 KiB of text, every `env` entry `NAME=VALUE` with a non-empty name, `working_dir` empty or absolute; an image past these is refused (exit 1, before the session exists) with a fixed sentence, none of its text repeated.

- `argv`: the command given on the command line; else `Entrypoint` followed by `Cmd`; else boxcar's `DEFAULT_ARGV` (`/bin/sh -l`). A given command replaces both, as the M5 plan rules (not Docker's `Entrypoint` prefixing).
- `env`: boxcar's defaults (`PATH`, `HOME`, `TERM`, `LANG`), then the image's `Env` in its order, then `--env`, merged to one value per name, the last given winning, and in first-seen order. Init keeps the environment as given and its `search_path` takes the first `PATH`, so the merge is what makes the precedence true: the image's `PATH` overrides the default and the user's overrides the image's. This also makes `--env` over the defaults behave as its help has always said; the run's existing tests pin it.
- `cwd`: `WorkingDir` when set, else `/workspace`; `HOME` stays boxcar's unless the image's `Env` sets it.
- `User` is ignored (the M5 plan's decision: the session runs as the host user).

### `vmm.start.image`

`VmmStart` gains `image: Option<ImageRef>`, omitted when there is none and read as none when absent: `ImageRef { reference: String, manifest_digest: String, config_digest: String }`, the reference as given on the command line (normalized: `docker.io/library/alpine:3.22`), the digests as `sha256:<hex>`. `VmConfig` carries it; the VMM records it. The schema is regenerated and `docs/audit-events.md` says the field. The record stays well under its limit (a reference is at most 255 bytes; the test pins the largest).

### `boxcar doctor`

A line `image cache: <dir>` whose status is *missing* with the hint `boxcar image pull REF makes it` when the default cache does not exist, and otherwise *ok* saying how many images and refs it holds and whether a copy into the default audit directory would reflink (`FICLONE` of a small probe file written under a dot name in the cache's root into the audit directory, both removed; `copy` when it is refused, `unknown` when either directory is missing).

### Loopback registries (`client.rs`)

A registry on `localhost` or `127.0.0.0/8` is spoken to over plain HTTP, as Docker treats insecure-by-default local registries (decision). Everything else about the client holds: challenges honoured only from the registry's own origin, credentials only to it, bodies and deadlines bounded. The gated M5 suite needs it, and so does anyone with a `localhost:5000` registry; Task 2's test-only `insecure_loopback` becomes this rule.

### The gated suite and `xtask`

`cargo xtask test-kvm m5` runs everything `m4` runs plus `crates/boxcar/tests/kvm_m5.rs`. The suite starts a `boxcar-testreg` registry on the loopback and builds its image at test time: layer 1 is the Alpine tree `BOXCAR_TEST_ROOTFS` names, tarred by the test; layer 2 carries `/tmp/boxcar-test-1.0-r0.apk`, an APKv2 package built by the test (its control and data streams gzip'd and concatenated, `datahash` computed, installed with `--allow-untrusted`), whose one file, `/opt/bin/boxcar-test`, prints a marker, plus `/etc/motd`, a `0o000` file with content, a populated `0o000` directory and a `0o555` `/etc` (so the boot paths land in it); the config's `Env` sets `BOXCAR_IMAGE_TEST=1` and `PATH=/opt/bin:/usr/local/bin:/usr/bin:/bin` (so the package's program is found only through the image's `PATH`), `WorkingDir` is `/app/project` with `/app` a link to `/workspace` in the image and `project` absent everywhere, `Entrypoint` is `/bin/sh -c` and `Cmd` prints `from-image`. The image is published both by tag and through an index, so a digest reference to the index is tested.

## 3. Events and the orders they come in

- **P1.** `--pull missing`, an empty cache: lock shared, pull (the registry sees the manifest, the config and both layers), copy, boot paths, modes, defaults, boot. A second run: lock, found, no request to the registry, copy, boot; stderr has no `layer` line.
- **P2.** `--pull always` on an unchanged tag: one manifest request, nothing else fetched. On a moved tag: the new image pulled and copied; the old stays until `prune`.
- **P3.** `--pull never` on an empty cache: exit 1 naming `boxcar image pull`; no session directory, no cache entry.
- **P4.** `prune` or `rm` started while a run holds the shared lock: it waits until the copy is done, then removes what nothing names; the running session's copy is its own and unaffected.
- **P5.** Two runs of one image at once: both hold the lock shared, both copy, each into its own session directory; a third run arriving as one of them pulls waits on the pull's staging only as Task 2 orders it.
- **P6.** The copy fails midway (no space, a descriptor limit, an I/O error, an unreadable entry from an older cache): the partial copy is removed, the audit log closes with no records, the run exits 1 with the reason; the cache is as it was.
- **P7.** The guest writes, removes and `chmod`s everywhere it can, `/workspace` and `/tmp` included, and installs a package: the cached tree's hashes, modes, links and names are the same after the session; the copy differs.
- **P8.** An image without `/dev`, `/proc`, `/sys`, `/run`, `/etc/resolv.conf` or its `WorkingDir`: the host makes them, init's steps find them, the boot proceeds. An image with `/etc/resolv.conf` a link into `/run`: nothing made, init binds over the tmpfs path as today.
- **P9.** An image whose config has an `Env` entry without `=`, a relative `WorkingDir`, a `WorkingDir` under `/run`, or 40 KiB of defaults: refused before the session exists, exit 1, the text not repeated.
- **P10.** The session copy is made on another filesystem than the cache, or on one without reflinks: the data is copied; the result is the same tree.
- **P11.** A hostile cache? None: the cache is the user's own directory, written by Task 2's unpacker. The copy still follows no link and resolves no path, so a tree altered by hand cannot send the copy outside the cache or the session directory.
- **P12.** An image with a `0o000` file holding data, a `0o000` directory holding files and a `0o444` directory: pulled, the cache stores them readable and lists them in `modes`; the copy reads them all, and in the copy they have the image's modes, the directories' set after their children's and after the boot paths.
- **P13.** A reference by an index's digest: pulled once, then found offline by `missing` and by `never` through its index entry; `boxcar image ls` shows the entry; `rm` of the image removes it. A tag pulled at index A, moved to index B and pulled again: two images, two entries; `prune` removes A's image (no tag names it) and A's entry with it, and keeps B's; a run by A's digest afterwards finds nothing offline and pulls. The tag removed and `prune` run: both images and both entries go.
- **P14.** `WorkingDir=/workspace/app`: made in the workspace's host directory, seen by the guest at `/workspace/app` once init has mounted the share there; the session starts in it. `WorkingDir=/app/project` with `/app -> /workspace` in the image: the same, through the link, and the guest starts in `/app/project`. `WorkingDir=/run/app`, or `/var/run/app` with `/var/run -> /run`: refused before the session.
- **P15.** `/etc` is `0o555` in the image and holds no `resolv.conf`: the copy's `/etc` is 0o700 while `resolv.conf` is made in it, then `0o555`; init binds over the file without writing to the share.
- **P16.** `/etc/resolv.conf` is a link to `/srv/app/resolv.conf` and `WorkingDir` is `/srv/app`, absent in the image: the working directory is made first, then the file in it; init finds both and touches nothing.
- **P17.** The image's `PATH` names a directory only it has: the entrypoint there runs; `--env PATH=…` replaces the image's and the session sees one `PATH`.
- **P18.** `--image` with `--no-vsock`: exit 2, nothing made.

## 4. Invariants

- **I1.** A run opens nothing in the cache for writing: only the lock file for `flock`, and the tree for reading.
- **I2.** When the VM is built, the session's root share is a complete copy; otherwise the run has exited 1 and the copy is gone.
- **I3.** The copy equals the image's tree in names, kinds, data, modes (setuid, setgid and sticky included, the true modes where the cache stores readable ones), symlink targets and hardlink groups, plus the boot paths added, which touch nothing that exists.
- **I4.** No inode of the copy is an inode of the cache (a reflink shares extents, not inodes); writing in the copy changes nothing in the cache.
- **I5.** The image is found and copied under one shared lock, so it cannot be removed between the two.
- **I6.** What the session runs comes from the command line first, the image second, boxcar's defaults last, in `argv`, `env` and `cwd` alike; the environment carries each name once.
- **I7.** `vmm.start.image` names the manifest whose tree was copied and its config.
- **I8.** Nothing an image says (its config's text, its paths) reaches an error message or a log line; failures are fixed sentences.
- **I9.** Every entry of a cached tree is readable by its owner; the true modes are in `image.json`.
- **I10.** No mode that restricts the owner is set in the copy before the copy and the boot paths are complete.

## 5. Out of scope

Ownership in the guest (#32), an overlay instead of a copy (#31), credential helpers (#35), the image's `User`, `Volumes`, `ExposedPorts`, `Healthcheck`, `Labels` and `StopSignal`, images for other platforms (Task 2 resolves indexes to `linux/amd64`), the policy files and their enforcement (Tasks 4 and 5), the docs beyond `docs/audit-events.md` and the command's help (Task 8), reclaiming session copies, and image defaults for the console session (`--image` needs vsock).

## 6. Tests

Every test is written before its code and fails on the stub.

- `oci::unpack`, `oci::store`: a layer with a `0o000` file, a populated `0o000` directory and a `0o444` directory unpacks to readable stored modes with the three in `modes`; `modes` is in the metadata budget; `image.json` without `modes` reads as none. Index entries: written, listed apart from refs, not counted by prune, removed with their image (by `rm` and by `prune`), overwritten when stale; a tag moved between two indexes then pruned keeps the current image only; a tag named `_indexes` impossible by the reference grammar.
- `oci::session` (unit, temporary directories): a tree with files, `0o555` and `0o000` directories, a `0o000` file, a setuid file, a sticky directory, absolute, relative and dangling symlinks and one to `/etc/passwd`, a hardlink pair and nesting, copied from a cache made by the unpacker: the copy's listing equals the image's (kind, true mode, size, data, link target), the pair shares an inode in the copy and none with the source, no inode is shared with the source, the source's listing is unchanged; a write in the copy leaves the source's bytes as they were; a tree 2,500 deep copies (and a binary-level test copies one under `ulimit -n 64`); the fallback path forced by a test hook that refuses `FICLONE` gives the same tree; a failure midway (a destination made read-only) leaves nothing behind; an unreadable entry in a cache written by hand fails with the fixed sentence. Boot paths: each path made when missing and left when present (bytes compared); `resolv.conf` as a link into `/run` left alone, as a link to a missing directory left alone, as a link to an existing file left alone, as a loop left alone, as a link to a file beneath the working directory made after that directory; the trust file made only with `inspect` and only where its directory exists; the working directory made with its parents in the copy, or in the workspace directory when it leads under `/workspace` as written or through a link (`/app -> /workspace`), and refused when it leads under `/run`, `/dev`, `/proc`, `/sys` as written or through a link (`/var/run -> /run`), or through a loop; a `0o555` `/etc` getting `resolv.conf` and then its mode. Modes: set after the boot paths, deepest first, true modes from `modes` winning.
- `oci::defaults`: `argv`, `env` and `cwd` for each combination of command line, image and defaults; the environment merged to unique names with the last value winning and first-seen order; the bounds and the malformed entries refused with fixed text; the largest accepted image.
- `oci::pull::ensure` against `boxcar-testreg`: each `--pull` mode by tag, by manifest digest and by index digest, the requests the registry saw, `missing` and `never` with the registry stopped after a pull, `never` on an empty cache; a loopback registry over HTTP and a non-loopback host refusing HTTP.
- `tests/run_args.rs`: `--image` with `--rootfs`, with `--no-fs` and with `--no-vsock` refused; `--pull` and `--cache-dir` without `--image` refused; a bad reference exits 2 and leaves no session directory; `--pull never` on an empty cache exits 1 and leaves no session directory.
- `boxcar-proto`: `vmm.start` with and without `image` (absent reads as none); the largest `image` within the record's limit; the schema and golden lines regenerated.
- `cmd::doctor`: the cache line missing, present with counts, reflink or copy.
- `tests/kvm_m5.rs` (gated): from the test-registry image, a run with no command prints `from-image`; a run with a command installs the package from the local layer (`apk add --allow-untrusted --no-network`, with `--repositories-file /dev/null` if the index fetch gets in the way), runs `boxcar-test` found through the image's `PATH`, prints `pwd` as `/app/project` (the image's `WorkingDir`, with `/app -> /workspace` in the image, so the directory is made in the workspace share and the guest starts in it through the link), `BOXCAR_IMAGE_TEST` as `1`, `env | grep -c ^PATH=` as `1`, and reads the `0o000` file's mode as the image gave it; `--env PATH=/usr/bin:/bin` then fails to find `boxcar-test`; `vmm.start.image` names the reference and both digests and `shares[0].host_root` is under the session directory; a session that writes, removes and `chmod`s everywhere leaves the cached tree's hash (every path's kind, mode, size, content and link target, hardlink groups) unchanged while the copy's differs; a second run fetches nothing; a run by the index's digest with the registry stopped boots; `--pull never` without the image exits 1 before a session exists.

## 7. Decisions (to the M5 plan's section 8 when the task ships)

- **The cache stores readable modes and `image.json` the true ones** (Task 2 amended): an owner cannot read their own `0o000` file, and the copy must read every entry without touching the cache; the copy gives the session the image's modes. Trees cached before this are copied until an unreadable entry, which names the cure.
- **Index digests are lookup mappings** (Task 2 amended): a digest reference can name an index, Task 2 keeps the platform manifest's image only, and `--pull missing` and `never` must find it offline; `_indexes` entries beside `_tags` share the refs' durability and go with their image, but only tags keep an image from `prune`, so a moved tag's old index pins nothing.
- **`--image` needs vsock.** The console session carries only the command; an image's environment and working directory would be silently lost, so the combination is refused.
- **The environment is merged to one value per name.** Init keeps duplicates and takes the first `PATH`, so appending cannot give the promised precedence; the merge also makes `--env` over the defaults do what its help says.
- **The working directory is made where the guest will see it**: the guest's view is the copy with init's mounts applied where `mount(2)` puts them, at the places the image's `/workspace`, `/run`, `/dev`, `/proc` and `/sys` lead once their links are followed; beneath the workspace's place the workspace's host directory is looked up, beneath a kernel filesystem's nothing is, and the working directory is made in the workspace's host directory, in the copy, or refused accordingly.
- **Modes last, boot paths before them**, deepest first: nothing that restricts the owner is set until the copy and its preparation are complete.
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
