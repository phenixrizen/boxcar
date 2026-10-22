# Running from an image

What `boxcar run --image REF` does: how a reference is read, how boxcar's
own registry client fetches and verifies an image, how the layers are
unpacked into a per-user cache, and how each session gets its own copy of
the tree as its root filesystem. Booting from a directory is the README's
[quick start](../README.md#quick-start); what happens from `boxcar run` to
the agent's shell is [boot.md](boot.md); the policy a session runs under,
which can keep writes out of the root share, is [policy.md](policy.md); the
`vmm.start` record that names the image is in
[audit-events.md](audit-events.md).

## `--image` and `--rootfs`

```bash
boxcar run --kernel target/guest/vmlinux --initramfs target/guest/initramfs.cpio \
    --image docker.io/library/alpine:3.22 -- /bin/sh -c 'cat /etc/os-release'
```

`--image REF` takes the place of `--rootfs DIR`, and conflicts with
`--rootfs`, `--no-fs` and `--no-vsock`: the image's environment and working
directory travel in the session's config over the vsock channel, which the
console session does not have. The network, the vsock session and the
sensor are on by default, as with `--rootfs`. `--pull` and
`--cache-dir DIR` without `--image` are a usage error (exit 2).

`--rootfs` hands the guest a directory it changes in place, for the next
session too. `--image` copies the cached tree into the session's directory,
`<audit dir>/sessions/<session-id>/rootfs`, and that copy is the root
share: what the session writes stays in its copy, which stays with the
session, and the next session starts from the image again. The run reads
the cached tree and never writes it; where Landlock confines the run, its
domain grants only reading beneath that tree.

`--pull` says when to ask the registry:

- `missing` (the default): the cached image when there is one, with no
  request to the registry; else a pull, as `boxcar image pull` makes it.
- `always`: a pull. An unchanged tag fetches its manifest (and its index)
  and nothing else; a moved tag pulls the new image, and the old one stays
  until `prune`.
- `never`: the cached image, or exit 1, saying to `boxcar image pull` it
  first.

A reference with a digest is found as that manifest's image, or through the
repository's index entry when the digest is an index's; a reference with a
tag only, through its tag. The run says on stderr what it booted,
`image: <reference> <manifest digest>`, with `(cached)` when no layer was
fetched. A pull that fails exits 1 before the session's log opens.

## References

References are read as Docker reads them,
`[host[:port]/]path[:tag][@sha256:hex]`, at most 255 bytes:

- The first component is the registry when it holds a `.` or a `:`, or is
  `localhost`; otherwise the registry is `docker.io`. `index.docker.io` is
  `docker.io`; the host is lowercased.
- On `docker.io` a one-component path gets `library/`: `alpine` is
  `docker.io/library/alpine:latest`, `team/app` is
  `docker.io/team/app:latest`. Docker Hub's API is `registry-1.docker.io`;
  any other registry is reached at its own host and port
  (`localhost:5000/app`, `ghcr.io/owner/app:v1`).
- Path components are lowercase letters and digits joined by `.`, `_`, `__`
  or a run of `-`. A tag is a letter, digit or `_`, then up to 127 letters,
  digits, `_`, `.` or `-`. A digest is `sha256:` and 64 lowercase hex
  digits.
- No tag and no digest means `latest`. A digest decides what is fetched; a
  tag beside it still names the tag the pull records.
- An index (an OCI index or a Docker manifest list) is resolved to its
  `linux/amd64` manifest, attestations left out. An index without one, an
  index of indexes, and a config that is not `os: linux`,
  `architecture: amd64` fail the pull.

A reference that does not parse is a usage error: `boxcar run` and
`boxcar image pull` exit 2.

## The registry client

boxcar speaks the distribution API itself: `GET
/v2/<repository>/manifests/<tag or digest>`, accepting the OCI manifest and
index and the Docker v2 manifest and manifest list (schema 1 is refused),
then `GET /v2/<repository>/blobs/<digest>` for the config and each layer.

- **HTTPS only**, verified against the host's trust store. The exception is
  a registry on `localhost` or `127.0.0.0/8`, spoken to over plain HTTP, as
  Docker treats local registries, and over HTTPS when it declines that. Up
  to 5 redirects are followed; one to plain HTTP is refused, except from a
  loopback registry to the loopback.
- **Tokens.** Requests start anonymous. A `401` from the registry's own
  origin (scheme, host and port) with `WWW-Authenticate: Bearer realm=…`
  gets a token from the realm, with the challenge's `service` and `scope`,
  and the request is sent once more with it. The realm must be `https`
  (plain `http` only for a loopback registry's loopback realm), and the
  token request follows no redirect. A `Basic` challenge is answered once
  with the user's credentials. A `401` from anywhere else (a blob
  redirected to a CDN, say) fails the pull with no credential sent; a
  second `401` fails it as `authentication failed for
  <registry>/<repository>`.
- **Credentials** come from `$DOCKER_CONFIG/config.json` (when
  `DOCKER_CONFIG` is an absolute path) or `~/.docker/config.json`, as
  Docker reads it. The credential helper it names for the registry
  (`credHelpers[<registry>]`, else `credsStore`) is asked first, once, at
  the registry's first challenge, so a public image runs no helper:
  `docker-credential-<name> get`, found on the PATH, the registry's name
  on its stdin (Docker Hub's as `https://index.docker.io/v1/`), with this
  process's environment and 60 s to answer. Its `Username` and `Secret`
  are the credentials; a helper that says it has none leaves the `auths`
  entry to answer, if there is one. One that is not on the PATH, cannot be
  run, fails, times out, or answers with what boxcar cannot read (an
  identity token among them) fails the pull, named, with nothing it wrote
  repeated. Without a helper, the `auths` entry: its `auth` (base64
  `user:password`) or its `username` and `password`, under the registry's
  name (Docker Hub's under `https://index.docker.io/v1/`,
  `index.docker.io`, `docker.io` or `registry-1.docker.io`). Credentials
  go to two places only: the token realm the registry's own challenge
  named, and the registry's origin for Basic. When authentication fails
  the error says whether the helper had none for the registry, or gave
  credentials the registry refused. A config that does not parse fails a
  pull.
- **Errors** name the registry, the repository, the request and the HTTP
  status, with the registry's error codes (`MANIFEST_UNKNOWN`, `DENIED`,
  `TOOMANYREQUESTS`, ...) in boxcar's own words. Nothing the registry sent
  is repeated, and no credential or token appears in an error, a log line
  or any output. A failed request is not retried.
- **Timeouts.** Resolving, connecting and a response's headers take 30 s
  each at most. A blob's body must arrive within 30 s plus one second per
  64 KiB of its size, so a stalled transfer fails and one slower than
  64 KiB/s is refused; a manifest's or a token's body, within 30 s.

## Verification

- A manifest's digest is the SHA-256 of the bytes received. Fetched by
  digest (as an index's manifest always is), it must be the digest asked
  for; a `Docker-Content-Digest` header, when sent, must match it.
- A manifest may name at most 128 layers, a config of at most 1 MiB and
  layers of at most 8 GiB each, and every layer's media type must be one
  boxcar unpacks: `application/vnd.oci.image.layer.v1.tar`, `+gzip` or
  `+zstd`, or `application/vnd.docker.image.rootfs.diff.tar` or
  `.tar.gzip`. Foreign and non-distributable layers fail the pull.
- Every blob (the manifest, the config, each layer) is written under a
  staging name while its SHA-256 is computed, and takes its final name only
  when its digest and size are the manifest's; a mismatch removes it and
  fails the pull. A config's or layer's `Content-Length` must be its size,
  and nothing past that size is read. A blob already cached is used without
  a download when its size is the manifest's.
- Decompression is bounded as it streams: gzip (every member, trailers
  checked), zstd (every frame, its checksum checked, a window of at most
  128 MiB) or a plain tar. Every decompressed byte, what follows the
  archive's end included, and every tar header count against the image's
  budget of 16 GiB and 1,000,000 headers. Each layer is read twice (below),
  and both reads count.

## Unpacking

The layers are applied in order into one tree, as the user who runs
boxcar, with no privileges:

- Every path is resolved with the tree as its root (`openat2`,
  `RESOLVE_IN_ROOT`): an absolute symlink in the image resolves inside the
  tree, `..` at the root stays there, and nothing resolves outside it. The
  final name is never followed: each entry replaces what is at its name,
  except that a directory is kept for a directory entry. A `..` component
  or a NUL in a name fails the pull.
- Whiteouts apply to the layers below: `.wh.<name>` removes `<name>`, a file
  or a whole directory; `.wh..wh..opq` empties its directory. Each layer is
  read twice, whiteouts first and entries second, so an entry survives its
  own layer's whiteouts wherever they stand in the archive. A whiteout of a
  missing name is ignored; one of `..` fails the pull.
- Symlink targets are kept as written. A hardlink's target is resolved in
  the tree; one to a missing target or a directory fails the pull.
- Device nodes and FIFOs are not made; `image.json` lists them as
  `skipped`.
- Sparse files (GNU `S`, any `GNU.sparse.*` PAX key), unknown entry types,
  a global PAX header that sets `path`, `linkpath` or `size`, an extension
  record (PAX, GNU long name or link) over 64 KiB, and a header whose
  checksum does not match fail the pull.
- Modes are kept, setuid and setgid included where the host allows, but the
  cache stores every entry readable by its owner (owner read on a file,
  owner read, write and search on a directory), so a session's copy can
  read it all; `image.json` lists the image's modes of those entries as
  `modes`, and each copy gets them back. Directory modes are set after the
  last layer, deepest first.
- Ownership and times are not set: everything belongs to the user who
  pulled. `/tmp` (mode `1777`) and `/workspace` are made when the image
  lacks them.

A failed pull removes what it was building; verified blobs stay.

## The cache

`--cache-dir DIR`, else `$XDG_CACHE_HOME/boxcar`, else `~/.cache/boxcar`,
made mode 0700:

```
blobs/sha256/<hex>                           a verified blob: manifest, config or layer
images/<manifest-hex>/rootfs/                the unpacked tree
images/<manifest-hex>/image.json             digests, layers, the config's defaults, skipped, modes
refs/<registry>/<repository>/_tags/<tag>     a tag: the manifest digest
refs/<registry>/<repository>/_indexes/<hex>  an index's digest: its manifest's digest
.lock                                        shared by pulls and runs, exclusive for rm and prune
```

- **Whole or absent.** What is being built or removed has a `.`-name
  carrying the pid and a counter, which no final name can have, and only
  final names are read. A blob, image or ref is made durable before its
  rename to a final name, and its directory synced after; a tag is written
  after its image. What a process that is gone left half done is swept
  when a pull starts and by `prune`.
- **Locking.** A pull holds `.lock` shared, and so does `boxcar run
  --image` from finding the image until its copy is made; `rm` and `prune`
  hold it exclusive, so each waits for the other. Two pulls of one image
  at once each build a tree, and the second to finish uses the first's.
- **Sharing.** Blobs are shared: a layer two images have is fetched once
  and unpacked into each tree.
- **`image.json`** holds the manifest and config digests, the layers, the
  config's `env`, `entrypoint`, `cmd`, `working_dir` and `user`, and the
  `skipped` and `modes` lists.
- **Index entries** let a reference by an index's digest be found offline.
  They go with their image and keep nothing from `prune`: only tags do, so
  an image pulled by digest alone is pruned.

## `boxcar image`

Each takes `--cache-dir DIR`.

- `pull REF` prints a line per layer on stderr (`layer 3/7 sha256:<hex>
  12.3 MiB`, `(cached)` when the blob was there), then the manifest digest
  on stdout. An image already whole costs its manifest and moves its tag.
  Exit 0, 1 when the pull fails, 2 when REF does not parse.
- `ls` prints each tag (`<registry>/<repository>:<tag>`), each index entry
  (`<registry>/<repository>@sha256:<index>`), each with a tab and its
  manifest digest, then each image no tag names as `(no ref)`.
- `rm DIGEST|REF`: a manifest digest removes the image with every tag and
  index entry naming it; a reference with a digest does the same for the
  image it names; a reference with a tag removes the tag only. Exit 1 when
  there is nothing to remove, 2 when the argument is neither.
- `prune` removes the images no tag names and the blobs no remaining image
  names, and prints `removed N images and M blobs`.

Removal unlinks the tags and index entries first, then renames the image
out of its final name, then deletes it, whatever modes its layers set: an
interruption leaves no half-deleted image under a final name and no tag
naming a removed one.

## What the session runs

The config's defaults are checked first: `Env`, `Entrypoint`, `Cmd` and
`WorkingDir` together at most 32 KiB, every `Env` entry `NAME=VALUE` with a
name, no NUL, `WorkingDir` empty or absolute. An image past these is
refused (exit 1) before the VM is built, with a fixed sentence that repeats
none of its text.

- **Command:** `-- CMD` when given, replacing `Entrypoint` and `Cmd` both
  (an argv, not arguments to the entrypoint); else `Entrypoint` then `Cmd`;
  else boxcar's login shell, `/bin/sh -l`.
- **Environment:** boxcar's (`PATH`, `HOME`, `TERM`, `LANG`,
  `BOXCAR_SESSION_ID`), then the image's `Env`, then each `--env
  NAME=VALUE`, merged to one value per name, the last winning, in the order
  names were first seen: the image's `PATH` replaces the default, and
  `--env PATH=...` the image's.
- **Working directory:** `WorkingDir`, else `/workspace`. `HOME` stays
  boxcar's unless the image's `Env` or `--env` sets it.
- **`User` is ignored:** the session runs as the user who ran `boxcar run`,
  and owns every file of its root. There is no ownership override yet.

## The session's copy

The copy is made after the session's directory exists and before the VM is
built. The cached tree is walked with directory descriptors and `*at`
calls, following no link on either side. A regular file is reflinked
(`FICLONE`) where the filesystem can, sharing its data but not its inode,
and copied otherwise (`copy_file_range`, or reads and writes). Hardlink
groups stay groups within the copy, never linked to the cache. Symlinks keep
their targets. Times are not copied; anything but a file, directory or link
is skipped and counted on stderr. A failed copy is removed whole and the
run exits 1: no `vmm.start` is recorded. A tree cached by an earlier boxcar
can hold an entry its owner cannot read; the copy then fails, saying to
`boxcar image rm` the image and pull it again.

Init writes to the root share at boot. So that a policy keeping writes out
of the root share does not stand between init and its setup, the host
makes in the copy what init would, following the image's links as init
will, while every directory of the copy is still 0o700:

1. The mount points `/dev`, `/proc`, `/sys` and `/run` (0o755), where each
   leads, when missing.
2. The working directory and its parents (0o755). Where it leads under
   `/workspace`, as written or through a link (`/app -> /workspace`), it is
   made in the workspace's host directory. The run is refused (exit 1)
   when it leads under `/run`, `/dev`, `/proc` or `/sys` (mounts that
   would hide it), through more than 40 links, or above `/`. An image whose
   `/workspace` is a link to nothing or to a file is refused the same way:
   the workspace share could not be mounted there.
3. `/etc/resolv.conf`, with a network: an empty file (0o644) where it
   leads, when nothing is there and its directory is; nothing where it
   leads under `/run`, init's tmpfs.
4. `/etc/ssl/certs/ca-certificates.crt`, when the session inspects
   ([gate.md](gate.md)): the same.

The modes come last, deepest first: every directory and every entry in
`modes` gets the image's mode, so a `0o555` `/etc` still gets its
`resolv.conf`.

## What is recorded

`vmm.start` carries `image {reference, manifest_digest, config_digest}`:
the reference normalized (`alpine:3.22` is recorded as
`docker.io/library/alpine:3.22`), and the digests of the manifest and
config whose tree was copied. `shares[0].host_root` is the copy. The pull
is not in the log: it happens before the log opens.

## `boxcar doctor`

Two lines about the default cache (`doctor` takes no `--cache-dir`):

- `image cache: <dir>`: missing until a pull makes it; otherwise how many
  images and tags it holds, and `sessions reflink it` or `sessions copy
  it`, from a probe file cloned from the cache into the default audit
  directory (unknown before a session has made that directory).
- The free space where the cache is or will be: missing under 2 GiB, with
  the hint to free some or point `--cache-dir` or `XDG_CACHE_HOME` at a
  larger filesystem.

## Limits

| What | Limit |
|---|---|
| A reference | 255 bytes |
| A manifest or index; a config; a token response | 4 MiB; 1 MiB; 64 KiB |
| Layers in an image; a blob | 128; 8 GiB |
| Redirects per request | 5 |
| Resolving, connecting, a response's headers; a blob's body | 30 s each; 30 s plus 1 s per 64 KiB |
| Decompressed bytes; tar headers (per image, both passes counted) | 16 GiB; 1,000,000 |
| An extension record; a zstd window | 64 KiB; 128 MiB |
| Paths kept while unpacking (directory modes, `modes`, `skipped`) | 64 MiB |
| An image's defaults | 32 KiB |

Not done: platforms other than `linux/amd64`, schema 1 manifests, sparse
files, identity tokens from a credential helper, retries, signature
verification, and presenting the image's ownership.
