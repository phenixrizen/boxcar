# OCI images: pull, verify and unpack into a cache

**Goal.** `boxcar image pull REF` fetches an image from a registry with boxcar's own client, verifies every byte it uses against the digest the manifest names, and unpacks the layers into one root filesystem tree in a per-user cache, as an unprivileged user, so that no entry of any layer can write outside that tree, no credential leaves the client, and a layer that passes its digest and size checks still cannot exhaust memory or disk. `boxcar image ls|rm|prune` manage the cache. Nothing boots from it yet: that is Task 3 (`--image`).

This is M5 Task 2 (`docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`, section 3: the image store, the registry client, unpacking; section 4: review focus 1, 2, 3; issue #24). Branch `oci-image-cache`, its own pull request from `main`. Subject: `oci: pull, verify and unpack images into a cache`.

## 1. Where it sits

New module `crates/boxcar/src/oci/` in the `boxcar` crate (the CLI; nothing in the VMM or the audit crates changes):

| File | Holds |
|---|---|
| `reference.rs` | `Reference`: a parsed image reference |
| `client.rs` | `Client`: HTTP to a registry, auth, limits |
| `auth.rs` | `~/.docker/config.json` credentials, the token flow |
| `manifest.rs` | manifest, index and config types and their checks |
| `store.rs` | `Store`: the cache directory, its lock, blobs, images, refs |
| `framer.rs` | the tar stream reader |
| `unpack.rs` | applying framed entries into a tree beneath a directory fd |
| `pull.rs` | the pull, in order, over the pieces above |
| `testreg.rs` | the in-process test registry (`cfg(any(test, feature = "kvm-tests"))`) |
| `crates/boxcar/src/cmd/image.rs`, `cli.rs` | `boxcar image pull\|ls\|rm\|prune`, `--cache-dir` |

Dependencies, workspace-wide, crates.io only: `ureq = { version = "3.4", default-features = false, features = ["rustls-no-provider"] }`, `tar = { version = "0.4", default-features = false }` (its header and PAX parsers only, no `xattr`), `ruzstd = "0.9"`, `flate2` (present) for gzip, `ring` (present) for SHA-256, `rustls` and `rustls-native-certs` (present) for TLS. `base64` moves from 0.22 to 0.23 (`default-features = false, features = ["std"]`, keeping the SIMD engines out); its `Engine` API, all boxcar uses, is unchanged. New crates and their licences: ureq, ureq-proto, http, percent-encoding, utf8-zero, tar, filetime (MIT OR Apache-2.0), ruzstd, twox-hash (MIT). No `deny.toml` change: nothing new in `skip`.

## 2. The pieces

### References (`reference.rs`)

Parsed as Docker parses them, into `{registry, repository, tag: Option, digest: Option}`:
- `[host[:port]/]path[:tag][@sha256:hex]`. The first component is the registry when it holds a `.` or a `:` or is `localhost`; else the registry is `docker.io`. `index.docker.io` is `docker.io`. On `docker.io` a one-component path gets `library/` in front.
- Path components: `[a-z0-9]+` joined by `.`, `_`, `__` or one or more `-`, separated by `/`. Tag: `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`. Digest: `sha256:` and 64 lowercase hex digits. The whole reference at most 255 bytes.
- No tag and no digest means tag `latest`. A digest wins over a tag for what is fetched; the tag is still what the ref file is named.
- `docker.io`'s API host is `registry-1.docker.io`; any other registry's is itself.

### The client (`client.rs`, `auth.rs`)

- One `ureq::Agent` per pull: rustls on the `ring` provider (`TlsConfig::builder().provider(Rustls).unversioned_rustls_crypto_provider(ring)`), roots from `rustls-native-certs` (as the gate's upstream leg), `https_only(true)`, `http_status_as_error(false)`, `max_redirects(5)`, `User-Agent: boxcar/<version>`. ureq never forwards `Authorization` on a redirect, so a blob redirected to a CDN carries no token.
- Timeouts: resolve, connect and response headers 30 s each; the body `30 s + size / 64 KiB/s`, so a stalled transfer fails within that, and a slow one at under 64 KiB/s is refused. (ureq times out a whole body, not a read; see Decisions.)
- Requests, in order, for a pull: `GET /v2/<repo>/manifests/<tag or digest>` with `Accept` naming the OCI manifest and index and the Docker v2 manifest and list; then `GET /v2/<repo>/blobs/<digest>` for the config and each layer.
- Auth. A `401` with `WWW-Authenticate: Bearer realm=…,service=…,scope=…` sends `GET <realm>?service&scope` (with `Authorization: Basic` from the credentials when there are any), reads a JSON body of at most 64 KiB, takes `token` or `access_token`, and retries once with `Authorization: Bearer`. The realm must be `https` (loopback `http` in test builds). `WWW-Authenticate: Basic` retries once with Basic. Anything else, or a second `401`, fails: "authentication failed for <registry>/<repo>", plus "its credentials are in the helper <name>, which boxcar does not run; `docker login` without a credential helper, or an `auths` entry" when `~/.docker/config.json` names a `credsStore` or a `credHelpers` entry for the registry.
- Credentials come only from `~/.docker/config.json` `auths`: the registry's key (for `docker.io`, also `https://index.docker.io/v1/` and `index.docker.io`), `auth` (base64 `user:password`) or `username` and `password`. They are held in a type whose `Debug` prints `[credentials]`, used only to build one header value, and never put in an error, a log line or output. Registry error bodies are not echoed: an error names the host, the repository, the status and the `errors[].code` values.
- Responses: `Content-Type` must be one of the accepted manifest types for a manifest request; a schema 1 manifest fails with "schema 1 manifests are not supported". Bodies are read with a limit: 4 MiB manifest, 1 MiB config, 64 KiB token, a layer's size from the manifest (at most 8 GiB). `Content-Length`, when present, must equal the size the manifest gives.

### Manifests (`manifest.rs`)

- An index (OCI or Docker list) is resolved to the manifest whose `platform` is `linux`/`amd64` and that is not an attestation (`vnd.docker.reference.type`); none fails the pull.
- The manifest's digest is the SHA-256 of the bytes received. Pulled by digest, it must equal the digest asked for. A `Docker-Content-Digest` header, when present, must equal it too.
- At most 128 layers. Each layer's `mediaType` must be `application/vnd.oci.image.layer.v1.tar`, `+gzip`, `+zstd`, `application/vnd.docker.image.rootfs.diff.tar` or `.tar.gzip`; foreign or non-distributable layers and anything else fail the pull.
- The config (`application/vnd.oci.image.config.v1+json` or Docker's) must say `os: linux`, `architecture: amd64`; its `config.Env`, `Entrypoint`, `Cmd`, `WorkingDir` and `User` are kept in `image.json` for Task 3.

### The store (`store.rs`)

`$XDG_CACHE_HOME/boxcar` (else `$HOME/.cache/boxcar`), or `--cache-dir DIR`, created mode 0700:

```
blobs/sha256/<hex>                 a verified blob: manifest, config or layer
images/<manifest-hex>/rootfs/      the unpacked tree
images/<manifest-hex>/image.json   manifest and config digests, the layers, the config's defaults, `skipped`
refs/<registry>/<repository>/<tag> a file holding the manifest digest
.lock                              flock: shared by a pull, exclusive by rm and prune
```

- A blob is written to `blobs/sha256/<hex>.partial.<pid>` while its SHA-256 is computed from the same bytes, and renamed to `<hex>` only when the digest and the size match. A mismatch deletes the partial and fails the pull. A blob already present is used as it is.
- An image is built in `images/<hex>.partial.<pid>/`: `rootfs/` unpacked, then `image.json` written and `fsync`ed, then the directory renamed to `images/<hex>`. If that name exists by then (another pull won), ours is removed and theirs is used.
- A ref is written to a temporary file beside it and renamed over. It is written last, after the image directory exists.
- `.partial.<pid>` entries whose pid is not alive (`/proc/<pid>` absent) are removed when a pull starts and by prune: an interrupted pull leaves nothing for long.
- `image ls` lists refs with their digests and image directories, and marks images no ref names. `image rm REF` removes the ref; `image rm DIGEST` removes the image directory and every ref naming it. `image prune` removes images no ref names and blobs no remaining image's `image.json` names (manifest, config, layers), under the exclusive lock. Blobs are kept across images so a layer shared by two images is fetched once.

### The tar framer (`framer.rs`)

Over a `Read` of the decompressed stream (`flate2::read::MultiGzDecoder`, `ruzstd::decoding::StreamingDecoder` with its 128 MiB window cap, or the stream itself), counting every byte read against the image's 16 GiB budget and every header against its 1,000,000 entries:

- Each 512-byte header is parsed with `tar::Header::from_byte_slice`; its checksum is recomputed (the checksum field as spaces, both unsigned and signed sums accepted, as GNU tar does) and must match; a mismatch fails the pull.
- Two zero blocks, or one followed by the end of the stream, end the archive.
- Entries are dispatched by type: `x` (PAX local) is read whole into a buffer of at most 64 KiB and parsed with `tar::PaxExtensions`, taking `size`, `path` and `linkpath` as overrides and failing the pull on any `GNU.sparse.*` key; `L` and `K` (GNU long name and link) are read into at most 64 KiB and taken as a NUL-terminated name; `g` (PAX global) is read within the same cap and fails the pull when it sets `size`, `path` or `linkpath`, else is ignored; `S` (GNU sparse) fails the pull; `D`, `M`, `N`, `V`, `A` and any other unknown type fail the pull. A larger extension record fails the pull.
- Overrides carry across a run of extension headers (`x`, then `L`, then the entry) and apply to the next ordinary entry (`0`, `\0`, `7` regular; `1` hardlink; `2` symlink; `3`, `4` devices; `5` directory; `6` FIFO) before its data and its padding to 512 bytes are read. An entry's data is handed to the unpacker as a bounded `Read` of exactly `size` bytes; the framer reads any remainder and the padding itself.

### Unpacking (`unpack.rs`)

Into `rootfs/` under the partial image directory, held open as a directory fd (`root`). Every path operation is relative to a parent directory fd obtained with `openat2(root, parent, O_PATH | O_DIRECTORY | O_CLOEXEC, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` and then a `*at` call on the final name:

- `RESOLVE_IN_ROOT` treats `root` as `/` for the resolution: an absolute symlink in a parent component (`/etc/alternatives/x -> /usr/bin/y`, common in images) resolves inside the tree, and `..` at the root stays at the root. Nothing can resolve outside `root`. `EAGAIN` (a concurrent change the kernel detected) is retried a few times, then fails the pull; nothing else writes the tree, so it does not happen in practice.
- Entry names are normalised: a leading `/` or `./` is stripped; an empty name is skipped; a `..` component, or a NUL, fails the pull. The final component is never followed: files are created with `O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC`, directories with `mkdirat`, symlinks with `symlinkat` (target kept verbatim), hardlinks with `linkat(target_parent, target_name, parent, name, 0)`, the target's parent resolved the same way, so the target is inside the tree. A hardlink to a missing target fails the pull.
- What exists at a final name is replaced: a file, symlink, FIFO or device is unlinked first; a directory is kept when the entry is a directory, else removed whole (a walk from a directory fd opened in-root, `unlinkat` on each child) and replaced.
- Regular file data is streamed from the framer to the file; its mode (`& 0o7777`, setuid and setgid included) is set with `fchmod` after writing. Ownership is not set: everything belongs to the invoking user (M5 plan decision). Directory modes are recorded and applied once all layers are in (so a `0o555` directory does not block its own children); until then directories are `0o700`. Times are not set.
- Devices (`3`, `4`) and FIFOs (`6`) are skipped and their paths listed in `image.json` `skipped`.
- Whiteouts: an entry named `.wh.<name>` removes `<name>` (a file, or a directory whole) from the tree and is not created; `.wh..wh..opq` removes every child of its directory that this layer has not itself written (the layer keeps a set of the paths it created), then is not created. A whiteout for a missing name is ignored.
- After the last layer: `tmp` (mode `0o1777`) and `workspace` are created at the root when missing, directory modes are applied, and the tree is `fsync`ed enough for the rename to be durable (the image directory and `image.json`).

### The pull (`pull.rs`) and the CLI

`boxcar image pull REF [--cache-dir DIR]`: parse the reference; lock shared; clean dead partials; `GET` manifest (index → manifest), verify, keep as a blob; `GET` config, verify, keep; for each layer in order: use the cached blob or download and verify; decompress, frame and apply into the partial tree; write `image.json`; rename; write the ref; print the manifest digest. Progress goes to stderr, one line per layer (`layer 3/7 sha256:ab12… 12.3 MiB`). Exit 0 on success, 1 on failure, 2 for a reference that does not parse. `image ls`, `image rm`, `image prune` as under the store.

## 3. Events and the orders they come in

The pull is a sequence of steps; what interacts with it is another process on the same cache, the registry, and the user interrupting it.

- **P1, two pulls of the same image at once** (two `boxcar run --image` starting together, Task 3). Both hold the shared lock. Each writes its own `.partial.<pid>` blobs and image directory. Blob renames over an identical existing blob are harmless (same content, same name). The image rename: the second finds `images/<hex>` present, removes its own partial, uses the existing one. The ref: both write the same digest. Nothing is half-written in a final name at any point.
- **P2, a pull and a prune at once.** Prune takes the exclusive lock: it waits for pulls to finish, and a pull started during a prune waits for it. So prune never removes a blob a pull is about to unpack, and a pull never builds on an image prune is removing.
- **P3, interrupted pull** (SIGINT, a crash, ENOSPC) at any step: before any blob (nothing written); mid-blob (a `.partial.<pid>` blob); after some blobs (verified blobs stay, usable next time); mid-unpack (a `.partial.<pid>` image directory); after `image.json` but before the rename (same); after the rename but before the ref (a complete image with no ref, listed by `ls` as unreferenced, removed by prune). Every partial is removed by the next pull or prune once the pid is gone. No final name is ever incomplete.
- **P4, a tag re-pulled** after it moved: the new manifest gets its own image directory; the ref is renamed over to the new digest; the old image stays until prune. Re-pulled unchanged: the manifest's blob and image directory exist, no layer is fetched or unpacked, the ref is rewritten with the same digest.
- **P5, a layer shared by two images**: the blob exists from the first pull; the second uses it without a download, and still unpacks it into its own tree.
- **P6, the registry misbehaves**: a manifest with a digest other than asked, a `Docker-Content-Digest` that does not match, a blob whose bytes hash to something else or whose length differs from the manifest's, a `Content-Length` that disagrees, a body past its limit, a redirect chain past 5, a stalled transfer: each fails the pull at that step; the partial is removed; verified blobs stay.
- **P7, a layer that is hostile** while its digest is right: names with `..`, absolute names, a symlink then a file through it, a hardlink to a path outside (`../../etc/passwd`, or through an absolute symlink), a whiteout of `..`, device nodes, a sparse entry, a PAX record of 100 MiB, a stream that expands past 16 GiB or 1,000,000 entries, a bad checksum: each is refused as section 2 says, and nothing outside `rootfs/` changes.
- **P8, auth**: anonymous 401 → token → 200; credentials in `auths` → Basic to the realm → token; wrong credentials → second 401 → failure; a helper configured and no `auths` entry → the helper message; a Basic challenge; the token endpoint over plain `http` → refused.
- **P9, two pulls of different images sharing layers** (both shared lock): the shared blob may be written by both as separate partials and renamed by both; the second rename replaces an identical file. A pull reading a blob while another renames the same content over it reads the inode it opened; the content is the same.

## 4. Invariants

- **I1.** Nothing outside the cache directory is written, and nothing outside `rootfs/` of the partial image is written by unpacking, whatever a layer holds: every operation goes through `openat2(root, …, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` and a `*at` call on a final name that is never followed.
- **I2.** A file at `blobs/sha256/<hex>` has SHA-256 `<hex>` and the size the manifest gave: it got its name only after both were checked on the bytes written.
- **I3.** `images/<hex>` exists only complete: `rootfs/` and `image.json` were finished and `fsync`ed before the rename, and the directory is never modified after.
- **I4.** A ref names an existing image: it is written after the rename, and prune and `rm` remove refs before images.
- **I5.** No credential, token or `Authorization` value reaches an error, a log line, stdout, stderr, a test's output or `image.json`.
- **I6.** Per image: at most 16 GiB of decompressed bytes, 1,000,000 headers, 64 KiB per extension record, 128 MiB of zstd window, 4 MiB manifest, 1 MiB config, 128 layers, 8 GiB per blob; nothing holds a layer in memory.
- **I7.** Concurrent pulls, and a pull with a prune, leave the cache consistent (I2–I4) in every order of P1, P2, P9.
- **I8.** Only HTTPS, with the host's roots, outside test builds; loopback plain `http` exists only under `cfg(any(test, feature = "kvm-tests"))`.
- **I9.** The result of unpacking is a function of the layers alone: no time, pid or host path in `rootfs/` or `image.json`.

## 5. Out of scope

- Booting from an image (`--image`, the per-session copy, `vmm.start.image`, the boot paths made on the host): Task 3.
- An overlay instead of a copy (#31), ownership (#32), credential helpers (#35).
- Other platforms than `linux/amd64`, sparse files, schema 1 manifests, `identitytoken`, registry mirrors, proxies, pushing.
- Retries on 5xx or 429: a failure is reported with its status and the registry's error codes.
- Signature verification (cosign, Notary).

## 6. Tests

Unit tests in the `oci` modules, run by `cargo test --workspace` (no KVM, loopback only), each failing before the code it pins:

- `reference`: Docker's cases (`alpine`, `library/alpine`, `docker.io/alpine:3.22`, `index.docker.io/…`, `localhost:5000/x`, `host.example/a/b@sha256:…`, a tag and a digest, uppercase in the path refused, a 256-byte reference refused).
- `framer`: a valid PAX entry whose `size` differs from its header's; valid `L` and `K`; an `x`, `L`, file run; oversized PAX and GNU records; both sparse encodings; a global header with `path`; a bad checksum; a zero-block end and a truncated stream; the entry and byte budgets, with a layer of 1,000,001 empty files and one that expands past the budget (a gzip of zeros).
- `unpack` (against a temporary directory, tree hashed before and after where nothing may change): every P7 case; whiteouts of a file and a directory, an opaque directory keeping this layer's own children; a hardlink to a symlink inside; a file replacing a directory and a directory replacing a file; modes including setuid and a `0o555` directory whose children still land; `tmp` and `workspace` added; devices and FIFOs listed in `skipped`; the same layers unpacked twice giving the same tree (I9).
- `store`: partial cleanup by pid; the shared/exclusive lock (a prune waits for a pull in another thread); `rm` and `prune` leaving I4 true; P3 at each step by simulating the interruption.
- `pull` against the in-process test registry (`testreg.rs`: a `/v2/` server over `std::net::TcpListener` on 127.0.0.1, an in-memory map of blobs and manifests built by test helpers, an optional Bearer challenge with a `/token` endpoint, optional TLS with an `rcgen` certificate): a pull by tag and by digest; an index resolved to `linux/amd64`; gzip, zstd and plain layers; P1 (two threads pulling the same image), P4, P5, P6 (each misbehaviour), P8 (each auth order); credentials never in any error string, log line or output (a test credential built at run time, searched for in everything the pull produced, I5); TLS with the test CA as the root set succeeds and with another root fails; a partial pull leaving nothing (P3).
- `boxcar image ls|rm|prune` as CLI tests on a temporary cache (`crates/boxcar/tests/image_cli.rs`), no network.

Gated (`test-kvm m5`) tests begin in Task 3, where a pulled image boots.

## 7. Decisions (to the M5 plan's section 8 when the task ships)

- **`RESOLVE_IN_ROOT`, not `RESOLVE_BENEATH`.** The M5 plan said `RESOLVE_BENEATH`, which fails on an absolute symlink in a parent component; images are full of them. `RESOLVE_IN_ROOT` interprets them against the tree's root, which is what a chroot would do, and still confines every resolution to the tree.
- **A body deadline from the size, not a stall timeout.** ureq 3 times out a whole body, not one read; a 30 s stall timeout would need its unversioned transport API. A deadline of 30 s plus the size at 64 KiB/s catches a stall and refuses a crawl.
- **Blobs are kept and shared across images;** the tree is unpacked per image. Disk holds both; `prune` reclaims.
- **One framer of our own** over `tar`'s header and PAX parsers, as the M5 plan's round 3 and 4 reviews settled.
- **`--cache-dir`** is added so tests and the test box can point the cache anywhere; the default is the XDG path.
