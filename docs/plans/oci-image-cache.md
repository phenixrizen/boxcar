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
| `decode.rs` | the decompressed, counted stream: plain, gzip, the multi-frame zstd adapter |
| `framer.rs` | the tar stream reader |
| `unpack.rs` | applying framed entries into a tree beneath a directory fd |
| `pull.rs` | the pull, in order, over the pieces above |
| `crates/boxcar/src/cmd/image.rs`, `cli.rs` | `boxcar image pull\|ls\|rm\|prune`, `--cache-dir` |
| `crates/boxcar-testreg/` | the in-process test registry and layer builders: a test-only workspace crate, a dev-dependency of `boxcar` (a binary-only crate, whose modules its integration tests cannot import), so the `oci` unit tests here and Task 3's gated tests share it |

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
- Auth. A challenge is honoured only when the response that carries it came from the registry's own origin (scheme, host and port, read from the final response URI, `ResponseExt::get_uri()`): a `401` reached through a redirect fails the pull without any credential being used. From the registry's origin, a `401` with `WWW-Authenticate: Bearer realm=…,service=…,scope=…` sends `GET <realm>?service&scope` (with `Authorization: Basic` from the credentials when there are any), reads a JSON body of at most 64 KiB, takes `token` or `access_token`, and retries once with `Authorization: Bearer`. The realm must be `https` (loopback `http` in test builds), and the token request follows no redirect. `WWW-Authenticate: Basic` from the registry's origin retries once with Basic. Anything else, or a second `401`, fails: "authentication failed for <registry>/<repo>", plus "its credentials are in the helper <name>, which boxcar does not run; `docker login` without a credential helper, or an `auths` entry" when `~/.docker/config.json` names a `credsStore` or a `credHelpers` entry for the registry. Credentials are sent to two places only: the token realm named by the registry's own challenge, and the registry's origin for Basic.
- Credentials come only from `~/.docker/config.json` `auths`: the registry's key (for `docker.io`, also `https://index.docker.io/v1/` and `index.docker.io`), `auth` (base64 `user:password`) or `username` and `password`. They are held in a type whose `Debug` prints `[credentials]`, used only to build one header value, and never put in an error, a log line or output. Nothing a registry sends is echoed: an error names the host, the repository and the status, and maps each `errors[].code` it recognises (`BLOB_UNKNOWN`, `MANIFEST_UNKNOWN`, `NAME_UNKNOWN`, `UNAUTHORIZED`, `DENIED`, `TOOMANYREQUESTS`, `UNSUPPORTED`, `BLOB_UPLOAD_UNKNOWN`, `MANIFEST_INVALID`, `NAME_INVALID`, `SIZE_INVALID`, `TAG_INVALID`) to a fixed sentence of boxcar's own; any other code is "an error the registry did not name". Headers, bodies and URLs the registry chose never appear in errors or logs.
- Responses: `Content-Type` must be one of the accepted manifest types for a manifest request; a schema 1 manifest fails with "schema 1 manifests are not supported". Bodies are read with a limit: 4 MiB manifest, 1 MiB config, 64 KiB token, a layer's size from the manifest (at most 8 GiB). `Content-Length`, when present, must equal the size the manifest gives.

### Manifests (`manifest.rs`)

- An index (OCI or Docker list) is resolved to the manifest whose `platform` is `linux`/`amd64` and that is not an attestation (`vnd.docker.reference.type`); none fails the pull.
- The manifest's digest is the SHA-256 of the bytes received. Pulled by digest, it must equal the digest asked for. A `Docker-Content-Digest` header, when present, must equal it too.
- At most 128 layers. Each layer's `mediaType` must be `application/vnd.oci.image.layer.v1.tar`, `+gzip`, `+zstd`, `application/vnd.docker.image.rootfs.diff.tar` or `.tar.gzip`; foreign or non-distributable layers and anything else fail the pull.
- The config (`application/vnd.oci.image.config.v1+json` or Docker's) must say `os: linux`, `architecture: amd64`; its `config.Env`, `Entrypoint`, `Cmd`, `WorkingDir` and `User` are kept in `image.json` for Task 3.

### The store (`store.rs`)

`$XDG_CACHE_HOME/boxcar` (else `$HOME/.cache/boxcar`), or `--cache-dir DIR`, created mode 0700:

```
blobs/sha256/<hex>                        a verified blob: manifest, config or layer
images/<manifest-hex>/rootfs/             the unpacked tree
images/<manifest-hex>/image.json          manifest and config digests, the layers, the config's defaults, `skipped`
refs/<registry>/<repository>/_tags/<tag>  a file holding the manifest digest
.lock                                     flock: shared by a pull, exclusive by rm and prune
```

Final names are the three above. Everything else under the cache is staging, and starts with a `.`, which no final name can (a digest is hex, a tag starts with a letter, digit or `_`, a repository component with a letter or digit): `.<name>.partial.<pid>-<n>` while being built (`n` from a process-wide counter, so two pulls in one process never share a name; created with `O_EXCL`/`mkdir`, never reused), and `.<name>.deleting.<pid>-<n>` while being removed. `ls`, `rm`, `prune` and a pull read final names only and skip every `.`-name. Staging entries whose pid is not alive (`/proc/<pid>` absent) are swept when a pull starts and by prune, so an interruption at any point leaves nothing for long and nothing a later pull would trust.

- **Blobs.** Written to `blobs/sha256/.<hex>.partial.<pid>-<n>` while the SHA-256 is computed from the bytes written; when the digest and the size match: `fsync` the file, rename to `<hex>`, `fsync` the directory. A mismatch removes the partial and fails the pull. A blob at its final name is used as it is.
- **Images.** Built in `images/.<hex>.partial.<pid>-<n>/`: `rootfs/` unpacked; `syncfs` on the cache's filesystem (one call makes every file and directory of the tree durable, where a per-file `fsync` would cost one call per file); `image.json` written and `fsync`ed; the partial image directory `fsync`ed (so `image.json`'s entry is durable too); the directory renamed to `images/<hex>`; the `images` directory `fsync`ed. If the final name exists by then (another pull won), ours is removed as below and theirs is used. A sync that fails (`EIO`, `ENOSPC`) fails the pull and removes the partial.
- **Refs.** Tags live under `_tags`, a component no repository path can have (components start with a letter or digit), so `team:app` and `team/app:latest` never meet. A ref is written to `_tags/.<tag>.partial.<pid>-<n>`, `fsync`ed, renamed over `_tags/<tag>`, and its directory `fsync`ed. It is written last, after the image directory is at its final name.
- **Removal.** Under the exclusive lock, `rm` and `prune` first unlink the refs and `fsync` each `_tags` directory they changed, stopping on a failure; then rename the image directory to `images/.<hex>.deleting.<pid>-<n>` and `fsync` `images`; then delete the tree. A blob is removed by rename to its `.deleting` name, `fsync` of the directory, then unlink. An interruption leaves a `.deleting` entry, swept later; no final name is ever half-deleted, and after power loss no ref outlives its image.
- **Deleting a tree we own**, whatever modes its layers set: each directory is opened `O_PATH | O_DIRECTORY | O_NOFOLLOW` relative to its parent's fd (so it is a directory of ours, never a link followed), given mode `0o700` through `chmod` on `/proc/self/fd/<fd>` (`fchmodat2` with `AT_SYMLINK_NOFOLLOW` where the kernel has it), opened for reading, its children unlinked (`unlinkat`, `AT_REMOVEDIR` for subdirectories after recursing). A `0o555` or `0o000` directory is deleted like any other.
- `image ls` lists refs with their digests and image directories, and marks images no ref names. `image rm REF` removes the ref; `image rm DIGEST` removes the image directory and every ref naming it. `image prune` removes images no ref names and blobs no remaining image's `image.json` names (manifest, config, layers), under the exclusive lock. Blobs are kept across images so a layer shared by two images is fetched once.

### The tar framer (`framer.rs`)

Over a `Read` of the decompressed stream, counting every byte read against the image's 16 GiB budget and every header against its 1,000,000 entries. The stream is `flate2::read::MultiGzDecoder` for gzip (every member decoded, trailers checked), the blob itself for plain tar, or, for zstd, an adapter of our own (`decode.rs`) over `ruzstd::decoding::StreamingDecoder`, which decodes one frame and then reports its end. When a frame ends the adapter checks the frame's checksum itself, since ruzstd only stores it (`FrameDecoder::get_checksum_from_data` against `get_calculated_checksum`; a mismatch fails the pull), then reads the next four bytes of compressed input: a zstd frame magic is replayed in front of the rest of the input (`Cursor::new(magic).chain(input)`) into a new decoder (window capped at 128 MiB), since the decoder reads the magic itself; a skippable-frame magic (`0x184D2A50`–`0x184D2A5F`) reads the four-byte length and skips that frame; the end of the input ends the stream; anything else fails the pull. After the tar's end-of-archive blocks the framer keeps reading the decompressed stream to its end, every byte counted, so a trailer that lies or a tail that expands past the budget fails the pull rather than being left unread.

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
- Whiteouts apply to the layers below, whatever their position in the archive (OCI: an entry of the same layer survives its own layer's whiteouts). Each layer is therefore read twice from its blob: the first pass frames it and applies each whiteout as it is met (`.wh.<name>`: `<name>` removed, a file or a directory whole; `.wh..wh..opq`: the directory emptied, itself kept), writing nothing else and keeping nothing in memory beyond the entry at hand, so the tree it acts on is the layers below plus whiteouts; the second pass applies the layer's entries, skipping the whiteout entries themselves. A whiteout for a missing name is ignored. Each pass counts against the byte and entry budgets, and the two passes must agree (same headers): a blob is a file, so they do. Removing a directory from the tree uses the owned-tree deletion of section 2 (the store), relative to fds inside the tree.
- After the last layer: `tmp` (mode `0o1777`) and `workspace` are created at the root when missing, then directory modes are applied, deepest first. Durability is the store's protocol above (`syncfs`, `image.json`, rename, parent).

### The pull (`pull.rs`) and the CLI

`boxcar image pull REF [--cache-dir DIR]`: parse the reference; lock shared; sweep staging entries of dead pids; `GET` manifest (index → manifest), verify, keep as a blob; `GET` config, verify, keep; for each layer in order: use the cached blob or download and verify; apply its whiteouts (first pass) then its entries (second pass) into the partial tree; write `image.json`; rename; write the ref; print the manifest digest. Progress goes to stderr, one line per layer (`layer 3/7 sha256:ab12… 12.3 MiB`). Exit 0 on success, 1 on failure, 2 for a reference that does not parse. `image ls`, `image rm`, `image prune` as under the store.

## 3. Events and the orders they come in

The pull is a sequence of steps; what interacts with it is another process on the same cache, the registry, and the user interrupting it.

- **P1, two pulls of the same image at once**, in two processes or two threads of one (two `boxcar run --image` starting together, Task 3; a test). Both hold the shared lock. Each writes its own `.partial.<pid>-<n>` blobs and image directory, names that cannot meet. Blob renames over an identical existing blob are harmless (same content, same name). The image rename: the second finds `images/<hex>` present, removes its own partial (through `.deleting`), uses the existing one. The ref: both write the same digest. Nothing is half-written in a final name at any point.
- **P2, a pull and a prune at once.** Prune takes the exclusive lock: it waits for pulls to finish, and a pull started during a prune waits for it. So prune never removes a blob a pull is about to unpack, and a pull never builds on an image prune is removing.
- **P3, interrupted pull** (SIGINT, a crash, ENOSPC, a failed sync) at any step: before any blob (nothing written); mid-blob (a partial blob); after some blobs (verified, durable blobs stay, usable next time); mid-unpack (a partial image directory); after `image.json` but before the rename (same); after the rename but before the ref (a complete image with no ref, listed by `ls` as unreferenced, removed by prune); mid-ref (a partial ref file). Every staging entry is swept by the next pull or prune once the pid is gone. No final name is ever incomplete, and after power loss each final name's contents are durable (the store's protocol), so what a later pull trusts is whole.
- **P4, a tag re-pulled** after it moved: the new manifest gets its own image directory; the ref is renamed over to the new digest; the old image stays until prune. Re-pulled unchanged: the manifest's blob and image directory exist, no layer is fetched or unpacked, the ref is rewritten with the same digest.
- **P5, a layer shared by two images**: the blob exists from the first pull; the second uses it without a download, and still unpacks it into its own tree.
- **P6, the registry misbehaves**: a manifest with a digest other than asked, a `Docker-Content-Digest` that does not match, a blob whose bytes hash to something else or whose length differs from the manifest's, a `Content-Length` that disagrees, a body past its limit, a redirect chain past 5, a stalled transfer: each fails the pull at that step; the partial is removed; verified blobs stay.
- **P7, a layer that is hostile** while its digest is right: names with `..`, absolute names, a symlink then a file through it, a hardlink to a path outside (`../../etc/passwd`, or through an absolute symlink), a whiteout of `..`, device nodes, a sparse entry, a PAX record of 100 MiB, a stream that expands past 16 GiB or 1,000,000 entries, a bad checksum: each is refused as section 2 says, and nothing outside `rootfs/` changes.
- **P8, auth**: anonymous 401 → token → 200; credentials in `auths` → Basic to the realm → token; wrong credentials → second 401 → failure; a helper configured and no `auths` entry → the helper message; a Basic challenge; the token endpoint over plain `http` → refused.
- **P9, two pulls of different images sharing layers** (both shared lock): the shared blob may be written by both as separate partials and renamed by both; the second rename replaces an identical file. A pull reading a blob while another renames the same content over it reads the inode it opened; the content is the same.
- **P10, interrupted `rm` or `prune`** at any step: refs removed but the image not yet renamed (an unreferenced image, pruned later); the image at `.deleting` and partly deleted (swept later); a blob at `.deleting` (swept). A pull after the interruption, with the same image, finds no final image name and pulls afresh; it never builds on a half-deleted tree.
- **P11, a challenge from the wrong place**: a blob request redirected to another host whose response is a `401` with a challenge, or a challenge naming a plain-`http` realm, or a token response that redirects. Each fails the pull, and no credential is sent anywhere but the registry's own realm.
- **P12, modes that block deletion**: a layer sets a directory to `0o555` or `0o000`; the image is later removed by `rm`, by the sweep after an interruption during finalisation, or as a losing partial in P1. The owned-tree deletion restores `0o700` on each directory it enters, so each case deletes the tree whole.

## 4. Invariants

- **I1.** Nothing outside the cache directory is written, and nothing outside `rootfs/` of the partial image is written by unpacking, whatever a layer holds: every operation goes through `openat2(root, …, RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS)` and a `*at` call on a final name that is never followed.
- **I2.** A file at `blobs/sha256/<hex>` has SHA-256 `<hex>` and the size the manifest gave: it got its name only after both were checked on the bytes written.
- **I3.** `images/<hex>` at its final name is complete and durable: `rootfs/` and `image.json` were finished and made durable before the rename, the rename's directory was synced, and a final name is never modified after; removal takes it out of the final namespace (rename to `.deleting`) before a byte of it is deleted.
- **I4.** A ref names an existing image: it is written after the rename, and prune and `rm` remove refs before images.
- **I5.** No credential, token or `Authorization` value reaches an error, a log line, stdout, stderr, a test's output or `image.json`; nothing a registry sent (a body, a code, a header, a URL) is echoed in any of them; credentials go only to the realm the registry's own challenge named, or the registry's origin.
- **I6.** Per image: at most 16 GiB of decompressed bytes, 1,000,000 headers, 64 KiB per extension record, 128 MiB of zstd window, 4 MiB manifest, 1 MiB config, 128 layers, 8 GiB per blob; nothing holds a layer in memory.
- **I7.** Concurrent pulls, and a pull with a prune, leave the cache consistent (I2–I4) in every order of P1, P2, P9.
- **I8.** Only HTTPS, with the host's roots, outside test builds; loopback plain `http` exists only under `cfg(any(test, feature = "kvm-tests"))`.
- **I9.** The result of unpacking is a function of the layers alone: no time, pid or host path in `rootfs/` or `image.json`.
- **I10.** Unpacking a layer gives the same tree whatever the order of its entries: whiteouts act on the layers below before the layer's own entries are applied.

## 5. Out of scope

- Booting from an image (`--image`, the per-session copy, `vmm.start.image`, the boot paths made on the host): Task 3.
- An overlay instead of a copy (#31), ownership (#32), credential helpers (#35).
- Other platforms than `linux/amd64`, sparse files, schema 1 manifests, `identitytoken`, registry mirrors, proxies, pushing.
- Retries on 5xx or 429: a failure is reported with its status and the registry's error codes.
- Signature verification (cosign, Notary).

## 6. Tests

Unit tests in the `oci` modules of the `boxcar` binary and in `boxcar-testreg`, run by `cargo test --workspace` (no KVM, loopback only), each failing before the code it pins:

- `reference`: Docker's cases (`alpine`, `library/alpine`, `docker.io/alpine:3.22`, `index.docker.io/…`, `localhost:5000/x`, `host.example/a/b@sha256:…`, a tag and a digest, uppercase in the path refused, a 256-byte reference refused).
- `decode`: a zstd layer split across two frames, one with a skippable frame between, one with a bad frame checksum in the first and in a later frame, one with trailing garbage; a gzip member with a wrong CRC; a plain tar; each counted against the budget.
- `framer`: a valid PAX entry whose `size` differs from its header's; valid `L` and `K`; an `x`, `L`, file run; oversized PAX and GNU records; both sparse encodings; a global header with `path`; a bad checksum; a zero-block end and a truncated stream; the entry and byte budgets, with a layer of 1,000,001 empty files and one whose tail after the end-of-archive blocks expands past the budget (a gzip of zeros); a layer of 100,000 whiteouts with 60,000-byte PAX paths, applied with no more memory than one entry's (P7, the first pass).
- `unpack` (against a temporary directory, tree hashed before and after where nothing may change): every P7 case; whiteouts of a file and a directory; `foo` then `.wh.foo` and `.wh.foo` then `foo` in one layer both keeping `foo` (I10); an opaque directory with children from below and from this layer, in both orders, keeping only this layer's; a hardlink to a symlink inside; a file replacing a directory and a directory replacing a file; modes including setuid and a `0o555` directory whose children still land; `tmp` and `workspace` added; devices and FIFOs listed in `skipped`; the same layers unpacked twice giving the same tree (I9).
- `store`: the sweep of staging entries by pid; two staging names from one process never equal; a tag named like a staging entry (`release.partial.1-1`) pulled, listed, kept by the sweep and by prune, and removed by `rm`; the shared/exclusive lock (a prune waits for a pull in another thread); `rm` and `prune` leaving I4 true; P3 and P10 at each step by simulating the interruption, then a re-pull that trusts nothing half-done; P12: `rm` of an image with `0o555` and `0o000` directories, and the sweep of such a partial; the durability calls made in order (a `Store` over a recording filesystem shim: the order is `syncfs`, `image.json` fsync, image directory fsync, rename, `images` fsync; refs unlinked and their directories synced before an image is renamed away).
- `pull` against the in-process test registry (`boxcar-testreg`: a `/v2/` server over `std::net::TcpListener` on 127.0.0.1, requests parsed with `httparse`, an in-memory map of blobs and manifests built by its layer, manifest and index builders (`tar`'s `Builder`, `flate2`'s encoder, `ruzstd::encoding::compress_to_vec`), an optional Bearer challenge with a `/token` endpoint, optional TLS with an `rcgen` certificate, and a log of every request it saw with its headers): a pull by tag and by digest; an index resolved to `linux/amd64`; gzip, zstd and plain layers; P1 (two threads pulling the same image, and two processes through the CLI), P4, P5, P6 (each misbehaviour), P8 (each auth order), P11 (a redirect target that challenges, and a token endpoint that redirects: no credential reaches them, which the test registry asserts on every request it saw); credentials never in any error string, log line or output, including a registry whose error `code` and `message` echo the `Authorization` header it received (a test credential built at run time, searched for in everything the pull produced, I5); TLS with the test CA as the root set succeeds and with another root fails; a partial pull leaving nothing (P3).
- `boxcar image ls|rm|prune` as CLI tests on a temporary cache (`crates/boxcar/tests/image_cli.rs`), no network.

Gated (`test-kvm m5`) tests begin in Task 3, where a pulled image boots.

## 7. Decisions (to the M5 plan's section 8 when the task ships)

- **`RESOLVE_IN_ROOT`, not `RESOLVE_BENEATH`.** The M5 plan said `RESOLVE_BENEATH`, which fails on an absolute symlink in a parent component; images are full of them. `RESOLVE_IN_ROOT` interprets them against the tree's root, which is what a chroot would do, and still confines every resolution to the tree.
- **A body deadline from the size, not a stall timeout.** ureq 3 times out a whole body, not one read; a 30 s stall timeout would need its unversioned transport API. A deadline of 30 s plus the size at 64 KiB/s catches a stall and refuses a crawl.
- **Blobs are kept and shared across images;** the tree is unpacked per image. Disk holds both; `prune` reclaims.
- **One framer of our own** over `tar`'s header and PAX parsers, as the M5 plan's round 3 and 4 reviews settled.
- **`--cache-dir`** is added so tests and the test box can point the cache anywhere; the default is the XDG path.
- **Whiteouts in a first pass.** Reading each layer twice costs one more decompression per layer and makes the result independent of entry order by construction; tracking provenance through a single pass would have to follow it into every subdirectory.
- **`syncfs` once, not `fsync` per file.** A tree of ten thousand files is made durable by one call before `image.json` and the rename; blobs and refs, single files, get `fsync` and their directory's.
- **`_tags` in the ref path**, a name no repository component can have, so a repository and a deeper repository's tag never claim the same path.
- **Staging and deleting names** start with `.`, carry pid and a counter, and only the three final names are ever read, so a half-built or half-deleted entry is never trusted and never collides with a tag.
- **Whiteouts applied as the first pass streams them**, not collected: the pass holds one entry at a time, whatever a layer declares.
- **The test registry is a crate.** `boxcar` is a binary; a test-only crate is the one place both its unit tests and the gated suites can reach.
