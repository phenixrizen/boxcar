# An overlay of our own for image sessions (#31)

Branch `issue-31`, from `main`. The M5 plan's section 8 decided *a per-session copy of the image, not an overlay*: fuse-backend-rs 0.14's `OverlayFs` answers every `rename` with `EXDEV`, and package managers rename files into place. The copy costs a reflink where the filesystem has them and a full copy otherwise. Subject: `fs: an overlay for image sessions, the image below and the session above`.

## 1. Design

An overlay filesystem of our own under `AuditFs`, in `boxcar-fs`: the cached image tree read-only below, a per-session directory above, both on the host.

- **Lookup and readdir** merge the two: an upper entry hides a lower one of the same name; a whiteout above (an empty file `.wh.<name>`, the OCI layer convention the unpacker already reads: no xattr to ask for on every lookup or listing) hides a lower entry; an opaque mark above (`.wh..wh..opq` in a directory) hides everything below it. `readdir` lists the union, upper entries first, the marks never shown; names beginning with `.wh.` are the overlay's own, never made (`EPERM`).
- **Reads** go to whichever layer holds the entry. **Writes** copy up first: a lower file opened for writing (or truncated, or whose attributes change) is copied to the upper directory with its data, times, mode, user xattrs and the ownership override (`docs/plans/ownership-override.md`), its parent directories made above as shells (same attributes), then the request goes to the copy. A `create`, `mkdir`, `mknod`, `symlink` or `link` makes its entry above.
- **Rename** works within the upper layer: a lower source is copied up first, a directory with its whole lower subtree (less what is whited out) and then marked opaque, so nothing of it is lost and nothing below merges back in; the old name gets a whiteout where a lower entry remains. So `rename(2)` never answers `EXDEV`, which is what the per-session copy was for. (The first draft had a directory come up as an opaque shell, which would have dropped its lower children: a `mv` of an image directory must keep them.)
- **Unlink and rmdir** remove the upper entry and, when a lower one remains, leave a whiteout; `rmdir` of a merged directory is refused unless empty in the merge.
- **The audit.** `AuditFs` sits above the overlay as it sits above the passthrough: the records say the guest's path; which layer served it is not the guest's business and is not recorded, except that a copy-up is one `fs.copy_up {path, bytes}` record, so a session's writes to the image can be told from its writes to its own files.
- **The session directory** is the upper layer; nothing of the cache is ever written. A reflink is no longer needed; a filesystem without one copies only what the session changes. The per-session copy, its mode pass and the `doctor` reflink probe go.
- **Modes.** The cache stores every entry readable by its owner and lists the image's modes of the rest; the overlay shows those modes for the lower entry and for its copy (which keeps the readable mode on the host, so copy-ups can go on beneath it), until the guest sets a mode of its own. The boot paths are made through the overlay itself (a temporary instance over the two directories, before the VM is built), so a directory made above a lower one is its shell, owner and all, and the image's links lead where the guest will see them lead.
- **Hashing and scanning.** `AuditFs` reopens a closed file for its hash beneath the session's directory, else beneath the cached tree; the boot scan covers the lower tree too.

## 2. Phases

1. Lookup, getattr, readdir, open-for-read over two layers (no writes): a session boots from an image through the overlay, with the gated image tests passing; writes still refused.
2. Copy-up, create, unlink, whiteouts, opaque directories: a session installs a package (the existing APK test) through the overlay.
3. Rename and link, with directories: the package manager's rename-into-place test; `mv` of a lower directory.
4. The record (`fs.copy_up`), the switch (`boxcar run --image` uses the overlay; `--rootfs` stays the passthrough), docs, and the box lane.

All four landed in one change (2026-10-21).

## 3. Where in the code

- `crates/boxcar-fs/src/overlay/{mod,lookup,copy_up,rename,whiteout}.rs`: the filesystem, implementing `fuse_backend_rs::api::filesystem::FileSystem` over two `PassthroughFs` instances or over raw `openat2(RESOLVE_IN_ROOT)` calls on the two roots, as the unpacker reaches a tree.
- `crates/boxcar-fs/src/device.rs`: the share's filesystem is the overlay for an image session (`Share::overlay(lower, upper)`).
- `crates/boxcar/src/cmd/run.rs`: no `copy_tree` for an image session; the session's upper directory beside the workspace.
- Docs: `docs/images.md` (the session's root), `docs/audit-events.md` (`fs.copy_up`), the M5 plan's section 8.

## 4. Tests

- Unit (a temp lower and upper): each operation above, whiteouts and opaque marks, copy-up keeping times, xattrs and the override, rename of files and directories, readdir merging and hiding.
- The existing gated image tests, and one that `mv`s a lower directory and renames a package's files into place.

## 5. Out of scope

- Several lower layers (the image is one unpacked tree).
- Sharing the lower tree between sessions through the page cache beyond what the host does on its own.
