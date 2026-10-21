# Ownership inside the guest without a privileged host process (#5, #32)

Branch `issue-5`, from `main`; #32 (an image's ownership presented in the guest) follows on it as branch `issue-32`, stacked. The design's section 9 and the M5 plan's section 8 (*No ownership override in M5*) set this aside. Subject: `fs: an ownership override the guest sees`.

The VMM runs unprivileged, so the passthrough cannot switch uid per request: AuditFs passes uid 0 to the inner filesystem, the guest session runs as the host user's uid and gid and owns what it creates, and `chown`, `mknod` and `security.*` xattrs fail with `EPERM`. An image's files all belong to the host user once unpacked; its device nodes are skipped and listed in `image.json`.

## 1. Design

- **The override.** Each file or directory on a share may carry `user.boxcar.stat`, an xattr of boxcar's own holding the ownership and kind the guest is to see: `uid`, `gid`, the `S_ISUID`/`S_ISGID`/`S_ISVTX` bits the host could not keep, and for a device node its type and `rdev`. The host file is what it is (the invoking user's, a regular empty file standing for a device node); AuditFs presents the override in every attribute it returns (`lookup`, `getattr`, `readdir` with attributes, `create`, `mkdir`, `mknod`, `setattr`) and hides the xattr from the guest (`listxattr` leaves it out, `getxattr`, `setxattr` and `removexattr` of it are refused). This is what `fuse-overlayfs` does with `user.containers.override_stat`.
- **What the guest may set.** `chown` writes the override (the host file is not touched; the invoking user cannot chown anyway); `chmod` keeps the host mode where the host allows it and the rest in the override; `mknod` of a character or block device makes an empty regular file with the override saying so (the guest kernel, told it is a device, opens the device by `rdev`, not the file); `security.*` xattrs stay `EPERM` (they are the host's). Every such request is still refused when the policy would refuse the write it is.
- **Who the guest is.** The guest kernel checks permissions against the attributes AuditFs returns (virtio-fs mounts with `default_permissions`), and the session has no capability whatever its uid (init empties the bounding set), so `chown` and `mknod` from the guest are refused by the guest kernel in every mode: the override is what the guest *sees*. The host side takes a `chown` or a device `mknod` into the override should one ever reach it. What carries no override is shown as the session's own identity, so a root session writes the shares it is given. `boxcar run --user UID[:GID]` chooses the identity (the invoking user's by default); a session from an image runs as the image's `User`, root when it names none, as a container does (#32). The host side is unchanged: the inner filesystem still runs as the invoking user, and the record carries the guest identity (`uid`, `gid`) as it does.
- **The record.** `fs.setattr` gains `override` (what the override now says) when a request changed it; `fs.mknod` records the device the guest asked for. Nothing else changes shape.
- **#32, images.** The unpacker writes each entry's owner and the setuid/setgid bits it could not keep into the override, and makes device nodes as above (no more `skipped` for them; `image.json` keeps the list for what is still skipped: sockets, FIFOs if any). The per-session copy copies the xattr with the file (`copy_tree` copies user xattrs already for the image's own; the override is one). `image.json` gains `ownership: "override"` so an older cache (unpacked without) is unpacked again on first use.
- **Without the xattr.** A host filesystem without user xattrs (`ENOTSUP` on the first write) fails the pull with a message naming the directory, as the cache does for other needs; a share given with `--rootfs` works as today when it carries no override.

## 2. Where in the code

- `crates/boxcar-fs/src/audit_fs.rs`: `Override` (parse and write the xattr), applied in each reply; the refusals and the record fields; `crates/boxcar-fs/src/share.rs` for the hidden xattr name.
- `crates/boxcar/src/oci/unpack.rs`: the override instead of skipping; `image.json`'s `ownership`; `crates/boxcar/src/oci/session.rs` copies it.
- `crates/boxcar-init/src/session.rs` and the VMM's config: the session's guest identity from the image (`User` parsed as Docker parses it: a name is looked up in the image's `/etc/passwd`).
- Docs: `docs/images.md`, `docs/policy.md` (what a writable rule means for an override), `docs/audit-events.md`, the design's amendments.

## 3. Tests

- Unit: the xattr's encoding round trip; AuditFs replies carry the override, and the session's identity where there is none (a test filesystem over a temp dir); the guest cannot see or set the xattr; a `chown` and a device `mknod` reaching AuditFs go into the override.
- Gated: with the override on, a host file given one shows its owner and stands for its device node, which the guest reads; what carries none is the session's own; `chown` and `mknod` are refused in every mode (#5). A session from an image whose files are root's sees them so and writes them as root (#32).

## 4. Out of scope

- Security xattrs (`security.capability` for file capabilities), which the guest kernel would honour: left `EPERM`.
- Mapping guest ids onto host ids (an id map): the host side stays one user.
