// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Delegation of every `FileSystem` method to the wrapped filesystem.
//!
//! [`forward!`] is invoked inside `impl FileSystem for AuditFs<F>` with every
//! method of fuse-backend-rs 0.14.0's trait, in trait order, each marked
//! `forward` or `audited`:
//!
//! - `forward` expands to a method that calls the same method of
//!   `self.inner` with the request context squashed ([`squash`]).
//! - `audited` expands to nothing; `audit_fs.rs` writes that method out.
//!
//! The invocation must name all 45 methods in order or the macro does not
//! match, so a method cannot be left out by accident and fall back to the
//! trait's default (ENOSYS for most). A method marked `audited` that is not
//! written out would fall back the same way; the differential test catches
//! that. fuse-backend-rs is pinned exactly, so this list is its trait; a
//! version bump must extend it.

use fuse_backend_rs::api::filesystem::Context;

/// The context the wrapped filesystem sees: the guest's pid, root's
/// credentials.
///
/// `PassthroughFs` switches its thread's effective uid and gid to the
/// caller's (`setresuid`/`setresgid`) around creating operations whenever
/// they are not 0, and an unprivileged boxcar cannot. With the ids squashed
/// it never tries: files are created as the user boxcar runs as, and the
/// guest's own ids go only into the audit subject.
pub(crate) fn squash(ctx: &Context) -> Context {
    Context {
        uid: 0,
        gid: 0,
        ..*ctx
    }
}

/// See the module docs.
macro_rules! forward {
    (
        init: $init:ident,
        destroy: $destroy:ident,
        lookup: $lookup:ident,
        forget: $forget:ident,
        batch_forget: $batch_forget:ident,
        getattr: $getattr:ident,
        setattr: $setattr:ident,
        readlink: $readlink:ident,
        symlink: $symlink:ident,
        mknod: $mknod:ident,
        mkdir: $mkdir:ident,
        unlink: $unlink:ident,
        rmdir: $rmdir:ident,
        rename: $rename:ident,
        link: $link:ident,
        open: $open:ident,
        create: $create:ident,
        read: $read:ident,
        write: $write:ident,
        flush: $flush:ident,
        fsync: $fsync:ident,
        fallocate: $fallocate:ident,
        release: $release:ident,
        statfs: $statfs:ident,
        setxattr: $setxattr:ident,
        getxattr: $getxattr:ident,
        listxattr: $listxattr:ident,
        removexattr: $removexattr:ident,
        opendir: $opendir:ident,
        readdir: $readdir:ident,
        readdirplus: $readdirplus:ident,
        fsyncdir: $fsyncdir:ident,
        releasedir: $releasedir:ident,
        setupmapping: $setupmapping:ident,
        removemapping: $removemapping:ident,
        access: $access:ident,
        lseek: $lseek:ident,
        getlk: $getlk:ident,
        setlk: $setlk:ident,
        setlkw: $setlkw:ident,
        ioctl: $ioctl:ident,
        bmap: $bmap:ident,
        poll: $poll:ident,
        notify_reply: $notify_reply:ident,
        id_remap: $id_remap:ident $(,)?
    ) => {
        forward!(@init $init);
        forward!(@destroy $destroy);
        forward!(@lookup $lookup);
        forward!(@forget $forget);
        forward!(@batch_forget $batch_forget);
        forward!(@getattr $getattr);
        forward!(@setattr $setattr);
        forward!(@readlink $readlink);
        forward!(@symlink $symlink);
        forward!(@mknod $mknod);
        forward!(@mkdir $mkdir);
        forward!(@unlink $unlink);
        forward!(@rmdir $rmdir);
        forward!(@rename $rename);
        forward!(@link $link);
        forward!(@open $open);
        forward!(@create $create);
        forward!(@read $read);
        forward!(@write $write);
        forward!(@flush $flush);
        forward!(@fsync $fsync);
        forward!(@fallocate $fallocate);
        forward!(@release $release);
        forward!(@statfs $statfs);
        forward!(@setxattr $setxattr);
        forward!(@getxattr $getxattr);
        forward!(@listxattr $listxattr);
        forward!(@removexattr $removexattr);
        forward!(@opendir $opendir);
        forward!(@readdir $readdir);
        forward!(@readdirplus $readdirplus);
        forward!(@fsyncdir $fsyncdir);
        forward!(@releasedir $releasedir);
        forward!(@setupmapping $setupmapping);
        forward!(@removemapping $removemapping);
        forward!(@access $access);
        forward!(@lseek $lseek);
        forward!(@getlk $getlk);
        forward!(@setlk $setlk);
        forward!(@setlkw $setlkw);
        forward!(@ioctl $ioctl);
        forward!(@bmap $bmap);
        forward!(@poll $poll);
        forward!(@notify_reply $notify_reply);
        forward!(@id_remap $id_remap);
    };

    // Written out in audit_fs.rs.
    (@$method:ident audited) => {};

    (@init forward) => {
        fn init(
            &self,
            capable: ::fuse_backend_rs::api::filesystem::FsOptions,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::FsOptions> {
            self.inner.init(capable)
        }
    };
    (@destroy forward) => {
        fn destroy(&self) {
            self.inner.destroy()
        }
    };
    (@lookup forward) => {
        fn lookup(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            parent: u64,
            name: &::std::ffi::CStr,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::Entry> {
            self.inner.lookup(&$crate::forward::squash(ctx), parent, name)
        }
    };
    (@forget forward) => {
        fn forget(&self, ctx: &::fuse_backend_rs::api::filesystem::Context, inode: u64, count: u64) {
            self.inner.forget(&$crate::forward::squash(ctx), inode, count)
        }
    };
    (@batch_forget forward) => {
        fn batch_forget(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            requests: ::std::vec::Vec<(u64, u64)>,
        ) {
            self.inner.batch_forget(&$crate::forward::squash(ctx), requests)
        }
    };
    (@getattr forward) => {
        fn getattr(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: ::std::option::Option<u64>,
        ) -> ::std::io::Result<(::fuse_backend_rs::abi::fuse_abi::stat64, ::std::time::Duration)> {
            self.inner.getattr(&$crate::forward::squash(ctx), inode, handle)
        }
    };
    (@setattr forward) => {
        fn setattr(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            attr: ::fuse_backend_rs::abi::fuse_abi::stat64,
            handle: ::std::option::Option<u64>,
            valid: ::fuse_backend_rs::api::filesystem::SetattrValid,
        ) -> ::std::io::Result<(::fuse_backend_rs::abi::fuse_abi::stat64, ::std::time::Duration)> {
            self.inner.setattr(&$crate::forward::squash(ctx), inode, attr, handle, valid)
        }
    };
    (@readlink forward) => {
        fn readlink(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
        ) -> ::std::io::Result<::std::vec::Vec<u8>> {
            self.inner.readlink(&$crate::forward::squash(ctx), inode)
        }
    };
    (@symlink forward) => {
        fn symlink(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            linkname: &::std::ffi::CStr,
            parent: u64,
            name: &::std::ffi::CStr,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::Entry> {
            self.inner.symlink(&$crate::forward::squash(ctx), linkname, parent, name)
        }
    };
    (@mknod forward) => {
        fn mknod(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            name: &::std::ffi::CStr,
            mode: u32,
            rdev: u32,
            umask: u32,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::Entry> {
            self.inner.mknod(&$crate::forward::squash(ctx), inode, name, mode, rdev, umask)
        }
    };
    (@mkdir forward) => {
        fn mkdir(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            parent: u64,
            name: &::std::ffi::CStr,
            mode: u32,
            umask: u32,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::Entry> {
            self.inner.mkdir(&$crate::forward::squash(ctx), parent, name, mode, umask)
        }
    };
    (@unlink forward) => {
        fn unlink(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            parent: u64,
            name: &::std::ffi::CStr,
        ) -> ::std::io::Result<()> {
            self.inner.unlink(&$crate::forward::squash(ctx), parent, name)
        }
    };
    (@rmdir forward) => {
        fn rmdir(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            parent: u64,
            name: &::std::ffi::CStr,
        ) -> ::std::io::Result<()> {
            self.inner.rmdir(&$crate::forward::squash(ctx), parent, name)
        }
    };
    (@rename forward) => {
        fn rename(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            olddir: u64,
            oldname: &::std::ffi::CStr,
            newdir: u64,
            newname: &::std::ffi::CStr,
            flags: u32,
        ) -> ::std::io::Result<()> {
            self.inner.rename(&$crate::forward::squash(ctx), olddir, oldname, newdir, newname, flags)
        }
    };
    (@link forward) => {
        fn link(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            newparent: u64,
            newname: &::std::ffi::CStr,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::Entry> {
            self.inner.link(&$crate::forward::squash(ctx), inode, newparent, newname)
        }
    };
    (@open forward) => {
        fn open(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            flags: u32,
            fuse_flags: u32,
        ) -> ::std::io::Result<(
            ::std::option::Option<u64>,
            ::fuse_backend_rs::api::filesystem::OpenOptions,
            ::std::option::Option<u32>,
        )> {
            self.inner.open(&$crate::forward::squash(ctx), inode, flags, fuse_flags)
        }
    };
    (@create forward) => {
        fn create(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            parent: u64,
            name: &::std::ffi::CStr,
            args: ::fuse_backend_rs::abi::fuse_abi::CreateIn,
        ) -> ::std::io::Result<(
            ::fuse_backend_rs::api::filesystem::Entry,
            ::std::option::Option<u64>,
            ::fuse_backend_rs::api::filesystem::OpenOptions,
            ::std::option::Option<u32>,
        )> {
            self.inner.create(&$crate::forward::squash(ctx), parent, name, args)
        }
    };
    (@read forward) => {
        fn read(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            w: &mut dyn ::fuse_backend_rs::api::filesystem::ZeroCopyWriter,
            size: u32,
            offset: u64,
            lock_owner: ::std::option::Option<u64>,
            flags: u32,
        ) -> ::std::io::Result<usize> {
            self.inner.read(
                &$crate::forward::squash(ctx),
                inode,
                handle,
                w,
                size,
                offset,
                lock_owner,
                flags,
            )
        }
    };
    (@write forward) => {
        fn write(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            r: &mut dyn ::fuse_backend_rs::api::filesystem::ZeroCopyReader,
            size: u32,
            offset: u64,
            lock_owner: ::std::option::Option<u64>,
            delayed_write: bool,
            flags: u32,
            fuse_flags: u32,
        ) -> ::std::io::Result<usize> {
            self.inner.write(
                &$crate::forward::squash(ctx),
                inode,
                handle,
                r,
                size,
                offset,
                lock_owner,
                delayed_write,
                flags,
                fuse_flags,
            )
        }
    };
    (@flush forward) => {
        fn flush(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            lock_owner: u64,
        ) -> ::std::io::Result<()> {
            self.inner.flush(&$crate::forward::squash(ctx), inode, handle, lock_owner)
        }
    };
    (@fsync forward) => {
        fn fsync(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            datasync: bool,
            handle: u64,
        ) -> ::std::io::Result<()> {
            self.inner.fsync(&$crate::forward::squash(ctx), inode, datasync, handle)
        }
    };
    (@fallocate forward) => {
        fn fallocate(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            mode: u32,
            offset: u64,
            length: u64,
        ) -> ::std::io::Result<()> {
            self.inner.fallocate(&$crate::forward::squash(ctx), inode, handle, mode, offset, length)
        }
    };
    (@release forward) => {
        fn release(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            flags: u32,
            handle: u64,
            flush: bool,
            flock_release: bool,
            lock_owner: ::std::option::Option<u64>,
        ) -> ::std::io::Result<()> {
            self.inner.release(
                &$crate::forward::squash(ctx),
                inode,
                flags,
                handle,
                flush,
                flock_release,
                lock_owner,
            )
        }
    };
    (@statfs forward) => {
        fn statfs(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
        ) -> ::std::io::Result<::fuse_backend_rs::abi::fuse_abi::statvfs64> {
            self.inner.statfs(&$crate::forward::squash(ctx), inode)
        }
    };
    (@setxattr forward) => {
        fn setxattr(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            name: &::std::ffi::CStr,
            value: &[u8],
            flags: u32,
        ) -> ::std::io::Result<()> {
            self.inner.setxattr(&$crate::forward::squash(ctx), inode, name, value, flags)
        }
    };
    (@getxattr forward) => {
        fn getxattr(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            name: &::std::ffi::CStr,
            size: u32,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::GetxattrReply> {
            self.inner.getxattr(&$crate::forward::squash(ctx), inode, name, size)
        }
    };
    (@listxattr forward) => {
        fn listxattr(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            size: u32,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::ListxattrReply> {
            self.inner.listxattr(&$crate::forward::squash(ctx), inode, size)
        }
    };
    (@removexattr forward) => {
        fn removexattr(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            name: &::std::ffi::CStr,
        ) -> ::std::io::Result<()> {
            self.inner.removexattr(&$crate::forward::squash(ctx), inode, name)
        }
    };
    (@opendir forward) => {
        fn opendir(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            flags: u32,
        ) -> ::std::io::Result<(
            ::std::option::Option<u64>,
            ::fuse_backend_rs::api::filesystem::OpenOptions,
        )> {
            self.inner.opendir(&$crate::forward::squash(ctx), inode, flags)
        }
    };
    (@readdir forward) => {
        fn readdir(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            size: u32,
            offset: u64,
            add_entry: &mut dyn FnMut(
                ::fuse_backend_rs::api::filesystem::DirEntry,
            ) -> ::std::io::Result<usize>,
        ) -> ::std::io::Result<()> {
            self.inner.readdir(&$crate::forward::squash(ctx), inode, handle, size, offset, add_entry)
        }
    };
    (@readdirplus forward) => {
        fn readdirplus(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            size: u32,
            offset: u64,
            add_entry: &mut dyn FnMut(
                ::fuse_backend_rs::api::filesystem::DirEntry,
                ::fuse_backend_rs::api::filesystem::Entry,
            ) -> ::std::io::Result<usize>,
        ) -> ::std::io::Result<()> {
            self.inner
                .readdirplus(&$crate::forward::squash(ctx), inode, handle, size, offset, add_entry)
        }
    };
    (@fsyncdir forward) => {
        fn fsyncdir(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            datasync: bool,
            handle: u64,
        ) -> ::std::io::Result<()> {
            self.inner.fsyncdir(&$crate::forward::squash(ctx), inode, datasync, handle)
        }
    };
    (@releasedir forward) => {
        fn releasedir(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            flags: u32,
            handle: u64,
        ) -> ::std::io::Result<()> {
            self.inner.releasedir(&$crate::forward::squash(ctx), inode, flags, handle)
        }
    };
    (@setupmapping forward) => {
        fn setupmapping(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            foffset: u64,
            len: u64,
            flags: u64,
            moffset: u64,
            vu_req: &mut dyn ::fuse_backend_rs::transport::FsCacheReqHandler,
        ) -> ::std::io::Result<()> {
            self.inner.setupmapping(
                &$crate::forward::squash(ctx),
                inode,
                handle,
                foffset,
                len,
                flags,
                moffset,
                vu_req,
            )
        }
    };
    (@removemapping forward) => {
        fn removemapping(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            requests: ::std::vec::Vec<::fuse_backend_rs::abi::virtio_fs::RemovemappingOne>,
            vu_req: &mut dyn ::fuse_backend_rs::transport::FsCacheReqHandler,
        ) -> ::std::io::Result<()> {
            self.inner.removemapping(&$crate::forward::squash(ctx), inode, requests, vu_req)
        }
    };
    (@access forward) => {
        fn access(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            mask: u32,
        ) -> ::std::io::Result<()> {
            self.inner.access(&$crate::forward::squash(ctx), inode, mask)
        }
    };
    (@lseek forward) => {
        fn lseek(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            offset: u64,
            whence: u32,
        ) -> ::std::io::Result<u64> {
            self.inner.lseek(&$crate::forward::squash(ctx), inode, handle, offset, whence)
        }
    };
    (@getlk forward) => {
        fn getlk(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            owner: u64,
            lock: ::fuse_backend_rs::api::filesystem::FileLock,
            flags: u32,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::FileLock> {
            self.inner.getlk(&$crate::forward::squash(ctx), inode, handle, owner, lock, flags)
        }
    };
    (@setlk forward) => {
        fn setlk(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            owner: u64,
            lock: ::fuse_backend_rs::api::filesystem::FileLock,
            flags: u32,
        ) -> ::std::io::Result<()> {
            self.inner.setlk(&$crate::forward::squash(ctx), inode, handle, owner, lock, flags)
        }
    };
    (@setlkw forward) => {
        fn setlkw(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            owner: u64,
            lock: ::fuse_backend_rs::api::filesystem::FileLock,
            flags: u32,
        ) -> ::std::io::Result<()> {
            self.inner.setlkw(&$crate::forward::squash(ctx), inode, handle, owner, lock, flags)
        }
    };
    (@ioctl forward) => {
        fn ioctl(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            flags: u32,
            cmd: u32,
            data: ::fuse_backend_rs::api::filesystem::IoctlData,
            out_size: u32,
        ) -> ::std::io::Result<::fuse_backend_rs::api::filesystem::IoctlData<'_>> {
            self.inner.ioctl(&$crate::forward::squash(ctx), inode, handle, flags, cmd, data, out_size)
        }
    };
    (@bmap forward) => {
        fn bmap(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            block: u64,
            blocksize: u32,
        ) -> ::std::io::Result<u64> {
            self.inner.bmap(&$crate::forward::squash(ctx), inode, block, blocksize)
        }
    };
    (@poll forward) => {
        fn poll(
            &self,
            ctx: &::fuse_backend_rs::api::filesystem::Context,
            inode: u64,
            handle: u64,
            khandle: u64,
            flags: u32,
            events: u32,
        ) -> ::std::io::Result<u32> {
            self.inner.poll(&$crate::forward::squash(ctx), inode, handle, khandle, flags, events)
        }
    };
    (@notify_reply forward) => {
        fn notify_reply(&self) -> ::std::io::Result<()> {
            self.inner.notify_reply()
        }
    };
    // The server calls this on every request before dispatching it, to let
    // a filesystem map the guest's ids. The guest's ids are what the audit
    // records, so `ctx` is left as it is; the wrapped filesystem sees the
    // squashed ids, as everywhere else, and may still refuse the request.
    (@id_remap forward) => {
        fn id_remap(&self, ctx: &mut ::fuse_backend_rs::api::filesystem::Context) -> ::std::io::Result<()> {
            let mut squashed = $crate::forward::squash(ctx);
            self.inner.id_remap(&mut squashed)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn squash_keeps_the_pid_and_drops_the_ids() {
        let ctx = Context {
            uid: 1000,
            gid: 1000,
            pid: 42,
        };
        let squashed = squash(&ctx);
        assert_eq!((squashed.uid, squashed.gid, squashed.pid), (0, 0, 42));
    }
}
