// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The filesystem beneath `AuditFs` on a share: the passthrough over the
//! share's directory, or, for an image session's root, the overlay of the
//! session's directory over the cached image. One type, so the device and
//! its server have one shape; every method goes to whichever it holds.

use std::ffi::CStr;
use std::io;
use std::time::Duration;

use fuse_backend_rs::abi::fuse_abi::{stat64, statvfs64, CreateIn};
use fuse_backend_rs::abi::virtio_fs::RemovemappingOne;
use fuse_backend_rs::api::filesystem::{
    Context, DirEntry, Entry, FileLock, FileSystem, FsOptions, GetxattrReply, IoctlData,
    ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use fuse_backend_rs::passthrough::PassthroughFs;
use fuse_backend_rs::transport::FsCacheReqHandler;

use crate::overlay::OverlayFs;

/// What serves a share beneath the audit.
pub enum Inner {
    Passthrough(Box<PassthroughFs<()>>),
    Overlay(Box<OverlayFs<PassthroughFs<()>, PassthroughFs<()>>>),
}

macro_rules! each {
    ($self:ident, $fs:ident => $e:expr) => {
        match $self {
            Inner::Passthrough($fs) => $e,
            Inner::Overlay($fs) => $e,
        }
    };
}

impl FileSystem for Inner {
    type Inode = u64;
    type Handle = u64;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        each!(self, fs => fs.init(capable))
    }

    fn destroy(&self) {
        each!(self, fs => fs.destroy())
    }

    fn lookup(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        each!(self, fs => fs.lookup(ctx, parent, name))
    }

    fn forget(&self, ctx: &Context, inode: u64, count: u64) {
        each!(self, fs => fs.forget(ctx, inode, count))
    }

    fn batch_forget(&self, ctx: &Context, requests: Vec<(u64, u64)>) {
        each!(self, fs => fs.batch_forget(ctx, requests))
    }

    fn getattr(
        &self,
        ctx: &Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        each!(self, fs => fs.getattr(ctx, inode, handle))
    }

    fn setattr(
        &self,
        ctx: &Context,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        each!(self, fs => fs.setattr(ctx, inode, attr, handle, valid))
    }

    fn readlink(&self, ctx: &Context, inode: u64) -> io::Result<Vec<u8>> {
        each!(self, fs => fs.readlink(ctx, inode))
    }

    fn symlink(
        &self,
        ctx: &Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
    ) -> io::Result<Entry> {
        each!(self, fs => fs.symlink(ctx, linkname, parent, name))
    }

    fn mknod(
        &self,
        ctx: &Context,
        inode: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        each!(self, fs => fs.mknod(ctx, inode, name, mode, rdev, umask))
    }

    fn mkdir(
        &self,
        ctx: &Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        each!(self, fs => fs.mkdir(ctx, parent, name, mode, umask))
    }

    fn unlink(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
        each!(self, fs => fs.unlink(ctx, parent, name))
    }

    fn rmdir(&self, ctx: &Context, parent: u64, name: &CStr) -> io::Result<()> {
        each!(self, fs => fs.rmdir(ctx, parent, name))
    }

    fn rename(
        &self,
        ctx: &Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        each!(self, fs => fs.rename(ctx, olddir, oldname, newdir, newname, flags))
    }

    fn link(&self, ctx: &Context, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        each!(self, fs => fs.link(ctx, inode, newparent, newname))
    }

    fn open(
        &self,
        ctx: &Context,
        inode: u64,
        flags: u32,
        fuse_flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions, Option<u32>)> {
        each!(self, fs => fs.open(ctx, inode, flags, fuse_flags))
    }

    fn create(
        &self,
        ctx: &Context,
        parent: u64,
        name: &CStr,
        args: CreateIn,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions, Option<u32>)> {
        each!(self, fs => fs.create(ctx, parent, name, args))
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        each!(self, fs => fs.read(ctx, inode, handle, w, size, offset, lock_owner, flags))
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        flags: u32,
        fuse_flags: u32,
    ) -> io::Result<usize> {
        each!(self, fs => fs.write(
            ctx,
            inode,
            handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            flags,
            fuse_flags
        ))
    }

    fn flush(&self, ctx: &Context, inode: u64, handle: u64, lock_owner: u64) -> io::Result<()> {
        each!(self, fs => fs.flush(ctx, inode, handle, lock_owner))
    }

    fn fsync(&self, ctx: &Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        each!(self, fs => fs.fsync(ctx, inode, datasync, handle))
    }

    fn fallocate(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        each!(self, fs => fs.fallocate(ctx, inode, handle, mode, offset, length))
    }

    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        ctx: &Context,
        inode: u64,
        flags: u32,
        handle: u64,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        each!(self, fs => fs.release(ctx, inode, flags, handle, flush, flock_release, lock_owner))
    }

    fn statfs(&self, ctx: &Context, inode: u64) -> io::Result<statvfs64> {
        each!(self, fs => fs.statfs(ctx, inode))
    }

    fn setxattr(
        &self,
        ctx: &Context,
        inode: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        each!(self, fs => fs.setxattr(ctx, inode, name, value, flags))
    }

    fn getxattr(
        &self,
        ctx: &Context,
        inode: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        each!(self, fs => fs.getxattr(ctx, inode, name, size))
    }

    fn listxattr(&self, ctx: &Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
        each!(self, fs => fs.listxattr(ctx, inode, size))
    }

    fn removexattr(&self, ctx: &Context, inode: u64, name: &CStr) -> io::Result<()> {
        each!(self, fs => fs.removexattr(ctx, inode, name))
    }

    fn opendir(
        &self,
        ctx: &Context,
        inode: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        each!(self, fs => fs.opendir(ctx, inode, flags))
    }

    fn readdir(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry) -> io::Result<usize>,
    ) -> io::Result<()> {
        each!(self, fs => fs.readdir(ctx, inode, handle, size, offset, add_entry))
    }

    fn readdirplus(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut dyn FnMut(DirEntry, Entry) -> io::Result<usize>,
    ) -> io::Result<()> {
        each!(self, fs => fs.readdirplus(ctx, inode, handle, size, offset, add_entry))
    }

    fn fsyncdir(&self, ctx: &Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        each!(self, fs => fs.fsyncdir(ctx, inode, datasync, handle))
    }

    fn releasedir(&self, ctx: &Context, inode: u64, flags: u32, handle: u64) -> io::Result<()> {
        each!(self, fs => fs.releasedir(ctx, inode, flags, handle))
    }

    #[allow(clippy::too_many_arguments)]
    fn setupmapping(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        vu_req: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        each!(self, fs => fs.setupmapping(ctx, inode, handle, foffset, len, flags, moffset, vu_req))
    }

    fn removemapping(
        &self,
        ctx: &Context,
        inode: u64,
        requests: Vec<RemovemappingOne>,
        vu_req: &mut dyn FsCacheReqHandler,
    ) -> io::Result<()> {
        each!(self, fs => fs.removemapping(ctx, inode, requests, vu_req))
    }

    fn access(&self, ctx: &Context, inode: u64, mask: u32) -> io::Result<()> {
        each!(self, fs => fs.access(ctx, inode, mask))
    }

    fn lseek(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        each!(self, fs => fs.lseek(ctx, inode, handle, offset, whence))
    }

    fn getlk(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        owner: u64,
        lock: FileLock,
        flags: u32,
    ) -> io::Result<FileLock> {
        each!(self, fs => fs.getlk(ctx, inode, handle, owner, lock, flags))
    }

    fn setlk(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        owner: u64,
        lock: FileLock,
        flags: u32,
    ) -> io::Result<()> {
        each!(self, fs => fs.setlk(ctx, inode, handle, owner, lock, flags))
    }

    fn setlkw(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        owner: u64,
        lock: FileLock,
        flags: u32,
    ) -> io::Result<()> {
        each!(self, fs => fs.setlkw(ctx, inode, handle, owner, lock, flags))
    }

    #[allow(clippy::too_many_arguments)]
    fn ioctl(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        flags: u32,
        cmd: u32,
        data: IoctlData,
        out_size: u32,
    ) -> io::Result<IoctlData<'_>> {
        each!(self, fs => fs.ioctl(ctx, inode, handle, flags, cmd, data, out_size))
    }

    fn bmap(&self, ctx: &Context, inode: u64, block: u64, blocksize: u32) -> io::Result<u64> {
        each!(self, fs => fs.bmap(ctx, inode, block, blocksize))
    }

    fn poll(
        &self,
        ctx: &Context,
        inode: u64,
        handle: u64,
        khandle: u64,
        flags: u32,
        events: u32,
    ) -> io::Result<u32> {
        each!(self, fs => fs.poll(ctx, inode, handle, khandle, flags, events))
    }

    fn notify_reply(&self) -> io::Result<()> {
        each!(self, fs => fs.notify_reply())
    }

    fn id_remap(&self, ctx: &mut Context) -> io::Result<()> {
        each!(self, fs => fs.id_remap(ctx))
    }
}
