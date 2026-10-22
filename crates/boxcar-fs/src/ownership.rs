// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The ownership override: what the guest is to see of a file's owner,
//! its special mode bits and its device kind, kept in an xattr of boxcar's
//! own on the host file (`user.boxcar.stat`), since the VMM runs
//! unprivileged and cannot give the file to anyone. The decorator presents
//! it in every attribute reply and hides the xattr from the guest; the
//! unpacker writes it for an image's files. The text form is small and
//! plain: `uid=0 gid=0 mode=4755 dev=c:1:3`, each part optional.

use std::fmt::Write as _;

/// The xattr's name.
pub const XATTR: &str = "user.boxcar.stat";

/// The special mode bits the override may add: setuid, setgid, sticky.
const SPECIAL: u32 = libc::S_ISUID | libc::S_ISGID | libc::S_ISVTX;

/// A device node's kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DevKind {
    Char,
    Block,
}

/// What the guest is to see of a file's ownership and kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Override {
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    /// Special mode bits (setuid, setgid, sticky) added to the host's mode.
    pub special: u32,
    /// A device node this file stands for: its kind and `rdev`.
    pub dev: Option<(DevKind, u64)>,
}

impl Override {
    /// Whether there is anything to present.
    pub fn is_empty(&self) -> bool {
        *self == Override::default()
    }

    /// The xattr's text.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::new();
        if let Some(uid) = self.uid {
            let _ = write!(out, "uid={uid} ");
        }
        if let Some(gid) = self.gid {
            let _ = write!(out, "gid={gid} ");
        }
        if self.special != 0 {
            let _ = write!(out, "mode={:o} ", self.special & SPECIAL);
        }
        if let Some((kind, rdev)) = self.dev {
            let k = match kind {
                DevKind::Char => 'c',
                DevKind::Block => 'b',
            };
            let _ = write!(out, "dev={k}:{}:{} ", libc::major(rdev), libc::minor(rdev));
        }
        out.trim_end().as_bytes().to_vec()
    }

    /// The override an xattr's text holds; `None` for text that is not one
    /// (a part unknown or malformed is the whole's fault: nothing is
    /// presented rather than something half-read).
    pub fn parse(text: &[u8]) -> Option<Override> {
        let text = std::str::from_utf8(text).ok()?;
        let mut over = Override::default();
        for part in text.split_ascii_whitespace() {
            let (key, value) = part.split_once('=')?;
            match key {
                "uid" => over.uid = Some(value.parse().ok()?),
                "gid" => over.gid = Some(value.parse().ok()?),
                "mode" => {
                    let bits = u32::from_str_radix(value, 8).ok()?;
                    if bits & !SPECIAL != 0 {
                        return None;
                    }
                    over.special = bits;
                }
                "dev" => {
                    let mut it = value.split(':');
                    let kind = match it.next()? {
                        "c" => DevKind::Char,
                        "b" => DevKind::Block,
                        _ => return None,
                    };
                    let major: u32 = it.next()?.parse().ok()?;
                    let minor: u32 = it.next()?.parse().ok()?;
                    if it.next().is_some() {
                        return None;
                    }
                    over.dev = Some((kind, libc::makedev(major, minor)));
                }
                _ => return None,
            }
        }
        Some(over)
    }

    /// `st` as the guest is to see it: the override's owner and bits over
    /// the host's, a device node in place of the file that stands for it.
    pub fn apply(&self, st: &mut libc::stat64) {
        if let Some(uid) = self.uid {
            st.st_uid = uid;
        }
        if let Some(gid) = self.gid {
            st.st_gid = gid;
        }
        st.st_mode |= self.special & SPECIAL;
        if let Some((kind, rdev)) = self.dev {
            let fmt = match kind {
                DevKind::Char => libc::S_IFCHR,
                DevKind::Block => libc::S_IFBLK,
            };
            st.st_mode = (st.st_mode & !libc::S_IFMT) | fmt;
            st.st_rdev = rdev;
            st.st_size = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_form_round_trips() {
        let over = Override {
            uid: Some(0),
            gid: Some(5),
            special: libc::S_ISUID | libc::S_ISGID,
            dev: Some((DevKind::Char, libc::makedev(1, 3))),
        };
        let text = over.encode();
        assert_eq!(text, b"uid=0 gid=5 mode=6000 dev=c:1:3");
        assert_eq!(Override::parse(&text), Some(over));
        assert_eq!(Override::parse(b""), Some(Override::default()));
        assert_eq!(
            Override::parse(b"uid=1000"),
            Some(Override {
                uid: Some(1000),
                ..Override::default()
            })
        );
        assert!(Override::default().is_empty());
        assert_eq!(Override::default().encode(), b"");
    }

    #[test]
    fn malformed_text_presents_nothing() {
        for bad in [
            "uid=x",
            "gid=-1",
            "mode=777",
            "mode=z",
            "dev=x:1:2",
            "dev=c:1",
            "dev=c:1:2:3",
            "owner=0",
            "uid",
            "\u{ff}",
        ] {
            assert_eq!(Override::parse(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn the_override_is_laid_over_the_hosts_attributes() {
        // SAFETY: stat64 is plain data; zeroed is a valid value.
        let mut st: libc::stat64 = unsafe { std::mem::zeroed() };
        st.st_mode = libc::S_IFREG | 0o644;
        st.st_uid = 1000;
        st.st_gid = 1000;
        st.st_size = 42;
        Override {
            uid: Some(0),
            gid: None,
            special: libc::S_ISUID,
            dev: None,
        }
        .apply(&mut st);
        assert_eq!((st.st_uid, st.st_gid), (0, 1000));
        assert_eq!(st.st_mode, libc::S_IFREG | libc::S_ISUID | 0o644);
        assert_eq!(st.st_size, 42);
        Override {
            dev: Some((DevKind::Block, libc::makedev(8, 1))),
            ..Override::default()
        }
        .apply(&mut st);
        assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFBLK);
        assert_eq!(st.st_rdev, libc::makedev(8, 1));
        assert_eq!(st.st_size, 0);
    }
}
