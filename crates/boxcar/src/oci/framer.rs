// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The tar stream reader: headers parsed and checked one at a time,
//! extension records (PAX, GNU long names) bounded and applied to the
//! entry that follows, sparse entries and unknown kinds refused, every
//! header counted against the image's entry budget. The `tar` crate's
//! own reader buffers extension records whole and frames a PAX-sized
//! entry by its header's size, so this one does the framing itself over
//! `tar::Header` and `tar::PaxExtensions`.

use std::cell::Cell;
use std::io::{self, Read};

/// The most bytes an extension record (PAX, GNU long name or link) may
/// hold.
pub const MAX_EXTENSION: u64 = 64 * 1024;

/// What an entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Hardlink,
    Symlink,
    Dir,
    CharDevice,
    BlockDevice,
    Fifo,
}

/// One entry, as the archive names it: the path and link target are raw
/// bytes, unnormalised.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub kind: Kind,
    pub path: Vec<u8>,
    /// A symlink's target or a hardlink's path.
    pub link: Vec<u8>,
    pub mode: u32,
    pub size: u64,
}

/// Reads entries from a tar stream.
pub struct Framer<'a, R: Read> {
    input: R,
    entries_left: &'a Cell<u64>,
    /// Headers read so far, so an error can say which entry.
    seen: u64,
    /// Data of the current entry not yet read, and its padding.
    remaining: u64,
    padding: u64,
    ended: bool,
}

/// What extension records set for the entry that follows them.
#[derive(Default)]
struct Overrides {
    size: Option<u64>,
    path: Option<Vec<u8>>,
    link: Option<Vec<u8>>,
}

/// The current entry's data: exactly its size, an early end an error.
pub struct Data<'f, 'a, R: Read> {
    framer: &'f mut Framer<'a, R>,
}

impl<R: Read> Read for Data<'_, '_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.framer.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = buf
            .len()
            .min(self.framer.remaining.min(usize::MAX as u64) as usize);
        match self.framer.input.read(&mut buf[..want])? {
            0 => Err(truncated("inside an entry's data")),
            n => {
                self.framer.remaining -= n as u64;
                Ok(n)
            }
        }
    }
}

fn truncated(where_: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("the archive ends {where_}"),
    )
}

fn malformed(what: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what.into())
}

impl<'a, R: Read> Framer<'a, R> {
    /// A framer over `input`, counting every header against
    /// `entries_left`.
    pub fn new(input: R, entries_left: &'a Cell<u64>) -> Framer<'a, R> {
        Framer {
            input,
            entries_left,
            seen: 0,
            remaining: 0,
            padding: 0,
            ended: false,
        }
    }

    /// The next ordinary entry, extension records applied, or `None` at
    /// the end-of-archive blocks. Whatever of the previous entry's data
    /// was not read is skipped first. An error says which entry by
    /// number and nothing the archive says.
    pub fn next(&mut self) -> io::Result<Option<Entry>> {
        self.next_entry().map_err(|error| {
            if error.kind() == io::ErrorKind::InvalidData {
                malformed(format!("entry {}: {error}", self.seen))
            } else {
                error
            }
        })
    }

    fn next_entry(&mut self) -> io::Result<Option<Entry>> {
        if self.ended {
            return Ok(None);
        }
        self.skip(self.remaining, "inside an entry's data")?;
        self.skip(self.padding, "inside an entry's padding")?;
        self.remaining = 0;
        self.padding = 0;
        let mut over = Overrides::default();
        loop {
            let mut block = [0u8; 512];
            self.read_block(&mut block, "inside a header")?;
            if block.iter().all(|b| *b == 0) {
                // The end: a second zero block, or nothing more.
                let mut second = [0u8; 512];
                let got = self.read_some(&mut second)?;
                if got != 0 && (got < 512 || second.iter().any(|b| *b != 0)) {
                    return Err(malformed(if got < 512 {
                        "the archive ends inside its end blocks".to_owned()
                    } else {
                        "a zero block inside the archive".to_owned()
                    }));
                }
                self.ended = true;
                return Ok(None);
            }
            self.count_header()?;
            let header = tar::Header::from_byte_slice(&block);
            check_checksum(header, &block)?;
            let size = header
                .entry_size()
                .map_err(|_| malformed("a header's size does not parse"))?;
            let kind = match header.entry_type().as_byte() {
                b'x' => {
                    let record = self.read_extension(size)?;
                    parse_pax(&record, &mut over, true)?;
                    continue;
                }
                b'g' => {
                    let record = self.read_extension(size)?;
                    parse_pax(&record, &mut Overrides::default(), false)?;
                    continue;
                }
                b'L' => {
                    over.path = Some(nul_terminated(self.read_extension(size)?));
                    continue;
                }
                b'K' => {
                    over.link = Some(nul_terminated(self.read_extension(size)?));
                    continue;
                }
                b'S' => return Err(malformed("sparse entries are not supported")),
                b'0' | 0 | b'7' => Kind::File,
                b'1' => Kind::Hardlink,
                b'2' => Kind::Symlink,
                b'3' => Kind::CharDevice,
                b'4' => Kind::BlockDevice,
                b'5' => Kind::Dir,
                b'6' => Kind::Fifo,
                _ => return Err(malformed("an entry of a kind that is not supported")),
            };
            let size = over.size.unwrap_or(size);
            let mode = header
                .mode()
                .map_err(|_| malformed("a header's mode does not parse"))?
                & 0o7777;
            let path = over
                .path
                .take()
                .unwrap_or_else(|| header.path_bytes().into_owned());
            let link = over
                .link
                .take()
                .or_else(|| header.link_name_bytes().map(|l| l.into_owned()))
                .unwrap_or_default();
            self.remaining = size;
            self.padding = (512 - size % 512) % 512;
            return Ok(Some(Entry {
                kind,
                path,
                link,
                mode,
                size,
            }));
        }
    }

    /// The current entry's data still to read, exactly its size.
    pub fn data(&mut self) -> Data<'_, 'a, R> {
        Data { framer: self }
    }

    fn count_header(&mut self) -> io::Result<()> {
        match self.entries_left.get().checked_sub(1) {
            Some(left) => {
                self.entries_left.set(left);
                self.seen += 1;
                Ok(())
            }
            None => Err(io::Error::other(
                "more entries than the image's budget allows",
            )),
        }
    }

    /// Reads exactly `block.len()` bytes, or the truncation error.
    fn read_block(&mut self, block: &mut [u8], where_: &str) -> io::Result<()> {
        if self.read_some(block)? != block.len() {
            return Err(truncated(where_));
        }
        Ok(())
    }

    /// Reads as much of `buf` as the stream has.
    fn read_some(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut got = 0;
        while got < buf.len() {
            match self.input.read(&mut buf[got..])? {
                0 => break,
                n => got += n,
            }
        }
        Ok(got)
    }

    /// Reads and drops `count` bytes.
    fn skip(&mut self, count: u64, where_: &str) -> io::Result<()> {
        if io::copy(&mut (&mut self.input).take(count), &mut io::sink())? != count {
            return Err(truncated(where_));
        }
        Ok(())
    }

    /// An extension record of `size` bytes, with its padding consumed.
    fn read_extension(&mut self, size: u64) -> io::Result<Vec<u8>> {
        if size > MAX_EXTENSION {
            return Err(malformed("an extension record larger than 64 KiB"));
        }
        let mut record = vec![0u8; size as usize];
        self.read_block(&mut record, "inside an extension record")?;
        self.skip((512 - size % 512) % 512, "inside an extension record")?;
        Ok(record)
    }

    /// After the end of the archive: reads the stream to its end, so that
    /// what follows the archive is counted and checked too.
    pub fn finish(mut self) -> io::Result<()> {
        if !self.ended {
            return Err(io::Error::other("the archive has not ended"));
        }
        io::copy(&mut self.input, &mut io::sink())?;
        Ok(())
    }
}

/// The header's stored checksum must be the sum of its bytes with the
/// checksum field as spaces, unsigned or (old tars) signed.
fn check_checksum(header: &tar::Header, block: &[u8; 512]) -> io::Result<()> {
    let stored = header
        .cksum()
        .map_err(|_| malformed("a header's checksum does not parse"))?;
    let (mut unsigned, mut signed) = (0u32, 0i64);
    for (at, byte) in block.iter().enumerate() {
        let byte = if (148..156).contains(&at) {
            b' '
        } else {
            *byte
        };
        unsigned += u32::from(byte);
        signed += i64::from(byte as i8);
    }
    if u64::from(stored) != u64::from(unsigned) && i64::from(stored) != signed {
        return Err(malformed("a header's checksum does not match its bytes"));
    }
    Ok(())
}

/// PAX records into `over`. A global header (`overrides` false) may not
/// set what names or sizes an entry; a sparse key fails either.
fn parse_pax(record: &[u8], over: &mut Overrides, overrides: bool) -> io::Result<()> {
    for extension in tar::PaxExtensions::new(record) {
        let extension = extension.map_err(|_| malformed("a PAX record does not parse"))?;
        let key = extension
            .key()
            .map_err(|_| malformed("a PAX key is not UTF-8"))?;
        if key.starts_with("GNU.sparse.") {
            return Err(malformed("sparse entries are not supported"));
        }
        let names = matches!(key, "size" | "path" | "linkpath");
        if names && !overrides {
            return Err(malformed("a global PAX header sets what is an entry's own"));
        }
        match key {
            "size" => {
                let text = extension
                    .value()
                    .map_err(|_| malformed("a PAX size is not UTF-8"))?;
                over.size = Some(
                    text.parse()
                        .map_err(|_| malformed("a PAX size does not parse"))?,
                );
            }
            "path" => over.path = Some(extension.value_bytes().to_vec()),
            "linkpath" => over.link = Some(extension.value_bytes().to_vec()),
            _ => {}
        }
    }
    Ok(())
}

/// `record` up to its first NUL.
fn nul_terminated(mut record: Vec<u8>) -> Vec<u8> {
    if let Some(end) = record.iter().position(|b| *b == 0) {
        record.truncate(end);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use tar::{EntryType, Header};

    /// A header for `path` of `kind` with `size` bytes, checksummed.
    fn header(kind: EntryType, path: &str, size: u64) -> Header {
        let mut h = Header::new_ustar();
        h.set_entry_type(kind);
        h.set_path(path).unwrap();
        h.set_size(size);
        h.set_mode(0o644);
        h.set_cksum();
        h
    }

    /// `data` padded to 512.
    fn padded(data: &[u8]) -> Vec<u8> {
        let mut out = data.to_vec();
        out.resize(data.len().next_multiple_of(512), 0);
        out
    }

    /// A file entry: header and padded data.
    fn file(path: &str, data: &[u8]) -> Vec<u8> {
        let mut out = header(EntryType::Regular, path, data.len() as u64)
            .as_bytes()
            .to_vec();
        out.extend(padded(data));
        out
    }

    /// One PAX record, `len key=value\n` with `len` counting itself.
    fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
        let body_len = 1 + key.len() + 1 + value.len() + 1;
        let mut len = body_len + 1;
        while len.to_string().len() + body_len != len {
            len += 1;
        }
        let mut out = format!("{len} {key}=").into_bytes();
        out.extend_from_slice(value);
        out.push(b'\n');
        out
    }

    /// An extension entry of `kind` holding `data`.
    fn extension(kind: EntryType, data: &[u8]) -> Vec<u8> {
        let mut out = header(kind, "././@PaxHeader", data.len() as u64)
            .as_bytes()
            .to_vec();
        out.extend(padded(data));
        out
    }

    fn end() -> Vec<u8> {
        vec![0u8; 1024]
    }

    /// Every entry of `archive`, with its data.
    fn entries(archive: &[u8]) -> io::Result<Vec<(Entry, Vec<u8>)>> {
        let left = Cell::new(u64::MAX);
        let mut framer = Framer::new(archive, &left);
        let mut out = Vec::new();
        while let Some(entry) = framer.next()? {
            let mut data = Vec::new();
            framer.data().read_to_end(&mut data)?;
            out.push((entry, data));
        }
        framer.finish()?;
        Ok(out)
    }

    #[test]
    fn plain_entries_come_with_their_data_and_kinds() {
        let mut archive = header(EntryType::Directory, "dir/", 0).as_bytes().to_vec();
        archive.extend(file("dir/a", b"hello"));
        let mut link = header(EntryType::Symlink, "dir/l", 0);
        link.set_link_name("a").unwrap();
        link.set_cksum();
        archive.extend(link.as_bytes());
        let mut hard = header(EntryType::Link, "dir/h", 0);
        hard.set_link_name("dir/a").unwrap();
        hard.set_cksum();
        archive.extend(hard.as_bytes());
        archive.extend(header(EntryType::Fifo, "dir/f", 0).as_bytes());
        archive.extend(header(EntryType::Char, "dir/c", 0).as_bytes());
        archive.extend(header(EntryType::Block, "dir/b", 0).as_bytes());
        archive.extend(end());
        let got = entries(&archive).unwrap();
        let kinds: Vec<(Kind, &[u8], &[u8])> = got
            .iter()
            .map(|(e, _)| (e.kind, e.path.as_slice(), e.link.as_slice()))
            .collect();
        assert_eq!(
            kinds,
            [
                (Kind::Dir, &b"dir/"[..], &b""[..]),
                (Kind::File, b"dir/a", b""),
                (Kind::Symlink, b"dir/l", b"a"),
                (Kind::Hardlink, b"dir/h", b"dir/a"),
                (Kind::Fifo, b"dir/f", b""),
                (Kind::CharDevice, b"dir/c", b""),
                (Kind::BlockDevice, b"dir/b", b""),
            ]
        );
        assert_eq!(got[1].1, b"hello");
        assert_eq!(got[1].0.size, 5);
        assert_eq!(got[1].0.mode, 0o644);
    }

    #[test]
    fn unread_data_is_skipped_and_a_contiguous_file_is_a_file() {
        let mut archive = file("a", &[1u8; 700]);
        let mut cont = header(EntryType::Continuous, "b", 3);
        cont.set_cksum();
        archive.extend(cont.as_bytes());
        archive.extend(padded(b"xyz"));
        archive.extend(end());
        let left = Cell::new(u64::MAX);
        let mut framer = Framer::new(&archive[..], &left);
        assert_eq!(framer.next().unwrap().unwrap().path, b"a");
        // Not reading a's data: b still comes right.
        let b = framer.next().unwrap().unwrap();
        assert_eq!((b.kind, b.path.as_slice()), (Kind::File, &b"b"[..]));
        let mut data = Vec::new();
        framer.data().read_to_end(&mut data).unwrap();
        assert_eq!(data, b"xyz");
        assert!(framer.next().unwrap().is_none());
        framer.finish().unwrap();
    }

    #[test]
    fn a_pax_size_frames_the_entry_not_the_headers_size() {
        // The header says 0; PAX says 11: the data is 11 bytes, then the
        // next entry starts where 11 padded to 512 ends.
        let mut archive = extension(EntryType::XHeader, &pax_record("size", b"11"));
        archive.extend(header(EntryType::Regular, "sized", 0).as_bytes());
        archive.extend(padded(b"hello world"));
        archive.extend(file("after", b"ok"));
        archive.extend(end());
        let got = entries(&archive).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0.size, 11);
        assert_eq!(got[0].1, b"hello world");
        assert_eq!(got[1].0.path, b"after");
    }

    #[test]
    fn long_names_come_from_gnu_and_pax_records() {
        let long = "d/".repeat(90) + "name";
        let target = "t/".repeat(90) + "target";
        let mut archive = extension(EntryType::GNULongName, format!("{long}\0").as_bytes());
        archive.extend(extension(
            EntryType::GNULongLink,
            format!("{target}\0").as_bytes(),
        ));
        let mut link = header(EntryType::Symlink, "short", 0);
        link.set_link_name("short").unwrap();
        link.set_cksum();
        archive.extend(link.as_bytes());
        // An x record, then an L record, then the file: the last word wins
        // for the path, the x record's size frames the data.
        let mut pax = pax_record("path", b"from-pax");
        pax.extend(pax_record("size", b"3"));
        archive.extend(extension(EntryType::XHeader, &pax));
        archive.extend(extension(EntryType::GNULongName, b"from-gnu\0"));
        archive.extend(header(EntryType::Regular, "short", 0).as_bytes());
        archive.extend(padded(b"abc"));
        archive.extend(end());
        let got = entries(&archive).unwrap();
        assert_eq!(got[0].0.path, long.as_bytes());
        assert_eq!(got[0].0.link, target.as_bytes());
        assert_eq!(got[1].0.path, b"from-gnu");
        assert_eq!(got[1].1, b"abc");
    }

    #[test]
    fn pax_linkpath_names_a_hardlinks_target() {
        let mut archive = extension(
            EntryType::XHeader,
            &pax_record("linkpath", b"a/very/long/target"),
        );
        let mut hard = header(EntryType::Link, "h", 0);
        hard.set_link_name("short").unwrap();
        hard.set_cksum();
        archive.extend(hard.as_bytes());
        archive.extend(end());
        let got = entries(&archive).unwrap();
        assert_eq!(got[0].0.link, b"a/very/long/target");
    }

    #[test]
    fn oversized_extension_records_are_refused() {
        for kind in [
            EntryType::XHeader,
            EntryType::GNULongName,
            EntryType::GNULongLink,
            EntryType::XGlobalHeader,
        ] {
            let big = vec![b'a'; MAX_EXTENSION as usize + 1];
            let mut archive = extension(kind, &big);
            archive.extend(file("a", b""));
            archive.extend(end());
            let err = entries(&archive).unwrap_err();
            assert!(err.to_string().contains("64 KiB"), "{kind:?}: {err}");
        }
        // Exactly the cap is fine.
        let mut name = vec![b'n'; MAX_EXTENSION as usize - 1];
        name.push(0);
        let mut archive = extension(EntryType::GNULongName, &name);
        archive.extend(file("a", b""));
        archive.extend(end());
        assert_eq!(
            entries(&archive).unwrap()[0].0.path.len(),
            MAX_EXTENSION as usize - 1
        );
    }

    #[test]
    fn sparse_entries_are_refused_in_both_encodings() {
        let mut archive = header(EntryType::GNUSparse, "s", 0).as_bytes().to_vec();
        archive.extend(end());
        let err = entries(&archive).unwrap_err();
        assert!(err.to_string().contains("sparse"), "{err}");
        let mut pax = pax_record("GNU.sparse.map", b"4096,5");
        pax.extend(pax_record("size", b"5"));
        let mut archive = extension(EntryType::XHeader, &pax);
        archive.extend(file("s", b"hello"));
        archive.extend(end());
        let err = entries(&archive).unwrap_err();
        assert!(err.to_string().contains("sparse"), "{err}");
    }

    #[test]
    fn a_global_header_may_not_override_an_entry() {
        let mut archive = extension(EntryType::XGlobalHeader, &pax_record("comment", b"hi"));
        archive.extend(file("a", b"x"));
        archive.extend(end());
        assert_eq!(entries(&archive).unwrap()[0].0.path, b"a");
        for key in ["size", "path", "linkpath"] {
            let mut archive = extension(EntryType::XGlobalHeader, &pax_record(key, b"1"));
            archive.extend(file("a", b"x"));
            archive.extend(end());
            let err = entries(&archive).unwrap_err();
            assert!(err.to_string().contains("global"), "{key}: {err}");
        }
    }

    #[test]
    fn unknown_kinds_are_refused() {
        for byte in [b'D', b'M', b'N', b'V', b'A', b'Z'] {
            let mut h = header(EntryType::Regular, "a", 0);
            h.set_entry_type(EntryType::new(byte));
            h.set_cksum();
            let mut archive = h.as_bytes().to_vec();
            archive.extend(end());
            let err = entries(&archive).unwrap_err();
            assert!(err.to_string().contains("kind"), "{}: {err}", byte as char);
        }
    }

    #[test]
    fn a_bad_checksum_is_refused_and_both_sums_are_accepted() {
        let mut archive = file("a", b"x");
        archive[0] ^= 0x01;
        archive.extend(end());
        let err = entries(&archive).unwrap_err();
        assert!(err.to_string().contains("checksum"), "{err}");
        // A header whose stored sum is the signed one.
        let mut h = header(EntryType::Regular, "a", 1);
        h.set_mode(0o644);
        let mut bytes = h.as_bytes().to_vec();
        bytes[99] = 0xff; // a byte that differs signed from unsigned, past the name's NUL
        let signed: i64 = bytes
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    b' ' as i64
                } else {
                    *b as i8 as i64
                }
            })
            .sum();
        let field = format!("{signed:06o}\0 ");
        bytes[148..156].copy_from_slice(field.as_bytes());
        let mut archive = bytes;
        archive.extend(padded(b"x"));
        archive.extend(end());
        let left = Cell::new(u64::MAX);
        let mut framer = Framer::new(&archive[..], &left);
        assert!(framer.next().is_ok(), "the signed sum is accepted");
    }

    #[test]
    fn the_archive_ends_at_zero_blocks_and_a_lone_one_is_an_error() {
        let mut archive = file("a", b"x");
        archive.extend(vec![0u8; 512]);
        // One zero block then the end of the stream: an end.
        assert_eq!(entries(&archive).unwrap().len(), 1);
        let mut archive = file("a", b"x");
        archive.extend(vec![0u8; 512]);
        archive.extend(file("b", b"y"));
        archive.extend(end());
        assert!(entries(&archive).is_err());
    }

    #[test]
    fn a_truncated_stream_is_an_error() {
        let whole = file("a", &[1u8; 600]);
        for cut in [100, 512, 700, whole.len() + 100] {
            let archive = whole[..cut.min(whole.len())].to_vec();
            let archive = if cut > whole.len() {
                [archive, vec![0u8; 100]].concat()
            } else {
                archive
            };
            assert!(entries(&archive).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn every_header_counts_against_the_entry_budget() {
        let mut archive = extension(EntryType::XHeader, &pax_record("comment", b"c"));
        archive.extend(file("a", b""));
        archive.extend(file("b", b""));
        archive.extend(end());
        let left = Cell::new(3);
        let mut framer = Framer::new(&archive[..], &left);
        assert!(framer.next().is_ok());
        assert!(framer.next().is_ok());
        assert!(framer.next().is_ok(), "the end blocks are not entries");
        let left = Cell::new(2);
        let mut framer = Framer::new(&archive[..], &left);
        assert!(framer.next().is_ok());
        let err = framer.next().unwrap_err();
        assert!(err.to_string().contains("entries"), "{err}");
    }

    #[test]
    fn what_follows_the_archive_is_read_by_finish() {
        let mut archive = file("a", b"x");
        archive.extend(end());
        archive.extend(vec![0u8; 100_000]);
        let entries = Cell::new(u64::MAX);
        let left = Cell::new(u64::MAX);
        let counted = crate::oci::decode::Counted::new(&archive[..], &left);
        let mut framer = Framer::new(counted, &entries);
        while framer.next().unwrap().is_some() {}
        framer.finish().unwrap();
        assert_eq!(u64::MAX - left.get(), archive.len() as u64);
        // Past the budget, finish fails.
        let left = Cell::new(2048 + 50_000);
        let counted = crate::oci::decode::Counted::new(&archive[..], &left);
        let mut framer = Framer::new(counted, &entries);
        while framer.next().unwrap().is_some() {}
        assert!(framer.finish().is_err());
    }
}
