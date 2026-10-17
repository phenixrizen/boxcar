// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A layer's decompressed stream, counted against the image's budget:
//! the blob itself for a plain tar, `flate2`'s gzip decoder (every member,
//! trailers checked), or the zstd adapter of this module over `ruzstd`,
//! which decodes one frame at a time, checks each frame's checksum itself
//! (ruzstd only stores it) and goes on to the next frame or skips a
//! skippable one.

use std::cell::Cell;
use std::io::{self, Read};

/// The most a zstd frame's window may take.
pub const MAX_ZSTD_WINDOW: u64 = 128 * 1024 * 1024;

/// How a layer's tar is compressed, from its media type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    Plain,
    Gzip,
    Zstd,
}

impl Compression {
    /// The compression a layer media type names; none for a type that is
    /// not a layer boxcar unpacks (foreign, non-distributable, unknown).
    pub fn for_media_type(media_type: &str) -> Option<Compression> {
        match media_type {
            "application/vnd.oci.image.layer.v1.tar"
            | "application/vnd.docker.image.rootfs.diff.tar" => Some(Compression::Plain),
            "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip" => Some(Compression::Gzip),
            "application/vnd.oci.image.layer.v1.tar+zstd" => Some(Compression::Zstd),
            _ => None,
        }
    }
}

/// A `Read` that counts what passes through it against `left`, and fails
/// once that is spent: the image's budget for decompressed bytes.
pub struct Counted<'a, R: Read> {
    inner: R,
    left: &'a Cell<u64>,
}

impl<'a, R: Read> Counted<'a, R> {
    pub fn new(inner: R, left: &'a Cell<u64>) -> Counted<'a, R> {
        Counted { inner, left }
    }
}

impl<R: Read> Read for Counted<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        match self.left.get().checked_sub(n as u64) {
            Some(left) => {
                self.left.set(left);
                Ok(n)
            }
            None => {
                self.left.set(0);
                Err(io::Error::other(
                    "the decompressed stream is past the image's budget",
                ))
            }
        }
    }
}

/// The decompressed stream of `input`, counted against `bytes_left`.
pub fn stream<'a, R: Read + 'a>(
    input: R,
    compression: Compression,
    bytes_left: &'a Cell<u64>,
) -> Box<dyn Read + 'a> {
    match compression {
        Compression::Plain => Box::new(Counted::new(input, bytes_left)),
        Compression::Gzip => Box::new(Counted::new(
            flate2::read::MultiGzDecoder::new(input),
            bytes_left,
        )),
        Compression::Zstd => Box::new(Counted::new(Zstd::new(input), bytes_left)),
    }
}

/// The magic of a zstd frame, little-endian.
const ZSTD_MAGIC: u32 = 0xFD2F_B528;
/// The magics of skippable frames.
const SKIPPABLE: std::ops::RangeInclusive<u32> = 0x184D_2A50..=0x184D_2A5F;

/// A zstd stream of any number of frames, skippable frames among them.
pub struct Zstd<R: Read> {
    state: ZstdState<R>,
}

enum ZstdState<R: Read> {
    /// Between frames: the next four bytes say what comes.
    Between(R),
    /// In a frame.
    Frame(
        ruzstd::decoding::StreamingDecoder<
            io::Chain<io::Cursor<[u8; 4]>, R>,
            ruzstd::decoding::FrameDecoder,
        >,
    ),
    Done,
}

impl<R: Read> Zstd<R> {
    pub fn new(input: R) -> Zstd<R> {
        Zstd {
            state: ZstdState::Between(input),
        }
    }
}

impl<R: Read> Read for Zstd<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match std::mem::replace(&mut self.state, ZstdState::Done) {
                ZstdState::Done => return Ok(0),
                ZstdState::Frame(mut decoder) => match decoder.read(buf)? {
                    0 => {
                        // The frame is done: its checksum, which ruzstd
                        // stores but does not compare, then what follows.
                        let frame = &decoder.decoder;
                        if let (Some(stored), Some(computed)) = (
                            frame.get_checksum_from_data(),
                            frame.get_calculated_checksum(),
                        ) {
                            if stored != computed {
                                return Err(io::Error::other(
                                    "a zstd frame's checksum does not match its data",
                                ));
                            }
                        }
                        let (chain, _) = decoder.into_parts();
                        let (_, input) = chain.into_inner();
                        self.state = ZstdState::Between(input);
                    }
                    n => {
                        self.state = ZstdState::Frame(decoder);
                        return Ok(n);
                    }
                },
                ZstdState::Between(mut input) => {
                    let mut magic = [0u8; 4];
                    let mut got = 0;
                    while got < 4 {
                        match input.read(&mut magic[got..])? {
                            0 => break,
                            n => got += n,
                        }
                    }
                    if got == 0 {
                        return Ok(0);
                    }
                    if got < 4 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "the zstd stream ends inside a frame header",
                        ));
                    }
                    let word = u32::from_le_bytes(magic);
                    if word == ZSTD_MAGIC {
                        // The decoder reads the magic itself: replayed.
                        let chained = io::Cursor::new(magic).chain(input);
                        let decoder = ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
                            chained,
                            MAX_ZSTD_WINDOW,
                        )
                        .map_err(|error| io::Error::other(format!("not a zstd frame: {error}")))?;
                        self.state = ZstdState::Frame(decoder);
                    } else if SKIPPABLE.contains(&word) {
                        let mut len = [0u8; 4];
                        input.read_exact(&mut len)?;
                        let len = u64::from(u32::from_le_bytes(len));
                        if io::copy(&mut (&mut input).take(len), &mut io::sink())? != len {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "the zstd stream ends inside a skippable frame",
                            ));
                        }
                        self.state = ZstdState::Between(input);
                    } else {
                        return Err(io::Error::other("not a zstd frame"));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zstd(data: &[u8]) -> Vec<u8> {
        ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
    }

    /// A zstd skippable frame holding `payload`.
    fn skippable(payload: &[u8]) -> Vec<u8> {
        let mut out = 0x184D_2A50u32.to_le_bytes().to_vec();
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// `frame` with its content checksum (the encoder writes one, its
    /// `hash` feature being on: the last four bytes) corrupted.
    fn bad_checksum(mut frame: Vec<u8>) -> Vec<u8> {
        assert_eq!(&frame[..4], &0xFD2F_B528u32.to_le_bytes());
        assert_ne!(frame[4] & 0b100, 0, "the encoder writes a checksum");
        let last = frame.len() - 1;
        frame[last] ^= 0xff;
        frame
    }

    fn read_all(mut r: impl Read) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn media_types_name_the_compression() {
        for (mt, want) in [
            (
                "application/vnd.oci.image.layer.v1.tar",
                Some(Compression::Plain),
            ),
            (
                "application/vnd.oci.image.layer.v1.tar+gzip",
                Some(Compression::Gzip),
            ),
            (
                "application/vnd.oci.image.layer.v1.tar+zstd",
                Some(Compression::Zstd),
            ),
            (
                "application/vnd.docker.image.rootfs.diff.tar",
                Some(Compression::Plain),
            ),
            (
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
                Some(Compression::Gzip),
            ),
            (
                "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
                None,
            ),
            (
                "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
                None,
            ),
            ("application/vnd.oci.image.layer.v1.tar+xz", None),
            ("application/octet-stream", None),
        ] {
            assert_eq!(Compression::for_media_type(mt), want, "{mt}");
        }
    }

    #[test]
    fn a_plain_stream_is_counted_and_stops_at_the_budget() {
        let data = vec![7u8; 1000];
        let left = Cell::new(1000);
        let out = read_all(stream(&data[..], Compression::Plain, &left)).unwrap();
        assert_eq!(out, data);
        assert_eq!(left.get(), 0);
        let left = Cell::new(999);
        let err = read_all(stream(&data[..], Compression::Plain, &left)).unwrap_err();
        assert!(err.to_string().contains("budget"), "{err}");
    }

    #[test]
    fn gzip_members_are_decoded_and_a_bad_crc_is_an_error() {
        let a = b"first member ".repeat(100);
        let b = b"second member".repeat(100);
        let mut both = gzip(&a);
        both.extend(gzip(&b));
        let left = Cell::new(u64::MAX);
        let out = read_all(stream(&both[..], Compression::Gzip, &left)).unwrap();
        assert_eq!(out, [a.clone(), b.clone()].concat());
        assert_eq!(u64::MAX - left.get(), out.len() as u64);
        // The CRC is the 8th to 5th byte from the end of a member.
        let mut bad = gzip(&a);
        let at = bad.len() - 8;
        bad[at] ^= 0xff;
        assert!(read_all(stream(&bad[..], Compression::Gzip, &left)).is_err());
        // A gzip of zeros expands past a small budget.
        let zeros = gzip(&vec![0u8; 1 << 20]);
        let left = Cell::new(4096);
        let err = read_all(stream(&zeros[..], Compression::Gzip, &left)).unwrap_err();
        assert!(err.to_string().contains("budget"), "{err}");
    }

    #[test]
    fn zstd_frames_are_decoded_in_turn_and_skippable_ones_skipped() {
        let a = b"frame one ".repeat(200);
        let b = b"frame two ".repeat(200);
        let mut all = zstd(&a);
        all.extend(skippable(b"metadata the decoder must step over"));
        all.extend(zstd(&b));
        let left = Cell::new(u64::MAX);
        let out = read_all(stream(&all[..], Compression::Zstd, &left)).unwrap();
        assert_eq!(out, [a.clone(), b.clone()].concat());
        // An empty input is an empty stream; a lone skippable frame too.
        assert_eq!(read_all(Zstd::new(&b""[..])).unwrap(), b"");
        assert_eq!(read_all(Zstd::new(&skippable(b"x")[..])).unwrap(), b"");
    }

    #[test]
    fn a_frame_checksum_is_checked_in_the_first_and_in_a_later_frame() {
        let a = b"frame one ".repeat(200);
        let b = b"frame two ".repeat(200);
        let bad_first = bad_checksum(zstd(&a));
        let err = read_all(Zstd::new(&bad_first[..])).unwrap_err();
        assert!(err.to_string().contains("checksum"), "{err}");
        let mut bad_later = zstd(&a);
        bad_later.extend(bad_checksum(zstd(&b)));
        let err = read_all(Zstd::new(&bad_later[..])).unwrap_err();
        assert!(err.to_string().contains("checksum"), "{err}");
    }

    #[test]
    fn what_is_not_a_zstd_frame_after_a_frame_is_an_error() {
        let mut garbage = zstd(b"a frame");
        garbage.extend_from_slice(b"and then garbage");
        let err = read_all(Zstd::new(&garbage[..])).unwrap_err();
        assert!(err.to_string().contains("zstd"), "{err}");
        // A truncated magic too.
        let mut short = zstd(b"a frame");
        short.extend_from_slice(&0xFD2F_B528u32.to_le_bytes()[..2]);
        assert!(read_all(Zstd::new(&short[..])).is_err());
    }
}
