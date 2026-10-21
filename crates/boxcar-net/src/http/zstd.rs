// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The `zstd` content coding decoded as its bytes come, over `ruzstd`
//! (pure Rust). ruzstd's frame decoder takes a frame's header and then
//! whole blocks, so this module delimits them from the bytes pushed so
//! far, as RFC 8878 frames them (the magic, the header's length from its
//! descriptor, each block's length from its header, the checksum after
//! the last block, skippable frames dropped), and hands each whole block
//! over. ruzstd gives decoded bytes up as they fall out of the frame's
//! window, and the rest at the frame's end; a frame whose window is past
//! [`MAX_WINDOW`] is refused before the window is allocated, as a
//! large-window Brotli stream is.

use std::io::{self, Cursor, Write};

use ruzstd::decoding::errors::FrameDecoderError;
use ruzstd::decoding::{BlockDecodingStrategy, FrameDecoder};

/// The largest window a frame may ask for: Brotli's standard largest,
/// which bounds what a decoder holds. zstd's own default is at most 8 MiB.
pub const MAX_WINDOW: u64 = 16 * 1024 * 1024;

/// The largest block RFC 8878 allows. A header asking for more is no zstd.
pub const MAX_BLOCK: usize = 128 * 1024;

/// A zstd frame's magic, and the skippable frames'.
const MAGIC: u32 = 0xFD2F_B528;
/// The magic as it is on the wire.
pub const MAGIC_BYTES: [u8; 4] = MAGIC.to_le_bytes();
const SKIPPABLE: std::ops::RangeInclusive<u32> = 0x184D_2A50..=0x184D_2A5F;

/// Why a stream stopped decoding.
#[derive(Debug)]
pub enum Error {
    /// A frame's window is past [`MAX_WINDOW`]: refused before allocation.
    WindowTooBig,
    /// The writer refused the decoded bytes.
    Write(io::Error),
    /// The bytes are no zstd, a frame's checksum does not match its data,
    /// or the stream ended inside a frame.
    Bad,
}

/// Where the next bytes of the stream belong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Between frames: the next four bytes say what comes.
    Magic,
    /// At a frame's header of so many bytes, the magic included.
    Header(usize),
    /// In a frame, at a block header; whether a checksum ends the frame.
    Block { checksum: bool },
    /// At a skippable frame's size, its magic read.
    SkipSize,
    /// In a skippable frame: so many bytes left to drop.
    Skip(u64),
}

/// Decodes a zstd stream into a writer, from the bytes pushed so far.
pub struct Decoder<W> {
    /// Bytes pushed and not yet handed over: at most one unit (a header,
    /// a block with its checksum) plus what the last push brought.
    pending: Vec<u8>,
    state: State,
    frame: FrameDecoder,
    out: W,
}

impl<W: Write> Decoder<W> {
    pub fn new(out: W) -> Decoder<W> {
        let mut frame = FrameDecoder::new();
        frame.set_max_window_size(MAX_WINDOW);
        Decoder {
            pending: Vec::new(),
            state: State::Magic,
            frame,
            out,
        }
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.out
    }

    /// Takes `raw` bytes of the stream; what they complete is decoded
    /// into the writer. After an error nothing more decodes.
    pub fn feed(&mut self, raw: &[u8]) -> Result<(), Error> {
        self.pending.extend_from_slice(raw);
        loop {
            let used = match self.state {
                State::Magic => self.at_magic()?,
                State::Header(len) => self.at_header(len)?,
                State::Block { checksum } => self.at_block(checksum)?,
                State::SkipSize => self.at_skip_size(),
                State::Skip(left) => self.at_skip(left),
            };
            match used {
                None => return Ok(()),
                Some(used) => {
                    self.pending.drain(..used);
                }
            }
        }
    }

    /// The stream ended: whole only between frames.
    pub fn finish(&mut self) -> Result<(), Error> {
        if self.state == State::Magic && self.pending.is_empty() {
            Ok(())
        } else {
            Err(Error::Bad)
        }
    }

    /// At a magic: a frame's, whose header's length its descriptor gives,
    /// or a skippable frame's.
    fn at_magic(&mut self) -> Result<Option<usize>, Error> {
        let Some(magic) = self.pending.get(..4) else {
            return Ok(None);
        };
        let word = u32::from_le_bytes(magic.try_into().unwrap());
        if SKIPPABLE.contains(&word) {
            self.state = State::SkipSize;
            return Ok(Some(4));
        }
        if word != MAGIC {
            return Err(Error::Bad);
        }
        let Some(&descriptor) = self.pending.get(4) else {
            return Ok(None);
        };
        let single_segment = descriptor & 0x20 != 0;
        let window = usize::from(!single_segment);
        let dictionary = [0, 1, 2, 4][usize::from(descriptor & 3)];
        let content_size = match descriptor >> 6 {
            0 => usize::from(single_segment),
            1 => 2,
            2 => 4,
            _ => 8,
        };
        self.state = State::Header(5 + window + dictionary + content_size);
        Ok(Some(0))
    }

    /// At a frame's header, whole: the decoder reads it, refusing a window
    /// past [`MAX_WINDOW`].
    fn at_header(&mut self, len: usize) -> Result<Option<usize>, Error> {
        let Some(header) = self.pending.get(..len) else {
            return Ok(None);
        };
        self.frame
            .reset(Cursor::new(header))
            .map_err(|error| match error {
                FrameDecoderError::WindowSizeTooBig { .. } => Error::WindowTooBig,
                _ => Error::Bad,
            })?;
        let checksum = header[4] & 0x04 != 0;
        self.state = State::Block { checksum };
        Ok(Some(len))
    }

    /// At a block header: the block, whole, with the frame's checksum when
    /// it is the last, decoded; what falls out of the window written.
    fn at_block(&mut self, checksum: bool) -> Result<Option<usize>, Error> {
        let Some(header) = self.pending.get(..3) else {
            return Ok(None);
        };
        let word = u32::from_le_bytes([header[0], header[1], header[2], 0]);
        let last = word & 1 == 1;
        let size = (word >> 3) as usize;
        let content = match (word >> 1) & 3 {
            0 | 2 => size,
            1 => 1,
            _ => return Err(Error::Bad),
        };
        if size > MAX_BLOCK {
            return Err(Error::Bad);
        }
        let need = 3 + content + if last && checksum { 4 } else { 0 };
        let Some(block) = self.pending.get(..need) else {
            return Ok(None);
        };
        self.frame
            .decode_blocks(Cursor::new(block), BlockDecodingStrategy::UptoBlocks(1))
            .map_err(|_| Error::Bad)?;
        self.frame
            .collect_to_writer(&mut self.out)
            .map_err(Error::Write)?;
        if last {
            if let (Some(stored), Some(computed)) = (
                self.frame.get_checksum_from_data(),
                self.frame.get_calculated_checksum(),
            ) {
                if stored != computed {
                    return Err(Error::Bad);
                }
            }
            self.state = State::Magic;
        }
        Ok(Some(need))
    }

    /// At a skippable frame's size.
    fn at_skip_size(&mut self) -> Option<usize> {
        let size = self.pending.get(..4)?;
        self.state = State::Skip(u64::from(u32::from_le_bytes(size.try_into().unwrap())));
        Some(4)
    }

    /// In a skippable frame: its bytes are dropped as they come.
    fn at_skip(&mut self, left: u64) -> Option<usize> {
        if left == 0 {
            self.state = State::Magic;
            return Some(0);
        }
        let drop = usize::try_from(left)
            .unwrap_or(usize::MAX)
            .min(self.pending.len());
        if drop == 0 {
            return None;
        }
        self.state = State::Skip(left - drop as u64);
        Some(drop)
    }
}

/// The fixtures are the body tests' too.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// `zstd -19` of the test body (3200 bytes), checksum included.
    pub const TEXT: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x64, 0x80, 0x0b, 0x4d, 0x01, 0x00, 0x04, 0x02, 0x7b, 0x22, 0x6d,
        0x6f, 0x64, 0x65, 0x6c, 0x22, 0x3a, 0x22, 0x63, 0x6c, 0x61, 0x75, 0x64, 0x65, 0x22, 0x2c,
        0x22, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x22, 0x3a, 0x5b, 0x5d, 0x7d, 0x01,
        0x00, 0xe8, 0xe2, 0xf0, 0xd5, 0x13, 0x9d, 0x50, 0xcb, 0x38,
    ];

    /// The same with `--no-check`.
    pub const TEXT_NO_CHECK: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x60, 0x80, 0x0b, 0x4d, 0x01, 0x00, 0x04, 0x02, 0x7b, 0x22, 0x6d,
        0x6f, 0x64, 0x65, 0x6c, 0x22, 0x3a, 0x22, 0x63, 0x6c, 0x61, 0x75, 0x64, 0x65, 0x22, 0x2c,
        0x22, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x22, 0x3a, 0x5b, 0x5d, 0x7d, 0x01,
        0x00, 0xe8, 0xe2, 0xf0, 0xd5, 0x13,
    ];

    /// `zstd` of nothing.
    pub const EMPTY: &[u8] = &[
        0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x00, 0x01, 0x00, 0x00, 0x99, 0xe9, 0xd8, 0x51,
    ];

    pub fn text() -> Vec<u8> {
        b"{\"model\":\"claude\",\"messages\":[]}".repeat(100)
    }

    /// A skippable frame holding `payload`.
    pub fn skippable(payload: &[u8]) -> Vec<u8> {
        let mut frame = 0x184D_2A5Au32.to_le_bytes().to_vec();
        frame.extend((payload.len() as u32).to_le_bytes());
        frame.extend(payload);
        frame
    }

    /// A frame of `blocks` RLE blocks of 128 KiB zeros each, with an 8 MiB
    /// window and no checksum: 4 bytes a block.
    pub fn zeros(blocks: usize) -> Vec<u8> {
        let mut frame = MAGIC.to_le_bytes().to_vec();
        frame.extend([0x00, 0x68]);
        for i in 0..blocks {
            let last = u32::from(i + 1 == blocks);
            let header = ((MAX_BLOCK as u32) << 3) | (1 << 1) | last;
            frame.extend(&header.to_le_bytes()[..3]);
            frame.push(0);
        }
        frame
    }

    fn decode_in_chunks(raw: &[u8], chunk: usize) -> Result<Vec<u8>, Error> {
        let mut decoder = Decoder::new(Vec::new());
        for piece in raw.chunks(chunk) {
            decoder.feed(piece)?;
        }
        decoder.finish()?;
        Ok(std::mem::take(decoder.get_mut()))
    }

    #[test]
    fn frames_decode_from_bytes_pushed_in_any_pieces() {
        for chunk in [1, 7, 64, 4096] {
            assert_eq!(decode_in_chunks(TEXT, chunk).unwrap(), text(), "{chunk}");
            assert_eq!(decode_in_chunks(TEXT_NO_CHECK, chunk).unwrap(), text());
            assert!(decode_in_chunks(EMPTY, chunk).unwrap().is_empty());
        }
        // ruzstd's own frames, compressed and not.
        for level in [
            ruzstd::encoding::CompressionLevel::Uncompressed,
            ruzstd::encoding::CompressionLevel::Fastest,
        ] {
            let raw = ruzstd::encoding::compress_to_vec(text().as_slice(), level);
            assert_eq!(decode_in_chunks(&raw, 7).unwrap(), text());
        }
    }

    #[test]
    fn frames_follow_one_another_and_skippable_ones_are_dropped() {
        let mut raw = TEXT.to_vec();
        raw.extend(skippable(b"metadata"));
        raw.extend(TEXT_NO_CHECK);
        raw.extend(skippable(b""));
        raw.extend(EMPTY);
        let mut want = text();
        want.extend(text());
        assert_eq!(decode_in_chunks(&raw, 5).unwrap(), want);
    }

    #[test]
    fn a_frame_with_a_window_past_the_cap_is_refused_at_its_header() {
        // A single-segment frame's window is its content size: 16 MiB + 1.
        let mut raw = MAGIC.to_le_bytes().to_vec();
        raw.push(0xa0);
        raw.extend((MAX_WINDOW as u32 + 1).to_le_bytes());
        let mut decoder = Decoder::new(Vec::new());
        assert!(matches!(decoder.feed(&raw), Err(Error::WindowTooBig)));
        // Exactly the cap passes the header.
        let mut raw = MAGIC.to_le_bytes().to_vec();
        raw.push(0xa0);
        raw.extend((MAX_WINDOW as u32).to_le_bytes());
        let mut decoder = Decoder::new(Vec::new());
        decoder.feed(&raw).unwrap();
        assert_eq!(decoder.state, State::Block { checksum: false });
    }

    #[test]
    fn bad_bytes_a_bad_checksum_and_a_cut_frame_are_errors() {
        assert!(matches!(
            decode_in_chunks(b"not zstd at all", 4),
            Err(Error::Bad)
        ));
        let mut flipped = TEXT.to_vec();
        *flipped.last_mut().unwrap() ^= 0xff;
        assert!(matches!(decode_in_chunks(&flipped, 7), Err(Error::Bad)));
        let cut = &TEXT[..TEXT.len() - 10];
        assert!(matches!(decode_in_chunks(cut, 7), Err(Error::Bad)));
        let mut decoder = Decoder::new(Vec::new());
        decoder.feed(&TEXT[..2]).unwrap();
        assert!(matches!(decoder.finish(), Err(Error::Bad)));
        // A block past 128 KiB is no zstd.
        let mut raw = MAGIC.to_le_bytes().to_vec();
        raw.extend([0x00, 0x68, 0x09, 0x00, 0x10]);
        let mut decoder = Decoder::new(Vec::new());
        assert!(matches!(decoder.feed(&raw), Err(Error::Bad)));
    }

    #[test]
    fn a_writer_that_refuses_stops_the_stream() {
        struct Refuse;
        impl Write for Refuse {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("full"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut decoder = Decoder::new(Refuse);
        assert!(matches!(decoder.feed(TEXT), Err(Error::Write(_))));
    }

    #[test]
    fn zeros_fill_from_four_bytes_a_block() {
        let raw = zeros(3);
        assert_eq!(raw.len(), 6 + 12);
        assert_eq!(decode_in_chunks(&raw, 5).unwrap(), vec![0u8; 3 * MAX_BLOCK]);
    }
}
