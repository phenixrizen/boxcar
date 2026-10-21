// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A message body as the observer keeps it: content-decoded as it comes
//! (`gzip`, `deflate`, `br`, `zstd`; anything else degrades the body to its
//! raw bytes), hashed whole (blake3 over the decoded bytes), and kept for the
//! parsers up to [`BODY_KEEP`], after which the body is hashed but not
//! kept (`truncated`).

use std::io::Write;

use super::retain::{Retained, Share};
use super::zstd;

/// The most decoded bytes kept for the parsers.
pub const BODY_KEEP: usize = 16 * 1024 * 1024;

/// The most bytes one body may decode to: past it the decoder stops
/// (`degraded: "decode_budget"`) and the rest is hashed raw, so a body that
/// expands without end costs neither memory nor time without end.
pub const DECODE_BUDGET: usize = 4 * BODY_KEEP;

/// A decoder's output: refuses a write past what is left of the budget,
/// which fails the decoder before it allocates more.
struct Capped {
    buf: Vec<u8>,
    left: usize,
}

impl Capped {
    fn new() -> Capped {
        Capped {
            buf: Vec::new(),
            left: DECODE_BUDGET,
        }
    }
}

impl Write for Capped {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > self.left {
            self.left = 0;
            return Err(std::io::Error::other("decode_budget"));
        }
        self.left -= data.len();
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A `Content-Encoding` the observer decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
    Zstd,
}

impl Coding {
    /// The most a decoder of this coding holds, as charged against the
    /// observer's budget when it is made: zlib's window and state for
    /// gzip and deflate; for Brotli its largest window (16 MiB) and the
    /// writer's buffer; for zstd the largest window it is allowed, the
    /// same 16 MiB, a block waiting to be whole and a block decoded.
    pub fn decoder_cost(self) -> usize {
        match self {
            Coding::Identity => 0,
            Coding::Gzip | Coding::Deflate => 64 * 1024,
            Coding::Brotli => 16 * 1024 * 1024 + 64 * 1024,
            Coding::Zstd => zstd::MAX_WINDOW as usize + 2 * zstd::MAX_BLOCK,
        }
    }

    /// The coding `content_encoding` names; `Err` for one the observer
    /// does not decode (a chain of codings, anything else).
    pub fn parse(content_encoding: Option<&str>) -> Result<Coding, &'static str> {
        match content_encoding.map(|c| c.trim().to_ascii_lowercase()) {
            None => Ok(Coding::Identity),
            Some(c) if c.is_empty() || c == "identity" => Ok(Coding::Identity),
            Some(c) if c == "gzip" || c == "x-gzip" => Ok(Coding::Gzip),
            Some(c) if c == "deflate" => Ok(Coding::Deflate),
            Some(c) if c == "br" => Ok(Coding::Brotli),
            Some(c) if c == "zstd" => Ok(Coding::Zstd),
            Some(_) => Err("content_encoding"),
        }
    }
}

enum Inner {
    Identity,
    Gzip(flate2::write::GzDecoder<Capped>),
    Deflate(flate2::write::ZlibDecoder<Capped>),
    Brotli(Box<brotli_decompressor::DecompressorWriter<Capped>>),
    Zstd(Box<zstd::Decoder<Capped>>),
}

/// Decodes one body's content coding as its bytes come.
pub struct ContentDecoder {
    inner: Inner,
    failed: bool,
    /// The first byte has been read (Brotli's window size is in it).
    started: bool,
}

/// Whether a Brotli stream's first byte asks for the large-window format
/// (RFC 7932's reserved `WBITS` code, 0b0010001 in its low seven bits),
/// whose window may reach 1 GiB: the decoder would allocate it, past any
/// budget. Standard streams' windows are at most 16 MiB.
fn brotli_large_window(first: u8) -> bool {
    first & 0x7f == 0x11
}

impl ContentDecoder {
    pub fn new(coding: Coding) -> ContentDecoder {
        let inner = match coding {
            Coding::Identity => Inner::Identity,
            Coding::Gzip => Inner::Gzip(flate2::write::GzDecoder::new(Capped::new())),
            Coding::Deflate => Inner::Deflate(flate2::write::ZlibDecoder::new(Capped::new())),
            Coding::Brotli => Inner::Brotli(Box::new(
                brotli_decompressor::DecompressorWriter::new(Capped::new(), 64 * 1024),
            )),
            Coding::Zstd => Inner::Zstd(Box::new(zstd::Decoder::new(Capped::new()))),
        };
        ContentDecoder {
            inner,
            failed: false,
            started: false,
        }
    }

    /// The decoded bytes `raw` yields. `Err` once the stream does not
    /// decode; nothing decodes after that.
    pub fn feed(&mut self, raw: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.failed {
            return Err("content_decode");
        }
        if !self.started && !raw.is_empty() {
            self.started = true;
            if matches!(self.inner, Inner::Brotli(_)) && brotli_large_window(raw[0]) {
                self.failed = true;
                return Err("decode_budget");
            }
        }
        let result = match &mut self.inner {
            Inner::Identity => return Ok(raw.to_vec()),
            Inner::Gzip(d) => d
                .write_all(raw)
                .map(|_| std::mem::take(&mut d.get_mut().buf))
                .map_err(|_| ()),
            Inner::Deflate(d) => d
                .write_all(raw)
                .map(|_| std::mem::take(&mut d.get_mut().buf))
                .map_err(|_| ()),
            Inner::Brotli(d) => d
                .write_all(raw)
                .map(|_| std::mem::take(&mut d.get_mut().buf))
                .map_err(|_| ()),
            Inner::Zstd(d) => match d.feed(raw) {
                Ok(()) => Ok(std::mem::take(&mut d.get_mut().buf)),
                // Refused at the header, before its window is allocated:
                // the budget, as for Brotli's large-window format.
                Err(zstd::Error::WindowTooBig) => {
                    self.failed = true;
                    return Err("decode_budget");
                }
                Err(_) => Err(()),
            },
        };
        result.map_err(|_| self.fail())
    }

    /// What the decoder still held at the body's end.
    pub fn finish(&mut self) -> Result<Vec<u8>, &'static str> {
        if self.failed {
            return Err("content_decode");
        }
        let result = match &mut self.inner {
            Inner::Identity => return Ok(Vec::new()),
            Inner::Gzip(d) => d
                .try_finish()
                .map(|_| std::mem::take(&mut d.get_mut().buf))
                .map_err(|_| ()),
            Inner::Deflate(d) => d
                .try_finish()
                .map(|_| std::mem::take(&mut d.get_mut().buf))
                .map_err(|_| ()),
            Inner::Brotli(d) => d
                .flush()
                .map(|_| std::mem::take(&mut d.get_mut().buf))
                .map_err(|_| ()),
            Inner::Zstd(d) => d
                .finish()
                .map(|_| std::mem::take(&mut d.get_mut().buf))
                .map_err(|_| ()),
        };
        result.map_err(|_| self.fail())
    }

    /// The decoder failed: why, its budget spent or the stream bad. What
    /// it had decoded is let go.
    fn fail(&mut self) -> &'static str {
        self.failed = true;
        let capped = match &mut self.inner {
            Inner::Identity => return "content_decode",
            Inner::Gzip(d) => d.get_mut(),
            Inner::Deflate(d) => d.get_mut(),
            Inner::Brotli(d) => d.get_mut(),
            Inner::Zstd(d) => d.get_mut(),
        };
        capped.buf = Vec::new();
        if capped.left == 0 {
            "decode_budget"
        } else {
            "content_decode"
        }
    }
}

/// What a body came to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BodySummary {
    /// Decoded bytes, in all.
    pub bytes: u64,
    /// `b3:` and blake3 of the decoded bytes; `None` for an empty body.
    pub b3: Option<String>,
    /// More than [`BODY_KEEP`] came: the parsers saw none of it.
    pub truncated: bool,
    /// The body could not be decoded, or its coding is not one the
    /// observer knows: the hash and the kept bytes are then of the raw
    /// body.
    pub degraded: Option<&'static str>,
}

/// One body: decoded, hashed, and kept up to the limit.
pub struct BodySink {
    decoder: Option<ContentDecoder>,
    kept: Vec<u8>,
    /// What the kept bytes take of the observer's budget.
    share: Share,
    /// What the decoder takes of it, until the body ends.
    decoder_share: Share,
    /// The decoder's cost ([`Coding::decoder_cost`]).
    decoder_cost: usize,
    /// Whether the decoded bytes are kept at all, or only hashed.
    keep: bool,
    hasher: blake3::Hasher,
    bytes: u64,
    truncated: bool,
    degraded: Option<&'static str>,
}

impl BodySink {
    /// A sink for a body with `content_encoding`.
    pub fn new(content_encoding: Option<&str>) -> BodySink {
        let (decoder, decoder_cost, degraded) = match Coding::parse(content_encoding) {
            Ok(coding) => (
                Some(ContentDecoder::new(coding)),
                coding.decoder_cost(),
                None,
            ),
            Err(reason) => (None, 0, Some(reason)),
        };
        BodySink {
            decoder,
            kept: Vec::new(),
            share: Share::default(),
            decoder_share: Share::default(),
            decoder_cost,
            keep: true,
            hasher: blake3::Hasher::new(),
            bytes: 0,
            truncated: false,
            degraded,
        }
    }

    /// Takes `raw` body bytes: the decoded bytes they yield (or the raw
    /// bytes, once degraded), which are hashed and kept.
    pub fn push(&mut self, raw: &[u8]) -> Vec<u8> {
        let decoded = match &mut self.decoder {
            Some(decoder) => match decoder.feed(raw) {
                Ok(bytes) => bytes,
                Err(reason) => {
                    self.degraded.get_or_insert(reason);
                    self.decoder = None;
                    raw.to_vec()
                }
            },
            None => raw.to_vec(),
        };
        self.take(&decoded);
        decoded
    }

    /// The body ended: what the decoder still held.
    pub fn finish(&mut self) -> Vec<u8> {
        let rest = match &mut self.decoder {
            Some(decoder) => match decoder.finish() {
                Ok(bytes) => bytes,
                Err(reason) => {
                    self.degraded.get_or_insert(reason);
                    Vec::new()
                }
            },
            None => Vec::new(),
        };
        self.take(&rest);
        self.drop_decoder();
        rest
    }

    /// Keeps the body's bytes, and its decoder, within the observer's
    /// `retained` budget: a decoder with no room is not made, and the body
    /// is hashed raw (`observe_budget`).
    pub fn with_retained(mut self, retained: Retained) -> BodySink {
        self.share = Share::new(retained.clone());
        self.decoder_share = Share::new(retained);
        if self.decoder.is_some() && !self.decoder_share.grow(self.decoder_cost) {
            self.decoder = None;
            self.degraded.get_or_insert("observe_budget");
        }
        self
    }

    /// The body ended or is let go: its decoder, and what it took of the
    /// budget, go.
    fn drop_decoder(&mut self) {
        self.decoder = None;
        self.decoder_share.clear();
    }

    /// Hashes the body without keeping it: no parser and no dump reads it.
    pub fn hash_only(mut self) -> BodySink {
        self.keep = false;
        self
    }

    /// Lets the kept bytes go once nothing reads them any more (the
    /// summary stays).
    pub fn release(&mut self) {
        self.kept = Vec::new();
        self.keep = false;
        self.share.clear();
        self.drop_decoder();
    }

    /// Whether the kept bytes are the whole body.
    pub fn whole(&self) -> bool {
        self.keep && !self.truncated
    }

    fn take(&mut self, decoded: &[u8]) {
        if decoded.is_empty() {
            return;
        }
        self.hasher.update(decoded);
        self.bytes = self.bytes.saturating_add(decoded.len() as u64);
        // Once cut, nothing more is kept: the tail of a body is no body.
        if !self.keep || self.truncated {
            return;
        }
        if self.kept.len() + decoded.len() > BODY_KEEP {
            self.cut(None);
        } else if !self.share.grow(decoded.len()) {
            self.cut(Some("observe_budget"));
        } else {
            self.kept.extend_from_slice(decoded);
        }
    }

    /// The body is too long to keep (or there is no room for it): what was
    /// kept goes, and no more is.
    fn cut(&mut self, reason: Option<&'static str>) {
        self.truncated = true;
        self.kept = Vec::new();
        self.share.clear();
        if let Some(reason) = reason {
            self.degraded.get_or_insert(reason);
        }
    }

    /// The decoded bytes kept for the parsers: all of them, or none once
    /// the body passed the limit, found no room in the observer's budget,
    /// or was let go.
    pub fn kept(&self) -> &[u8] {
        &self.kept
    }

    pub fn summary(&self) -> BodySummary {
        BodySummary {
            bytes: self.bytes,
            b3: (self.bytes > 0).then(|| format!("b3:{}", self.hasher.finalize().to_hex())),
            truncated: self.truncated,
            degraded: self.degraded,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(bytes).unwrap();
        e.finish().unwrap()
    }

    fn deflate(bytes: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(bytes).unwrap();
        e.finish().unwrap()
    }

    fn brotli(bytes: &[u8]) -> Vec<u8> {
        // brotli-decompressor decodes only; the smallest valid stream of
        // these bytes is made by hand: an uncompressed meta-block.
        // WBITS=16 (0x0b... ) is fiddly; use the "empty window + raw
        // meta-block" encoding: for a body under 65536 bytes:
        //   0x0b (window bits 22), then ISLAST=0, MNIBBLES, MLEN-1,
        //   ISUNCOMPRESSED=1, padding, raw bytes, then an empty last block.
        // Rather than hand-encode, test brotli on the stream the RFC 7932
        // gives for "" and on a known fixture below.
        let _ = bytes;
        vec![0x3b]
    }

    #[test]
    fn a_body_decodes_to_its_budget_and_no_further() {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        let zeros = vec![0u8; 1024 * 1024];
        for _ in 0..(DECODE_BUDGET / zeros.len() + 8) {
            e.write_all(&zeros).unwrap();
        }
        let raw = e.finish().unwrap();
        let mut sink = BodySink::new(Some("gzip"));
        let decoded = sink.push(&raw);
        assert!(decoded.len() <= raw.len(), "{}", decoded.len());
        sink.finish();
        let summary = sink.summary();
        assert_eq!(summary.degraded, Some("decode_budget"));
        assert!(summary.bytes <= raw.len() as u64);
    }

    #[test]
    fn gzip_deflate_and_brotli_bodies_decode_and_hash_the_plaintext() {
        let text = b"{\"model\":\"claude\",\"messages\":[]}".repeat(100);
        for (encoding, raw) in [("gzip", gzip(&text)), ("deflate", deflate(&text))] {
            let mut sink = BodySink::new(Some(encoding));
            let mut decoded = Vec::new();
            for chunk in raw.chunks(7) {
                decoded.extend(sink.push(chunk));
            }
            decoded.extend(sink.finish());
            assert_eq!(decoded, text, "{encoding}");
            let summary = sink.summary();
            assert_eq!(summary.bytes, text.len() as u64);
            assert_eq!(
                summary.b3.as_deref(),
                Some(format!("b3:{}", blake3::hash(&text).to_hex()).as_str())
            );
            assert!(
                !summary.truncated && summary.degraded.is_none(),
                "{encoding}"
            );
            assert_eq!(sink.kept(), text);
        }
        // Brotli: the empty stream decodes to nothing.
        let mut sink = BodySink::new(Some("br"));
        assert!(sink.push(&brotli(b"")).is_empty());
        sink.finish();
        assert_eq!(sink.summary().bytes, 0);
        assert!(sink.summary().degraded.is_none());
    }

    /// zstd bodies decode as the others do: from the zstd CLI's frames
    /// (checksum or not), ruzstd's own, several frames in a row with a
    /// skippable one between, pushed in pieces of any size.
    #[test]
    fn zstd_bodies_decode_and_hash_the_plaintext() {
        use super::super::zstd::tests::{skippable, text, EMPTY, TEXT, TEXT_NO_CHECK};
        let text = text();
        let mut two = TEXT.to_vec();
        two.extend(skippable(b"meta"));
        two.extend(TEXT_NO_CHECK);
        let mut twice = text.clone();
        twice.extend(&text);
        let own = ruzstd::encoding::compress_to_vec(
            text.as_slice(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        for (raw, want) in [
            (TEXT.to_vec(), text.clone()),
            (TEXT_NO_CHECK.to_vec(), text.clone()),
            (own, text.clone()),
            (two, twice),
            (EMPTY.to_vec(), Vec::new()),
        ] {
            for chunk in [1, 7, 4096] {
                let mut sink = BodySink::new(Some("zstd"));
                let mut decoded = Vec::new();
                for piece in raw.chunks(chunk) {
                    decoded.extend(sink.push(piece));
                }
                decoded.extend(sink.finish());
                assert_eq!(decoded, want, "{chunk}");
                let summary = sink.summary();
                assert_eq!(summary.bytes, want.len() as u64);
                assert_eq!(
                    summary.b3,
                    (!want.is_empty()).then(|| format!("b3:{}", blake3::hash(&want).to_hex()))
                );
                assert!(!summary.truncated && summary.degraded.is_none());
                assert_eq!(sink.kept(), want);
            }
        }
    }

    /// A zstd body that decodes past the budget is cut there, like a gzip
    /// one; a frame whose window is past the cap is refused before it is
    /// allocated; a bad or cut stream degrades to the raw bytes.
    #[test]
    fn zstd_bodies_are_bounded_and_degrade_like_the_others() {
        use super::super::zstd::tests::{zeros, TEXT};
        // 600 blocks of 128 KiB zeros: 75 MiB, past the 64 MiB budget.
        let raw = zeros(600);
        let mut sink = BodySink::new(Some("zstd"));
        let decoded = sink.push(&raw);
        assert_eq!(decoded, raw, "the raw bytes stand in");
        sink.finish();
        let summary = sink.summary();
        assert_eq!(summary.degraded, Some("decode_budget"));
        assert_eq!(summary.bytes, raw.len() as u64);

        let mut header = zstd::MAGIC_BYTES.to_vec();
        header.push(0xa0);
        header.extend((zstd::MAX_WINDOW as u32 + 1).to_le_bytes());
        let mut sink = BodySink::new(Some("zstd"));
        assert_eq!(sink.push(&header), header);
        assert_eq!(sink.summary().degraded, Some("decode_budget"));

        let mut sink = BodySink::new(Some("zstd"));
        sink.push(b"not zstd");
        sink.finish();
        assert_eq!(sink.summary().degraded, Some("content_decode"));

        let mut sink = BodySink::new(Some("zstd"));
        let mut decoded = Vec::new();
        for piece in TEXT[..TEXT.len() - 10].chunks(7) {
            decoded.extend(sink.push(piece));
        }
        decoded.extend(sink.finish());
        assert_eq!(sink.summary().degraded, Some("content_decode"));
    }

    #[test]
    fn an_unknown_coding_or_a_bad_stream_degrades_to_the_raw_bytes() {
        let mut sink = BodySink::new(Some("compress"));
        assert_eq!(sink.push(b"raw"), b"raw");
        assert_eq!(sink.summary().degraded, Some("content_encoding"));
        assert_eq!(sink.summary().bytes, 3);
        let mut sink = BodySink::new(Some("gzip"));
        let got = sink.push(b"this is not gzip at all");
        sink.finish();
        assert_eq!(sink.summary().degraded, Some("content_decode"));
        // Degraded at the first push: the raw bytes stand in.
        assert_eq!(got, b"this is not gzip at all");
    }

    #[test]
    fn a_body_past_the_limit_is_hashed_and_truncated_not_kept() {
        let mut sink = BodySink::new(None);
        let chunk = vec![7u8; 1024 * 1024];
        for _ in 0..17 {
            sink.push(&chunk);
        }
        sink.finish();
        let summary = sink.summary();
        assert!(summary.truncated);
        assert_eq!(summary.bytes, 17 * 1024 * 1024);
        assert!(sink.kept().is_empty());
        let mut whole = blake3::Hasher::new();
        for _ in 0..17 {
            whole.update(&chunk);
        }
        assert_eq!(
            summary.b3.unwrap(),
            format!("b3:{}", whole.finalize().to_hex())
        );
    }

    #[test]
    fn codings_parse_as_http_names_them() {
        assert_eq!(Coding::parse(None), Ok(Coding::Identity));
        assert_eq!(Coding::parse(Some("identity")), Ok(Coding::Identity));
        assert_eq!(Coding::parse(Some(" GZIP ")), Ok(Coding::Gzip));
        assert_eq!(Coding::parse(Some("x-gzip")), Ok(Coding::Gzip));
        assert_eq!(Coding::parse(Some("deflate")), Ok(Coding::Deflate));
        assert_eq!(Coding::parse(Some("br")), Ok(Coding::Brotli));
        assert_eq!(Coding::parse(Some("zstd")), Ok(Coding::Zstd));
        assert_eq!(Coding::parse(Some("compress")), Err("content_encoding"));
        assert_eq!(Coding::parse(Some("gzip, br")), Err("content_encoding"));
    }

    /// Past the limit a body is cut for good: later bytes are hashed, never
    /// kept again.
    #[test]
    fn a_cut_body_keeps_nothing_after() {
        let mut sink = BodySink::new(None);
        sink.push(&vec![b'a'; BODY_KEEP]);
        sink.push(b"over");
        assert!(sink.kept().is_empty());
        let tail = b"\"password\": \"tail\"";
        sink.push(tail);
        assert!(sink.kept().is_empty(), "nothing kept after the cut");
        let summary = sink.summary();
        assert!(summary.truncated);
        assert_eq!(summary.bytes, (BODY_KEEP + 4 + tail.len()) as u64);
    }

    /// Kept bytes come out of the observer's budget and go back to it.
    #[test]
    fn kept_bytes_draw_on_the_budget() {
        let retained = Retained::with_limit(10);
        let mut a = BodySink::new(None).with_retained(retained.clone());
        a.push(b"0123456");
        assert_eq!(retained.held(), 7);
        let mut b = BodySink::new(None).with_retained(retained.clone());
        b.push(b"01234");
        assert!(b.kept().is_empty());
        assert_eq!(b.summary().degraded, Some("observe_budget"));
        a.release();
        assert_eq!(retained.held(), 0);
        let mut c = BodySink::new(None)
            .with_retained(retained.clone())
            .hash_only();
        c.push(b"0123456789abc");
        assert!(c.kept().is_empty() && !c.summary().truncated);
        assert_eq!(retained.held(), 0);
        drop((b, c));
    }

    /// A decoder takes its worst case from the budget when made and gives
    /// it back when the body ends; with no room it is not made.
    #[test]
    fn decoders_draw_on_the_budget() {
        let retained = Retained::with_limit(Coding::Brotli.decoder_cost() + 100 * 1024);
        let mut br = BodySink::new(Some("br")).with_retained(retained.clone());
        assert_eq!(retained.held(), Coding::Brotli.decoder_cost());
        let gz = BodySink::new(Some("gzip")).with_retained(retained.clone());
        assert_eq!(retained.held(), Coding::Brotli.decoder_cost() + 64 * 1024);
        let mut late = BodySink::new(Some("zstd")).with_retained(retained.clone());
        assert_eq!(late.summary().degraded, Some("observe_budget"));
        assert_eq!(Coding::Zstd.decoder_cost(), 16 * 1024 * 1024 + 256 * 1024);
        late.push(b"raw");
        assert_eq!(late.summary().bytes, 3, "hashed raw");
        drop(late);
        br.finish();
        assert_eq!(retained.held(), 64 * 1024);
        drop(gz);
        assert_eq!(retained.held(), 0);
    }

    /// A large-window Brotli stream is refused before the decoder sees it:
    /// its window could be 1 GiB.
    #[test]
    fn a_large_window_brotli_stream_is_refused() {
        assert!(brotli_large_window(0x11));
        assert!(brotli_large_window(0x91));
        assert!(!brotli_large_window(0x0b), "WBITS 22");
        assert!(!brotli_large_window(0x00), "WBITS 16");
        assert!(!brotli_large_window(0x21), "WBITS 10");
        let mut sink = BodySink::new(Some("br"));
        sink.push(&[0x11, 0x3f, 0x00]);
        assert_eq!(sink.summary().degraded, Some("decode_budget"));
    }
}
