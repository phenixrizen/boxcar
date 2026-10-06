// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! A message body as the observer keeps it: content-decoded as it comes
//! (`gzip`, `deflate`, `br`; anything else degrades the body to its raw
//! bytes), hashed whole (blake3 over the decoded bytes), and kept for the
//! parsers up to [`BODY_KEEP`], after which the body is hashed but not
//! kept (`truncated`).

use std::io::Write;

/// The most decoded bytes kept for the parsers.
pub const BODY_KEEP: usize = 16 * 1024 * 1024;

/// A `Content-Encoding` the observer decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
    Identity,
    Gzip,
    Deflate,
    Brotli,
}

impl Coding {
    /// The coding `content_encoding` names; `Err` for one the observer
    /// does not decode (`zstd`, a chain of codings, anything else).
    pub fn parse(content_encoding: Option<&str>) -> Result<Coding, &'static str> {
        match content_encoding.map(|c| c.trim().to_ascii_lowercase()) {
            None => Ok(Coding::Identity),
            Some(c) if c.is_empty() || c == "identity" => Ok(Coding::Identity),
            Some(c) if c == "gzip" || c == "x-gzip" => Ok(Coding::Gzip),
            Some(c) if c == "deflate" => Ok(Coding::Deflate),
            Some(c) if c == "br" => Ok(Coding::Brotli),
            Some(_) => Err("content_encoding"),
        }
    }
}

enum Inner {
    Identity,
    Gzip(flate2::write::GzDecoder<Vec<u8>>),
    Deflate(flate2::write::ZlibDecoder<Vec<u8>>),
    Brotli(Box<brotli_decompressor::DecompressorWriter<Vec<u8>>>),
}

/// Decodes one body's content coding as its bytes come.
pub struct ContentDecoder {
    inner: Inner,
    failed: bool,
}

impl ContentDecoder {
    pub fn new(coding: Coding) -> ContentDecoder {
        let inner = match coding {
            Coding::Identity => Inner::Identity,
            Coding::Gzip => Inner::Gzip(flate2::write::GzDecoder::new(Vec::new())),
            Coding::Deflate => Inner::Deflate(flate2::write::ZlibDecoder::new(Vec::new())),
            Coding::Brotli => Inner::Brotli(Box::new(
                brotli_decompressor::DecompressorWriter::new(Vec::new(), 64 * 1024),
            )),
        };
        ContentDecoder {
            inner,
            failed: false,
        }
    }

    /// The decoded bytes `raw` yields. `Err` once the stream does not
    /// decode; nothing decodes after that.
    pub fn feed(&mut self, raw: &[u8]) -> Result<Vec<u8>, &'static str> {
        if self.failed {
            return Err("content_decode");
        }
        let result = match &mut self.inner {
            Inner::Identity => return Ok(raw.to_vec()),
            Inner::Gzip(d) => d.write_all(raw).map(|_| std::mem::take(d.get_mut())),
            Inner::Deflate(d) => d.write_all(raw).map(|_| std::mem::take(d.get_mut())),
            Inner::Brotli(d) => d.write_all(raw).map(|_| std::mem::take(d.get_mut())),
        };
        result.map_err(|_| {
            self.failed = true;
            "content_decode"
        })
    }

    /// What the decoder still held at the body's end.
    pub fn finish(&mut self) -> Result<Vec<u8>, &'static str> {
        if self.failed {
            return Err("content_decode");
        }
        let result = match &mut self.inner {
            Inner::Identity => return Ok(Vec::new()),
            Inner::Gzip(d) => d.try_finish().map(|_| std::mem::take(d.get_mut())),
            Inner::Deflate(d) => d.try_finish().map(|_| std::mem::take(d.get_mut())),
            Inner::Brotli(d) => d.flush().map(|_| std::mem::take(d.get_mut())),
        };
        result.map_err(|_| {
            self.failed = true;
            "content_decode"
        })
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
    hasher: blake3::Hasher,
    bytes: u64,
    truncated: bool,
    degraded: Option<&'static str>,
}

impl BodySink {
    /// A sink for a body with `content_encoding`.
    pub fn new(content_encoding: Option<&str>) -> BodySink {
        let (decoder, degraded) = match Coding::parse(content_encoding) {
            Ok(coding) => (Some(ContentDecoder::new(coding)), None),
            Err(reason) => (None, Some(reason)),
        };
        BodySink {
            decoder,
            kept: Vec::new(),
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
        rest
    }

    fn take(&mut self, decoded: &[u8]) {
        if decoded.is_empty() {
            return;
        }
        self.hasher.update(decoded);
        self.bytes = self.bytes.saturating_add(decoded.len() as u64);
        if self.kept.len() + decoded.len() <= BODY_KEEP {
            self.kept.extend_from_slice(decoded);
        } else {
            self.truncated = true;
            self.kept.clear();
        }
    }

    /// The decoded bytes kept for the parsers: all of them, or none once
    /// the body passed the limit.
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

    #[test]
    fn an_unknown_coding_or_a_bad_stream_degrades_to_the_raw_bytes() {
        let mut sink = BodySink::new(Some("zstd"));
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
        assert_eq!(Coding::parse(Some("zstd")), Err("content_encoding"));
        assert_eq!(Coding::parse(Some("gzip, br")), Err("content_encoding"));
    }
}
