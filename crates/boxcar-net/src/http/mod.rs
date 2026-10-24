// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The HTTP observer's parsers: what an inspected flow's plaintext says,
//! read passively, in both directions, as the bytes come.
//!
//! [`Connection::feed`] takes plaintext with its direction and gives
//! [`Event`]s: a request's head, its body in pieces, its end; a response's
//! the same; the connection switching to WebSocket on a `101`, and the
//! messages after; and `Degraded` when something could not be read. The
//! framing is HTTP/1.1 ([`h1`]: request lines, headers, `Content-Length`,
//! chunked bodies, pipelining) or HTTP/2 ([`h2`]: frames, HPACK through
//! `fluke-hpack`, streams), chosen by the ALPN protocol the TLS legs
//! agreed on. Bodies come out as framed, still content-coded; [`body`]
//! decodes and hashes them ([`zstd`] delimits that coding's frames for
//! its decoder), [`sse`] splits event streams, [`ws`] reads WebSocket
//! frames. Headers come out as [`Headers`], which never hold a
//! credential's value.
//!
//! Nothing here allocates without a bound: a head is at most 64 KiB, a
//! field 8 KiB, and the bodies the observer keeps are bounded in [`body`].

pub mod body;
pub mod h1;
pub mod h2;
pub mod headers;
pub mod retain;
pub mod sse;
pub mod ws;
pub mod zstd;

pub use body::{BodySink, BodySummary, Coding, ContentDecoder, BODY_KEEP};
pub use headers::{is_credential, Headers};
pub use retain::{Retained, Share, RETAINED_LIMIT};
pub use sse::{SseEvent, SseItem, SseParser};

use crate::gate::Direction;

/// Which HTTP a connection speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Version {
    Http1,
    Http2,
}

impl Version {
    /// As `http.*` records name it.
    pub fn as_str(self) -> &'static str {
        match self {
            Version::Http1 => "1.1",
            Version::Http2 => "2",
        }
    }
}

/// What the parsers read. `stream` tells a connection's exchanges apart:
/// HTTP/2's stream id, or 1, 2, 3... for HTTP/1.1's requests in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    RequestHead {
        stream: u32,
        method: String,
        /// `:authority`, or the `Host` header.
        authority: Option<String>,
        path: Option<String>,
        version: Version,
        headers: Headers,
    },
    /// Body bytes as framed: still content-coded.
    RequestBody {
        stream: u32,
        bytes: Vec<u8>,
    },
    RequestEnd {
        stream: u32,
    },
    ResponseHead {
        stream: u32,
        status: u16,
        headers: Headers,
    },
    ResponseBody {
        stream: u32,
        bytes: Vec<u8>,
    },
    ResponseEnd {
        stream: u32,
    },
    /// A `101` switched the connection to WebSocket, with these
    /// extensions agreed; the frames follow as `WsMessage`s.
    Upgraded {
        stream: u32,
        extensions: Vec<String>,
    },
    /// A whole WebSocket message, inflated if it was compressed.
    WsMessage {
        stream: u32,
        dir: Direction,
        text: bool,
        payload: Vec<u8>,
    },
    /// A WebSocket close frame.
    WsClosed {
        stream: u32,
    },
    /// Something could not be read. With `whole` the direction (both, for
    /// a `direction` of `None`) is read no further; otherwise only
    /// `stream` is. `stream` is `None` when no stream is concerned.
    Degraded {
        /// The direction that stopped being read, or `None` for both.
        direction: Option<Direction>,
        stream: Option<u32>,
        reason: &'static str,
        /// The direction (or, with none, the connection) is read no
        /// further, not only the stream.
        whole: bool,
    },
}

impl Event {
    pub fn stream(&self) -> Option<u32> {
        match self {
            Event::RequestHead { stream, .. }
            | Event::RequestBody { stream, .. }
            | Event::RequestEnd { stream }
            | Event::ResponseHead { stream, .. }
            | Event::ResponseBody { stream, .. }
            | Event::ResponseEnd { stream }
            | Event::Upgraded { stream, .. }
            | Event::WsMessage { stream, .. }
            | Event::WsClosed { stream } => Some(*stream),
            Event::Degraded { stream, .. } => *stream,
        }
    }
}

enum Inner {
    H1(h1::H1),
    H2(h2::H2),
    Ws(ws::Ws),
    /// Nothing more is read: the reason was reported.
    Broken,
}

/// One inspected connection's plaintext, both ways.
pub struct Connection {
    inner: Inner,
}

/// A buffer that holds much less than its allocation shrinks to fit (with
/// some room): a buffer drained after a large frame or line does not keep
/// its peak allocation, so what is held is what is charged.
pub(crate) fn trim(buf: &mut Vec<u8>) {
    const SLACK: usize = 64 * 1024;
    if buf.capacity() > SLACK && buf.capacity() > 2 * buf.len() {
        buf.shrink_to(buf.len().max(SLACK / 4));
    }
}

impl Connection {
    /// A connection speaking the protocol `alpn` named (`h2`), else
    /// HTTP/1.1.
    pub fn new(alpn: Option<&str>) -> Connection {
        let inner = match alpn {
            Some("h2") => Inner::H2(h2::H2::new()),
            _ => Inner::H1(h1::H1::new()),
        };
        Connection { inner }
    }

    pub fn version(&self) -> Version {
        match self.inner {
            Inner::H2(_) => Version::Http2,
            _ => Version::Http1,
        }
    }

    /// Takes plaintext that moved in `dir`, appending what it completes to
    /// `out`.
    pub fn feed(&mut self, dir: Direction, bytes: &[u8], out: &mut Vec<Event>) {
        match &mut self.inner {
            Inner::H1(h1) => {
                h1.feed(dir, bytes, out);
                if let Some(upgrade) = h1.take_upgrade() {
                    match ws::Ws::new(upgrade.stream, &upgrade.extensions) {
                        Ok(mut ws) => {
                            ws.feed(Direction::ToHost, &upgrade.c2s, out);
                            ws.feed(Direction::ToGuest, &upgrade.s2c, out);
                            self.inner = Inner::Ws(ws);
                        }
                        Err(reason) => {
                            out.push(Event::Degraded {
                                direction: None,
                                stream: Some(upgrade.stream),
                                reason,
                                whole: true,
                            });
                            self.inner = Inner::Broken;
                        }
                    }
                }
            }
            Inner::H2(h2) => h2.feed(dir, bytes, out),
            Inner::Ws(ws) => ws.feed(dir, bytes, out),
            Inner::Broken => {}
        }
    }

    /// Plaintext was lost in `dir` (the observer's channel had no room):
    /// what was open there cannot be read further.
    pub fn lost(&mut self, dir: Direction, out: &mut Vec<Event>) {
        match &mut self.inner {
            Inner::H1(h1) => h1.lost(dir, out),
            Inner::H2(h2) => {
                // HPACK's table is gone with the bytes: nothing further
                // decodes either way.
                h2.lost(out);
                self.inner = Inner::Broken;
            }
            Inner::Ws(ws) => ws.lost(dir, out),
            Inner::Broken => {}
        }
    }

    /// The bytes the parsers hold for this connection (their buffers'
    /// allocations), after trimming what they no longer need.
    pub fn held(&mut self) -> usize {
        match &mut self.inner {
            Inner::H1(h1) => h1.held(),
            Inner::H2(h2) => h2.held(),
            Inner::Ws(ws) => ws.held(),
            Inner::Broken => 0,
        }
    }

    /// The connection is observed no further (`reason`): its parsers and
    /// what they held go.
    pub fn give_up(&mut self, reason: &'static str, out: &mut Vec<Event>) {
        if !matches!(self.inner, Inner::Broken) {
            self.inner = Inner::Broken;
            out.push(Event::Degraded {
                direction: None,
                stream: None,
                reason,
                whole: true,
            });
        }
    }

    /// The connection ended: what was open ends.
    pub fn finish(&mut self, out: &mut Vec<Event>) {
        match &mut self.inner {
            Inner::H1(h1) => h1.finish(out),
            Inner::H2(h2) => h2.finish(out),
            Inner::Ws(ws) => ws.finish(out),
            Inner::Broken => {}
        }
    }
}
