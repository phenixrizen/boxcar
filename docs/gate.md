# The model traffic gate

What `--inspect` does to a connection, what it records of the model
traffic, what it leaves out on purpose, and how to look at the traffic by
hand. The record fields are in [audit-events.md](audit-events.md); the
network around it is [networking.md](networking.md); what the reconciler
makes of the records is [reconciler.md](reconciler.md).

## What is inspected

An `inspect RULE` (`boxcar run --inspect RULE`, or an `inspect` line in
`--policy-file`) is written like an `allow` rule: `name[:port]`,
`*.name[:port]`, `address[:port]` or `address/prefix[:port]`. It decides
nothing: an `allow` rule must still admit the connection. Once one has,
and the connection's first bytes show a name (a TLS server name or an
HTTP `Host`) an `inspect` line names, or its destination falls in an
`inspect` line's network, the connection is watched:

- **TLS.** The guest's TLS ends in boxcar. The real host is reached with
  boxcar's own TLS, verified against the host's trust store (the system's
  roots; nothing else in a release build), and the guest is handed a
  certificate for the name it asked for, signed by the session's CA. The
  plaintext is relayed byte for byte both ways, with a copy to the
  observer. Nothing is modified, and nothing is injected: the agent's own
  credential goes to the provider as the agent sent it, and boxcar never
  holds one. `net.tls{inspect:true}` says the connection was decided for
  inspection, `net.inspect` says how it went (`ok`, `upstream_untrusted`,
  `upstream_failed`, `guest_rejected`, `timeout`) with the server name,
  the ALPN protocol and the TLS version agreed.
- **Plain HTTP.** Observed as it is; nothing to end.
- **Neither.** A connection read for inspection that shows neither TLS
  nor HTTP within the gate's limit is relayed untouched.

A host the trust store does not vouch for, a guest that refuses the leaf,
and a handshake slower than 5 s end the connection with nothing relayed:
`net.inspect` says which, and `net.close{reason:"inspect"}` follows. The
gate fails closed; it never falls back to relaying a connection it could
not verify.

## The session's CA

Each session with an `inspect` line makes its own CA: ECDSA P-256, named
`boxcar session <id>`, valid for 30 days from an hour before it was made.
The key lives in the `boxcar run` process and nowhere else; the leaves it
signs are made on demand, one per name, and kept in memory. The
certificate (never the key) goes to the guest with the session's config:
init writes it to `/run/boxcar/ca.pem`, binds a bundle holding it and the
guest's own roots over `/etc/ssl/certs/ca-certificates.crt`, and names it
in the session's environment (`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`,
`CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`), so Node, Bun,
Python, curl and git trust it without configuration. `vmm.start` records
the CA's fingerprint (`inspect_ca_sha256`), so a log can be matched to the
CA its session trusted. A later session trusts nothing from an earlier
one.

## What is recorded

The observer (thread `gate-observe`, fed by a bounded channel the net
thread never waits on) reads each inspected flow's plaintext as HTTP/1.1
or HTTP/2 (chosen by the ALPN protocol), with HPACK, chunked and
content-length framing, gzip, deflate and brotli content codings, event
streams and WebSocket upgrades.

- `http.request` and `http.response`: one pair per exchange, with the
  method, authority, path, content type, status, the body's size and
  blake3 hash, and the duration. Bodies are hashed whatever their size and
  parsed up to 16 MiB; past that the record says `body_truncated`.
- `llm.request` and `llm.response`: the model APIs the gate knows, chosen
  by the request's path: the Anthropic Messages API (`/v1/messages`),
  OpenAI Chat Completions (`/chat/completions`) and OpenAI Responses
  (`/responses`, as a document, as an event stream, or over WebSocket).
  The provider, the model, whether the reply streamed, the message count,
  the system prompt's hash, the tools offered, the token counts, the stop
  reason, the reply text's size and hash.
- `tool.open` and `tool.close`: each tool use in a reply opens a span (the
  tool, its arguments' hash and a 512-byte scrubbed summary, the arguments
  inline when their JSON is at most 8 KiB); the tool result the agent
  sends back in its next request closes it (its status, size, hash and
  summary). Both carry the span in their envelope: the session id as the
  trace id, the provider's tool use id as the span id. The reconciler
  attributes the processes and effects in between to the span and writes
  `span.effects`.

A body that cannot be read (a truncated body, a lost chunk, a flow closed
mid-reply, an unknown content coding, a WebSocket extension the observer
does not inflate) degrades the record rather than losing it: `degraded`
says why.

## What is not recorded

- **No text is ever inline.** Prompts, replies and tool results appear as
  sizes and hashes, and in summaries of at most 512 bytes that go through
  the redaction scrub. Tool arguments are the one thing kept whole, up to
  8 KiB, because they are what the agent asked to run.
- **No credential.** The header names `authorization`,
  `proxy-authorization`, `x-api-key`, `cookie`, `set-cookie`,
  `x-goog-api-key`, `api-key`, and any name ending in `-token`, `-secret`
  or `-password`, have their values dropped at the parser, the one place
  headers are read: no record, summary, dump file or log line ever holds
  one. The scrub on summaries is defence in depth, not the mechanism.
- **Not the bytes of other protocols.** A connection that is not HTTP is
  relayed and counted, not read.

## Limits

| What | Limit |
|---|---|
| The observer's channel | 4096 messages of at most 64 KiB; a full channel drops the chunk, marks the flow's streams `degraded{observer_lag}` and counts `net.drop{reason:"observe"}` |
| A header block; a header name or value | 64 KiB; 8 KiB each |
| A path in a record; a user agent | 4096 bytes; 512 bytes |
| Concurrent streams per flow | 256 |
| A body kept for parsing | 16 MiB (hashed whatever its size) |
| A WebSocket message | 16 MiB |
| Tool arguments inline; a summary | 8 KiB; 512 bytes |
| Leaves the CA keeps | 1024, the oldest dropped first |
| An inspected handshake, either leg | 5 s |

## Looking at the traffic: `--dump DIR`

`boxcar run --dump DIR` writes, for debugging:

- `frames.pcap`: every frame the guest sent and every frame it was given,
  as a pcap 2.4 file (Ethernet, microsecond timestamps), after bitvessel's
  `DebugNet`. Open it with Wireshark or `tcpdump -r`. A frame the dump's
  queue had no room for is dropped and counted (`net.drop{reason:"dump"}`);
  the net thread never waits on the dump.
- `http/<flow>-<stream>.req` and `.resp`: each decoded exchange of an
  inspected flow, by its `net.connect` flow id and stream: the start line,
  the headers as the observer keeps them (a credential's value is already
  gone), a blank line, the decoded body. A JSON body has its secret-looking
  fields scrubbed as the audit log's summaries are, and a form body (the
  shape of an OAuth token exchange) its credential fields' values replaced.
  The raw plaintext is not written: it would hold what the records never
  do. An exchange upgraded to WebSocket gets `http/<flow>-<stream>.ws` as
  well: its messages one after another, each with its direction and size
  and, for a text message, the text scrubbed the same way.

DIR is made mode 0700 and every file 0600; it may be neither a share nor
inside one, nor hold one. The dump is an aid, not part of the audit log:
nothing in it is hashed or chained, and `boxcar audit verify` does not
look at it. Filesystem traffic has its own dump: `--audit-level verbose`.

## Running an agent inside

Claude Code (installed natively or from npm, which since 2.1 installs the same native build) and Codex run
inside on their own account logins: the agent presents its token to the
provider as it would anywhere, over a connection the gate inspects, and
boxcar records what was asked and what was answered without ever holding
the token. The README's "Running Claude Code and Codex inside" has the
commands; `cargo xtask rootfs debian` builds the guest they need.
