// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Reading a session's log back as typed records.
//!
//! [`LogReader`] parses each line as a [`Record`], whose `data` stays an
//! untyped `Value`. It trusts the log's hashes: to check one, use
//! [`verify_session`](crate::verify_session), which works from the raw bytes.
//! It does not trust its syntax: a line with the same key twice in one
//! object, at any depth, is an error, as it is for the verifier, since
//! `serde_json` would keep the last of them and a reader that keeps the first
//! would see another record.
//!
//! A reader may run while the writer is still appending. A partial line at
//! the end of the newest segment is a write in progress (or, after a crash,
//! a torn tail) and ends the iteration without an error.
//!
//! A [`Filter`] picks records by type prefix, subject pid and score; the
//! live subscriptions of [`AuditSink::subscribe`](crate::AuditSink::subscribe)
//! use the same one on the writer's side.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use boxcar_proto::Record;
use serde::Deserialize;
use serde_json::Value;

use crate::checkpoint::read_index;
use crate::segment::{invalid_data, last_line, list_segments, segment_name};
use crate::verify::parse_record;

/// A place in the log: the start of a line, or the end of the last segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Position {
    segment: u32,
    offset: u64,
}

const START: Position = Position {
    segment: 1,
    offset: 0,
};

/// Which records a reader or a subscription wants. All three conditions must
/// hold; the default holds for every record.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Filter {
    /// Record types, each a prefix: `"net."` takes every `net.*` type,
    /// `"fs.write"` takes that type (and any longer one that starts with
    /// it). Empty takes every type.
    pub kinds: Vec<String>,
    /// The guest process the record is attributed to: its `subject.pid`. A
    /// record with no subject does not match.
    pub pid: Option<u32>,
    /// At least this `data.score`. A record whose `data` has no numeric
    /// `score` passes: only the sensor records of M3 carry one.
    pub min_score: Option<u8>,
}

impl Filter {
    /// Whether `record` is one the filter takes.
    pub fn matches(&self, record: &Record) -> bool {
        if !self.kinds.is_empty()
            && !self
                .kinds
                .iter()
                .any(|k| record.kind.starts_with(k.as_str()))
        {
            return false;
        }
        if let Some(pid) = self.pid {
            if record.subject.as_ref().map(|s| s.pid) != Some(pid) {
                return false;
            }
        }
        if let Some(min) = self.min_score {
            if let Some(score) = record.data.get("score").and_then(Value::as_f64) {
                if score < f64::from(min) {
                    return false;
                }
            }
        }
        true
    }
}

/// Reads the records of one session directory in log order.
#[derive(Debug)]
pub struct LogReader {
    dir: PathBuf,
    start: Position,
}

impl LogReader {
    /// Opens the session in `session_dir`, positioned at its first record.
    pub fn open(session_dir: &Path) -> io::Result<Self> {
        let first = session_dir.join(segment_name(1));
        File::open(&first)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", first.display())))?;
        Ok(LogReader {
            dir: session_dir.to_owned(),
            start: START,
        })
    }

    /// The records from the current position to the end of the log. A line
    /// that is not a record (or has a key twice) yields an error naming its
    /// segment and line number, and ends the iteration.
    pub fn records(&self) -> Records {
        Records::new(&self.dir, Origin::At(self.start))
    }

    /// The records from the first whose seq is `seq` or more to the end of
    /// the log, whatever the reader's own position: see
    /// [`seek_seq`](Self::seek_seq) for how it finds the start. The reader
    /// is not moved. The iterator owns what it reads, so it may be kept
    /// while the reader is not. Errors as [`records`](Self::records) does,
    /// the first of them one from finding the start.
    pub fn records_from(&self, seq: u64) -> Records {
        Records::new(&self.dir, Origin::Seq(seq))
    }

    /// Positions the reader at the first record whose seq is `seq` or more,
    /// or at the end of the log if there is none.
    ///
    /// It starts from the last checkpoint at or before `seq` that
    /// `checkpoints.jsonl` names, when the record there is the one named, and
    /// reads on from there; otherwise from the first record.
    pub fn seek_seq(&mut self, seq: u64) -> io::Result<()> {
        self.start = find_seq(&self.dir, seq)?;
        Ok(())
    }

    /// The last record of the log, or `None` if it has none.
    pub fn last(&self) -> io::Result<Option<Record>> {
        for n in list_segments(&self.dir)?.into_iter().rev() {
            if let Some((offset, line)) = last_line(&self.dir.join(segment_name(n)))? {
                let at = Position { segment: n, offset };
                return parse_record(&line)
                    .map(Some)
                    .map_err(|e| bad_line(&self.dir, at, &e));
            }
        }
        Ok(None)
    }
}

/// Where a [`Records`] starts.
#[derive(Clone, Copy, Debug)]
enum Origin {
    At(Position),
    /// The first record with this seq or more, found when the iteration
    /// starts.
    Seq(u64),
}

/// The records of a log from a point on, in order: what
/// [`LogReader::records`] and [`LogReader::records_from`] return. It owns
/// what it needs, and reads the log as it goes, so it sees records the
/// writer appends meanwhile, up to the end of the log at the moment it
/// reaches it.
#[derive(Debug)]
pub struct Records {
    dir: PathBuf,
    origin: Origin,
    lines: Option<Lines>,
    done: bool,
}

impl Records {
    fn new(dir: &Path, origin: Origin) -> Records {
        Records {
            dir: dir.to_owned(),
            origin,
            lines: None,
            done: false,
        }
    }

    fn step(&mut self) -> io::Result<Option<Record>> {
        let lines = match &mut self.lines {
            Some(lines) => lines,
            None => {
                let at = match self.origin {
                    Origin::At(at) => at,
                    Origin::Seq(seq) => find_seq(&self.dir, seq)?,
                };
                self.lines.insert(Lines::new(&self.dir, at))
            }
        };
        match lines.next_line()? {
            Some((at, line)) => parse_record(&line)
                .map(Some)
                .map_err(|e| bad_line(&self.dir, at, &e)),
            None => Ok(None),
        }
    }
}

impl Iterator for Records {
    type Item = io::Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let item = self.step().transpose();
        self.done = !matches!(item, Some(Ok(_)));
        item
    }
}

/// Where the first record with seq `seq` or more starts, or the end of the
/// log if there is none.
fn find_seq(dir: &Path, seq: u64) -> io::Result<Position> {
    #[derive(Deserialize)]
    struct Seq {
        seq: u64,
    }

    let mut from = START;
    if let Some(entry) = read_index(dir).into_iter().rev().find(|e| e.seq <= seq) {
        let at = Position {
            segment: entry.segment,
            offset: entry.offset,
        };
        let named = Lines::new(dir, at).next_line().ok().flatten();
        let named = named.and_then(|(_, line)| serde_json::from_slice::<Seq>(&line).ok());
        if named.is_some_and(|s| s.seq == entry.seq) {
            from = at;
        }
    }

    let mut lines = Lines::new(dir, from);
    while let Some((at, line)) = lines.next_line()? {
        let found: Seq =
            serde_json::from_slice(&line).map_err(|e| bad_line(dir, at, &e.to_string()))?;
        if found.seq >= seq {
            return Ok(at);
        }
    }
    Ok(lines.position())
}

/// The complete lines of a log from a position on, across segments.
#[derive(Debug)]
struct Lines {
    dir: PathBuf,
    at: Position,
    reader: Option<BufReader<File>>,
    buf: Vec<u8>,
}

impl Lines {
    fn new(dir: &Path, at: Position) -> Self {
        Lines {
            dir: dir.to_owned(),
            at,
            reader: None,
            buf: Vec::new(),
        }
    }

    /// Where the next line would start.
    fn position(&self) -> Position {
        self.at
    }

    /// The next complete line, without its newline, and where it starts.
    fn next_line(&mut self) -> io::Result<Option<(Position, Vec<u8>)>> {
        loop {
            let reader = match &mut self.reader {
                Some(reader) => reader,
                None => {
                    let path = self.dir.join(segment_name(self.at.segment));
                    let mut file = match File::open(&path) {
                        Ok(file) => file,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
                        Err(e) => return Err(e),
                    };
                    file.seek(SeekFrom::Start(self.at.offset))?;
                    self.reader.insert(BufReader::with_capacity(1 << 20, file))
                }
            };
            self.buf.clear();
            let n = reader.read_until(b'\n', &mut self.buf)?;
            if self.buf.ends_with(b"\n") {
                let at = self.at;
                self.at.offset += n as u64;
                self.buf.pop();
                return Ok(Some((at, std::mem::take(&mut self.buf))));
            }
            // The end of this segment, perhaps after a partial line. In the
            // newest segment that is the end of the log; before it, a
            // partial line is damage.
            let next = self.dir.join(segment_name(self.at.segment + 1));
            if !next.try_exists()? {
                return Ok(None);
            }
            if n > 0 {
                return Err(bad_line(&self.dir, self.at, "no newline at the end"));
            }
            self.at = Position {
                segment: self.at.segment + 1,
                offset: 0,
            };
            self.reader = None;
        }
    }
}

/// An error for the line at `at`, naming its segment and line number.
fn bad_line(dir: &Path, at: Position, reason: &str) -> io::Error {
    let line = match line_number(&dir.join(segment_name(at.segment)), at.offset) {
        Ok(line) => line.to_string(),
        Err(_) => format!("at byte {}", at.offset),
    };
    invalid_data(format!("segment {} line {line}: {reason}", at.segment))
}

/// The number, counting from 1, of the line that starts at `offset`.
fn line_number(path: &Path, offset: u64) -> io::Result<u64> {
    let mut prefix = File::open(path)?.take(offset);
    let mut buf = vec![0; 64 * 1024];
    let mut newlines = 0;
    loop {
        let n = prefix.read(&mut buf)?;
        if n == 0 {
            return Ok(newlines + 1);
        }
        newlines += buf[..n].iter().filter(|&&b| b == b'\n').count() as u64;
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use boxcar_proto::{Attrib, FsIo, OpResult, Payload, Ring, SessionId, Subject};
    use tempfile::TempDir;

    use super::*;
    use crate::sink::{Priority, Submission};
    use crate::writer::{spawn, WriterConfig};

    fn event(n: u64, pid: u32) -> Submission {
        Submission {
            ring: Ring::Host,
            ts_guest_ns: None,
            subject: Some(Subject {
                pid,
                uid: 1000,
                gid: 1000,
            }),
            payload: Payload::FsWrite(FsIo {
                mount: "workspace".into(),
                path: format!("/f{n}"),
                fh: n,
                offset: 0,
                len: 1,
                result: OpResult::ok(),
                attrib: Attrib::Caller,
            }),
            span: None,
            priority: Priority::Normal,
        }
    }

    /// A session of `n` events, closed, and its directory.
    fn session(tmp: &TempDir, n: u64) -> PathBuf {
        let (sink, writer) = spawn(WriterConfig::new(tmp.path(), SessionId::new())).unwrap();
        let dir = writer.session_dir().to_owned();
        for i in 0..n {
            sink.emit(event(i, 7)).unwrap();
        }
        writer.close().unwrap();
        dir
    }

    fn record(kind: &str, pid: Option<u32>, data: Value) -> Record {
        let mut record: Record = serde_json::from_value(serde_json::json!({
            "v": 1,
            "session_id": SessionId::new(),
            "seq": 1,
            "ring": 0,
            "src": "fs",
            "type": kind,
            "ts_host_ns": 1,
            "ts_mono_ns": 1,
            "data": data,
            "prev": format!("b3:{}", "0".repeat(64)),
            "hash": format!("b3:{}", "0".repeat(64)),
        }))
        .unwrap();
        record.subject = pid.map(|pid| Subject {
            pid,
            uid: 0,
            gid: 0,
        });
        record
    }

    #[test]
    fn reader_rejects_duplicate_keys() {
        let tmp = TempDir::new().unwrap();
        let dir = session(&tmp, 4);
        let segment = dir.join(segment_name(1));
        let text = fs::read_to_string(&segment).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 5, "four events and the closing checkpoint");

        // The same key twice: inside `data`, among the keys a record does
        // not know, and a known one at the top. Plain serde_json takes the
        // first two, keeping the last of each pair; it refuses the third
        // only because a typed field is a duplicate.
        let in_data = lines[2].replacen(r#""data":{"#, r#""data":{"fh":999,"#, 1);
        assert_ne!(in_data, lines[2]);
        let unknown = lines[2].replacen('{', r#"{"extra":1,"extra":2,"#, 1);
        let known = lines[2].replacen('{', r#"{"seq":999,"#, 1);
        for taken in [&in_data, &unknown] {
            assert!(
                serde_json::from_str::<Record>(taken).is_ok(),
                "serde_json takes it: {taken}"
            );
        }

        for (name, crafted) in [("data", &in_data), ("unknown", &unknown), ("seq", &known)] {
            let mut rewritten = lines.clone();
            rewritten[2] = crafted;
            fs::write(&segment, rewritten.join("\n") + "\n").unwrap();
            let reader = LogReader::open(&dir).unwrap();

            // From the start, and from a seq before it.
            let got: Vec<io::Result<Record>> = reader.records().collect();
            assert_eq!(got.len(), 3, "{name}: two records, then the error");
            assert!(got[0].is_ok() && got[1].is_ok());
            let error = got[2].as_ref().unwrap_err().to_string();
            assert!(
                error.contains("segment 1 line 3") && error.contains("duplicate"),
                "{name}: {error}"
            );

            let got: Vec<io::Result<Record>> = reader.records_from(2).collect();
            assert_eq!(got.len(), 2, "{name}");
            assert_eq!(got[0].as_ref().unwrap().seq, 2);
            assert!(got[1].as_ref().unwrap_err().to_string().contains("line 3"));

            // A seek reads only each line's seq, and stops after the line
            // it wants: past the damage it is read but does not matter,
            // unless it is the seq itself that is doubled.
            let got: Vec<io::Result<Record>> = reader.records_from(4).collect();
            if name == "seq" {
                assert!(got.len() == 1 && got[0].is_err(), "{name}");
            } else {
                assert!(got.iter().all(Result::is_ok), "{name}");
                assert_eq!(got.len(), 2, "{name}");
            }
        }

        // The last line, too.
        let mut rewritten = lines.clone();
        let last = rewritten[4].replacen(r#""data":{"#, r#""data":{"records_since":0,"#, 1);
        rewritten[4] = &last;
        fs::write(&segment, rewritten.join("\n") + "\n").unwrap();
        let error = LogReader::open(&dir).unwrap().last().unwrap_err();
        assert!(error.to_string().contains("duplicate key"), "{error}");
    }

    #[test]
    fn records_from_reads_from_a_seq_without_moving_the_reader() {
        let tmp = TempDir::new().unwrap();
        let dir = session(&tmp, 10);
        let reader = LogReader::open(&dir).unwrap();
        let seqs =
            |from: u64| -> Vec<u64> { reader.records_from(from).map(|r| r.unwrap().seq).collect() };
        assert_eq!(seqs(1), (1..=11).collect::<Vec<_>>());
        assert_eq!(seqs(0), (1..=11).collect::<Vec<_>>());
        assert_eq!(seqs(8), [8, 9, 10, 11]);
        assert_eq!(seqs(11), [11]);
        assert_eq!(seqs(12), Vec::<u64>::new());
        // The reader's own position is where it was.
        assert_eq!(reader.records().count(), 11);
        // An iterator outlives the reader that made it.
        let from_seven = reader.records_from(7);
        drop(reader);
        assert_eq!(from_seven.count(), 5);
    }

    #[test]
    fn a_filter_matches_by_prefix_pid_and_score() {
        let net = record("net.connect", Some(10), serde_json::json!({}));
        let fs = record("fs.write", Some(20), serde_json::json!({}));
        let unattributed = record("checkpoint", None, serde_json::json!({}));
        let all = Filter::default();
        assert!([&net, &fs, &unattributed].iter().all(|r| all.matches(r)));

        let kinds = |prefixes: &[&str]| Filter {
            kinds: prefixes.iter().map(|p| (*p).to_owned()).collect(),
            ..Filter::default()
        };
        // A prefix, the whole type, and any of several.
        assert!(kinds(&["net."]).matches(&net));
        assert!(!kinds(&["net."]).matches(&fs));
        assert!(kinds(&["fs.write"]).matches(&fs));
        assert!(!kinds(&["fs.write"]).matches(&record("fs.read", None, Value::Null)));
        assert!(kinds(&["net.", "fs."]).matches(&fs));
        assert!(kinds(&["net.", "fs."]).matches(&net));
        assert!(!kinds(&["net.", "fs."]).matches(&unattributed));
        assert!(
            kinds(&["net"]).matches(&net),
            "a prefix need not end at a dot"
        );

        // The pid is the subject's; no subject, no match.
        let pid = |pid| Filter {
            pid: Some(pid),
            ..Filter::default()
        };
        assert!(pid(10).matches(&net));
        assert!(!pid(10).matches(&fs));
        assert!(!pid(10).matches(&unattributed));

        // Both conditions must hold.
        let both = Filter {
            kinds: vec!["net.".into()],
            pid: Some(20),
            ..Filter::default()
        };
        assert!(!both.matches(&net) && !both.matches(&fs));

        // A score is compared when the record has one; without, it passes.
        let score = |n: u8| Filter {
            min_score: Some(n),
            ..Filter::default()
        };
        let scored = |s: Value| record("sensor.x", None, serde_json::json!({ "score": s }));
        assert!(score(50).matches(&scored(50.into())));
        assert!(score(50).matches(&scored(serde_json::json!(80.5))));
        assert!(!score(50).matches(&scored(49.into())));
        assert!(!score(50).matches(&scored(serde_json::json!(49.9))));
        assert!(score(50).matches(&net), "no score: it passes");
        assert!(score(50).matches(&scored("high".into())), "not a number");
    }
}
