// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Reading a session's log back as typed records.
//!
//! [`LogReader`] parses each line as a [`Record`], whose `data` stays an
//! untyped `Value`. It trusts the log: to check one, use
//! [`verify_session`](crate::verify_session), which works from the raw bytes.
//!
//! A reader may run while the writer is still appending. A partial line at
//! the end of the newest segment is a write in progress (or, after a crash,
//! a torn tail) and ends the iteration without an error.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use boxcar_proto::Record;
use serde::Deserialize;

use crate::checkpoint::read_index;
use crate::segment::{invalid_data, last_line, list_segments, segment_name};

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
    /// that is not a record yields an error naming its segment and line
    /// number, and ends the iteration.
    pub fn records(&self) -> impl Iterator<Item = io::Result<Record>> + '_ {
        let mut lines = Lines::new(&self.dir, self.start);
        let mut done = false;
        std::iter::from_fn(move || {
            if done {
                return None;
            }
            let item = match lines.next_line() {
                Ok(Some((at, line))) => serde_json::from_slice::<Record>(&line)
                    .map_err(|e| bad_line(&self.dir, at, &e.to_string())),
                Ok(None) => return None,
                Err(e) => Err(e),
            };
            done = item.is_err();
            Some(item)
        })
    }

    /// Positions the reader at the first record whose seq is `seq` or more,
    /// or at the end of the log if there is none.
    ///
    /// It starts from the last checkpoint at or before `seq` that
    /// `checkpoints.jsonl` names, when the record there is the one named, and
    /// reads on from there; otherwise from the first record.
    pub fn seek_seq(&mut self, seq: u64) -> io::Result<()> {
        #[derive(Deserialize)]
        struct Seq {
            seq: u64,
        }

        let mut from = START;
        if let Some(entry) = read_index(&self.dir)
            .into_iter()
            .rev()
            .find(|e| e.seq <= seq)
        {
            let at = Position {
                segment: entry.segment,
                offset: entry.offset,
            };
            let named = Lines::new(&self.dir, at).next_line().ok().flatten();
            let named = named.and_then(|(_, line)| serde_json::from_slice::<Seq>(&line).ok());
            if named.is_some_and(|s| s.seq == entry.seq) {
                from = at;
            }
        }

        let mut lines = Lines::new(&self.dir, from);
        while let Some((at, line)) = lines.next_line()? {
            let found: Seq = serde_json::from_slice(&line)
                .map_err(|e| bad_line(&self.dir, at, &e.to_string()))?;
            if found.seq >= seq {
                self.start = at;
                return Ok(());
            }
        }
        self.start = lines.position();
        Ok(())
    }

    /// The last record of the log, or `None` if it has none.
    pub fn last(&self) -> io::Result<Option<Record>> {
        for n in list_segments(&self.dir)?.into_iter().rev() {
            if let Some((offset, line)) = last_line(&self.dir.join(segment_name(n)))? {
                let at = Position { segment: n, offset };
                return serde_json::from_slice(&line)
                    .map(Some)
                    .map_err(|e| bad_line(&self.dir, at, &e.to_string()));
            }
        }
        Ok(None)
    }
}

/// The complete lines of a log from a position on, across segments.
struct Lines<'a> {
    dir: &'a Path,
    at: Position,
    reader: Option<BufReader<File>>,
    buf: Vec<u8>,
}

impl<'a> Lines<'a> {
    fn new(dir: &'a Path, at: Position) -> Self {
        Lines {
            dir,
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
                return Err(bad_line(self.dir, self.at, "no newline at the end"));
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
