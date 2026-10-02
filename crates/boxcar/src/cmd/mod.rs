// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The subcommands, one module each.

mod attach;
mod audit;
mod doctor;
mod events;
mod nofile;
mod policy;
pub(crate) mod run;
mod status;
mod stop;

use std::io::{self, Write};
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::cli::{Cli, Command};

/// How long [`tell`] waits for stderr.
const TELL_LIMIT: Duration = Duration::from_millis(250);

/// Says `line` on stderr, but does not wait for it longer than
/// [`TELL_LIMIT`]. For what is said once a VM has stopped: when stderr
/// shares a stalled sink with the console (`boxcar run ... 2>&1 |
/// slow-reader`) a plain `eprintln!` blocks for as long as the reader does,
/// and the process, whose work is done, never exits. A line that cannot be
/// written in time is lost.
pub(crate) fn tell(line: &str) {
    tell_to(io::stderr(), line, TELL_LIMIT);
}

fn tell_to(mut out: impl Write + Send + 'static, line: &str, limit: Duration) {
    let line = format!("{line}\n");
    let (done, finished) = mpsc::channel();
    // The thread is left behind if the write is stuck; it ends with the
    // process.
    let spawned = thread::Builder::new().name("tell".into()).spawn(move || {
        let _ = out.write_all(line.as_bytes());
        let _ = done.send(());
    });
    if spawned.is_ok() {
        let _ = finished.recv_timeout(limit);
    }
}

/// Runs the command `cli` names and returns the process exit code.
pub fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    match cli.command {
        Command::Attach(args) => attach::run(&args),
        Command::Audit(command) => audit::run(command),
        Command::Doctor => doctor::run(),
        Command::Events(args) => events::run(&args),
        Command::Policy(command) => policy::run(command),
        Command::Run(args) => run::run(*args),
        Command::Status(args) => status::run(&args),
        Command::Stop(args) => stop::run(&args),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use super::*;

    /// A stderr that keeps what it is given, and blocks while `gate` is held.
    #[derive(Clone, Default)]
    struct Stderr {
        gate: Arc<Mutex<()>>,
        got: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for Stderr {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let _gate = self.gate.lock().unwrap();
            self.got.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_line_is_written_when_stderr_takes_it() {
        let err = Stderr::default();
        tell_to(err.clone(), "stop requested", Duration::from_secs(5));
        assert_eq!(*err.got.lock().unwrap(), b"stop requested\n");
    }

    #[test]
    fn a_stalled_stderr_does_not_keep_the_process_from_exiting() {
        let err = Stderr::default();
        let stall = err.gate.lock().unwrap();
        let start = Instant::now();
        tell_to(err.clone(), "stop requested", Duration::from_millis(200));
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(200), "{waited:?}");
        assert!(waited < Duration::from_secs(3), "{waited:?}");
        // Released, the abandoned write completes on its own thread.
        drop(stall);
        let deadline = Instant::now() + Duration::from_secs(5);
        while err.got.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "the write never finished");
            thread::sleep(Duration::from_millis(5));
        }
    }
}
