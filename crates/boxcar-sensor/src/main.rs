// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The guest sensor: ring 1 of the audit log. Started by init before the
//! session's privileges drop, it connects to the VMM on vsock port 1026,
//! loads the eBPF programs it carries ([`object`]) with the session's cgroup
//! as their filter, attaches them, says what it attached
//! (`proc.sensor_status`), and then streams their events as `proc.*` frames
//! with a heartbeat every second. One thread, on `poll(2)`: the ring
//! buffer's descriptor, or the time to the next heartbeat.
//!
//! Whatever fails to load is reported, not fatal: a sensor with no programs
//! at all still connects and heartbeats, so its silence always means
//! something. The stream's end (the VMM closed it) ends the sensor.
//!
//! `boxcar-sensor probe-bpf` and `probe-kill [PID]` are for the gated
//! tests ([`probe`]).

mod frame;
mod heartbeat;
mod load;
mod object;
mod probe;
mod status;
mod vsock;

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;
use std::time::Instant;

use boxcar_proto::sensor::{encode, SensorFrame};

use crate::heartbeat::Heartbeat;
use crate::status::Facts;

/// The cgroup init puts the session in; its inode is its id.
const SESSION_CGROUP: &str = "/sys/fs/cgroup/session";

/// Where the kernel offers its BTF.
const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

#[derive(Debug, thiserror::Error)]
enum SensorError {
    #[error("{0}")]
    Args(String),
    #[error("cannot connect to the VMM's sensor port: {0}")]
    Connect(std::io::Error),
    #[error("the stream to the VMM ended: {0}")]
    Write(std::io::Error),
    #[error("a frame of the sensor's own was refused: {0}")]
    Frame(#[from] boxcar_proto::sensor::FrameError),
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("probe-bpf") => probe::bpf(),
        Some("probe-kill") => probe::kill(args.get(2)),
        _ => match run(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("boxcar-sensor: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

/// `--session-cgroup=<id>`, or the inode of the session cgroup.
fn session_cgroup(args: &[String]) -> Result<u64, SensorError> {
    for arg in args {
        if let Some(value) = arg.strip_prefix("--session-cgroup=") {
            return value
                .parse()
                .map_err(|_| SensorError::Args(format!("--session-cgroup={value}: not a number")));
        }
    }
    std::fs::metadata(SESSION_CGROUP)
        .map(|meta| meta.ino())
        .map_err(|e| SensorError::Args(format!("{SESSION_CGROUP}: {e}; pass --session-cgroup")))
}

/// The guest's `CLOCK_MONOTONIC`, the clock the programs stamp events with.
fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid pointer to a timespec, which the call fills.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    u64::try_from(ts.tv_sec).unwrap_or(0) * 1_000_000_000 + u64::try_from(ts.tv_nsec).unwrap_or(0)
}

fn kernel_release() -> String {
    // SAFETY: utsname is plain data; uname fills it.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: a valid pointer to a utsname.
    if unsafe { libc::uname(&mut name) } != 0 {
        return "unknown".to_owned();
    }
    let bytes: Vec<u8> = name
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn write_frame(out: &mut std::fs::File, frame: &SensorFrame) -> Result<(), SensorError> {
    let bytes = encode(frame)?;
    out.write_all(&bytes).map_err(SensorError::Write)
}

fn run(args: &[String]) -> Result<(), SensorError> {
    let cgroup = session_cgroup(args)?;
    let mut out = vsock::connect().map_err(SensorError::Connect)?;
    let pid = std::process::id();
    let facts = Facts {
        btf_ok: std::path::Path::new(BTF_PATH).exists(),
        kernel_release: kernel_release(),
        session_cgroup_id: cgroup,
        pid,
    };
    let loaded = load::load(cgroup, u64::from(pid));
    let mut heartbeat = Heartbeat::new(Instant::now());
    write_frame(
        &mut out,
        &status::status_frame(
            &loaded.results,
            &facts,
            loaded.reason.clone(),
            monotonic_ns(),
        ),
    )?;
    heartbeat.sent();
    for result in &loaded.results {
        if let Some(error) = &result.error {
            eprintln!("boxcar-sensor: {}: {error}", result.name);
        }
    }

    let load::Loaded {
        ebpf: _ebpf,
        events,
        drops,
        ..
    } = loaded;
    let mut events = events;
    let mut poll = [libc::pollfd {
        fd: events.as_ref().map_or(-1, |ring| ring.as_raw_fd()),
        events: libc::POLLIN,
        revents: 0,
    }];
    loop {
        let now = Instant::now();
        if heartbeat.due(now) {
            let frame = heartbeat.frame(now, load::drops_total(drops.as_ref()), monotonic_ns());
            write_frame(&mut out, &frame)?;
            heartbeat.sent();
        }
        let wait = heartbeat.wait(Instant::now());
        let timeout = libc::c_int::try_from(wait.as_millis()).unwrap_or(libc::c_int::MAX);
        poll[0].revents = 0;
        // SAFETY: poll reads and writes the one pollfd given, for the count given.
        let ready = unsafe { libc::poll(poll.as_mut_ptr(), 1, timeout) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SensorError::Write(error));
        }
        if ready == 0 || poll[0].revents & libc::POLLIN == 0 {
            continue;
        }
        let Some(ring) = events.as_mut() else {
            continue;
        };
        while let Some(item) = ring.next() {
            match frame::frame_from_event(&item) {
                Ok(frame) => {
                    write_frame(&mut out, &frame)?;
                    heartbeat.events_emitted += 1;
                    heartbeat.sent();
                }
                Err(error) => eprintln!("boxcar-sensor: dropped an event: {error}"),
            }
        }
    }
}
