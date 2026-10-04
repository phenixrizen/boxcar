// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! From an event the ring buffer hands over to the frame the VMM reads: the
//! `Header`'s kind picks the struct, the struct becomes a `proc.*` payload,
//! and the thread, user and guest clock from the header go beside it.

use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use boxcar_proto::limits::{MAX_ARGV_ELEMS, MAX_PATH};
use boxcar_proto::sensor::SensorFrame;
use boxcar_proto::{
    Payload, ProcConnectAttempt, ProcExec, ProcExit, ProcFileOpen, ProcFork, ProcLsmDeny,
    ProcMemfd, ProcTcpConnect, Subject,
};
use boxcar_sensor_common::{
    ConnectAttempt, ExecEvent, ExitEvent, FileOpen, ForkEvent, Header, Hook, Kind, LsmDeny,
    MemfdEvent, TcpConnect, AF_INET, AF_INET6, MEMFD_NAME_MAX,
};

/// Why bytes from the ring buffer are not an event.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum EventError {
    /// Fewer bytes than a header.
    #[error("{0} bytes, fewer than an event's header")]
    Short(usize),
    /// A header whose kind this build does not know.
    #[error("event kind {0} is not one this sensor knows")]
    UnknownKind(u32),
    /// A header's kind and the record's size disagree.
    #[error("a {kind:?} event of {got} bytes, not {expected}")]
    Size {
        kind: Kind,
        expected: usize,
        got: usize,
    },
}

/// Reads a `repr(C)` event out of `bytes`, which hold exactly one.
///
/// # Safety
/// `bytes.len() == size_of::<T>()`, and `T` is plain data (every bit
/// pattern is a value), which the event structs are.
unsafe fn read<T: Copy>(bytes: &[u8]) -> T {
    std::ptr::read_unaligned(bytes.as_ptr().cast::<T>())
}

/// The frame for one event the ring buffer handed over.
pub fn frame_from_event(bytes: &[u8]) -> Result<SensorFrame, EventError> {
    if bytes.len() < size_of::<Header>() {
        return Err(EventError::Short(bytes.len()));
    }
    // SAFETY: at least a header's worth of plain data; the header is read
    // from the first bytes, whatever follows.
    let header: Header = unsafe { read(&bytes[..size_of::<Header>()]) };
    let kind = Kind::from_u32(header.kind).ok_or(EventError::UnknownKind(header.kind))?;
    if bytes.len() != kind.size() {
        return Err(EventError::Size {
            kind,
            expected: kind.size(),
            got: bytes.len(),
        });
    }
    // SAFETY: the length is the struct's, checked above, and every event
    // struct is plain data.
    let payload = unsafe {
        match kind {
            Kind::Exec => Payload::ProcExec(exec(&header, &read::<ExecEvent>(bytes))),
            Kind::Fork => Payload::ProcFork(fork(&header, &read::<ForkEvent>(bytes))),
            Kind::Exit => Payload::ProcExit(exit(&header, &read::<ExitEvent>(bytes))),
            Kind::ConnectAttempt => {
                Payload::ProcConnectAttempt(connect(&header, &read::<ConnectAttempt>(bytes)))
            }
            Kind::TcpConnect => Payload::ProcTcpConnect(tcp(&header, &read::<TcpConnect>(bytes))),
            Kind::FileOpen => Payload::ProcFileOpen(file_open(&header, &read::<FileOpen>(bytes))),
            Kind::Memfd => Payload::ProcMemfd(memfd(&header, &read::<MemfdEvent>(bytes))),
            Kind::LsmDeny => Payload::ProcLsmDeny(lsm_deny(&header, &read::<LsmDeny>(bytes))),
        }
    };
    Ok(SensorFrame {
        ts_guest_ns: header.ts_ns,
        subject: Some(Subject {
            pid: header.tid,
            uid: header.uid,
            gid: header.gid,
        }),
        payload,
    })
}

/// `bytes[..len]` as text, lossily; `len` is cut to the buffer.
fn text(bytes: &[u8], len: u32) -> String {
    let end = (len as usize).min(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn exec(header: &Header, ev: &ExecEvent) -> ProcExec {
    let argv_bytes = &ev.argv[..(ev.argv_len as usize).min(ev.argv.len())];
    let mut parts = argv_bytes.split(|&b| b == 0).peekable();
    let mut argv = Vec::new();
    let mut truncated = ev.argv_truncated != 0;
    while let Some(part) = parts.next() {
        // The NUL after the last argument leaves an empty tail: not an argument.
        if part.is_empty() && parts.peek().is_none() {
            break;
        }
        if argv.len() == MAX_ARGV_ELEMS {
            truncated = true;
            break;
        }
        argv.push(String::from_utf8_lossy(part).into_owned());
    }
    ProcExec {
        tid: header.tid,
        tgid: header.tgid,
        ppid: ev.ppid,
        uid: header.uid,
        gid: header.gid,
        filename: text(&ev.filename, ev.filename_len.min(MAX_PATH as u32)),
        argv,
        argv_truncated: truncated,
        start_ns: ev.start_ns,
        cgroup_id: header.cgroup_id,
    }
}

fn fork(header: &Header, ev: &ForkEvent) -> ProcFork {
    ProcFork {
        parent_tid: header.tid,
        parent_tgid: header.tgid,
        child_pid: ev.child_pid,
        child_start_ns: ev.child_start_ns,
        uid: header.uid,
        gid: header.gid,
        thread: ev.thread != 0,
    }
}

fn exit(header: &Header, ev: &ExitEvent) -> ProcExit {
    ProcExit {
        tid: header.tid,
        tgid: header.tgid,
        exit_code: ev.exit_code,
        group_dead: ev.group_dead != 0,
        start_ns: ev.start_ns,
    }
}

/// The address `bytes` hold for `family`, if it is one we read.
fn address(family: u16, bytes: &[u8; 16]) -> Option<IpAddr> {
    match family {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(*bytes))),
        _ => None,
    }
}

/// The transport's name for an `IPPROTO_*` number.
fn protocol(proto: u32) -> String {
    match proto {
        1 => "icmp".to_owned(),
        6 => "tcp".to_owned(),
        17 => "udp".to_owned(),
        58 => "icmpv6".to_owned(),
        132 => "sctp".to_owned(),
        other => other.to_string(),
    }
}

fn connect(header: &Header, ev: &ConnectAttempt) -> ProcConnectAttempt {
    let dst = address(ev.family, &ev.dst);
    ProcConnectAttempt {
        tid: header.tid,
        tgid: header.tgid,
        family: ev.family,
        proto: protocol(ev.proto),
        dst_port: dst.is_some().then_some(ev.dst_port),
        dst,
    }
}

fn tcp(header: &Header, ev: &TcpConnect) -> ProcTcpConnect {
    // The kernel's socket is IPv4 or IPv6; anything else reads as IPv4.
    let family = if ev.family == AF_INET6 {
        AF_INET6
    } else {
        AF_INET
    };
    let unspecified = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    ProcTcpConnect {
        tid: header.tid,
        tgid: header.tgid,
        src: address(family, &ev.src).unwrap_or(unspecified),
        src_port: ev.src_port,
        dst: address(family, &ev.dst).unwrap_or(unspecified),
        dst_port: ev.dst_port,
    }
}

fn file_open(header: &Header, ev: &FileOpen) -> ProcFileOpen {
    ProcFileOpen {
        tid: header.tid,
        tgid: header.tgid,
        path: text(&ev.path, ev.path_len.min(MAX_PATH as u32)),
        flags: ev.flags,
        sample: ev.sample,
    }
}

fn memfd(header: &Header, ev: &MemfdEvent) -> ProcMemfd {
    ProcMemfd {
        tid: header.tid,
        tgid: header.tgid,
        name: text(&ev.name, ev.name_len.min(MEMFD_NAME_MAX as u32)),
        flags: ev.flags,
    }
}

fn lsm_deny(header: &Header, ev: &LsmDeny) -> ProcLsmDeny {
    ProcLsmDeny {
        tid: header.tid,
        tgid: header.tgid,
        hook: match Hook::from_u32(ev.hook) {
            Some(hook) => hook.name().to_owned(),
            None => format!("hook_{}", ev.hook),
        },
        detail: ev.detail,
    }
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;

    use boxcar_proto::sensor::{encode, Decoder};
    use boxcar_proto::Payload;
    use boxcar_sensor_common::{
        ConnectAttempt, ExecEvent, ExitEvent, Header, Kind, LsmDeny, TcpConnect, AF_INET, AF_INET6,
        HOOK_TASK_KILL,
    };

    use super::*;

    fn header(kind: Kind) -> Header {
        Header {
            kind: kind as u32,
            tid: 212,
            tgid: 210,
            uid: 1000,
            gid: 1001,
            _pad: 0,
            ts_ns: 5_000_000_000,
            cgroup_id: 4242,
        }
    }

    /// The bytes of a `repr(C)` event, as the ring buffer holds them.
    fn bytes<T: Copy>(event: &T) -> &[u8] {
        // SAFETY: a plain-data struct viewed as bytes, for its size.
        unsafe { core::slice::from_raw_parts((event as *const T).cast::<u8>(), size_of::<T>()) }
    }

    fn exec_event(argv: &[&[u8]], truncated: bool) -> ExecEvent {
        // SAFETY: all-zero bytes are a valid ExecEvent.
        let mut ev: ExecEvent = unsafe { core::mem::zeroed() };
        ev.header = header(Kind::Exec);
        ev.ppid = 7;
        ev.start_ns = 99;
        let name = b"/usr/bin/curl";
        ev.filename[..name.len()].copy_from_slice(name);
        ev.filename_len = name.len() as u32;
        let mut at = 0;
        for arg in argv {
            ev.argv[at..at + arg.len()].copy_from_slice(arg);
            at += arg.len();
            ev.argv[at] = 0;
            at += 1;
        }
        ev.argv_len = at as u32;
        ev.argv_truncated = u32::from(truncated);
        ev
    }

    #[test]
    fn an_exec_event_becomes_proc_exec_with_split_argv() {
        let ev = exec_event(&[b"curl", b"-sS", b"https://example.com/"], false);
        let frame = frame_from_event(bytes(&ev)).unwrap();
        assert_eq!(frame.ts_guest_ns, 5_000_000_000);
        let subject = frame.subject.unwrap();
        assert_eq!((subject.pid, subject.uid, subject.gid), (212, 1000, 1001));
        let Payload::ProcExec(exec) = &frame.payload else {
            panic!("{:?}", frame.payload);
        };
        assert_eq!(exec.argv, ["curl", "-sS", "https://example.com/"]);
        assert_eq!(exec.filename, "/usr/bin/curl");
        assert_eq!((exec.tid, exec.tgid, exec.ppid), (212, 210, 7));
        assert_eq!((exec.uid, exec.gid), (1000, 1001));
        assert_eq!(exec.start_ns, 99);
        assert_eq!(exec.cgroup_id, 4242);
        assert!(!exec.argv_truncated);
        // What the VMM accepts.
        let mut decoder = Decoder::new();
        decoder.feed(&encode(&frame).unwrap());
        assert_eq!(decoder.next_frame().unwrap(), Some(frame));
    }

    #[test]
    fn argv_is_cut_to_the_limits_and_marked() {
        // The kernel's own cut: the last argument has no NUL.
        let mut ev = exec_event(&[b"a", b"bb"], true);
        ev.argv_len -= 1;
        let frame = frame_from_event(bytes(&ev)).unwrap();
        let Payload::ProcExec(exec) = frame.payload else {
            unreachable!()
        };
        assert_eq!(exec.argv, ["a", "bb"]);
        assert!(exec.argv_truncated);

        // More than 256 elements: the first 256 are kept and it is marked.
        let args: Vec<Vec<u8>> = (0..300).map(|i| format!("{i}").into_bytes()).collect();
        let refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
        let ev = exec_event(&refs, false);
        let frame = frame_from_event(bytes(&ev)).unwrap();
        let Payload::ProcExec(exec) = &frame.payload else {
            unreachable!()
        };
        assert_eq!(exec.argv.len(), 256);
        assert_eq!(exec.argv[255], "255");
        assert!(exec.argv_truncated);
        encode(&frame).unwrap();

        // Bytes that are not UTF-8 become their lossy form, never an error.
        let ev = exec_event(&[b"\xff\xfe", b"ok"], false);
        let frame = frame_from_event(bytes(&ev)).unwrap();
        let Payload::ProcExec(exec) = frame.payload else {
            unreachable!()
        };
        assert_eq!(exec.argv[1], "ok");
        assert!(exec.argv[0].contains('\u{fffd}'));
    }

    #[test]
    fn addresses_are_read_by_family_and_ports_as_sent() {
        // SAFETY: all-zero bytes are a valid event.
        let mut ev: ConnectAttempt = unsafe { core::mem::zeroed() };
        ev.header = header(Kind::ConnectAttempt);
        ev.family = AF_INET;
        ev.dst_port = 443;
        ev.proto = 6;
        ev.dst[..4].copy_from_slice(&[93, 184, 216, 34]);
        let frame = frame_from_event(bytes(&ev)).unwrap();
        let Payload::ProcConnectAttempt(attempt) = frame.payload else {
            unreachable!()
        };
        assert_eq!(attempt.dst, Some("93.184.216.34".parse().unwrap()));
        assert_eq!(attempt.dst_port, Some(443));
        assert_eq!(attempt.proto, "tcp");
        assert_eq!(attempt.family, AF_INET);

        ev.family = 1; // AF_UNIX: nothing to say about the address.
        let frame = frame_from_event(bytes(&ev)).unwrap();
        let Payload::ProcConnectAttempt(attempt) = frame.payload else {
            unreachable!()
        };
        assert_eq!((attempt.dst, attempt.dst_port), (None, None));

        // SAFETY: as above.
        let mut tcp: TcpConnect = unsafe { core::mem::zeroed() };
        tcp.header = header(Kind::TcpConnect);
        tcp.family = AF_INET6;
        tcp.src_port = 40000;
        tcp.dst_port = 443;
        tcp.src[15] = 1;
        tcp.dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let frame = frame_from_event(bytes(&tcp)).unwrap();
        let Payload::ProcTcpConnect(connect) = frame.payload else {
            unreachable!()
        };
        assert_eq!(connect.src, "::1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(
            connect.dst,
            "2001:db8::2".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!((connect.src_port, connect.dst_port), (40000, 443));
    }

    #[test]
    fn forks_tell_threads_from_processes() {
        // SAFETY: all-zero bytes are a valid event.
        let mut ev: boxcar_sensor_common::ForkEvent = unsafe { core::mem::zeroed() };
        ev.header = header(Kind::Fork);
        ev.child_pid = 213;
        ev.child_start_ns = 77;
        for (flag, is_thread) in [(0u32, false), (1u32, true)] {
            ev.thread = flag;
            let frame = frame_from_event(bytes(&ev)).unwrap();
            let Payload::ProcFork(fork) = frame.payload else {
                unreachable!()
            };
            assert_eq!((fork.parent_tid, fork.parent_tgid), (212, 210));
            assert_eq!((fork.child_pid, fork.child_start_ns), (213, 77));
            assert_eq!(fork.thread, is_thread);
        }
    }

    #[test]
    fn exits_and_denials_carry_their_numbers() {
        // SAFETY: as above.
        let mut ev: ExitEvent = unsafe { core::mem::zeroed() };
        ev.header = header(Kind::Exit);
        ev.exit_code = 256;
        ev.group_dead = 1;
        ev.start_ns = 99;
        let frame = frame_from_event(bytes(&ev)).unwrap();
        let Payload::ProcExit(exit) = frame.payload else {
            unreachable!()
        };
        assert_eq!(
            (exit.exit_code, exit.group_dead, exit.start_ns),
            (256, true, 99)
        );

        // SAFETY: as above.
        let mut deny: LsmDeny = unsafe { core::mem::zeroed() };
        deny.header = header(Kind::LsmDeny);
        deny.hook = HOOK_TASK_KILL;
        deny.detail = 9;
        let frame = frame_from_event(bytes(&deny)).unwrap();
        let Payload::ProcLsmDeny(deny) = frame.payload else {
            unreachable!()
        };
        assert_eq!((deny.hook.as_str(), deny.detail), ("task_kill", 9));
    }

    #[test]
    fn bytes_that_are_not_an_event_are_refused() {
        assert!(matches!(
            frame_from_event(&[1, 2, 3]),
            Err(EventError::Short(3))
        ));
        let mut unknown = header(Kind::Exec);
        unknown.kind = 99;
        assert!(matches!(
            frame_from_event(bytes(&unknown)),
            Err(EventError::UnknownKind(99))
        ));
        // The right kind with the wrong size: not this struct.
        let short = header(Kind::Exec);
        assert!(matches!(
            frame_from_event(bytes(&short)),
            Err(EventError::Size {
                kind: Kind::Exec,
                ..
            })
        ));
    }
}
