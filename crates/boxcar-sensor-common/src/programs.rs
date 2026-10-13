// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the eBPF object must contain: its programs and their kinds, its
//! maps, its globals and its licence. The lane (`cargo xtask sensor`)
//! checks a built object against this table, the sensor's own test checks
//! the object it carries, and the loader attaches by these names.

/// How a program attaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramKind {
    /// A BTF tracepoint (`tp_btf/<hook>`).
    BtfTracepoint,
    /// An LSM hook (`lsm/<hook>`).
    Lsm,
    /// A sleepable LSM hook (`lsm.s/<hook>`).
    SleepableLsm,
    /// A function entry (`fentry/<hook>`).
    FEntry,
    /// A probe on a user function (`uprobe`), attached by the userspace
    /// sensor to each file that exports the symbol `hook` names.
    UProbe,
    /// A probe on a user function's return (`uretprobe`), attached the
    /// same way.
    URetProbe,
}

/// One of the sensor's programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Program {
    /// The function's name: the key the object lists it under.
    pub name: &'static str,
    pub kind: ProgramKind,
    /// The tracepoint, hook or function it attaches to.
    pub hook: &'static str,
    /// Whether the sensor is `degraded` rather than failed when this one
    /// cannot attach.
    pub optional: bool,
}

const fn program(name: &'static str, kind: ProgramKind, hook: &'static str) -> Program {
    Program {
        name,
        kind,
        hook,
        optional: false,
    }
}

/// A TLS probe: loaded with the others, attached later to each file that
/// exports `symbol`; optional, as a session may run nothing that does.
const fn tls(name: &'static str, kind: ProgramKind, symbol: &'static str) -> Program {
    Program {
        name,
        kind,
        hook: symbol,
        optional: true,
    }
}

/// The programs, in the order the loader attaches them: the two guards
/// last, `bpf_guard` very last, since loading is itself a `bpf()` call.
pub const PROGRAMS: [Program; 15] = [
    program(
        "sched_process_exec",
        ProgramKind::BtfTracepoint,
        "sched_process_exec",
    ),
    program(
        "sched_process_fork",
        ProgramKind::BtfTracepoint,
        "sched_process_fork",
    ),
    program(
        "sched_process_exit",
        ProgramKind::BtfTracepoint,
        "sched_process_exit",
    ),
    program("socket_connect", ProgramKind::Lsm, "socket_connect"),
    program("tcp_connect", ProgramKind::FEntry, "tcp_connect"),
    Program {
        name: "file_open",
        kind: ProgramKind::SleepableLsm,
        hook: "file_open",
        optional: true,
    },
    program(
        "memfd_create",
        ProgramKind::FEntry,
        "__x64_sys_memfd_create",
    ),
    tls("ssl_write", ProgramKind::UProbe, "SSL_write"),
    tls("ssl_write_ex", ProgramKind::UProbe, "SSL_write_ex"),
    tls("ssl_read", ProgramKind::UProbe, "SSL_read"),
    tls("ssl_read_ret", ProgramKind::URetProbe, "SSL_read"),
    tls("ssl_read_ex", ProgramKind::UProbe, "SSL_read_ex"),
    tls("ssl_read_ex_ret", ProgramKind::URetProbe, "SSL_read_ex"),
    program("kill_guard", ProgramKind::Lsm, "task_kill"),
    program("bpf_guard", ProgramKind::Lsm, "bpf"),
];

/// The maps, with their `bpf_map_type` numbers: the ring buffer the events
/// travel in, the two per-CPU counters, and the TLS reads under way.
pub const MAPS: [(&str, u32); 4] = [
    ("EVENTS", BPF_MAP_TYPE_RINGBUF),
    ("DROPS", BPF_MAP_TYPE_PERCPU_ARRAY),
    ("SAMPLES", BPF_MAP_TYPE_PERCPU_ARRAY),
    ("TLS_READS", BPF_MAP_TYPE_HASH),
];

/// `BPF_MAP_TYPE_HASH`.
pub const BPF_MAP_TYPE_HASH: u32 = 1;
/// `BPF_MAP_TYPE_RINGBUF`.
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
/// `BPF_MAP_TYPE_PERCPU_ARRAY`.
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;

/// How many threads may be inside `SSL_read` or `SSL_read_ex` at once.
pub const TLS_READS_ENTRIES: u32 = 1024;

/// The ring buffer's size in bytes.
pub const RING_BUFFER_BYTES: u32 = 256 * 1024;

/// The globals the loader sets before load.
pub const GLOBALS: [&str; 2] = ["SESSION_CGROUP", "SENSOR_TGID"];

/// The value a global holds until the loader sets it; it matches no
/// cgroup and no process.
pub const UNSET: u64 = u64::MAX;

/// The object's `license` section, as the kernel reads it.
pub const LICENSE: &str = "Dual MIT/GPL";

/// `file_open` reports one open in this many, per CPU.
pub const FILE_OPEN_SAMPLE: u64 = 64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_consistent() {
        for (i, a) in PROGRAMS.iter().enumerate() {
            assert!(!a.name.is_empty() && !a.hook.is_empty());
            for b in &PROGRAMS[i + 1..] {
                assert_ne!(a.name, b.name);
            }
        }
        assert_eq!(PROGRAMS[PROGRAMS.len() - 1].name, "bpf_guard");
        assert_eq!(PROGRAMS[PROGRAMS.len() - 2].name, "kill_guard");
        assert_eq!(
            PROGRAMS.iter().filter(|p| p.optional).count(),
            7,
            "file_open and the six TLS probes are optional"
        );
        assert_eq!(PROGRAMS.len(), 15);
        let tls = || {
            PROGRAMS
                .iter()
                .filter(|p| matches!(p.kind, ProgramKind::UProbe | ProgramKind::URetProbe))
        };
        assert_eq!(tls().count(), 6);
        assert!(tls().all(|p| p.optional && p.hook.starts_with("SSL_")));
        assert_eq!(
            tls().filter(|p| p.kind == ProgramKind::URetProbe).count(),
            2
        );
        assert_eq!(MAPS.len(), 4);
        assert_eq!(
            LICENSE.len() + 1,
            13,
            "the static in the eBPF crate is 13 bytes"
        );
        assert!(FILE_OPEN_SAMPLE.is_power_of_two());
    }
}
