// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Loading and attaching the programs: the object the binary carries, the
//! kernel's BTF, the two globals, then each program in the table's order,
//! the guards last. What did not attach is reported, not fatal: a sensor
//! with fewer programs still heartbeats, and the reconciler knows which
//! rules to skip. The TLS probes are only loaded here: `tls` attaches them
//! to each file found to export their symbols.

use aya::maps::{MapData, PerCpuArray, RingBuf};
use aya::programs::{BtfTracePoint, FEntry, Lsm, UProbe};
use aya::{Btf, Ebpf, EbpfLoader};
use boxcar_sensor_common::programs::{ProgramKind, GLOBALS, PROGRAMS};

use crate::object::OBJECT;
use crate::status::Attached;

/// What loading left: the programs attached (or not), and the maps.
pub struct Loaded {
    /// Keeps the programs attached; dropping it detaches them.
    pub ebpf: Option<Ebpf>,
    pub results: Vec<Attached>,
    pub events: Option<RingBuf<MapData>>,
    pub drops: Option<PerCpuArray<MapData, u64>>,
    /// One reason that covers everything that did not load.
    pub reason: Option<String>,
}

impl Loaded {
    fn none(reason: String) -> Loaded {
        Loaded {
            ebpf: None,
            results: PROGRAMS
                .iter()
                .map(|p| Attached::failed(p.name, &reason))
                .collect(),
            events: None,
            drops: None,
            reason: Some(reason),
        }
    }
}

/// Loads the object with `session_cgroup` and `sensor_tgid` as its globals
/// and attaches every program it can.
pub fn load(session_cgroup: u64, sensor_tgid: u64) -> Loaded {
    if OBJECT.is_empty() {
        return Loaded::none("no_programs".to_owned());
    }
    let btf = match Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(error) => return Loaded::none(format!("no_btf: {error}")),
    };
    let mut ebpf = match EbpfLoader::new()
        .btf(Some(&btf))
        .override_global(GLOBALS[0], &session_cgroup, true)
        .override_global(GLOBALS[1], &sensor_tgid, true)
        .load(OBJECT)
    {
        Ok(ebpf) => ebpf,
        Err(error) => return Loaded::none(format!("load: {error}")),
    };
    let mut results = Vec::with_capacity(PROGRAMS.len());
    for program in PROGRAMS {
        results.push(
            match attach(&mut ebpf, program.name, program.kind, program.hook, &btf) {
                Ok(()) => Attached::ok(program.name),
                Err(error) => Attached::failed(program.name, &error),
            },
        );
    }
    let events = ebpf
        .take_map("EVENTS")
        .and_then(|map| RingBuf::try_from(map).ok());
    let drops = ebpf
        .take_map("DROPS")
        .and_then(|map| PerCpuArray::try_from(map).ok());
    let reason = match (&events, &drops) {
        (Some(_), Some(_)) => None,
        _ => Some("maps: EVENTS or DROPS is missing from the object".to_owned()),
    };
    Loaded {
        ebpf: Some(ebpf),
        results,
        events,
        drops,
        reason,
    }
}

/// Loads and attaches one program by its kind.
fn attach(
    ebpf: &mut Ebpf,
    name: &str,
    kind: ProgramKind,
    hook: &str,
    btf: &Btf,
) -> Result<(), String> {
    let program = ebpf
        .program_mut(name)
        .ok_or_else(|| format!("{name} is not in the object"))?;
    let describe = |what: &str, error: &dyn std::fmt::Display| format!("{what}: {error}");
    match kind {
        ProgramKind::BtfTracepoint => {
            let program: &mut BtfTracePoint = program
                .try_into()
                .map_err(|e| describe("not a BTF tracepoint", &e))?;
            program.load(hook, btf).map_err(|e| describe("load", &e))?;
            program.attach().map_err(|e| describe("attach", &e))?;
        }
        ProgramKind::Lsm | ProgramKind::SleepableLsm => {
            let program: &mut Lsm = program
                .try_into()
                .map_err(|e| describe("not an LSM program", &e))?;
            program.load(hook, btf).map_err(|e| describe("load", &e))?;
            program.attach().map_err(|e| describe("attach", &e))?;
        }
        ProgramKind::FEntry => {
            let program: &mut FEntry = program
                .try_into()
                .map_err(|e| describe("not an fentry program", &e))?;
            program.load(hook, btf).map_err(|e| describe("load", &e))?;
            program.attach().map_err(|e| describe("attach", &e))?;
        }
        ProgramKind::UProbe | ProgramKind::URetProbe => {
            // Loaded now; attached by `tls` to each file that exports
            // `hook`, as the session runs them.
            let program: &mut UProbe = program
                .try_into()
                .map_err(|e| describe("not a uprobe program", &e))?;
            program.load().map_err(|e| describe("load", &e))?;
        }
    }
    Ok(())
}

/// The events the kernel could not place in the ring buffer, summed over
/// the CPUs; 0 when the map is not there or cannot be read.
pub fn drops_total(drops: Option<&PerCpuArray<MapData, u64>>) -> u64 {
    drops
        .and_then(|map| map.get(&0, 0).ok())
        .map(|values| values.iter().sum())
        .unwrap_or(0)
}
