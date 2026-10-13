// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What the sensor says about itself: `proc.sensor_status`, from what
//! attached and what did not.

use boxcar_proto::limits::MAX_SUMMARY;
use boxcar_proto::sensor::SensorFrame;
use boxcar_proto::{Payload, ProcSensorStatus, ProgramStatus, SensorPhase};

/// How one program's attach went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attached {
    pub name: &'static str,
    pub attached: bool,
    pub error: Option<String>,
}

impl Attached {
    pub fn ok(name: &'static str) -> Attached {
        Attached {
            name,
            attached: true,
            error: None,
        }
    }

    pub fn failed(name: &'static str, error: &str) -> Attached {
        Attached {
            name,
            attached: false,
            error: Some(cut(error)),
        }
    }
}

/// What the sensor knows about where it runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    /// `/sys/kernel/btf/vmlinux` is there.
    pub btf_ok: bool,
    pub kernel_release: String,
    pub session_cgroup_id: u64,
    /// The sensor's own process id.
    pub pid: u32,
    /// Its other threads (the TLS resolver's).
    pub threads: Vec<u32>,
}

/// `attached` when every program is, `degraded` otherwise (no program at
/// all included).
pub fn phase(results: &[Attached]) -> SensorPhase {
    if !results.is_empty() && results.iter().all(|r| r.attached) {
        SensorPhase::Attached
    } else {
        SensorPhase::Degraded
    }
}

/// The `proc.sensor_status` frame for `results`.
pub fn status_frame(
    results: &[Attached],
    facts: &Facts,
    reason: Option<String>,
    ts_guest_ns: u64,
) -> SensorFrame {
    SensorFrame {
        ts_guest_ns,
        subject: None,
        payload: Payload::ProcSensorStatus(ProcSensorStatus {
            phase: phase(results),
            programs: results
                .iter()
                .map(|r| ProgramStatus {
                    name: r.name.to_owned(),
                    attached: r.attached,
                    error: r.error.clone(),
                })
                .collect(),
            kernel_release: cut(&facts.kernel_release),
            btf_ok: facts.btf_ok,
            session_cgroup_id: facts.session_cgroup_id,
            pid: facts.pid,
            threads: facts.threads.clone(),
            reason: reason.map(|r| cut(&r)),
        }),
    }
}

/// `text` within the summary limit, cut at a character boundary.
pub fn cut(text: &str) -> String {
    if text.len() <= MAX_SUMMARY {
        return text.to_owned();
    }
    let mut end = MAX_SUMMARY;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use boxcar_proto::sensor::encode;
    use boxcar_proto::{Payload, SensorPhase};

    use super::*;

    #[test]
    fn status_lists_every_program_with_its_error() {
        let results = vec![
            Attached::ok("sched_process_exec"),
            Attached::failed("file_open", "the hook is not sleepable here"),
        ];
        assert_eq!(phase(&results), SensorPhase::Degraded);
        let frame = status_frame(
            &results,
            &Facts {
                btf_ok: true,
                kernel_release: "6.18.54".into(),
                session_cgroup_id: 4242,
                pid: 77,
                threads: vec![78],
            },
            None,
            1_000,
        );
        assert_eq!(frame.ts_guest_ns, 1_000);
        assert!(frame.subject.is_none());
        let Payload::ProcSensorStatus(status) = &frame.payload else {
            panic!("{:?}", frame.payload);
        };
        assert_eq!(status.phase, SensorPhase::Degraded);
        assert_eq!(status.programs.len(), 2);
        assert_eq!(status.programs[0].name, "sched_process_exec");
        assert!(status.programs[0].attached && status.programs[0].error.is_none());
        assert_eq!(
            status.programs[1].error.as_deref(),
            Some("the hook is not sleepable here")
        );
        assert_eq!(
            (status.btf_ok, status.pid, status.session_cgroup_id),
            (true, 77, 4242)
        );
        assert_eq!(status.kernel_release, "6.18.54");
        assert!(status.reason.is_none());
        encode(&frame).unwrap();

        let all_ok = vec![Attached::ok("a"), Attached::ok("b")];
        assert_eq!(phase(&all_ok), SensorPhase::Attached);

        // No programs at all: degraded for the one reason given.
        let none = status_frame(
            &[],
            &Facts {
                btf_ok: false,
                kernel_release: "6.18.54".into(),
                session_cgroup_id: 0,
                pid: 1,
                threads: Vec::new(),
            },
            Some("no_programs".into()),
            2,
        );
        let Payload::ProcSensorStatus(status) = none.payload else {
            unreachable!()
        };
        assert_eq!(status.phase, SensorPhase::Degraded);
        assert_eq!(status.reason.as_deref(), Some("no_programs"));
        assert!(!status.btf_ok);
    }

    #[test]
    fn an_error_is_cut_to_the_summary_limit() {
        let long = "x".repeat(2000);
        let results = vec![Attached::failed("tcp_connect", &long)];
        let frame = status_frame(
            &results,
            &Facts {
                btf_ok: true,
                kernel_release: "6.18.54".into(),
                session_cgroup_id: 1,
                pid: 1,
                threads: Vec::new(),
            },
            None,
            3,
        );
        let Payload::ProcSensorStatus(status) = &frame.payload else {
            unreachable!()
        };
        assert!(status.programs[0].error.as_ref().unwrap().len() <= 512);
        encode(&frame).unwrap();
    }
}
