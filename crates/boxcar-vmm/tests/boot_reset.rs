// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! Devices the guest resets and activates again, under the seccomp filter
//! (each test runs confined: see `confined`): a guest that can make the
//! VMM issue a call off the allowlist can kill it, and a reset and a
//! reactivation start threads, make eventfds and epolls, and remake
//! sockets, on a vCPU thread.
//!
//! The session runs as root in the guest, so it can unbind and bind the
//! virtio drivers through sysfs:
//! - the network card, then a lookup through the stack again (the policy
//!   denies the name, so the VMM itself answers NXDOMAIN);
//! - the workspace's virtio-fs, unmounted first, then mounted again and
//!   written;
//! - the vsock device: the session's control channel goes with it, so the
//!   session ends, and the VMM must still stop as it always does.
//!
//! Skips with a printed reason unless `BOXCAR_TEST_KERNEL`,
//! `BOXCAR_TEST_INITRAMFS` and `BOXCAR_TEST_ROOTFS` are set and `/dev/kvm`
//! is accessible. Relative paths are taken from the workspace root, where
//! `cargo xtask` writes them.

#![cfg(feature = "kvm-tests")]

#[macro_use]
mod confined;

use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use arc_swap::ArcSwap;
use boxcar_audit::{verify_session, LogReader, WriterConfig};
use boxcar_fs::{CachePolicyKind, FsShareConfig};
use boxcar_net::{NetConfig, Policy};
use boxcar_proto::{guestcmd, Record, SessionId};
use boxcar_vmm::guest_ctl::SessionConfig;
use boxcar_vmm::kvm::kvm_available;
use boxcar_vmm::pty::out::{self, Target};
use boxcar_vmm::pty::Mode;
use boxcar_vmm::vmm::{ConsoleOut, ControlConfig, StopReason, VmConfig, VmExit, Vmm};
use boxcar_vsock::VsockConfig;

const TEST: &str = "boot_reset";
/// Boot, two resets and the checks after them.
const LIMIT: Duration = Duration::from_secs(90);

/// What the first session runs, as root: the network card, then the
/// workspace's virtio-fs, each unbound, bound again and used.
const NET_AND_FS: &str = r#"
dev() { basename "$(readlink -f "$1")"; }
n=$(dev /sys/class/net/eth0/device)
echo "$n" > /sys/bus/virtio/drivers/virtio_net/unbind && echo NET_UNBOUND
echo "$n" > /sys/bus/virtio/drivers/virtio_net/bind && echo NET_BOUND
sleep 1
ip link set eth0 up && ip addr add 10.0.2.15/24 dev eth0 && ip route add default via 10.0.2.2
nslookup reset.boxcar.test 10.0.2.2 > /tmp/lookup 2>&1
grep -qi nxdomain /tmp/lookup && echo NET_OK || cat /tmp/lookup
ws=
for tag in /sys/fs/virtiofs/*/tag; do
  [ "$(cat "$tag")" = workspace ] && ws=$(dev "${tag%/tag}/device")
done
cd / && umount /workspace && echo FS_UNMOUNTED
echo "$ws" > /sys/bus/virtio/drivers/virtiofs/unbind && echo FS_UNBOUND
echo "$ws" > /sys/bus/virtio/drivers/virtiofs/bind && echo FS_BOUND
mount -t virtiofs workspace /workspace && echo again > /workspace/after && echo FS_OK
echo DONE
"#;

/// What the second session runs, as root: the vsock device unbound, which
/// takes the session's control channel with it.
const VSOCK: &str = r#"
d=vmw_vsock_virtio_transport
for v in /sys/bus/virtio/drivers/$d/virtio*; do echo "$(basename "$v")" > /sys/bus/virtio/drivers/$d/unbind; done
sleep 30
"#;

/// The artifact `var` names, or `None` when it is unset.
fn artifact(var: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env::var_os(var)?);
    if path.is_absolute() || path.exists() {
        return Some(path);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    Some(root.join(path))
}

/// The kernel, initramfs and rootfs, or `None` after printing why the test
/// skips.
fn guest_or_skip() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let (Some(kernel), Some(initramfs), Some(rootfs)) = (
        artifact("BOXCAR_TEST_KERNEL"),
        artifact("BOXCAR_TEST_INITRAMFS"),
        artifact("BOXCAR_TEST_ROOTFS"),
    ) else {
        eprintln!(
            "skipping {TEST}: BOXCAR_TEST_KERNEL, BOXCAR_TEST_INITRAMFS and \
             BOXCAR_TEST_ROOTFS must all be set"
        );
        return None;
    };
    if let Err(reason) = kvm_available() {
        eprintln!("skipping {TEST}: {reason}");
        return None;
    }
    Some((kernel, initramfs, rootfs))
}

fn share(tag: &str, host_dir: PathBuf, guest_path: &str, cache: CachePolicyKind) -> FsShareConfig {
    FsShareConfig {
        tag: tag.into(),
        host_dir,
        guest_path: guest_path.into(),
        cache,
    }
}

/// Runs `vmm` until it stops, or until a watchdog stops it after [`LIMIT`].
fn run_to_a_stop(vmm: Vmm) -> VmExit {
    let handle = vmm.handle();
    let (done, finished) = mpsc::channel::<()>();
    let watchdog = thread::spawn(move || {
        if finished.recv_timeout(LIMIT).is_err() {
            handle.request_stop(StopReason::Requested);
        }
    });
    let exit = vmm.run().unwrap();
    drop(done);
    watchdog.join().unwrap();
    exit
}

/// The session's records, once its log is verified.
fn records(session_dir: &Path) -> Vec<Record> {
    let report = verify_session(session_dir).unwrap();
    eprintln!("{TEST}: {report:?}");
    LogReader::open(session_dir)
        .unwrap()
        .records()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn the_network_card_and_a_share_work_after_the_guest_resets_them() {
    confine!();
    let Some((kernel, initramfs, rootfs)) = guest_or_skip() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let console = dir.path().join("console.log");
    let argv = ["/bin/sh", "-c", NET_AND_FS].map(String::from);
    let cfg = VmConfig {
        cmdline_extra: vec![
            "boxcar.mode=console".into(),
            "boxcar.uid=0".into(),
            "boxcar.gid=0".into(),
            format!("boxcar.cmd={}", guestcmd::encode(&argv)),
        ],
        console: ConsoleOut::File(console.clone()),
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share(
                "workspace",
                workspace.clone(),
                "/workspace",
                CachePolicyKind::Auto,
            ),
        ],
        net: Some(NetConfig::from_host()),
        policy: Arc::new(ArcSwap::from_pointee(Policy::default())),
        seccomp: confined::seccomp(),
        ..VmConfig::new(kernel, sink)
    };
    let exit = run_to_a_stop(Vmm::new(cfg).unwrap());
    writer.close().unwrap();

    let output = String::from_utf8_lossy(&fs::read(&console).unwrap()).into_owned();
    eprintln!("{TEST}: {exit:?}\n{output}");
    assert!(
        matches!(exit, VmExit::GuestReset { .. }),
        "{exit:?}; console:\n{output}"
    );
    for line in [
        "NET_UNBOUND",
        "NET_BOUND",
        "NET_OK",
        "FS_UNMOUNTED",
        "FS_UNBOUND",
        "FS_BOUND",
        "FS_OK",
        "DONE",
    ] {
        assert!(output.contains(line), "no {line}:\n{output}");
    }
    assert_eq!(
        fs::read_to_string(workspace.join("after")).unwrap(),
        "again\n"
    );
    let records = records(&session_dir);
    assert!(
        records
            .iter()
            .any(|r| r.kind == "net.dns" && r.data["qname"] == "reset.boxcar.test"),
        "no lookup after the network card came back"
    );
    assert_eq!(records.last().map(|r| r.kind.as_str()), Some("checkpoint"));
    assert!(records.iter().any(|r| r.kind == "vmm.stop"));
}

#[test]
fn the_vmm_stops_as_usual_when_the_guest_resets_vsock() {
    confine!();
    let Some((kernel, initramfs, rootfs)) = guest_or_skip() else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    fs::create_dir(&workspace).unwrap();
    let (sink, writer) =
        boxcar_audit::spawn(WriterConfig::new(dir.path().join("data"), SessionId::new())).unwrap();
    let session_dir = writer.session_dir().to_path_buf();
    let state = dir.path().join("state");
    let argv = ["/bin/sh", "-c", VSOCK].map(String::from).to_vec();
    let cfg = VmConfig {
        cmdline_extra: vec!["boxcar.mode=vsock".into()],
        console: ConsoleOut::File(dir.path().join("console.log")),
        stdin: false,
        initramfs: Some(initramfs),
        fs_shares: vec![
            share("root", rootfs, "/", CachePolicyKind::Always),
            share("workspace", workspace, "/workspace", CachePolicyKind::Auto),
        ],
        vsock: Some(VsockConfig::new(state.join("vsock.sock"))),
        session: SessionConfig::for_user(argv, 0, 0),
        control: Some(ControlConfig {
            state_dir: state.clone(),
            session_id: SessionId::new(),
        }),
        seccomp: confined::seccomp(),
        ..VmConfig::new(kernel, sink)
    };
    let vmm = Vmm::new(cfg).unwrap();
    let hub = vmm.handle().pty().expect("the hub, with the vsock device");
    let (_, output, _) = hub.attach_primary(Mode::Ro).unwrap();
    let session_out = out::spawn(
        output,
        Target::file(File::create(dir.path().join("session.out")).unwrap()),
    )
    .unwrap();
    let exit = run_to_a_stop(vmm);
    let _ = session_out.wait(Duration::from_secs(2));
    writer.close().unwrap();

    let console = fs::read_to_string(dir.path().join("console.log")).unwrap_or_default();
    eprintln!("{TEST}: {exit:?}\n{console}");
    // The guest's init ends the session once its channel is gone; the
    // watchdog's stop would be a hang.
    assert!(
        !matches!(exit, VmExit::StopRequested(StopReason::Requested)),
        "{exit:?}; console:\n{console}"
    );
    let records = records(&session_dir);
    assert!(
        records.iter().any(|r| r.kind == "vmm.stop"),
        "no vmm.stop: the VMM did not stop as it always does"
    );
}
