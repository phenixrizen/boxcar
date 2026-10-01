// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The VMM: [`Vmm::new`] builds a VM that boots a Linux ELF kernel with an
//! optional initramfs, and [`Vmm::run`] runs it until it stops.
//!
//! Boot order in `Vmm::new`: open KVM and check its capabilities, raise
//! `RLIMIT_NOFILE`, create the VM with its TSS, in-kernel irqchip and PIT,
//! map guest memory, load the kernel and the initramfs, create the devices
//! (the legacy PIO devices, then one virtio-fs device per share, each in its
//! fixed slot of [`crate::devices::slots`]), write the command line with a
//! `virtio_mmio.device=` entry for each slot of the [`DeviceSet`], write the
//! zero page and MP table, create and set up the vCPUs, record `vmm.start`,
//! and bind the control socket when the config asks for one, so that a
//! client can connect while the VM boots (its state is `booting` until
//! [`Vmm::run`] starts the vCPU threads).

use std::fs::File;
use std::io;
use std::mem;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;

use boxcar_audit::{AuditSink, EmitError, Priority, Submission};
use boxcar_fs::{AuditFsOptions, FsShareConfig};
use boxcar_proto::{ArtifactRef, Hash, Payload, Ring, SessionId, ShareRef, VmmStart};
use boxcar_virtio::bus::{Bus, BusError};
use boxcar_virtio::{SlotAllocator, SlotError};
use event_manager::{EventManager, EventSet, Events, MutEventSubscriber, SubscriberOps};
use kvm_bindings::{kvm_pit_config, kvm_userspace_memory_region, KVM_PIT_SPEAKER_DUMMY};
use kvm_ioctls::{VcpuFd, VmFd};
use linux_loader::loader::{load_cmdline, Elf, KernelLoader};
use vm_memory::{
    Address, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap, GuestMemoryRegion,
    MemoryRegionAddress,
};
use vmm_sys_util::eventfd::{EventFd, EFD_NONBLOCK};

use crate::arch::x86_64::boot::{configure_system, InitrdConfig};
pub use crate::arch::x86_64::layout::CMDLINE_MAX_SIZE;
use crate::arch::x86_64::layout::{CMDLINE_START, HIMEM_START, KVM_TSS_ADDRESS};
use crate::arch::x86_64::{cpuid, interrupts, msr, regs};
use crate::cmdline::{build_cmdline, MmioDeviceEntry};
use crate::control::{ControlServer, VmmOps};
use crate::devices::legacy::COM1_GSI;
use crate::devices::slots::{present_slots, DeviceSet};
use crate::devices::{DeviceError, FsDevices, LegacyDevices};
use crate::kick::register_kick_handler;
use crate::kvm::{KvmContext, KvmError};
use crate::lifecycle::{
    block_stop_signals, exit_code_for, record_stop, stop, wait_for_stop, ControlSubscriber,
    MainLoop, SignalFd, StopLatch, Teardown, VmInfo,
};
use crate::memory::{create_guest_memory, initrd_load_addr};
use crate::stdin::{stdin_is_tty, RawModeGuard, StdinSubscriber};
use crate::vcpu::VcpuSet;

pub use crate::devices::ConsoleOut;
pub use crate::lifecycle::{SessionOutcome, StopReason, VmExit, VmState, VmmHandle};

/// The kernel command line every boot starts from.
pub const BASE_CMDLINE: &str = "console=ttyS0 reboot=k panic=1 pci=off nomodule 8250.nr_uarts=1 i8042.noaux i8042.nomux i8042.dumbkbd lockdown=integrity random.trust_cpu=on quiet loglevel=4 rdinit=/init";

/// The part of [`BASE_CMDLINE`] that `--debug-boot` replaces...
const QUIET: &str = "quiet loglevel=4";
/// ...with this: early console output on ttyS0 and every kernel message.
const DEBUG_BOOT: &str = "earlyprintk=serial,ttyS0,115200 loglevel=7";

/// The base command line: [`BASE_CMDLINE`], or with `debug_boot` its quiet
/// part swapped for early printk on the serial port and full logging.
pub fn base_cmdline(debug_boot: bool) -> String {
    if debug_boot {
        BASE_CMDLINE.replace(QUIET, DEBUG_BOOT)
    } else {
        BASE_CMDLINE.to_owned()
    }
}

/// The size, NUL terminator included, of the kernel command line
/// [`Vmm::new`] writes for a VM with `debug_boot`, `extra` and the devices
/// in `set`, whether or not it fits in the [`CMDLINE_MAX_SIZE`] bytes the
/// kernel takes: composed by `kernel_cmdline`, the function `Vmm::new`
/// uses (the base, `extra`, a `virtio_mmio.device=` entry for each present
/// slot of the fixed table), without building the VM. A caller can refuse a
/// command line that is too long, with its size, before it starts anything.
/// `set` is [`DeviceSet::from_config`] of the config the VM is built from,
/// or [`DeviceSet::from_shares`] for a caller that has no [`VmConfig`] yet.
pub fn cmdline_size(
    debug_boot: bool,
    extra: &[String],
    set: &DeviceSet,
) -> Result<usize, VmmError> {
    let (base, extras) = cmdline_parts(debug_boot, extra);
    Ok(crate::cmdline::cmdline_size(
        &base,
        &extras,
        &cmdline_entries(set),
    )?)
}

/// The `virtio_mmio.device=` entries of the devices in `set`: one per
/// present slot of the fixed table, in slot order.
fn cmdline_entries(set: &DeviceSet) -> Vec<MmioDeviceEntry> {
    present_slots(set)
        .iter()
        .map(|slot| slot.cmdline_entry())
        .collect()
}

/// The kernel command line of a VM with `debug_boot`, `extra` and the
/// devices in `set`.
fn kernel_cmdline(
    debug_boot: bool,
    extra: &[String],
    set: &DeviceSet,
) -> crate::arch::Result<linux_loader::cmdline::Cmdline> {
    let (base, extras) = cmdline_parts(debug_boot, extra);
    build_cmdline(&base, &extras, &cmdline_entries(set))
}

/// The base command line and the extra arguments, in order.
fn cmdline_parts(debug_boot: bool, extra: &[String]) -> (String, Vec<&str>) {
    (
        base_cmdline(debug_boot),
        extra.iter().map(String::as_str).collect(),
    )
}

/// Guest memory when not configured.
pub const DEFAULT_MEM_MIB: u64 = 512;
/// vCPUs when not configured.
pub const DEFAULT_VCPUS: u8 = 1;

/// What to boot and how.
pub struct VmConfig {
    /// An uncompressed ELF `vmlinux`.
    pub kernel: PathBuf,
    /// A cpio archive for the kernel to unpack as its root filesystem.
    pub initramfs: Option<PathBuf>,
    pub mem_mib: u64,
    pub vcpus: u8,
    /// Appended to the base command line, in order.
    pub cmdline_extra: Vec<String>,
    /// See [`base_cmdline`].
    pub debug_boot: bool,
    /// Where the serial console's output goes. With [`ConsoleOut::Stdio`],
    /// a TTY on stdin and [`VmConfig::stdin`], stdin is forwarded to the
    /// guest.
    pub console: ConsoleOut,
    /// Whether the guest may read the host's stdin: when it is a TTY and the
    /// console is on stdout, the terminal goes into raw mode and what is
    /// typed goes to the guest. Off for a run that needs no input, which
    /// leaves the terminal as it is.
    pub stdin: bool,
    /// Receives `vmm.start` and `vmm.stop`, and every share's records.
    pub audit: AuditSink,
    /// The directories shared with the guest over virtio-fs, in slot order:
    /// none, or `root` then `workspace` (see [`crate::devices::FS_TAGS`]).
    pub fs_shares: Vec<FsShareConfig>,
    /// How much the shares record.
    pub fs_audit: AuditFsOptions,
    /// The control socket, if any: see [`ControlConfig`].
    pub control: Option<ControlConfig>,
}

/// Where the control socket goes and which session it serves.
#[derive(Clone, Debug)]
pub struct ControlConfig {
    /// The session's state directory, created mode 0700 if missing; the
    /// socket is `control.sock` in it, mode 0600. Both are removed when
    /// the VM stops (the directory only when it is empty).
    pub state_dir: PathBuf,
    /// The session the hello and `status` name: the audit log's.
    pub session_id: SessionId,
}

impl VmConfig {
    /// A config for `kernel` with the defaults: no initramfs,
    /// [`DEFAULT_MEM_MIB`], [`DEFAULT_VCPUS`], no extra arguments, a quiet
    /// boot, the console on stdio with stdin, no shares, and no control
    /// socket.
    pub fn new(kernel: impl Into<PathBuf>, audit: AuditSink) -> Self {
        VmConfig {
            kernel: kernel.into(),
            initramfs: None,
            mem_mib: DEFAULT_MEM_MIB,
            vcpus: DEFAULT_VCPUS,
            cmdline_extra: Vec::new(),
            debug_boot: false,
            console: ConsoleOut::Stdio,
            stdin: true,
            audit,
            fs_shares: Vec::new(),
            fs_audit: AuditFsOptions::default(),
            control: None,
        }
    }
}

/// Why a VM could not be built or run.
#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    #[error(transparent)]
    Kvm(#[from] KvmError),
    #[error("KVM {op} failed")]
    KvmIoctl {
        op: &'static str,
        #[source]
        source: kvm_ioctls::Error,
    },
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("cannot raise RLIMIT_NOFILE")]
    Rlimit(#[source] io::Error),
    #[error("boot setup failed")]
    Arch(#[from] crate::arch::Error),
    #[error("cannot read {what} {}", path.display())]
    Read {
        what: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cannot load the kernel {}", path.display())]
    Kernel {
        path: PathBuf,
        #[source]
        source: linux_loader::loader::Error,
    },
    #[error("cannot load the initramfs {} into guest memory", path.display())]
    Initramfs {
        path: PathBuf,
        #[source]
        source: vm_memory::GuestMemoryError,
    },
    #[error("cannot write the kernel command line")]
    Cmdline(#[source] linux_loader::loader::Error),
    #[error("cannot open the console")]
    Console(#[source] io::Error),
    #[error("cannot create the {what}")]
    Setup {
        what: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("cannot place a device on the bus")]
    Bus(#[from] BusError),
    #[error("cannot set up the virtio-mmio slots")]
    Slots(#[from] SlotError),
    #[error(transparent)]
    Device(#[from] DeviceError),
    #[error("cannot record vmm.start")]
    Audit(#[from] EmitError),
    #[error("cannot bind the control socket in {}", state_dir.display())]
    Control {
        state_dir: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the main event loop failed")]
    EventLoop(#[source] event_manager::Error),
}

fn kvm_ioctl(op: &'static str) -> impl FnOnce(kvm_ioctls::Error) -> VmmError {
    move |source| VmmError::KvmIoctl { op, source }
}

fn setup(what: &'static str) -> impl FnOnce(io::Error) -> VmmError {
    move |source| VmmError::Setup { what, source }
}

/// A VM, built and ready to run.
pub struct Vmm {
    // Field order is drop order: the vCPU fds before the VM, the VM before
    // the memory it maps. The virtio devices share the memory, so it may
    // outlive `_mem`, never the VM.
    vcpus: Vec<VcpuFd>,
    _vm: VmFd,
    _mem: Arc<GuestMemoryMmap>,
    _kvm: KvmContext,
    pio: Arc<Bus>,
    mmio: Arc<Bus>,
    legacy: LegacyDevices,
    fs: FsDevices,
    latch: Arc<StopLatch>,
    info: Arc<VmInfo>,
    /// Closed by the stop sequence, before `vmm.stop`.
    control: Option<ControlServer>,
    control_path: Option<PathBuf>,
    audit: AuditSink,
    /// Forward stdin to the console and put the terminal in raw mode.
    interactive: bool,
}

impl Vmm {
    /// Builds the VM described by `cfg`, in the boot order of the module
    /// docs, and records `vmm.start`.
    pub fn new(cfg: VmConfig) -> Result<Vmm, VmmError> {
        let built = Instant::now();
        if cfg.vcpus == 0 {
            return Err(VmmError::Config("a VM needs at least one vCPU".into()));
        }
        let mem_size = cfg
            .mem_mib
            .checked_mul(1 << 20)
            .ok_or_else(|| VmmError::Config(format!("{} MiB of memory", cfg.mem_mib)))?;
        let kvm = KvmContext::open()?;
        let missing = kvm.missing_caps();
        if !missing.is_empty() {
            return Err(KvmError::MissingCaps(missing).into());
        }
        if usize::from(cfg.vcpus) > kvm.max_vcpus() {
            return Err(VmmError::Config(format!(
                "{} vCPUs exceed this host's KVM limit of {}",
                cfg.vcpus,
                kvm.max_vcpus()
            )));
        }
        raise_nofile_limit()?;

        let vm = kvm.kvm.create_vm().map_err(kvm_ioctl("create_vm"))?;
        vm.set_tss_address(KVM_TSS_ADDRESS as usize)
            .map_err(kvm_ioctl("set_tss_address"))?;
        vm.create_irq_chip().map_err(kvm_ioctl("create_irq_chip"))?;
        vm.create_pit2(kvm_pit_config {
            flags: KVM_PIT_SPEAKER_DUMMY,
            ..Default::default()
        })
        .map_err(kvm_ioctl("create_pit2"))?;

        let mem = Arc::new(create_guest_memory(mem_size)?);
        register_memory(&vm, &mem)?;

        let (entry, kernel_end) = load_kernel(&mem, &cfg.kernel)?;
        let initrd = match &cfg.initramfs {
            Some(path) => Some(load_initramfs(&mem, path, kernel_end)?),
            None => None,
        };

        let console = cfg.console.open().map_err(VmmError::Console)?;
        let legacy = LegacyDevices::new(console).map_err(setup("legacy devices"))?;
        let mut pio = Bus::new();
        legacy.attach(&mut pio)?;
        {
            let serial = legacy.serial.lock().unwrap_or_else(|e| e.into_inner());
            vm.register_irqfd(serial.interrupt_evt(), COM1_GSI)
                .map_err(kvm_ioctl("register_irqfd"))?;
        }
        let set = DeviceSet::from_config(&cfg);
        let mut mmio = Bus::new();
        let mut slots = SlotAllocator::new()?;
        let fs = FsDevices::attach(
            &vm,
            &mem,
            &mut mmio,
            &mut slots,
            &cfg.fs_shares,
            &cfg.audit,
            cfg.fs_audit,
        )?;

        let cmdline = kernel_cmdline(cfg.debug_boot, &cfg.cmdline_extra, &set)?;
        load_cmdline(&*mem, GuestAddress(CMDLINE_START), &cmdline).map_err(VmmError::Cmdline)?;
        let cmdline = cmdline
            .as_cstring()
            .map_err(|e| VmmError::Arch(crate::arch::Error::Cmdline(e)))?;
        let cmdline_size = cmdline.as_bytes_with_nul().len();
        let cmdline = cmdline.to_string_lossy().into_owned();

        configure_system(
            &mem,
            GuestAddress(CMDLINE_START),
            cmdline_size,
            initrd,
            cfg.vcpus,
        )?;

        let vcpus = create_vcpus(&kvm, &vm, &mem, cfg.vcpus, entry)?;
        let latch = Arc::new(StopLatch::new().map_err(setup("stop eventfd"))?);
        let info = Arc::new(VmInfo {
            session_id: cfg
                .control
                .as_ref()
                .map(|control| control.session_id.to_string())
                .unwrap_or_default(),
            built,
            vcpus: cfg.vcpus,
            mem_mib: cfg.mem_mib,
            devices: present_slots(&set)
                .iter()
                .map(|slot| slot.id.name().to_owned())
                .collect(),
            audit: cfg.audit.clone(),
        });

        let start = VmmStart {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            kernel: artifact("kernel", &cfg.kernel)?,
            initramfs: match &cfg.initramfs {
                Some(path) => Some(artifact("initramfs", path)?),
                None => None,
            },
            cmdline,
            vcpus: u32::from(cfg.vcpus),
            mem_mib: cfg.mem_mib,
            shares: share_refs(&cfg.fs_shares),
        };
        tracing::debug!("vmm.start: {start:?}");
        cfg.audit.emit(Submission {
            ring: Ring::Host,
            ts_guest_ns: None,
            subject: None,
            payload: Payload::VmmStart(start),
            span: None,
            priority: Priority::Normal,
        })?;

        // After vmm.start, so the log never has a control.connect before
        // it; a failure here is recorded like one in `run`.
        let (control, control_path) = match &cfg.control {
            None => (None, None),
            Some(control) => {
                let handle = VmmHandle::new(latch.clone(), info.clone());
                let ops = Arc::new(VmmOps::new(handle.clone()));
                match ControlServer::bind(&control.state_dir, handle, ops) {
                    Ok((server, path)) => (Some(server), Some(path)),
                    Err(source) => {
                        record_stop(&cfg.audit, "vmm_error", 1);
                        return Err(VmmError::Control {
                            state_dir: control.state_dir.clone(),
                            source,
                        });
                    }
                }
            }
        };

        Ok(Vmm {
            vcpus,
            _vm: vm,
            _mem: mem,
            _kvm: kvm,
            pio: Arc::new(pio),
            mmio: Arc::new(mmio),
            legacy,
            fs,
            latch,
            info,
            control,
            control_path,
            interactive: cfg.stdin && matches!(cfg.console, ConsoleOut::Stdio) && stdin_is_tty(),
            audit: cfg.audit,
        })
    }

    /// A handle that can stop the VM from another thread.
    pub fn handle(&self) -> VmmHandle {
        VmmHandle::new(self.latch.clone(), self.info.clone())
    }

    /// The control socket's path, when the VM has one.
    pub fn control_path(&self) -> Option<&Path> {
        self.control_path.as_deref()
    }

    /// Runs the VM until it stops, then runs the stop sequence (see
    /// [`crate::lifecycle`]) and returns how it ended. `vmm.stop` is
    /// recorded on every path, with reason `vmm_error` when the VMM itself
    /// failed.
    pub fn run(mut self) -> Result<VmExit, VmmError> {
        let vcpus = mem::take(&mut self.vcpus);
        let Started {
            mut main_loop,
            vcpus,
            terminal,
        } = match self.start(vcpus) {
            Ok(started) => started,
            Err(error) => {
                self.fs.close();
                self.latch.mark_stopped();
                if let Some(control) = self.control.take() {
                    control.shutdown();
                }
                record_stop(&self.audit, "vmm_error", 1);
                return Err(error);
            }
        };
        let outcome = wait_for_stop(&mut main_loop, &self.latch).map_err(VmmError::EventLoop);
        let (reason, exit_code) = match &outcome {
            Ok(exit) => (exit.audit_reason(), exit_code_for(exit)),
            Err(_) => ("vmm_error", 1),
        };
        let teardown = Teardown {
            vcpus,
            fs: &self.fs,
            devices: &self.legacy,
            control: self.control.take(),
            latch: &self.latch,
            audit: &self.audit,
            terminal,
        };
        stop(teardown, reason, exit_code);
        outcome
    }

    /// Sets up the main loop, enters raw mode when interactive, and starts
    /// the vCPU threads, last, so that nothing fallible follows them.
    fn start(&self, vcpus: Vec<VcpuFd>) -> Result<Started, VmmError> {
        register_kick_handler().map_err(setup("vCPU kick signal handler"))?;
        block_stop_signals().map_err(setup("signal mask"))?;
        let signals = SignalFd::new().map_err(setup("signalfd"))?;
        let mut main_loop: MainLoop = EventManager::new().map_err(VmmError::EventLoop)?;

        let reset_evt = self
            .legacy
            .reset_evt
            .try_clone()
            .map_err(setup("reset eventfd"))?;
        let mut exited = Vec::with_capacity(vcpus.len());
        let mut exited_watch = Vec::with_capacity(vcpus.len());
        for _ in &vcpus {
            let evt = EventFd::new(EFD_NONBLOCK).map_err(setup("vCPU exit eventfd"))?;
            exited_watch.push(evt.try_clone().map_err(setup("vCPU exit eventfd"))?);
            exited.push(evt);
        }
        let (exits_tx, exits) = mpsc::channel();
        let control = ControlSubscriber::new(
            self.latch.clone(),
            reset_evt,
            signals,
            exited_watch,
            exits,
            self.audit.clone(),
        );
        let fds = control.fds();
        add_subscriber(&mut main_loop, Box::new(control), &fds)?;

        let terminal = if self.interactive {
            let subscriber = StdinSubscriber::new(self.legacy.serial.clone(), self.handle())
                .map_err(setup("stdin subscriber"))?;
            let fds = subscriber.fds();
            add_subscriber(&mut main_loop, Box::new(subscriber), &fds)?;
            RawModeGuard::enter().map_err(setup("raw terminal"))?
        } else {
            None
        };

        let vcpus = VcpuSet::spawn(vcpus, &self.pio, &self.mmio, &exits_tx, exited)
            .map_err(setup("vCPU threads"))?;
        self.latch.mark_running();
        Ok(Started {
            main_loop,
            vcpus,
            terminal,
        })
    }
}

/// A VM whose vCPUs run.
struct Started {
    main_loop: MainLoop,
    vcpus: VcpuSet,
    terminal: Option<RawModeGuard>,
}

/// Adds `subscriber` to the main loop and registers `fds` for input on its
/// behalf, so that a registration failure is an error here.
fn add_subscriber(
    main_loop: &mut MainLoop,
    subscriber: Box<dyn MutEventSubscriber>,
    fds: &[std::os::fd::RawFd],
) -> Result<(), VmmError> {
    let id = main_loop.add_subscriber(subscriber);
    let mut ops = main_loop.event_ops(id).map_err(VmmError::EventLoop)?;
    for &fd in fds {
        ops.add(Events::new_raw(fd, EventSet::IN))
            .map_err(VmmError::EventLoop)?;
    }
    Ok(())
}

/// Raises the soft `RLIMIT_NOFILE` to the hard limit: every device queue,
/// eventfd and open guest file takes a descriptor.
fn raise_nofile_limit() -> Result<(), VmmError> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes one rlimit into `limit`.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(VmmError::Rlimit(io::Error::last_os_error()));
    }
    if limit.rlim_cur < limit.rlim_max {
        limit.rlim_cur = limit.rlim_max;
        // SAFETY: setrlimit reads one rlimit from `limit`.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
            return Err(VmmError::Rlimit(io::Error::last_os_error()));
        }
    }
    Ok(())
}

/// Maps each guest memory region into the VM, slot `i` for region `i`.
fn register_memory(vm: &VmFd, mem: &GuestMemoryMmap) -> Result<(), VmmError> {
    for (slot, region) in mem.iter().enumerate() {
        let host = region
            .get_host_address(MemoryRegionAddress(0))
            .map_err(|_| VmmError::Config("a guest memory region has no host mapping".into()))?;
        let region = kvm_userspace_memory_region {
            slot: u32::try_from(slot)
                .map_err(|_| VmmError::Config("too many memory regions".into()))?,
            flags: 0,
            guest_phys_addr: region.start_addr().raw_value(),
            memory_size: region.len(),
            userspace_addr: host as u64,
        };
        // SAFETY: the region is a live mapping of `region.len()` bytes that
        // the Vmm keeps until after the VM is gone (see its field order).
        unsafe { vm.set_user_memory_region(region) }
            .map_err(kvm_ioctl("set_user_memory_region"))?;
    }
    Ok(())
}

/// Loads the ELF kernel at its physical addresses, which must be at or above
/// 1 MiB. Returns its 64-bit entry point and the end of its image.
fn load_kernel(
    mem: &GuestMemoryMmap,
    path: &Path,
) -> Result<(GuestAddress, GuestAddress), VmmError> {
    let mut file = File::open(path).map_err(|source| VmmError::Read {
        what: "the kernel",
        path: path.to_owned(),
        source,
    })?;
    let loaded =
        Elf::load(mem, None, &mut file, Some(GuestAddress(HIMEM_START))).map_err(|source| {
            VmmError::Kernel {
                path: path.to_owned(),
                source,
            }
        })?;
    tracing::debug!(
        "kernel: entry {:#x}, end {:#x}",
        loaded.kernel_load.raw_value(),
        loaded.kernel_end
    );
    Ok((loaded.kernel_load, GuestAddress(loaded.kernel_end)))
}

/// Copies the initramfs to the top of low memory.
fn load_initramfs(
    mem: &GuestMemoryMmap,
    path: &Path,
    kernel_end: GuestAddress,
) -> Result<InitrdConfig, VmmError> {
    let read_error = |source| VmmError::Read {
        what: "the initramfs",
        path: path.to_owned(),
        source,
    };
    let mut file = File::open(path).map_err(read_error)?;
    let size = file.metadata().map_err(read_error)?.len();
    let size = usize::try_from(size)
        .map_err(|_| VmmError::Config(format!("an initramfs of {size} bytes")))?;
    let address = initrd_load_addr(mem, size, kernel_end)?;
    mem.read_exact_volatile_from(address, &mut file, size)
        .map_err(|source| VmmError::Initramfs {
            path: path.to_owned(),
            source,
        })?;
    tracing::debug!("initramfs: {size} bytes at {:#x}", address.raw_value());
    Ok(InitrdConfig { address, size })
}

/// Creates and sets up the vCPUs: CPUID, MSRs and FPU on each; registers and
/// special registers on the BSP only; LINT0 and LINT1 on each.
fn create_vcpus(
    kvm: &KvmContext,
    vm: &VmFd,
    mem: &GuestMemoryMmap,
    count: u8,
    entry: GuestAddress,
) -> Result<Vec<VcpuFd>, VmmError> {
    let mut vcpus = Vec::with_capacity(usize::from(count));
    for id in 0..count {
        let vcpu = vm
            .create_vcpu(u64::from(id))
            .map_err(kvm_ioctl("create_vcpu"))?;
        cpuid::setup_cpuid(&kvm.kvm, &vcpu, id, count)?;
        msr::setup_msrs(&vcpu)?;
        regs::setup_fpu(&vcpu)?;
        if id == 0 {
            regs::setup_regs(&vcpu, entry)?;
            regs::setup_sregs(mem, &vcpu)?;
        }
        interrupts::set_lint(&vcpu)?;
        vcpus.push(vcpu);
    }
    Ok(vcpus)
}

/// The shares as `vmm.start` names them: each tag and the host directory
/// the guest may change through it, in slot order.
fn share_refs(shares: &[FsShareConfig]) -> Vec<ShareRef> {
    shares
        .iter()
        .map(|share| ShareRef {
            tag: share.tag.clone(),
            host_root: share.host_dir.to_string_lossy().into_owned(),
        })
        .collect()
}

/// The file at `path` as the audit log names it: its absolute path and the
/// blake3 of its contents.
fn artifact(what: &'static str, path: &Path) -> Result<ArtifactRef, VmmError> {
    let read_error = |source| VmmError::Read {
        what,
        path: path.to_owned(),
        source,
    };
    let absolute = path.canonicalize().map_err(read_error)?;
    let mut file = File::open(&absolute).map_err(read_error)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(&mut file).map_err(read_error)?;
    Ok(ArtifactRef {
        path: absolute.display().to_string(),
        blake3: Hash::from_blake3(hasher.finalize()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_cmdline_is_quiet_by_default() {
        assert_eq!(base_cmdline(false), BASE_CMDLINE);
        assert!(BASE_CMDLINE.contains(" quiet loglevel=4 "));
        assert!(!BASE_CMDLINE.contains("earlyprintk"));
    }

    #[test]
    fn debug_boot_swaps_quiet_for_early_printk() {
        assert_eq!(
            base_cmdline(true),
            "console=ttyS0 reboot=k panic=1 pci=off nomodule 8250.nr_uarts=1 \
             i8042.noaux i8042.nomux i8042.dumbkbd lockdown=integrity random.trust_cpu=on \
             earlyprintk=serial,ttyS0,115200 loglevel=7 rdinit=/init"
        );
    }

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|&a| a.to_owned()).collect()
    }

    /// The command line of a VM with both shares, as `Vmm::new` builds it:
    /// the base, the extras, then the two devices in their fixed slots.
    fn two_share_cmdline(debug_boot: bool, extra: &[&str]) -> String {
        let devices = [
            crate::cmdline::MmioDeviceEntry {
                size: 0x1000,
                base: 0xc000_0000,
                gsi: 5,
            },
            crate::cmdline::MmioDeviceEntry {
                size: 0x1000,
                base: 0xc000_1000,
                gsi: 6,
            },
        ];
        let cmdline =
            crate::cmdline::build_cmdline(&base_cmdline(debug_boot), extra, &devices).unwrap();
        cmdline.as_cstring().unwrap().into_string().unwrap()
    }

    #[test]
    fn cmdline_size_is_the_size_of_the_command_line_the_vm_gets() {
        let extra = ["boxcar.mode=console", "boxcar.uid=1000", "boxcar.gid=1000"];
        for debug_boot in [false, true] {
            let text = two_share_cmdline(debug_boot, &extra);
            assert_eq!(
                cmdline_size(debug_boot, &strings(&extra), &DeviceSet::from_shares(2)).unwrap(),
                text.len() + 1,
                "{text}"
            );
        }
        let hello =
            crate::cmdline::build_cmdline(&base_cmdline(false), &["boxcar.mode=hello"], &[])
                .unwrap();
        assert_eq!(
            cmdline_size(
                false,
                &strings(&["boxcar.mode=hello"]),
                &DeviceSet::from_shares(0)
            )
            .unwrap(),
            hello.as_cstring().unwrap().as_bytes_with_nul().len()
        );
    }

    /// Over the limit, the size is still reported: the caller says by how
    /// much.
    #[test]
    fn cmdline_size_measures_a_command_line_over_the_limit() {
        let long = "x".repeat(3000);
        let size = cmdline_size(false, &strings(&[&long]), &DeviceSet::from_shares(2)).unwrap();
        // The extra and the space before it, then the NUL terminator.
        let without = two_share_cmdline(false, &[]).len();
        assert_eq!(size, without + 1 + long.len() + 1);
        assert!(size > CMDLINE_MAX_SIZE);
    }

    #[test]
    fn cmdline_size_refuses_what_the_vm_would_refuse() {
        assert!(matches!(
            cmdline_size(false, &strings(&["bad\u{7}"]), &DeviceSet::from_shares(0)),
            Err(VmmError::Arch(crate::arch::Error::Cmdline(_)))
        ));
    }

    #[test]
    fn vmm_start_names_every_share_and_its_host_directory() {
        let share = |tag: &str, dir: &str| FsShareConfig {
            tag: tag.into(),
            host_dir: PathBuf::from(dir),
            guest_path: "/".into(),
            cache: boxcar_fs::CachePolicyKind::Auto,
        };
        let refs = share_refs(&[share("root", "/r/rootfs"), share("workspace", "/w")]);
        let named: Vec<(&str, &str)> = refs
            .iter()
            .map(|s| (s.tag.as_str(), s.host_root.as_str()))
            .collect();
        assert_eq!(named, [("root", "/r/rootfs"), ("workspace", "/w")]);
        assert!(share_refs(&[]).is_empty());
    }

    /// The kernel command line of a VM with `set`, as text.
    fn cmdline_text(extra: &[&str], set: &DeviceSet) -> String {
        let extra = strings(extra);
        kernel_cmdline(false, &extra, set)
            .unwrap()
            .as_cstring()
            .unwrap()
            .into_string()
            .unwrap()
    }

    #[test]
    fn cmdline_size_uses_only_present_slots() {
        let none = DeviceSet {
            fs: false,
            net: false,
            vsock: false,
        };
        let text = cmdline_text(&[], &none);
        assert!(!text.contains("virtio_mmio.device="), "{text}");

        // Without virtio-fs, net and vsock keep their own slots: the entries
        // for slots 0 and 1 are not there to be taken over.
        let set = DeviceSet {
            fs: false,
            net: true,
            vsock: true,
        };
        let extra = ["boxcar.mode=hello"];
        let text = cmdline_text(&extra, &set);
        assert!(!text.contains("0xc0000000"), "{text}");
        assert!(!text.contains("0xc0001000"), "{text}");
        assert!(
            text.ends_with("virtio_mmio.device=4K@0xc0002000:7 virtio_mmio.device=4K@0xc0003000:8"),
            "{text}"
        );
        assert_eq!(
            cmdline_size(false, &strings(&extra), &set).unwrap(),
            text.len() + 1
        );
    }

    #[test]
    fn extras_follow_the_base() {
        let cmdline =
            crate::cmdline::build_cmdline(&base_cmdline(true), &["boxcar.mode=hello"], &[])
                .unwrap();
        let text = cmdline.as_cstring().unwrap().into_string().unwrap();
        assert!(text.starts_with("console=ttyS0 "), "{text}");
        assert!(
            text.ends_with("loglevel=7 rdinit=/init boxcar.mode=hello"),
            "{text}"
        );
    }
}
