// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! The fixed virtio-mmio slot table.
//!
//! Every virtio device has one slot, whether or not the VM has the device:
//! virtio-fs `root` at slot 0, virtio-fs `workspace` at slot 1, virtio-net
//! at slot 2 and virtio-vsock at slot 3. Each is 4 KiB, slot `n` at
//! `0xC000_0000` plus `n` times `0x1000`, on GSI `5 + n`. A device the VM
//! does not have leaves its slot empty and the others stay where they are,
//! so a guest, a log or a test can rely on a device's address and interrupt
//! whatever else is attached.
//!
//! [`DeviceSet`] says which devices a VM has and [`present_slots`] lists
//! their slots in slot order. The kernel command line takes its
//! `virtio_mmio.device=` entries from it, in [`Vmm::new`] and in
//! [`cmdline_size`], which `boxcar run` uses to refuse a command line that
//! is too long before it starts a session, so the two cannot disagree.
//!
//! [`Vmm::new`]: crate::vmm::Vmm::new
//! [`cmdline_size`]: crate::vmm::cmdline_size

use boxcar_virtio::mmio::MMIO_SLOT_SIZE;

use crate::cmdline::MmioDeviceEntry;
use crate::vmm::VmConfig;

/// Which slot of the table a device has. The number is the slot's index in
/// [`SLOT_TABLE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotId {
    /// The virtio-fs share tagged `root`.
    FsRoot = 0,
    /// The virtio-fs share tagged `workspace`.
    FsWorkspace = 1,
    /// virtio-net.
    Net = 2,
    /// virtio-vsock.
    Vsock = 3,
}

impl SlotId {
    /// The slot's name as the control socket's `status` lists it:
    /// `fs:root`, `fs:workspace`, `net`, `vsock`.
    pub fn name(self) -> &'static str {
        match self {
            SlotId::FsRoot => "fs:root",
            SlotId::FsWorkspace => "fs:workspace",
            SlotId::Net => "net",
            SlotId::Vsock => "vsock",
        }
    }
}

/// One entry of the table: where a device's registers are and which
/// interrupt it raises.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    pub id: SlotId,
    /// Guest physical base address of the slot.
    pub base: u64,
    /// The GSI the device interrupts on.
    pub gsi: u32,
    /// Size of the slot in bytes: [`MMIO_SLOT_SIZE`] (4 KiB) for every slot.
    pub size: u64,
}

/// [`MMIO_SLOT_SIZE`] as the kernel command line takes it.
const CMDLINE_SLOT_SIZE: u32 = 0x1000;
const _: () = assert!(CMDLINE_SLOT_SIZE as u64 == MMIO_SLOT_SIZE);

impl Slot {
    /// The `virtio_mmio.device=` entry that announces the slot to the guest.
    pub fn cmdline_entry(&self) -> MmioDeviceEntry {
        MmioDeviceEntry {
            size: CMDLINE_SLOT_SIZE,
            base: self.base,
            gsi: self.gsi,
        }
    }
}

/// The slots, in slot order: virtio-fs `root` at `0xC000_0000` on GSI 5,
/// virtio-fs `workspace` at `0xC000_1000` on GSI 6, virtio-net at
/// `0xC000_2000` on GSI 7, virtio-vsock at `0xC000_3000` on GSI 8.
pub const SLOT_TABLE: [Slot; 4] = [
    Slot {
        id: SlotId::FsRoot,
        base: 0xC000_0000,
        gsi: 5,
        size: MMIO_SLOT_SIZE,
    },
    Slot {
        id: SlotId::FsWorkspace,
        base: 0xC000_1000,
        gsi: 6,
        size: MMIO_SLOT_SIZE,
    },
    Slot {
        id: SlotId::Net,
        base: 0xC000_2000,
        gsi: 7,
        size: MMIO_SLOT_SIZE,
    },
    Slot {
        id: SlotId::Vsock,
        base: 0xC000_3000,
        gsi: 8,
        size: MMIO_SLOT_SIZE,
    },
];

// `slot` indexes the table by `SlotId`.
const _: () = {
    let mut i = 0;
    while i < SLOT_TABLE.len() {
        assert!(SLOT_TABLE[i].id as usize == i);
        i += 1;
    }
};

/// The entry of [`SLOT_TABLE`] for `id`.
pub fn slot(id: SlotId) -> Slot {
    SLOT_TABLE[id as usize]
}

/// Which devices a VM has.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceSet {
    /// Both virtio-fs devices: slots 0 and 1.
    pub fs: bool,
    /// virtio-net: slot 2.
    pub net: bool,
    /// virtio-vsock: slot 3.
    pub vsock: bool,
}

impl DeviceSet {
    /// The devices of a VM with `fs_shares` virtio-fs shares: both
    /// virtio-fs devices when there are any shares (the VMM takes none, or
    /// `root` and `workspace` together), and neither net nor vsock yet. The
    /// one place that decides what the devices are, for [`from_config`] and
    /// for `boxcar run`, which has to know before it can build a
    /// [`VmConfig`].
    ///
    /// [`from_config`]: DeviceSet::from_config
    pub fn from_shares(fs_shares: usize) -> DeviceSet {
        DeviceSet {
            fs: fs_shares > 0,
            net: false,
            vsock: false,
        }
    }

    /// The devices `Vmm::new` creates for `cfg`.
    pub fn from_config(cfg: &VmConfig) -> DeviceSet {
        DeviceSet::from_shares(cfg.fs_shares.len())
    }

    /// Whether the device of slot `id` is present.
    pub fn has(&self, id: SlotId) -> bool {
        match id {
            SlotId::FsRoot | SlotId::FsWorkspace => self.fs,
            SlotId::Net => self.net,
            SlotId::Vsock => self.vsock,
        }
    }
}

/// The slots of the devices in `set`, in slot order, each at its fixed
/// place: without virtio-fs, net is still slot 2.
pub fn present_slots(set: &DeviceSet) -> Vec<Slot> {
    SLOT_TABLE
        .into_iter()
        .filter(|slot| set.has(slot.id))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_matches_the_constraints() {
        for (i, slot) in SLOT_TABLE.iter().enumerate() {
            assert_eq!(slot.id as usize, i);
            assert_eq!(slot.base, 0xC000_0000 + i as u64 * 0x1000);
            assert_eq!(slot.gsi, 5 + i as u32);
            assert_eq!(slot.size, 0x1000);
        }
        let named = [
            (SlotId::FsRoot, 0xC000_0000, 5),
            (SlotId::FsWorkspace, 0xC000_1000, 6),
            (SlotId::Net, 0xC000_2000, 7),
            (SlotId::Vsock, 0xC000_3000, 8),
        ];
        for (id, base, gsi) in named {
            let slot = slot(id);
            assert_eq!((slot.id, slot.base, slot.gsi), (id, base, gsi));
        }
    }

    #[test]
    fn present_slots_keeps_fixed_positions() {
        let set = DeviceSet {
            fs: false,
            net: true,
            vsock: true,
        };
        let present = present_slots(&set);
        let seen: Vec<(SlotId, u64, u32)> = present.iter().map(|s| (s.id, s.base, s.gsi)).collect();
        assert_eq!(
            seen,
            [
                (SlotId::Net, 0xC000_2000, 7),
                (SlotId::Vsock, 0xC000_3000, 8)
            ]
        );
    }

    #[test]
    fn present_slots_lists_every_enabled_device_in_slot_order() {
        let all = DeviceSet {
            fs: true,
            net: true,
            vsock: true,
        };
        assert_eq!(present_slots(&all), SLOT_TABLE);
        assert!(present_slots(&DeviceSet::default()).is_empty());
        let fs: Vec<SlotId> = present_slots(&DeviceSet::from_shares(2))
            .iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(fs, [SlotId::FsRoot, SlotId::FsWorkspace]);
    }

    #[test]
    fn present_slots_are_named_for_the_status() {
        let names: Vec<&str> = present_slots(&DeviceSet::from_shares(2))
            .iter()
            .map(|slot| slot.id.name())
            .collect();
        assert_eq!(names, ["fs:root", "fs:workspace"]);
        let all: Vec<&str> = SLOT_TABLE.iter().map(|slot| slot.id.name()).collect();
        assert_eq!(all, ["fs:root", "fs:workspace", "net", "vsock"]);
    }

    #[test]
    fn a_slot_announces_itself_to_the_guest_at_its_fixed_place() {
        let entry = slot(SlotId::Net).cmdline_entry();
        assert_eq!(
            (entry.size, entry.base, entry.gsi),
            (0x1000, 0xC000_2000, 7)
        );
        for slot in SLOT_TABLE {
            assert_eq!(u64::from(slot.cmdline_entry().size), slot.size);
        }
    }

    #[test]
    fn the_device_set_follows_the_shares() {
        let none = DeviceSet::from_shares(0);
        assert_eq!(none, DeviceSet::default());
        for shares in [1, 2] {
            let set = DeviceSet::from_shares(shares);
            assert_eq!((set.fs, set.net, set.vsock), (true, false, false));
        }
    }

    #[test]
    fn from_config_and_from_shares_agree() {
        let dir = tempfile::tempdir().unwrap();
        let (sink, writer) = boxcar_audit::spawn(boxcar_audit::WriterConfig::new(
            dir.path(),
            boxcar_proto::SessionId::new(),
        ))
        .unwrap();
        let mut cfg = VmConfig::new("vmlinux", sink);
        assert_eq!(DeviceSet::from_config(&cfg), DeviceSet::from_shares(0));
        let share = |tag: &str| boxcar_fs::FsShareConfig {
            tag: tag.into(),
            host_dir: dir.path().to_path_buf(),
            guest_path: "/".into(),
            cache: boxcar_fs::CachePolicyKind::Auto,
        };
        cfg.fs_shares = vec![share("root"), share("workspace")];
        let set = DeviceSet::from_config(&cfg);
        assert_eq!(set, DeviceSet::from_shares(2));
        assert!(set.fs);
        drop(cfg);
        writer.close().unwrap();
    }
}
