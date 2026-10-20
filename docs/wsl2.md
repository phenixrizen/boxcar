# boxcar on WSL2

What running boxcar inside WSL2 needs beyond what any Linux machine needs:
KVM inside the WSL2 VM, access to `/dev/kvm`, and a kernel whose seccomp
and Landlock boxcar can use. `boxcar doctor` checks each of these, so run it
first:

```bash
cargo run -p boxcar -- doctor
```

## Nested virtualization

boxcar runs its guest under KVM. Under WSL2, Linux is itself a guest of
Windows' hypervisor, so KVM works there only when Windows passes the CPU's
virtualization extensions through to it: nested virtualization. When it is
on, the `flags` lines of `/proc/cpuinfo` list `vmx` (Intel) or `svm` (AMD),
and `/dev/kvm` exists. When it is off, neither is there, and `boxcar doctor`
says so on its first line:

```
FAIL WSL2 nested virtualization: neither vmx nor svm in /proc/cpuinfo, so there is no KVM; ...
```

It can go off with no change inside WSL: the development machine lost it
after a Windows restart. To turn it on, in Windows:

1. Put these lines in `%UserProfile%\.wslconfig`, making the file if there
   is none (other settings under `[wsl2]` stay):

   ```ini
   [wsl2]
   nestedVirtualization=true
   ```

   Microsoft's `.wslconfig` reference documents this setting for Windows 11.

2. Stop WSL, from PowerShell or a command prompt, so that the next start
   reads the file:

   ```
   wsl --shutdown
   ```

3. Start WSL again, and check:

   ```bash
   grep -o -w -E 'vmx|svm' /proc/cpuinfo | sort -u   # prints vmx or svm
   ls -l /dev/kvm                                     # exists
   cargo run -p boxcar -- doctor
   ```

## Access to `/dev/kvm`

boxcar opens `/dev/kvm` for reading and writing as you, without root. When
`boxcar doctor` says it cannot (`Permission denied`), see who owns the
device, then either join its group or give yourself access by ACL:

```bash
ls -l /dev/kvm                             # its owner, group and mode
sudo usermod -aG kvm "$USER"               # join its group (here kvm), or
sudo setfacl -m "u:$(id -un):rw" /dev/kvm  # give yourself rw by ACL
```

A group you join applies from your next login; `wsl --shutdown` and
starting WSL again makes sure of it. The ACL lasts until WSL restarts,
which makes the device node again.

## seccomp and Landlock under WSL's kernel

`boxcar run` confines its own process, the VMM, with a seccomp filter and
with Landlock. Both come from the kernel, and WSL2 runs Microsoft's kernel,
not the distribution's, so what a session gets depends on that kernel's
version and configuration. `boxcar doctor` reports both:

- **seccomp.** WSL2's kernel has seccomp filters. `--seccomp enforce`,
  `boxcar run`'s default, needs the kernel's `SECCOMP_RET_KILL_PROCESS`
  action, and `--seccomp log` its `SECCOMP_RET_LOG`. `boxcar doctor` reads
  the actions from `/proc/sys/kernel/seccomp/actions_avail`: it fails when
  `kill_process` is missing, and reports `log` missing without failing.
- **Landlock.** Whether there is one depends on the WSL kernel: on its
  version, and on `landlock` being in the kernel's `lsm=` list. boxcar uses
  ABI 2 (Linux 5.19) or later; it treats ABI 1 as no Landlock, because
  without the `REFER` right a rename across directories fails. `boxcar
  doctor` prints the ABI the kernel offers (`OK   Landlock ABI N`), or why
  there is none it can use. Without one, a session runs on without Landlock
  and records `"unsupported"` in `vmm.start`'s `hardening.landlock` (see
  [audit-events.md](audit-events.md)). On 2026-10-20 the development
  machine's kernel, `6.18.54.1-microsoft-standard-WSL2`, offered ABI 7;
  check yours with `boxcar doctor`.

Two flags take either away when it stops a session: `--seccomp off` and
`--landlock off` (or `BOXCAR_SECCOMP=off` and `BOXCAR_LANDLOCK=off`; the
flag wins over the variable). The session then records `"off"` for it in
`vmm.start`.
