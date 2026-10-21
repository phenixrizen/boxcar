# Denying programs by policy wherever they run from (#33)

Branch `issue-33`, from `main`. The M5 plan (`docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`, section 8) decided *exec denial at ring 0, by path, on the shares*, and set aside denial that also covers programs off the shares: a program copied to the guest's tmpfs first and run from there is not stopped (the copy is a recorded write, and the reconciler's rules still see the exec). This plan is that work. Subject: `sensor: deny a denied program's name wherever it runs from`.

## 1. What exists

- **`[exec] deny`** is a list of globs of guest paths (`docs/policy.md`): `**/nc`, `/usr/bin/{socat,telnet}`, the default profile's `**/nc`, `**/nc.openbsd`, `**/netcat`, `**/ncat`, `**/socat`, `**/telnet`. AuditFs refuses any open of a matching path on a share (`fs.denied{op: "exec"}`), its rename and its link. A live exception (`policy.update`, kind `exec`) lifts a deny for its TTL.
- **The sensor** (ring 1) runs as root in the guest with BPF LSM programs already (`socket_connect`, `file_open`, `bpf`, `task_kill`; `guards.rs` refuses with `-EPERM` and reports `proc.lsm_deny`). The guest kernel's LSM list is `landlock,lockdown,yama,bpf`. The sensor's stream to the VMM (vsock port 1026) carries frames one way, sensor to VMM; the sensor's loop polls its ring buffer and its TLS resolver, never the stream. The VMM's `SensorIngest` holds the other end of a `UnixStream` pair, writable.
- **The policy lives in the VMM** (`boxcar-vmm/src/policy.rs`, `LivePolicy`): the globs, the exceptions and their expiry. The sensor is told nothing of it today; init gets `--session-cgroup` only.

## 2. Design

- **What ring 1 denies: a name, wherever it is.** A glob's last component is the name it denies: `**/nc` denies `nc`; `/usr/bin/{socat,telnet}` denies `socat` and `telnet`. A name with `*` or `?` in it cannot be matched in a BPF program and is left to ring 0 alone, which `policy.loaded` says (`exec_ring1 {names, left_to_ring0}`). The denial is by the executed file's name (`bprm->filename`'s last component), so a copy under the same name anywhere (tmpfs, a home directory, `/proc/self/exe` of a renamed binary aside) is refused; a copy under another name is not, and the write that made it is in the log as before. That is the bound of this task: content identity (a hash of the file at exec, through IMA) is a later one.
- **The program.** A sleepable LSM program on `bprm_check_security`: in the session's cgroup only; reads the filename, finds its last component (a bounded scan of at most 256 bytes), looks it up in `EXEC_DENY` (a `HashMap<[u8; 64], u8>`, names longer than 63 bytes never match), and on a hit reports `proc.exec_denied {tid, tgid, filename}` (a new event kind, written through at once like `proc.lsm_deny`) and returns `-EPERM`. `execve` then fails with `EPERM`; the shell says *Permission denied*.
- **The channel.** The VMM writes host frames to the sensor's stream, the sensor reads them: `[u32 LE len][json]` as the sensor's own frames, `HostFrame::ExecDeny { version, names }`, the whole set each time (at most 1024 names, each at most 63 bytes). The sensor's loop gains the stream as a third `pollfd`; a frame replaces the map's contents. The VMM sends the set when the sensor connects (after its `proc.sensor_status`) and whenever the live policy changes it (`policy.update`, an exception granted or expired); `policy.loaded` and `policy.changed` carry `exec_ring1` with the count sent.
- **Ring 0 keeps its denial** on the shares, by path, as today: the two are layers, and a session without the sensor (`--no-sensor`) keeps what it had.
- **The record and the rules.** `proc.exec_denied` is a ring 1 record; the reconciler's `policy_denial` rule fires on it as on `fs.denied`.

## 3. Where in the code

- `crates/boxcar-sensor-common`: `Kind::ExecDenied`, `ExecDeniedEvent { header, filename_len, filename[256] }`, the `EXEC_DENY` key type and bounds.
- `crates/boxcar-sensor-ebpf/src/exec_deny.rs`: the LSM program and the map; `main.rs` registers it; `cargo xtask sensor` checks the object for it.
- `crates/boxcar-sensor`: `load.rs` attaches it (`proc.sensor_status` names it); `main.rs` polls the stream and applies `ExecDeny` frames to the map; `frame.rs` converts the event; `host_frame.rs` parses host frames.
- `crates/boxcar-proto`: `ProcExecDenied` payload (`proc.exec_denied`), `sensor::HostFrame`, `policy.loaded`/`policy.changed` gain `exec_ring1`; schemas regenerated.
- `crates/boxcar-vmm`: `sensor_ingest.rs` keeps the writable end and sends frames; `policy.rs` derives the names from the globs and exceptions (`exec_names()`), and the policy's change path calls the sender; `vmm.rs` wires the two.
- `crates/boxcar-audit/src/reconcile/rules.rs`: `policy_denial` on `proc.exec_denied`.
- Docs: `docs/policy.md` (`[exec] deny`: by name wherever it runs from, through the sensor; by path on the shares), `docs/audit-events.md` (the record, `policy.loaded`), `docs/reconciler.md` (the rule's row), `docs/architecture.md` (the sensor's programs), the M5 plan's section 8.

## 4. Tests

- **Unit:** names from globs (`**/nc` → `nc`; braces expanded; `*` left to ring 0; a name over 63 bytes left); host frame encoding and parsing, with its limits; the sensor's map update from a frame (in a test with no programs loaded, the parser alone).
- **Gated (M3/M5):** with the default policy, `cp /bin/busybox /dev/shm/nc && /dev/shm/nc` (the guest's own tmpfs, off the shares, where ring 0 cannot see it) fails with *Permission denied* and the log holds `proc.exec_denied{filename: "/dev/shm/nc"}` and a `policy_denial` finding; `cp /bin/busybox /dev/shm/true && /dev/shm/true` runs (busybox answers to the name it is run by) (the bound, recorded as such); an exception of kind `exec` for `**/nc` lets `/dev/shm/nc` run until it expires; `--no-sensor` keeps ring 0's denial on the shares and none off them.
- **The sensor's object:** `cargo xtask sensor` lists the new program and map.

## 5. Out of scope

- Denial by content (IMA's hash at exec), which needs `CONFIG_IMA` in the guest kernel and the hashes of the shares' denied files.
- Names with wildcards in ring 1.
- Denying `mmap(PROT_EXEC)` of a denied file, or interpreters (`sh /tmp/script`): the policy denies programs, not scripts.

## 6. Decisions

- **By name, through the sensor; by path, through the shares.** Two layers, each what its ring can see.
- **The whole set each time**, so the sensor's map never holds a stale name and a lost frame costs nothing but the next.
- **A session without the sensor keeps ring 0's denial**, and `policy.loaded` says ring 1 sent nothing.
