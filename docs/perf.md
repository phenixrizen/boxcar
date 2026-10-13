# virtio-fs throughput: one request queue against four

Measured 2026-10-02 for Task 14 of M2, on the development machine (WSL2,
Linux 6.18, KVM), with a **debug build** of `boxcar` (`target/debug`), the
Alpine 3.22 minirootfs as the guest, 1 GiB of guest memory, no network
card, the audit log at its normal level (every `fs.create` and `fs.close`
recorded, every closed file that was written hashed off the reply path by
two threads a share). The VMM gives each share's virtio-fs device one
request queue per vCPU, four at most (`--vcpus 1` is one queue, `--vcpus
4` four), and one worker thread per request queue; Linux picks a queue by
the CPU the request comes from.

Two workloads, inside the guest on the `workspace` share:

- `tar -xf alpine-minirootfs-3.22.6-x86_64.tar.gz` (about 3.4 MB, 500
  files);
- a copy of an `npm ci`-sized tree: 200 packages of 100 files each, 20,000
  files of 1 to 8 KiB (about 80 MB), once with a single `cp -r`, once as
  four `cp -r` of 50 packages each running at once.

Timed with `/proc/uptime` around the command and a `sync`; three runs each
for the serial cases, two for the parallel one. Script:
`target/perf/measure.sh` and `measure-parallel.sh` (kept out of the tree;
reproduce from this description).

## Results

| Workload | vCPUs (queues) | Runs, seconds | Median |
|---|---|---|---|
| `tar -xf` Alpine | 1 (1) | 2.47, 2.27, 2.09 | 2.27 |
| `tar -xf` Alpine | 4 (4) | 2.72, 2.96, 3.00 | 2.96 |
| one `cp -r` of the tree | 1 (1) | 99.9, 114.0, 94.4 | 99.9 |
| one `cp -r` of the tree | 4 (4) | 124.4, 130.3, 129.8 | 129.8 |
| four `cp -r`, a quarter each | 1 (1) | 45.5, 52.3 | 48.9 |
| four `cp -r`, a quarter each | 4 (4) | 38.0, 36.9 | 37.5 |

## Reading

- A single-threaded guest workload gains nothing from more queues, and
  loses a little: with one process issuing requests, one queue is busy at
  a time, and four vCPUs add scheduling and cache cost on the host. This
  is the expected shape, not a regression: the queues are there for
  guests with several processes doing I/O.
- The copy of the tree is dominated by the audit, not the queue: 20,000
  creates and 20,000 closes, each close a hash of the file on the host,
  all in a debug build. About 5 ms a file in the serial case.
- Four processes copying at once are served about a quarter faster with
  four queues and four vCPUs than with one of each (37.5 s against 48.9 s):
  each queue has its own worker thread, so four guest CPUs' requests are
  answered side by side instead of one at a time. With one vCPU the four
  copies already beat one (48.9 s against 99.9 s), because each process's
  wait on the audit and the hash overlaps the others'.

The numbers are a baseline for this machine and a debug build. They are
not a benchmark of virtio-fs; they say that multiqueue does what it should
(serve concurrent guest I/O from several threads) and costs little when
the guest does not use it.

# The gate's cost on an inspected download

Measured 2026-10-06 for Task 7 of M4, on the development machine (WSL2,
Linux 6.18, KVM), with a **debug build** of `boxcar` built with
`--features boxcar/kvm-tests` (so that `BOXCAR_TEST_UPSTREAM_ROOTS` is
read), the Alpine 3.22 minirootfs as the guest, one vCPU, and a TLS
server on the host's own address (Python's `http.server` behind `ssl`,
HTTP/1.1, a self-signed end-entity certificate for the address, trusted
through the test hook) serving a 100 MB file of random bytes. The guest
downloads the file with busybox `wget --no-check-certificate -O
/dev/null` three times each way, in one session:

- **relayed**: `--allow <host>/32:<port>` and the private range the
  address is in, the connection relayed as any TLS connection is (the
  gate reads the first bytes for the name and steps back);
- **inspected**: the same with `--inspect <host>:<port>`: the guest's
  TLS ends in boxcar, boxcar's own TLS reaches the server, the plaintext
  is relayed byte for byte and copied to the observer, which parses the
  HTTP/1.1 response and hashes the body (kept for parsing up to 16 MiB,
  hashed whole).

Timed by each flow's `net.close.dur_ms`, with nothing else running.
Script: `target/perf/gate-download.sh` (kept out of the tree; reproduce
from this description).

## Results

| Case | Runs, seconds | Median | MB/s at the median |
|---|---|---|---|
| relayed | 5.96, 12.22, 8.32 | 8.32 | 12.6 |
| inspected | 7.66, 7.75, 8.02 | 7.75 | 13.5 |

Every inspected run's `http.response` says `body_bytes: 104857600`, and
no `net.drop{reason:"observe"}` was counted: the observer kept up.

## Reading

- At this build's speed the gate costs nothing measurable: the three
  relayed runs spread over twice the difference between the two medians,
  and the inspected runs were the steadier. What bounds both is the
  guest's own TLS (busybox's `ssl_client` on one vCPU) and the relay's
  copying in a debug build, not the two rustls record layers the gate
  adds on the net thread (decrypt the guest's, encrypt for the server,
  and back) nor the copy to the observer.
- The observer never slows the relay: it is fed by a bounded channel
  with `try_send`, and a chunk it has no room for is dropped and counted
  (`net.drop{reason:"observe"}`), which marks the flow's streams degraded
  rather than holding the guest.
- A release build, and a guest client faster than busybox's, would move
  both numbers; the gate's share would show then. The shape is what this
  measurement pins: inspection is in line with the relay, not a step
  behind it.
