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
