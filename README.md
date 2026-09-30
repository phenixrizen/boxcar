# boxcar

A microVM runtime for running AI coding agents in isolation, with a complete,
tamper-evident record of everything the agent did.

boxcar boots a small Linux guest on KVM from a directory, not a disk image.
The root filesystem and the workspace are served by the runtime itself over
virtio-fs, the guest's network is terminated by a user-mode stack inside the
runtime, and the model API is reached through a gateway that holds the real
key. Every file operation, connection, DNS query, process, and model tool call
lands in one append-only, hash-chained log. A second, best-effort sensor
inside the guest reports process lineage, and a reconciler flags where the
two views, or the model's stated intent, disagree.

Status: pre-alpha. See [docs/superpowers/specs](docs/superpowers/specs) for
the design and [docs/superpowers/plans](docs/superpowers/plans) for the
roadmap.

Licensed under Apache-2.0. Ported code keeps its original notices; see
[NOTICE](NOTICE).
