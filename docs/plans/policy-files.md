# TOML policy files and built-in profiles (M5 Task 4, #26)

Branch `issue-26`, from `main` at c1b6426. The M5 plan is `docs/plans/2026-10-13-m5-images-policy-exporters-hardening.md`, section 3 (*Crate boundaries*, *Policy files*) and section 6, Task 4. Subject: `policy: TOML policy files and built-in profiles`.

This task makes the policy file and puts its network half into force: `[egress]` through today's line policy, and the DNS rate. The other sections (`[fs]`, `[exec]`, `[spans]`, `[record]`) are parsed, checked, counted in `policy.loaded` and printed with the profiles, and take effect in Task 5 (#27), which enforces them at ring 0 and adds the live exceptions. Until then `boxcar run` says so on stderr when a policy restricts anything there (section 7).

## 1. Where it sits

| File | What |
| --- | --- |
| `crates/boxcar-policy/src/{lib,model,parse,profiles}.rs` | new crate: the TOML model, parsing with line and column, the compiled egress, the profiles |
| `crates/boxcar-net/src/policy.rs` | `Policy::from_lists(default, deny, allow, inspect)`: the lists in the order the VMM's `policy.update` already compiles them, shared by both |
| `crates/boxcar-net/src/{config,stack}.rs`, `dns/mod.rs` | `NetConfig::max_dns_qps`, the rate in `dns_query`, `REFUSED` |
| `crates/boxcar-vmm/src/{vmm,policy}.rs` | `VmConfig::policy_loaded`, recorded after `vmm.start`; `net_policy` on `Policy::from_lists` |
| `crates/boxcar-proto/src/{audit.rs,audit/payloads.rs,lib.rs}`, `proto/schema/audit-v1.json` | `policy.loaded` (58 kinds) |
| `crates/boxcar-audit/src/reconcile/rules.rs` | a query refused for the rate says so in its `policy_denial` |
| `crates/boxcar/src/{cli.rs,cmd/run.rs,cmd/policy.rs}` | `run --policy FILE\|NAME`, `policy profile NAME` |
| `crates/boxcar/tests/{run_args,policy_cli,kvm_m5}.rs` | the flags, the profiles, a gated run |
| `docs/audit-events.md`, `docs/networking.md` | `policy.loaded`, `net.dns`'s `REFUSED` and `dns_rate` |

Dependencies, as the M5 plan names them: `toml = "1"` (serde and parsing only, no writer) and `globset = "0.4"`, both in `boxcar-policy` only. `boxcar-policy` depends on `boxcar-net` for the line policy; `boxcar-fs` gains no dependency here (its `PathRules` view is Task 5's, made where it is enforced). The guest is unchanged.

## 2. The pieces

### The file

```toml
version = 1                 # required, and 1

[egress]
default = "deny"            # "allow" or "deny"; deny when absent
allow = ["api.example.com:443", "198.51.100.0/24:22"]
deny = ["*.ads.example"]
inspect = ["api.example.com:443"]
max_dns_qps = 20            # optional, 1 to 10000

[fs]
writable = ["/workspace/**"]    # the default when absent
denied = ["/workspace/.env"]
indicators = ["/var/log/**"]

[exec]
deny = ["**/nc"]

[spans]
keep_tool_args = true       # the default

[record]
scrub_argv = false          # the default
```

Every table is optional; every key in it too. Unknown keys are refused at every level (`deny_unknown_fields`). Targets are today's (`name[:port]`, `*.name[:port]`, `ip[:port]`, `ip/prefix[:port]`), checked by `boxcar_net::Policy`'s own parser so their meaning is the line policy's exactly. Path globs are `globset` globs with `literal_separator`, absolute (starting `/` or `**/`): a relative glob could never match a guest path, so it is refused rather than left to match nothing. Limits: the text at most 1 MiB, each list at most 1024 entries.

### Errors with line and column

`boxcar_policy::parse(text)` returns the policy or a `ParseError { line, column, message }`, both from 1. TOML's own errors (syntax, a wrong type, an unknown key, a missing `version`) carry the span `toml` gives; the checks after the shape is read (a target, a glob, `version`, the DNS rate, a list's length) carry the span of the value, read through `toml::Spanned`. `boxcar run` says `error: --policy PATH:LINE:COLUMN: MESSAGE` and exits 2 before anything exists, as for a line policy that does not parse.

### Compiling `[egress]`

`Policy::from_lists(default, deny, allow, inspect)` builds the lines `default D`, then `deny T` for each deny, `allow T` for each allow, `inspect T` for each inspect, and parses them: a deny of a target wins over an allow of it, as `boxcar run` orders `--deny` before `--allow` and as `policy.update` already does (`crates/boxcar-vmm/src/policy.rs`, `net_policy`, which moves onto it). It answers which list and index a failure is in, which each caller turns into its own words (a TOML span; `net.allow[2]`). The flags still add to a TOML policy as they add to a line file: its rules first, then `--deny`, `--allow`, `--inspect`.

### The DNS rate

`NetConfig::max_dns_qps: Option<u32>`, fixed for the session: `policy.update` replaces the network rules and never the rate, so a client allowing a name cannot drop it. In `dns_query`, every message that gets an answer (one with a whole header) takes a turn from the rate before anything else is decided: over the rate it is answered `REFUSED` (rcode 5) and recorded `net.dns{verdict: "deny", rule: "dns_rate", rcode: 5}` with the question as well as it reads, and nothing goes upstream. The rate is a generic cell rate: a burst of `max_dns_qps` queries, then one each `1 s / max_dns_qps`, on the stack's own `Instant`s.

### The profiles

`agent-isolate` and `agent-isolate-strict`, TOML texts in `profiles.rs`, printed by `boxcar policy profile NAME`:

- **agent-isolate**: deny by default; `allow` and `inspect` for the model providers (`api.anthropic.com`, `*.anthropic.com`, `api.openai.com`, `chatgpt.com`, `*.openai.com`); `allow` for the package registries (`registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `crates.io`, `static.crates.io`, `index.crates.io`, `dl-cdn.alpinelinux.org`, `deb.debian.org`, `security.debian.org`) and the git hosts (`github.com`, `*.githubusercontent.com`, `codeload.github.com`, `gitlab.com`); all on 443, and the two Debian mirrors on 80 too (section 7); `max_dns_qps = 20`; `writable = ["/**"]`; the reconciler's indicators as globs.
- **agent-isolate-strict**: the same egress and indicators, `writable = ["/workspace/**", "/tmp/**"]`, `[exec] deny` for `**/nc`, `**/ncat`, `**/socat`, `**/telnet`.

### `boxcar run --policy FILE|NAME`

A profile's name is the profile; anything else is a path (a file named like a profile is `./agent-isolate`). It conflicts with `--policy-file`, which keeps the line format; it does not need the network (its other sections are not about it), unlike `--policy-file`. With inspect rules the session makes its CA, and an image session its trust store, exactly as `--inspect` does today.

### `policy.loaded`

`{source, name, sha256, egress_rules, fs_rules, exec_rules}`, `src: "policy"`, recorded once for every session, right after `vmm.start` and before anything else (the control socket, the devices, the vCPUs):

- `source`: `profile` (`--policy NAME`), `file` (`--policy PATH`), or `flags` (the line policy: `--policy-file`, `--deny`, `--allow`, `--inspect`, or none of them).
- `name`: the profile's name, the path as given (`--policy` or `--policy-file`), or null; at most 4096 bytes, cut as paths are.
- `sha256`: lowercase hex of the text the policy came from (the TOML file, the profile's text, or the `--policy-file` file), or null.
- `egress_rules`: the allow, deny and inspect rules in force at boot, the flags' included. `fs_rules`: the `writable` (the default's one included), `denied` and `indicators` entries. `exec_rules`: `[exec] deny`. All 0 for a line policy's `fs_rules` and `exec_rules`.

## 3. Events and the orders they come in

- `vmm.start`, then `policy.loaded`, then whatever comes next (`control.connect`, `fs.mount`, ...). Both are emitted in `Vmm::new` before the control socket binds, so no client sees a session without them.
- A DNS message: header read (else dropped as today), then the rate, then the question (FORMERR when it is not one plain query), then the policy (NXDOMAIN), then upstream. A refused message is answered and recorded at once and costs the upstream nothing.
- `policy.update` swaps the rules (as today) and leaves the rate.

## 4. Invariants

- A TOML policy's egress is the line policy its lists would give, in the deny, allow, inspect order; pinned for `agent-isolate` by a test that parses the line policy the profile was written from and compares.
- A policy that does not parse never starts a session: refused before the audit log exists, exit 2, with line and column.
- Every DNS message that gets an answer gets one `net.dns`, the refused ones included; over the rate nothing goes upstream.
- Nothing in `[fs]`, `[exec]`, `[spans]` or `[record]` changes what a session does in this task; `policy.loaded` counts them, and stderr says they wait for Task 5 when they would restrict anything.
- Every record kind has a test of its exact JSON (`cases()`), and `policy.loaded` stays within the record limit at its longest `name`.

## 5. Out of scope

Enforcing `[fs]` and `[exec]`, applying `[spans]`, `[record]` and `indicators`, `boxcar_fs::PathRules`, live exceptions and `policy.exception` (all Task 5, #27); showing the policy file or the rate in `policy.get`; `docs/policy.md` (Task 8, #30).

## 6. Tests

- `boxcar-policy`: a table of accepted files, each field and its default; a table of refusals, each with its line and column (TOML syntax, a wrong type, an unknown key at every level, `version` missing or not 1, `default` not allow or deny, a bad target in each egress list, a bad or relative glob in each path list, `max_dns_qps` 0, over 10000, negative or fractional, a list over 1024, a text over 1 MiB); both profiles parse; `agent-isolate`'s egress equals the line policy it was written from; the strict profile's egress is the same; profile names.
- `boxcar-net`: `Policy::from_lists` (order, errors naming list and index); the rate in the stack with explicit instants: a burst passes, the next is `REFUSED` with `dns_rate` and never forwarded, the rate refills, a malformed message counts, no rate means none.
- `boxcar-proto`: `policy.loaded`'s exact JSON in `cases()`, 58 kinds, its size at a 4096-byte name; the schema regenerated.
- `boxcar-vmm`: `net_policy` errors unchanged on the shared builder.
- `boxcar-audit`: a rate refusal's `policy_denial` summary.
- `boxcar`: `--policy` and `--policy-file` conflict; an unknown file, a file that does not parse (line and column), a profile given by name, a path that looks like a name (`./agent-isolate`); `policy profile` prints each profile byte for byte and refuses an unknown name with the list; `policy.loaded`'s fields for each source.
- Gated (`kvm_m5`): an image session under a policy file with `max_dns_qps = 2` records `policy.loaded` at seq 2 with its sha256, and a burst of lookups in the guest gets `REFUSED` answers recorded with `dns_rate`.
- Checks: the Rust checks with the eBPF programs built, `cargo xtask schema` with no further diff, and `cargo xtask test-kvm m5` (the whole gated suite) on the test box.

## 7. Decisions (to the M5 plan's section 8 when the task ships)

- **Denies before allows.** The file's lists have no order between them, so a deny of a target wins over an allow of it, as the flags and `policy.update` already order them.
- **The rate is the session's, not the rules'.** `policy.update` replaces rules; a rate it could drop would be a rate a client could lift.
- **Every answered message counts against the rate**, malformed ones included, before the policy is read: it bounds what the guest can make the stack do and log per second.
- **A profile's name is the profile.** `--policy NAME|PATH` cannot ask the filesystem first without a file named `agent-isolate` changing what the flag means.
- **The Debian mirrors on 80 too.** apt's default sources are plain HTTP (signed); 443 alone would leave `apt-get update` failing under `agent-isolate`. A domain rule on 80 still admits only a request that names the host.
- **Absolute globs only**, and a 1 MiB, 1024-per-list cap: a relative glob matches no guest path, and a policy is decided linearly per connection.
- **The network half now, the rest with its enforcement.** Task 5 makes the views the filesystem reads where it reads them; this task prints a warning, not silence, for a policy whose other sections would restrict.
