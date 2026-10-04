// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The boxcar Authors

//! What `boxcar` accepts on its command line.

use std::ffi::OsString;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};

/// Run AI coding agents in a microVM with a tamper-evident audit log.
#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// Parses `args` (the program name first), and also refuses a `--`
    /// after `run` with no command after it. clap cannot see that one: it
    /// parses as no command at all, which would start an interactive shell
    /// instead of the command meant. clap refuses `--` as the value of an
    /// option, so a `--` in arguments it accepted is the separator.
    pub fn try_parse_args<I, T>(args: I) -> Result<Cli, clap::Error>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
        let cli = Cli::try_parse_from(&args)?;
        if let Command::Run(run) = &cli.command {
            if run.command.is_empty() && args.iter().any(|arg| arg == "--") {
                let (kind, message) = (
                    ErrorKind::MissingRequiredArgument,
                    "a command is required after `--`",
                );
                // Built, so that the error shows `boxcar run`'s usage.
                let mut command = Cli::command();
                command.build();
                return Err(match command.find_subcommand_mut("run") {
                    Some(run) => run.error(kind, message),
                    None => command.error(kind, message),
                });
            }
        }
        Ok(cli)
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Attach this terminal to a running session's terminal.
    ///
    /// What the session prints shows here, starting with the last 64 KiB
    /// it printed (see `--replay`), and what is typed here goes to the
    /// session, every key included: several terminals may be attached at
    /// once, and `boxcar run`'s own. The terminal is put in raw mode while
    /// attached and restored after, and the session's terminal takes this
    /// one's size, now and whenever it changes (the latest size any client
    /// asks for wins). Press Ctrl-P then Ctrl-Q, within a second, to
    /// detach: the session goes on, and the two keys are not sent (a Ctrl-P
    /// not followed by Ctrl-Q is sent after all). The session is the one
    /// `--control` or SESSION_ID names, or the only one running.
    ///
    /// `boxcar attach` takes the terminal only while it is in the
    /// foreground. One started in the background (`boxcar attach ... &`)
    /// just shows the session, and takes the terminal, raw, when `fg`
    /// brings it to the foreground. A stop (`kill -TSTP`; Ctrl-Z goes to
    /// the session while the terminal is raw) gives the terminal back to the
    /// shell as it was, and a continue in the foreground takes it again.
    ///
    /// Exits 0 on detach and when the session ends, 1 when the control
    /// socket cannot be reached or refuses the attach, 3 when the session's
    /// output came faster than this terminal took it and the VMM detached
    /// it (it keeps at most 1 MiB for each client), and 128 plus the signal
    /// after SIGINT, SIGTERM, SIGHUP or SIGQUIT.
    Attach(AttachArgs),
    /// Work with audit logs.
    #[command(subcommand)]
    Audit(AuditCommand),
    /// Check that this machine can build and run boxcar.
    ///
    /// Prints one line per check: KVM access and capabilities, Docker, the
    /// musl target, and the guest kernel and initramfs. Exits 1 when a
    /// required check fails; a guest artifact that is not built yet is not a
    /// failure.
    Doctor,
    /// Stream a running session's audit records.
    ///
    /// Prints each record of the session's audit log as one line of
    /// compact JSON on stdout, exactly as the log holds it: the records
    /// already in the log from `--from`, then the new ones as they are made,
    /// in seq order with none missed or repeated, until the VM stops (the
    /// control socket closes) or Ctrl-C. `--type` (any number) and `--pid`
    /// choose records by type prefix (`--type net.` takes every `net.*`
    /// record, `--type fs.write` that type) and by the guest process they
    /// are attributed to; a record must pass both. The session is the one
    /// `--control` or SESSION_ID names, or the only one running.
    ///
    /// A client that reads slower than the log is written is told on
    /// stderr, `{"event":"audit.lagged","resume_seq":N}`, and the records
    /// from N on follow: nothing is lost, they are read back from the log.
    /// Stdout may be a pipe that closes early (`| head`): that ends the
    /// command quietly, with exit 0.
    ///
    /// Exits 0 when the connection closes and after Ctrl-C (SIGINT), 1
    /// when the control socket cannot be reached or refuses the
    /// subscription (at most 4 per connection) or the server sends
    /// something that is not the protocol, and 128 plus the signal after
    /// SIGTERM, SIGHUP or SIGQUIT.
    Events(EventsArgs),
    /// Show or change a running session's network policy.
    ///
    /// `show` prints the policy in force, as a table or with `--json` as
    /// the control socket returns it: its version, its default, the allow
    /// and deny rules, and the vsock ports the guest may reach. `allow
    /// RULE` and `deny RULE` add RULE, written as for `boxcar run --allow`
    /// (`name[:port]`, `*.name[:port]`, `address[:port]`,
    /// `address/prefix[:port]`), to that list, taking the same RULE out of
    /// the other, and replace the whole network policy; the VMM then ends
    /// the connections the new policy denies (`net.close` with reason
    /// `policy`) and records `policy.changed`. Every deny comes before every
    /// allow, so a deny of a target wins over an allow of it. The session is
    /// the one `--control` or SESSION_ID names, or the only one running.
    ///
    /// Exits 0 and prints `policy version N`, 1 when the control socket
    /// cannot be reached or refuses the change (a VM without a network card
    /// has no policy to change), 2 for a RULE that does not parse.
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// Boot a microVM.
    ///
    /// Shares `--rootfs` with the guest as its root filesystem and
    /// `--workspace` at /workspace, both over virtio-fs, and records what
    /// the guest does to them. The guest runs a login shell as the invoking
    /// user's uid and gid, or, after `--`, the command given. Prints the
    /// session id, its audit log directory, the workspace and the control
    /// socket (see `boxcar status`) on stderr.
    ///
    /// With the vsock device (the default with shares), the session runs on
    /// a terminal of its own in the guest, which `boxcar run` relays: what
    /// the session prints goes to stdout, and only that; the guest's serial
    /// console (the kernel's and init's messages) goes to `console.log` in
    /// the session's state directory, beside the control socket (see
    /// `--console-log` and `--console-stdout`). The run exits with the
    /// session's own exit code, 128 plus the signal that killed it (137
    /// for SIGKILL), or 0 after `boxcar stop`, which asks the guest to end
    /// the session first (a hangup and SIGTERM, then SIGKILL after its
    /// timeout).
    ///
    /// With `--no-vsock`, M1's console session: the session runs on the
    /// serial console, which goes to stdout (or `--console-log`), and the
    /// run exits 0 whatever the session's exit status, which the console
    /// shows as `boxcar: session exited <code>`.
    ///
    /// Either way the run exits 0 when the guest reset with no session to
    /// report and after `boxcar stop`, 1 after a vCPU error, 3 when the
    /// audit log could not be written (the VM is stopped and stderr says
    /// `audit log failed: <why>`), 130 after SIGINT (Ctrl-C) or the console
    /// escape, 143 after SIGTERM, 129 after SIGHUP and 131 after SIGQUIT.
    /// When stdin is a terminal, the terminal is the session's: every key
    /// goes to the guest, Ctrl-C included; press Ctrl-] twice within a
    /// second to stop the VM. A run started in the background (`boxcar run
    /// ... &`), or moved there, does not take the terminal: it reads no key
    /// from it and leaves its settings to the shell; the session's output
    /// still shows. `fg` brings it back to the terminal, which it takes,
    /// raw, again. A stop (`kill -TSTP`; Ctrl-Z goes to the guest while the
    /// terminal is raw) gives the terminal back to the shell as it was, and
    /// a continue in the foreground takes it again. With the vsock device all
    /// of this holds for a `-- CMD` run too, and input from a pipe or a file
    /// goes to the session as well when no command is given (or with
    /// `--stdin`), its end an end-of-file there; the session's terminal takes
    /// this one's size, now and whenever it changes; and other terminals can
    /// attach to the session (`boxcar attach`). A slow stdout slows the
    /// session down: once 1 MiB of its output waits for stdout, the session
    /// waits too. Once the VM has stopped, boxcar writes out what is left for
    /// as long as stdout takes it (giving up after 2 s with none taken, or 30
    /// s in all), and says on stderr how many bytes stdout did not get.
    ///
    /// With shares the guest also gets a network card (see `--net`): it
    /// reaches only what the policy allows (`--policy-file`, `--deny`,
    /// `--allow`; everything else is denied), and every DNS query and
    /// connection is in the audit log. A policy rule that does not parse
    /// exits 2.
    ///
    /// With shares the guest also gets a vsock device (see `--vsock`),
    /// whose host socket is `vsock.sock` beside the control socket: host
    /// processes reach a guest port by connecting to it and sending
    /// `CONNECT <port>`, and the guest reaches host ports listed with
    /// `--vsock-allow`. Every vsock connection is in the audit log.
    // Boxed: the run's arguments are most of the enum's size.
    Run(Box<RunArgs>),
    /// Show a running VM's status.
    ///
    /// Asks the session's control socket and prints a short table, or with
    /// `--json` the status object as the socket returns it. The session is
    /// the one `--control` or SESSION_ID names, or the only one running.
    Status(StatusArgs),
    /// Stop a running VM.
    ///
    /// Asks the session's VMM to stop, waits until it has, and exits 0;
    /// `boxcar run` then exits 0 as well. The session is the one
    /// `--control` or SESSION_ID names, or the only one running.
    Stop(StopArgs),
}

#[derive(Debug, Subcommand)]
pub enum PolicyCommand {
    /// Print the policy in force.
    Show(PolicyShowArgs),
    /// Allow RULE: add it to the allow rules (and take it out of the
    /// denies).
    Allow(PolicyRuleArgs),
    /// Deny RULE: add it to the deny rules (and take it out of the allows).
    Deny(PolicyRuleArgs),
}

#[derive(Debug, Args)]
pub struct PolicyShowArgs {
    #[command(flatten)]
    pub session: SessionArgs,
    /// Print the policy as the control socket returns it, one JSON object.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct PolicyRuleArgs {
    /// The rule's target: `name[:port]`, `*.name[:port]`, `address[:port]`
    /// or `address/prefix[:port]`.
    #[arg(value_name = "RULE")]
    pub rule: String,
    #[command(flatten)]
    pub session: SessionArgs,
}

#[derive(Debug, Subcommand)]
pub enum AuditCommand {
    /// Check that a log is intact: every hash, link, sequence number and
    /// checkpoint. Exits 0 when it is, 1 at the first break.
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// A session directory, or a single `.jsonl` log file.
    pub path: PathBuf,
    /// Print the report, or the first break, as one JSON object.
    #[arg(long)]
    pub json: bool,
}

/// Which session a control command talks to.
#[derive(Debug, Args)]
pub struct SessionArgs {
    /// The session's control socket. Default: the session's, under
    /// $XDG_RUNTIME_DIR/boxcar/, or `/tmp/boxcar-<uid>/` without a usable
    /// XDG_RUNTIME_DIR.
    #[arg(long, value_name = "PATH", conflicts_with = "session_id")]
    pub control: Option<PathBuf>,
    /// The session's id, or a prefix of it that names one session.
    /// Default: the one session running.
    #[arg(value_name = "SESSION_ID")]
    pub session_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct AttachArgs {
    #[command(flatten)]
    pub session: SessionArgs,
    /// Attach read-only: what is typed is not sent (the detach keys still
    /// work).
    #[arg(long)]
    pub ro: bool,
    /// How much of what the session printed last to show first, in bytes:
    /// at most the VMM's 256 KiB scrollback; 0 for none.
    #[arg(long, value_name = "BYTES", default_value_t = 64 * 1024)]
    pub replay: u64,
}

#[derive(Debug, Args)]
pub struct EventsArgs {
    #[command(flatten)]
    pub session: SessionArgs,
    /// The first seq wanted: the records from it on, those in the log and
    /// then the live ones. Default: 1, the start (0 is the same). A seq
    /// past the log's end waits for the live records from it on.
    #[arg(long, value_name = "SEQ")]
    pub from: Option<u64>,
    /// Only records whose type starts with PREFIX, such as `net.` or
    /// `fs.write`. May be given more than once: a record of any of them.
    /// At most 32, each 1 to 64 bytes.
    #[arg(long = "type", value_name = "PREFIX")]
    pub types: Vec<String>,
    /// Only records attributed to the guest process with this pid.
    #[arg(long, value_name = "PID")]
    pub pid: Option<u32>,

    /// Only records whose score is at least this (findings carry one; a
    /// record without a score passes). 0 to 100.
    #[arg(long, value_name = "SCORE", value_parser = clap::value_parser!(u8).range(0..=100))]
    pub min_score: Option<u8>,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[command(flatten)]
    pub session: SessionArgs,
    /// Print the status as one JSON object.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct StopArgs {
    #[command(flatten)]
    pub session: SessionArgs,
    /// Stop at once, without asking the guest to end its session first.
    #[arg(long)]
    pub force: bool,
    /// How long a graceful stop waits for the guest. Default: 5000.
    #[arg(long, value_name = "N")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    /// The guest kernel: an uncompressed ELF vmlinux.
    #[arg(long, value_name = "PATH")]
    pub kernel: PathBuf,
    /// A cpio archive the kernel unpacks as its initial root filesystem.
    #[arg(long, value_name = "PATH")]
    pub initramfs: Option<PathBuf>,
    /// Guest memory in MiB.
    #[arg(
        long,
        value_name = "N",
        default_value_t = boxcar_vmm::vmm::DEFAULT_MEM_MIB,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub mem_mib: u64,
    /// Number of vCPUs.
    #[arg(
        long,
        value_name = "N",
        default_value_t = boxcar_vmm::vmm::DEFAULT_VCPUS,
        value_parser = clap::value_parser!(u8).range(1..)
    )]
    pub vcpus: u8,
    /// The guest's root filesystem: a host directory shared over virtio-fs
    /// as tag `root`. Required unless `--no-fs`.
    #[arg(
        long,
        value_name = "DIR",
        required_unless_present = "no_fs",
        conflicts_with = "no_fs"
    )]
    pub rootfs: Option<PathBuf>,
    /// A host directory shared over virtio-fs as tag `workspace`, which the
    /// guest mounts at /workspace. Default: a new `workspace/` directory in
    /// the session's audit directory.
    #[arg(long, value_name = "DIR", conflicts_with = "no_fs")]
    pub workspace: Option<PathBuf>,
    /// Boot without filesystem shares: the guest init prints a marker and
    /// reboots.
    #[arg(long)]
    pub no_fs: bool,
    /// What the shares record: `normal` (opens, closes with content hashes,
    /// changes and denials) or `verbose` (also every read, write and
    /// directory listing).
    #[arg(long, value_enum, value_name = "LEVEL", default_value_t = AuditLevelArg::Normal)]
    pub audit_level: AuditLevelArg,
    /// An extra kernel command line argument. Repeatable. These follow the
    /// `boxcar.mode` key boxcar sets (and, with `--no-vsock`, `boxcar.uid`
    /// and `boxcar.gid`), so they can override them; with `--no-vsock`,
    /// `boxcar.cmd` from `-- CMD` comes after them. The whole command line
    /// may not exceed 2048 bytes.
    #[arg(long, value_name = "STR")]
    pub cmdline_extra: Vec<String>,
    /// Early printk on the serial console and every kernel message.
    #[arg(long)]
    pub debug_boot: bool,
    /// Where audit logs go: `DIR/sessions/<session-id>/`. Default:
    /// $XDG_DATA_HOME/boxcar, or ~/.local/share/boxcar. It may not be
    /// inside `--rootfs` or `--workspace`, nor may either of them be DIR,
    /// DIR/sessions or a session's directory, which hold the logs; a
    /// directory deeper in a session, such as its workspace, may be shared.
    #[arg(long, value_name = "DIR")]
    pub audit_dir: Option<PathBuf>,
    /// Write the serial console to PATH. Default: with the vsock device,
    /// `console.log` in the session's state directory (mode 0600), which
    /// stays there after the run; with `--no-vsock`, stdout (and when PATH
    /// is given instead, stdin is not forwarded to the guest).
    #[arg(long, value_name = "PATH", conflicts_with = "console_stdout")]
    pub console_log: Option<PathBuf>,
    /// With the vsock device, write the serial console to stdout as well as
    /// the session's terminal, as M1 did: for debugging a boot. The two
    /// interleave.
    #[arg(long)]
    pub console_stdout: bool,
    /// The command the guest runs instead of a login shell, and its
    /// arguments, after `--`: an argv, run without a shell, with CMD looked
    /// up in the guest's PATH unless it holds a `/`. A `--` must be
    /// followed by one. With the vsock device, the command takes stdin when
    /// it is a terminal (in raw mode: Ctrl-C reaches the command, Ctrl-]
    /// twice stops the VM), or with `--stdin`; otherwise stdin is not read.
    /// The command and its environment may take up to 64 KiB. With
    /// `--no-vsock` the run is not interactive (stdin is not forwarded and
    /// the terminal is left as it is), and the command travels on the
    /// kernel command line.
    #[arg(last = true, value_name = "CMD", conflicts_with = "no_fs")]
    pub command: Vec<String>,
    /// Send stdin to the session's terminal when it is not a terminal (a
    /// pipe or a file) for a `-- CMD` run, which otherwise does not read
    /// it; its end is an end-of-file there. Needs the vsock device.
    #[arg(long, conflicts_with = "no_vsock")]
    pub stdin: bool,
    /// Once the control socket is ready, write one line to file descriptor
    /// FD, `{"ready":true,"control":"<path>","session_id":"<id>"}`, and
    /// close it. FD must be open for writing, and not 0, 1 or 2.
    #[arg(long, value_name = "FD", allow_negative_numbers = true)]
    pub ready_fd: Option<i32>,
    /// Give the guest a network card. The network is played on the host,
    /// with no TAP device and no privileges: the guest is 10.0.2.15/24,
    /// and 10.0.2.2 is its gateway and DNS server. Default: on with shares,
    /// off with `--no-fs` (where `--allow`, `--deny`, `--policy-file` and
    /// `--dns` need it). The last of `--net` and `--no-net` wins.
    #[arg(long, overrides_with = "no_net")]
    pub net: bool,
    /// No network card: the guest has no network at all.
    #[arg(long, overrides_with = "net")]
    pub no_net: bool,
    /// Let the guest reach RULE: `domain[:port]` (the name, or every name
    /// under it for `*.domain`) or `cidr[:port]` (an address or a network,
    /// such as 192.0.2.10:22 or 198.51.100.0/24). A domain rule admits only
    /// clients that present the name, in a TLS SNI or an HTTP Host header,
    /// and lets it resolve; SSH, SMTP, and UDP need a CIDR rule. Private
    /// and local networks stay denied unless a rule names one exactly.
    /// Repeatable; the allows come after `--policy-file` and `--deny`, and
    /// the first rule that matches decides.
    #[arg(long, value_name = "RULE", conflicts_with = "no_net")]
    pub allow: Vec<String>,
    /// Deny the guest RULE, written as for `--allow`. Repeatable; the
    /// denies come after `--policy-file` and before `--allow`.
    #[arg(long, value_name = "RULE", conflicts_with = "no_net")]
    pub deny: Vec<String>,
    /// Read policy rules from PATH, one a line: `allow RULE`, `deny RULE`,
    /// and at most one `default allow` or `default deny` (deny if none
    /// says); `#` starts a comment. Its rules come first.
    #[arg(long, value_name = "PATH", conflicts_with = "no_net")]
    pub policy_file: Option<PathBuf>,
    /// Where the guest's DNS queries are forwarded: an address, on port 53
    /// unless given as `ip:port`. Repeatable, in order of preference.
    /// Default: the nameservers in the host's /etc/resolv.conf.
    #[arg(
        long,
        value_name = "UPSTREAM",
        value_parser = parse_upstream,
        conflicts_with = "no_net"
    )]
    pub dns: Vec<SocketAddr>,
    /// Give the guest a vsock device (CID 3): the VMM's own channels to the
    /// guest (the session's control channel and its terminal), and
    /// connections between guest and host ports. Its host
    /// socket is `vsock.sock` in the session's state directory, mode 0600:
    /// a host process reaches guest port P by connecting to it and sending
    /// `CONNECT P` and a newline; once the guest accepts, it reads `OK
    /// <port>` and a newline (the port the guest sees the connection come
    /// from), and the socket carries the connection. Default: on with
    /// shares, off with `--no-fs`. The last of `--vsock` and `--no-vsock`
    /// wins.
    /// Run the guest without its sensor (ring 1 of the audit log): no
    /// `proc.*` records, and `status` says the sensor is off. Implied by
    /// --no-vsock, which leaves the sensor no way to reach the host.
    #[arg(long)]
    pub no_sensor: bool,

    #[arg(long, overrides_with = "no_vsock")]
    pub vsock: bool,
    /// No vsock device: the guest runs M1's console session (see `run`).
    #[arg(long, overrides_with = "vsock")]
    pub no_vsock: bool,
    /// Let the guest connect to host vsock port PORT, which reaches the
    /// Unix socket `vsock.sock_PORT` beside the vsock socket. PORT is 1027
    /// or more: 1024 to 1026 are the VMM's own, and below 1024 is
    /// reserved. A connection to a port not listed is refused and recorded.
    /// Repeatable.
    #[arg(
        long,
        value_name = "PORT",
        value_parser = parse_vsock_port,
        conflicts_with = "no_vsock"
    )]
    pub vsock_allow: Vec<u32>,
}

/// A host vsock port for `--vsock-allow`: a number from 1027 up, not an
/// internal port (1024 to 1026), which the VMM keeps for itself, nor below
/// 1024.
pub fn parse_vsock_port(text: &str) -> Result<u32, String> {
    let port: u32 = text
        .parse()
        .map_err(|_| format!("{text:?} is not a port number"))?;
    if boxcar_vsock::services::is_internal(port) {
        return Err(format!(
            "{port} is an internal port (1024 to 1026), the VMM's own"
        ));
    }
    if port < boxcar_vsock::services::PRIVILEGED_PORT_LIMIT {
        return Err(format!("{port} is below 1024"));
    }
    Ok(port)
}

/// A DNS upstream for `--dns`: `ip`, on port 53, or `ip:port` (an IPv6
/// address with a port in brackets).
pub fn parse_upstream(text: &str) -> Result<SocketAddr, String> {
    let addr = text
        .parse::<SocketAddr>()
        .or_else(|_| text.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| format!("{text:?} is not an address or address:port"))?;
    if addr.port() == 0 {
        return Err(format!("{text:?}: port 0"));
    }
    Ok(addr)
}

/// `--audit-level`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum AuditLevelArg {
    Normal,
    Verbose,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn run(args: &[&str]) -> Result<Cli, clap::Error> {
        let base = ["boxcar", "run", "--kernel", "vmlinux", "--rootfs", "root"];
        Cli::try_parse_args(base.iter().chain(args))
    }

    fn command(cli: &Cli) -> &[String] {
        match &cli.command {
            Command::Run(args) => &args.command,
            _ => panic!("not a run"),
        }
    }

    #[test]
    fn a_command_follows_the_separator() {
        assert_eq!(command(&run(&["--", "ls", "-l"]).unwrap()), ["ls", "-l"]);
        assert_eq!(
            command(&run(&["--", "sh", "-c", "x", "--", "y"]).unwrap()),
            ["sh", "-c", "x", "--", "y"]
        );
        assert!(command(&run(&[]).unwrap()).is_empty());
    }

    /// clap parses `--` with nothing after it as no command at all, which
    /// would be an interactive shell instead of the command meant.
    #[test]
    fn a_separator_with_no_command_is_refused() {
        let error = run(&["--"]).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument);
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("after `--`"), "{error}");
    }

    fn run_args(cli: &Cli) -> &RunArgs {
        match &cli.command {
            Command::Run(args) => args,
            _ => panic!("not a run"),
        }
    }

    /// `--net` and `--no-net`: the last one given wins; neither leaves the
    /// default to `boxcar run`.
    #[test]
    fn net_and_no_net_override_each_other() {
        let cli = run(&[]).unwrap();
        assert_eq!((run_args(&cli).net, run_args(&cli).no_net), (false, false));
        let cli = run(&["--net", "--no-net"]).unwrap();
        assert_eq!((run_args(&cli).net, run_args(&cli).no_net), (false, true));
        let cli = run(&["--no-net", "--net"]).unwrap();
        assert_eq!((run_args(&cli).net, run_args(&cli).no_net), (true, false));
    }

    #[test]
    fn policy_flags_repeat_and_keep_their_order() {
        let cli = run(&[
            "--allow",
            "a.example",
            "--deny",
            "b.example",
            "--allow",
            "192.0.2.0/24:22",
            "--policy-file",
            "team.policy",
            "--dns",
            "9.9.9.9",
            "--dns",
            "[::1]:5353",
        ])
        .unwrap();
        let args = run_args(&cli);
        assert_eq!(args.allow, ["a.example", "192.0.2.0/24:22"]);
        assert_eq!(args.deny, ["b.example"]);
        assert_eq!(args.policy_file.as_deref(), Some(Path::new("team.policy")));
        let dns: Vec<String> = args.dns.iter().map(|a| a.to_string()).collect();
        assert_eq!(dns, ["9.9.9.9:53", "[::1]:5353"]);
        let error = run(&["--dns", "dns.example"]).err().unwrap();
        assert_eq!(error.exit_code(), 2);
    }

    /// Rules for a network the VM does not have are refused.
    #[test]
    fn policy_flags_conflict_with_no_net() {
        for flag in [
            ["--allow", "a.example"],
            ["--deny", "a.example"],
            ["--policy-file", "p"],
            ["--dns", "9.9.9.9"],
        ] {
            let error = run(&["--no-net", flag[0], flag[1]]).err().unwrap();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{flag:?}");
        }
    }

    #[test]
    fn a_dns_upstream_is_an_address_with_port_53_by_default() {
        let parsed = |s: &str| parse_upstream(s).map(|a| a.to_string());
        assert_eq!(parsed("9.9.9.9"), Ok("9.9.9.9:53".to_owned()));
        assert_eq!(parsed("9.9.9.9:5353"), Ok("9.9.9.9:5353".to_owned()));
        assert_eq!(
            parsed("2606:4700:4700::1111"),
            Ok("[2606:4700:4700::1111]:53".to_owned())
        );
        assert_eq!(parsed("[::1]:5353"), Ok("[::1]:5353".to_owned()));
        for bad in ["dns.example", "9.9.9.9:0", "9.9.9.9:x", ""] {
            assert!(parse_upstream(bad).is_err(), "{bad:?}");
        }
    }

    /// `--vsock` and `--no-vsock`: the last one given wins; neither leaves
    /// the default to `boxcar run`.
    #[test]
    fn vsock_and_no_vsock_override_each_other() {
        let cli = run(&[]).unwrap();
        assert_eq!(
            (run_args(&cli).vsock, run_args(&cli).no_vsock),
            (false, false)
        );
        let cli = run(&["--vsock", "--no-vsock"]).unwrap();
        assert_eq!(
            (run_args(&cli).vsock, run_args(&cli).no_vsock),
            (false, true)
        );
        let cli = run(&["--no-vsock", "--vsock"]).unwrap();
        assert_eq!(
            (run_args(&cli).vsock, run_args(&cli).no_vsock),
            (true, false)
        );
    }

    /// `--vsock-allow` repeats; a port below 1024, an internal port (1024
    /// to 1026) or no number at all is a usage error.
    #[test]
    fn vsock_allow_takes_ports_above_the_internal_ones() {
        let cli = run(&["--vsock-allow", "5000", "--vsock-allow", "1027"]).unwrap();
        assert_eq!(run_args(&cli).vsock_allow, [5000, 1027]);
        let cli = run(&["--vsock-allow", "4294967295"]).unwrap();
        assert_eq!(run_args(&cli).vsock_allow, [u32::MAX]);
        for bad in [
            "1023",
            "1024",
            "1025",
            "1026",
            "0",
            "-1",
            "x",
            "4294967296",
            "",
        ] {
            let error = run(&["--vsock-allow", bad]).err().unwrap();
            assert_eq!(error.exit_code(), 2, "{bad:?}");
        }
        let error = run(&["--no-vsock", "--vsock-allow", "5000"]).err().unwrap();
        assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
    }

    #[test]
    fn a_vsock_port_is_above_1023_and_not_internal() {
        assert_eq!(parse_vsock_port("5000"), Ok(5000));
        assert_eq!(parse_vsock_port("1027"), Ok(1027));
        for internal in ["1024", "1025", "1026"] {
            let error = parse_vsock_port(internal).unwrap_err();
            assert!(error.contains("internal"), "{error}");
        }
        assert!(parse_vsock_port("80").unwrap_err().contains("1024"));
        assert!(parse_vsock_port("port").is_err());
    }

    #[test]
    fn other_subcommands_parse_as_before() {
        let cli = Cli::try_parse_args(["boxcar", "audit", "verify", "--", "log.jsonl"]).unwrap();
        assert!(matches!(cli.command, Command::Audit(_)));
    }
}
