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
    /// Boot a microVM.
    ///
    /// Shares `--rootfs` with the guest as its root filesystem and
    /// `--workspace` at /workspace, both over virtio-fs, and records what
    /// the guest does to them. The guest runs a login shell on its serial
    /// console as the invoking user's uid and gid, or, after `--`, the
    /// command given. Prints the session id, its audit log directory, the
    /// workspace and the control socket (see `boxcar status`) on stderr,
    /// runs the guest with its serial console on stdout (or in
    /// `--console-log`), and exits when it stops: 0 when the guest reset or
    /// shut down (whatever the session's own exit status, which the console
    /// shows as `boxcar: session exited <code>`) and after `boxcar stop`, 1
    /// after a vCPU error, 3 when the audit log could not be written (the
    /// VM is stopped and stderr says `audit log failed: <why>`), 130 after
    /// SIGINT (Ctrl-C) or the console escape, 143 after SIGTERM, 129 after
    /// SIGHUP and 131 after SIGQUIT. When stdin is a terminal, the console
    /// is on stdout and no command is given, every key goes to the guest,
    /// Ctrl-C included; press Ctrl-] twice within a second to stop the VM.
    ///
    /// With shares the guest also gets a network card (see `--net`): it
    /// reaches only what the policy allows (`--policy-file`, `--deny`,
    /// `--allow`; everything else is denied), and every DNS query and
    /// connection is in the audit log. A policy rule that does not parse
    /// exits 2.
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
    /// $XDG_RUNTIME_DIR/boxcar/, or /tmp/boxcar-<uid>/ without a usable
    /// XDG_RUNTIME_DIR.
    #[arg(long, value_name = "PATH", conflicts_with = "session_id")]
    pub control: Option<PathBuf>,
    /// The session's id, or a prefix of it that names one session.
    /// Default: the one session running.
    #[arg(value_name = "SESSION_ID")]
    pub session_id: Option<String>,
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
    /// `boxcar.mode`, `boxcar.uid` and `boxcar.gid` keys boxcar sets, so
    /// they can override them; `boxcar.cmd` from `-- CMD` comes after them.
    /// The whole command line may not exceed 2048 bytes.
    #[arg(long, value_name = "STR")]
    pub cmdline_extra: Vec<String>,
    /// Early printk on the serial console and every kernel message.
    #[arg(long)]
    pub debug_boot: bool,
    /// Where audit logs go: DIR/sessions/<session-id>/. Default:
    /// $XDG_DATA_HOME/boxcar, or ~/.local/share/boxcar. It may not be
    /// inside `--rootfs` or `--workspace`, nor may either of them be DIR,
    /// DIR/sessions or a session's directory, which hold the logs; a
    /// directory deeper in a session, such as its workspace, may be shared.
    #[arg(long, value_name = "DIR")]
    pub audit_dir: Option<PathBuf>,
    /// Write the serial console to PATH instead of stdout. Stdin is then not
    /// forwarded to the guest.
    #[arg(long, value_name = "PATH")]
    pub console_log: Option<PathBuf>,
    /// The command the guest runs instead of a login shell, and its
    /// arguments, after `--`: an argv, run without a shell, with CMD looked
    /// up in the guest's PATH unless it holds a `/`. A `--` must be
    /// followed by one. The run is not interactive: stdin is not forwarded
    /// and the terminal is left as it is.
    #[arg(last = true, value_name = "CMD", conflicts_with = "no_fs")]
    pub command: Vec<String>,
    /// Once the control socket is ready, write one line to file descriptor
    /// FD, `{"ready":true,"control":"<path>","session_id":"<id>"}`, and
    /// close it. FD must be open for writing, and not 0, 1 or 2.
    #[arg(long, value_name = "FD", allow_negative_numbers = true)]
    pub ready_fd: Option<i32>,
    /// Give the guest a network card. The network is played on the host,
    /// with no TAP device and no privileges: the guest is 10.0.2.15/24,
    /// and 10.0.2.2 is its gateway and DNS server. Default: on with shares,
    /// off with `--no-fs`. The last of `--net` and `--no-net` wins.
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

    #[test]
    fn other_subcommands_parse_as_before() {
        let cli = Cli::try_parse_args(["boxcar", "audit", "verify", "--", "log.jsonl"]).unwrap();
        assert!(matches!(cli.command, Command::Audit(_)));
    }
}
