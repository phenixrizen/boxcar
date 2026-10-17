#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Run a Codex adversarial review of this branch (AGENTS.md "Reviews").

The Codex plugin for Claude Code (openai/codex-plugin-cc, codex@openai-codex)
keeps its slash commands from agents, so this runs the same review through
the plugin's own script: the installation that applies here, read from
Claude Code's plugin registry (one installed for this repository, else the
user's), never the newest copy in the cache.

    python3 scripts/codex_review.py "<focus: the risks this change touches>"

It reviews the commits origin/main...HEAD (the plugin's --base), not the
working tree, and waits for the result, in the directory it is run from.
It fetches a remote comparison base, then reviews immutable head/base inputs.
A behind-base branch can be reviewed; integration readiness is a separate check.
Branch reviews use a detached snapshot and never include uncommitted changes.
The wrapper-only --head SHA pins a caller's recorded revision; it is never
forwarded as an invented plugin option. JSON output includes actual inputs.
Only --base <ref> (in place of origin/main) and --scope <auto|branch|
working-tree> may go before the focus; any other flag is refused, the
plugin's directory options among them, since the installation is chosen
for this repository. Git's repository-selecting variables (GIT_DIR and the
rest, set inside git hooks) are dropped, so the repository is the
directory's. The registry is under CLAUDE_CONFIG_DIR when that is set, as
Claude Code's own is.
"""

from __future__ import annotations

import contextlib
import json
import tempfile
import os
from pathlib import Path
import subprocess
import sys
import stat

import security_guard

PLUGIN = "codex@openai-codex"
SCRIPT = "scripts/codex-companion.mjs"
VALUED_FLAGS = ("--base", "--scope", "--head")
# git rev-parse --local-env-vars: what points git at a repository other than the directory's.
GIT_LOCAL_ENV = (
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_OBJECT_DIRECTORY",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_GRAFT_FILE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_PREFIX",
    "GIT_SHALLOW_FILE",
    "GIT_COMMON_DIR",
)


class NotInstalled(Exception):
    pass


class BaseUnknown(Exception):
    pass


class BaseRepeated(Exception):
    pass


def base_of(argv: list[str]) -> str:
    """The base the review compares with: --base's one value, else origin/main.
    A second --base is refused: the plugin takes the last, and the check
    must look at the base the review uses. An empty one is refused too: the
    plugin takes it for no base and picks its own, which nothing checked."""
    found = []
    for i, a in enumerate(argv):
        if a == "--base":
            found.append(argv[i + 1] if i + 1 < len(argv) else "")
        elif a.startswith("--base="):
            found.append(a.split("=", 1)[1])
    if len(found) > 1:
        raise BaseRepeated(
            "--base is given more than once; give the base the review compares with once"
        )
    if found and not found[0].strip():
        raise BaseUnknown(
            "--base is given no ref; name the base the review compares with"
        )
    return found[0] if found else "origin/main"


def remote_of(
    base: str, run=subprocess.run, env: dict[str, str] | None = None
) -> tuple[str, str]:
    """The remote whose branch base names, by its full ref
    (refs/remotes/<remote>/<branch>), and that branch; ("", "") for a local
    base."""
    r = run(
        ["git", "rev-parse", "--symbolic-full-name", base],
        capture_output=True,
        text=True,
        env=env,
    )
    full = r.stdout.strip() if r.returncode == 0 else ""
    if not full.startswith("refs/remotes/"):
        return "", ""
    rest = full[len("refs/remotes/") :]
    remotes = run(["git", "remote"], capture_output=True, text=True, env=env)
    names = remotes.stdout.split() if remotes.returncode == 0 else []
    for name in sorted(names, key=len, reverse=True):
        if rest.startswith(name + "/"):
            return name, rest[len(name) + 1 :]
    return "", ""


def behind(base: str, run=subprocess.run, env: dict[str, str] | None = None) -> int:
    """How many commits base has that HEAD lacks, once base's remote is
    fetched by its own refspec when base is a remote's branch (however it is
    spelled). A fetch that fails refuses the review: what the remote holds
    is unknown."""
    remote, branch = remote_of(base, run, env)
    if remote:
        # The branch itself, by refspec: a plain fetch of the remote refreshes only
        # the refspecs the checkout is configured with (a single-branch clone's one).
        f = run(
            [
                "git",
                "fetch",
                "-q",
                remote,
                f"+refs/heads/{branch}:refs/remotes/{remote}/{branch}",
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        if f.returncode != 0:
            raise BaseUnknown(
                f"could not fetch {remote}/{branch} ({f.stderr.strip() or 'fetch failed'}): the review needs the current {base}"
            )
    r = run(
        ["git", "rev-list", "--count", f"HEAD..{base}"],
        capture_output=True,
        text=True,
        env=env,
    )
    if r.returncode != 0:
        raise BaseUnknown(
            f"cannot compare this branch with {base}: {r.stderr.strip() or 'unknown revision'}"
        )
    return int(r.stdout.strip() or "0")


def clean_env(env: dict[str, str]) -> dict[str, str]:
    """env without git's repository-selecting variables."""
    return {k: v for k, v in env.items() if k not in GIT_LOCAL_ENV}


def refused_flag(argv: list[str]) -> str:
    """The first argument that is a flag other than --base or --scope (with
    its value), or ""."""
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in VALUED_FLAGS:
            i += 2
            continue
        if a == "--json":
            i += 1
            continue
        if a.startswith("-") and not any(a.startswith(f + "=") for f in VALUED_FLAGS):
            return a
        i += 1
    return ""


def registry_path(env: dict[str, str]) -> Path:
    """Claude Code's plugin registry: under CLAUDE_CONFIG_DIR, else ~/.claude."""
    return (
        Path(os.path.expanduser(env.get("CLAUDE_CONFIG_DIR") or "~/.claude"))
        / "plugins/installed_plugins.json"
    )


def repository(path: Path) -> Path:
    """The repository path belongs to, the same for its main checkout and every
    linked worktree (git's common directory); path itself outside git."""
    try:
        out = subprocess.run(
            [
                "git",
                "-C",
                str(path),
                "rev-parse",
                "--path-format=absolute",
                "--git-common-dir",
            ],
            check=True,
            capture_output=True,
            text=True,
            env=clean_env(dict(os.environ)),
        ).stdout.strip()
        return Path(out).resolve()
    except (OSError, subprocess.CalledProcessError):
        return path.resolve()


def install_root(registry: dict, project: Path, repo=repository) -> Path:
    """The installPath of the plugin's installation that applies to project:
    the one installed for project's repository (from any of its worktrees),
    else the one installed for the user; two that apply equally are refused
    rather than guessed between."""
    entries = registry.get("plugins", {}).get(PLUGIN, [])
    mine = repo(project)
    here = [
        e
        for e in entries
        if e.get("projectPath") and repo(Path(e["projectPath"])) == mine
    ]
    user = [e for e in entries if e.get("scope") == "user" and not e.get("projectPath")]
    for found in (here, user):
        if len(found) > 1:
            raise NotInstalled(
                f"{PLUGIN} is installed {len(found)} times for the same scope; remove the extra installation"
            )
        if found:
            return Path(found[0]["installPath"])
    raise NotInstalled(
        f"{PLUGIN} is not installed for this repository or the user: /plugin marketplace add openai/codex-plugin-cc, /plugin install {PLUGIN}, /codex:setup"
    )


def main(argv: list[str]) -> int:
    private = "--private" in argv
    argv = [a for a in argv if a != "--private"]
    try:
        if private:
            security_guard.verify()
            output = os.fstat(sys.stdout.fileno())
            if (
                "--json" not in argv
                or not stat.S_ISREG(output.st_mode)
                or output.st_mode & 0o077
            ):
                raise ValueError(
                    "private review needs restricted regular-file JSON output"
                )
            # Linux private execution path: prohibit a report redirected into Git.
            from security_advisory import secure_path, Error as PrivateError

            try:
                secure_path(os.readlink("/proc/self/fd/1"))
            except PrivateError:
                raise ValueError("private output must remain outside Git") from None
            if value_of(argv, "--scope", "branch") != "branch":
                raise ValueError("private review requires immutable branch scope")
        else:
            security_guard.public_only()
    except (ValueError, OSError, KeyError):
        sys.stderr.write(
            "codex_review: confidential workspace requires the private advisory review path and restricted output\n"
        )
        return 2
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip() if __doc__ else "")
        return 0 if argv else 2
    bad = refused_flag(argv)
    if bad:
        sys.stderr.write(
            f"codex_review: {bad} is refused: only --base and --scope go before the focus; run it from the repository to review\n"
        )
        return 2
    try:
        base = base_of(argv)
        behind(base, env=clean_env(dict(os.environ)))
    except (BaseRepeated, BaseUnknown) as e:
        sys.stderr.write(f"codex_review: {e}\n")
        return 2
    try:
        reg = registry_path(dict(os.environ))
        registry = json.loads(reg.read_text()) if reg.exists() else {}
        root = install_root(registry, Path.cwd())
    except NotInstalled as e:
        sys.stderr.write(f"codex_review: {e}\n")
        return 1
    script = root / SCRIPT
    if not script.exists():
        sys.stderr.write(f"codex_review: {script} is missing; reinstall {PLUGIN}\n")
        return 1
    try:
        return invoke(script, argv)
    except (BaseUnknown, OSError, ValueError) as e:
        sys.stderr.write(f"codex_review: {e}\n")
        return 2


def value_of(argv, flag, default):
    values = []
    for i, arg in enumerate(argv):
        if arg == flag:
            values.append(argv[i + 1] if i + 1 < len(argv) else "")
        elif arg.startswith(flag + "="):
            values.append(arg.split("=", 1)[1])
    if len(values) > 1 or (values and not values[0]):
        raise BaseUnknown(f"give {flag} exactly once with a value")
    return values[0] if values else default


def without(argv, flags):
    result = []
    i = 0
    while i < len(argv):
        if argv[i] in flags:
            i += 2
        elif any(argv[i].startswith(f + "=") for f in flags):
            i += 1
        else:
            result.append(argv[i])
            i += 1
    return result


def git_value(*args):
    p = subprocess.run(
        ["git", *args], capture_output=True, text=True, env=clean_env(dict(os.environ))
    )
    if p.returncode:
        raise BaseUnknown("cannot resolve immutable review inputs: " + p.stderr.strip())
    return p.stdout.strip()


@contextlib.contextmanager
def snapshot(head):
    common = Path(git_value("rev-parse", "--path-format=absolute", "--git-common-dir"))
    with tempfile.TemporaryDirectory(prefix="review-", dir=common) as tmp:
        path = Path(tmp) / "tree"
        git_value("worktree", "add", "--detach", str(path), head)
        try:
            yield path
        finally:
            git_value("worktree", "remove", "--force", str(path))


def invoke(script, argv):
    scope = value_of(argv, "--scope", "branch")
    if scope not in ("auto", "branch", "working-tree"):
        raise BaseUnknown("unknown review scope")
    if scope == "auto":
        scope = "working-tree" if git_value("status", "--porcelain") else "branch"
    if scope == "working-tree":
        if any(a == "--head" or a.startswith("--head=") for a in argv):
            raise BaseUnknown("--head requires branch scope")
        flags = (
            []
            if any(a == "--base" or a.startswith("--base=") for a in argv)
            else ["--base", "origin/main"]
        )
        return subprocess.run(
            ["node", str(script), "adversarial-review", "--wait", *flags, *argv],
            env=clean_env(dict(os.environ)),
        ).returncode
    head = git_value(
        "rev-parse", "--verify", value_of(argv, "--head", "HEAD") + "^{commit}"
    )
    base = git_value("rev-parse", "--verify", base_of(argv) + "^{commit}")
    inputs = {
        "head": head,
        "base": base,
        "merge_base": git_value("merge-base", head, base),
    }
    args = without(argv, ("--base", "--scope", "--head"))
    with snapshot(head) as tree:
        result = subprocess.run(
            [
                "node",
                str(script),
                "adversarial-review",
                "--wait",
                "--base",
                base,
                "--scope",
                "branch",
                *args,
            ],
            cwd=tree,
            env=clean_env(dict(os.environ)),
            capture_output="--json" in argv,
            text=True,
            umask=0o077,
        )
    if "--json" in argv:
        try:
            payload = json.loads(result.stdout)
            payload["inputs"] = inputs
        except (ValueError, TypeError):
            # Never convert a missing result into an approval. Keep raw output local.
            payload = {
                "inputs": inputs,
                "parseError": "missing structured reviewer output",
                "rawOutput": result.stdout,
            }
        print(json.dumps(payload))
    return result.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
