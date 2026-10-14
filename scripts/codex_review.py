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
It first fetches the base's remote and refuses a branch that is behind its
base, or one whose base cannot be fetched or compared: the review is of
what will merge, so a branch is rebased onto the current base first (a
branch stacked on another names that one with --base, once).
Only --base <ref> (in place of origin/main) and --scope <auto|branch|
working-tree> may go before the focus; any other flag is refused, the
plugin's directory options among them, since the installation is chosen
for this repository. Git's repository-selecting variables (GIT_DIR and the
rest, set inside git hooks) are dropped, so the repository is the
directory's. The registry is under CLAUDE_CONFIG_DIR when that is set, as
Claude Code's own is.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

PLUGIN = "codex@openai-codex"
SCRIPT = "scripts/codex-companion.mjs"
VALUED_FLAGS = ("--base", "--scope")
# git rev-parse --local-env-vars: what points git at a repository other than the directory's.
GIT_LOCAL_ENV = ("GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CONFIG", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
                 "GIT_OBJECT_DIRECTORY", "GIT_DIR", "GIT_WORK_TREE", "GIT_IMPLICIT_WORK_TREE", "GIT_GRAFT_FILE",
                 "GIT_INDEX_FILE", "GIT_NO_REPLACE_OBJECTS", "GIT_REPLACE_REF_BASE", "GIT_PREFIX", "GIT_SHALLOW_FILE",
                 "GIT_COMMON_DIR")


class NotInstalled(Exception):
    pass


class BaseUnknown(Exception):
    pass


class BaseRepeated(Exception):
    pass


def base_of(argv: list[str]) -> str:
    """The base the review compares with: --base's one value, else origin/main.
    A second --base is refused: the plugin takes the last, and the check
    must look at the base the review uses."""
    found = []
    for i, a in enumerate(argv):
        if a == "--base" and i + 1 < len(argv):
            found.append(argv[i + 1])
        elif a.startswith("--base="):
            found.append(a.split("=", 1)[1])
    if len(found) > 1:
        raise BaseRepeated("--base is given more than once; give the base the review compares with once")
    return found[0] if found else "origin/main"


def remote_of(base: str, run=subprocess.run, env: dict[str, str] | None = None) -> tuple[str, str]:
    """The remote whose branch base names, by its full ref
    (refs/remotes/<remote>/<branch>), and that branch; ("", "") for a local
    base."""
    r = run(["git", "rev-parse", "--symbolic-full-name", base], capture_output=True, text=True, env=env)
    full = r.stdout.strip() if r.returncode == 0 else ""
    if not full.startswith("refs/remotes/"):
        return "", ""
    rest = full[len("refs/remotes/"):]
    remotes = run(["git", "remote"], capture_output=True, text=True, env=env)
    names = remotes.stdout.split() if remotes.returncode == 0 else []
    for name in sorted(names, key=len, reverse=True):
        if rest.startswith(name + "/"):
            return name, rest[len(name) + 1:]
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
        f = run(["git", "fetch", "-q", remote, f"+refs/heads/{branch}:refs/remotes/{remote}/{branch}"],
                capture_output=True, text=True, env=env)
        if f.returncode != 0:
            raise BaseUnknown(f"could not fetch {remote}/{branch} ({f.stderr.strip() or 'fetch failed'}): the review needs the current {base}")
    r = run(["git", "rev-list", "--count", f"HEAD..{base}"], capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise BaseUnknown(f"cannot compare this branch with {base}: {r.stderr.strip() or 'unknown revision'}")
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
        if a.startswith("-") and not any(a.startswith(f + "=") for f in VALUED_FLAGS):
            return a
        i += 1
    return ""


def registry_path(env: dict[str, str]) -> Path:
    """Claude Code's plugin registry: under CLAUDE_CONFIG_DIR, else ~/.claude."""
    return Path(os.path.expanduser(env.get("CLAUDE_CONFIG_DIR") or "~/.claude")) / "plugins/installed_plugins.json"


def repository(path: Path) -> Path:
    """The repository path belongs to, the same for its main checkout and every
    linked worktree (git's common directory); path itself outside git."""
    try:
        out = subprocess.run(["git", "-C", str(path), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                             check=True, capture_output=True, text=True, env=clean_env(dict(os.environ))).stdout.strip()
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
    here = [e for e in entries if e.get("projectPath") and repo(Path(e["projectPath"])) == mine]
    user = [e for e in entries if e.get("scope") == "user" and not e.get("projectPath")]
    for found in (here, user):
        if len(found) > 1:
            raise NotInstalled(f"{PLUGIN} is installed {len(found)} times for the same scope; remove the extra installation")
        if found:
            return Path(found[0]["installPath"])
    raise NotInstalled(f"{PLUGIN} is not installed for this repository or the user: /plugin marketplace add openai/codex-plugin-cc, /plugin install {PLUGIN}, /codex:setup")


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip() if __doc__ else "")
        return 0 if argv else 2
    bad = refused_flag(argv)
    if bad:
        sys.stderr.write(f"codex_review: {bad} is refused: only --base and --scope go before the focus; run it from the repository to review\n")
        return 2
    try:
        base = base_of(argv)
        count = behind(base, env=clean_env(dict(os.environ)))
    except (BaseRepeated, BaseUnknown) as e:
        sys.stderr.write(f"codex_review: {e}\n")
        return 2
    if count:
        sys.stderr.write(f"codex_review: this branch is {count} commit{'s' if count != 1 else ''} behind {base}: rebase onto it first, "
                         "so the review covers what will merge (a branch stacked on another names that one with --base)\n")
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
    flags = [] if "--base" in argv else ["--base", "origin/main"]
    return subprocess.run(["node", str(script), "adversarial-review", "--wait", *flags, *argv], env=clean_env(dict(os.environ))).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
