#!/usr/bin/env python3
"""Accidental public-routing guard for confidential Git clones, not a sandbox."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys

MARKER = "security-advisory.json"


def environment():
    return {
        k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GH_DEBUG"))
    }


def command(args, cwd=None):
    p = subprocess.run(args, cwd=cwd, env=environment(), capture_output=True, text=True)
    if p.returncode:
        raise ValueError("confidential workspace validation failed")
    return p.stdout.strip()


def marker(cwd=None):
    root = Path(cwd or Path.cwd()).resolve()
    for parent in (root, *root.parents):
        git = parent / ".git"
        if git.is_dir():
            return git / MARKER
        if git.is_file():
            raw = git.read_text().strip()
            if not raw.startswith("gitdir: "):
                raise ValueError("invalid Git workspace metadata")
            directory = (parent / raw[8:]).resolve()
            common = directory / "commondir"
            if common.exists():
                directory = (directory / common.read_text().strip()).resolve()
            return directory / MARKER
    return None


def confidential(cwd=None):
    p = marker(cwd)
    return bool(p and p.exists())


def public_only():
    if confidential():
        raise ValueError("confidential workspace: use the private advisory workflow")


def remote_name(url):
    m = re.fullmatch(
        r"(?:https://github\.com/|git@github\.com:)([\w.-]+/[\w.-]+?)(?:\.git)?", url
    )
    if not m:
        raise ValueError("unrecognized private-fork remote")
    return m[1]


def verify(cwd=None, destination=None):
    path = marker(cwd)
    if not path or not path.exists():
        raise ValueError("confidential workspace marker required")
    data = json.loads(path.read_text())
    fork = data["fork"]
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", fork):
        raise ValueError("invalid private fork identity")
    live = json.loads(
        command(["gh", "api", "--hostname", "github.com", "repos/" + fork], cwd)
    )
    if live.get("full_name") != fork or live.get("private") is not True:
        raise ValueError("private-fork access or privacy could not be verified")
    remotes = command(["git", "remote"], cwd).splitlines()
    if remotes != ["origin"]:
        raise ValueError("confidential clone must have only its private origin")
    for direction in ([], ["--push"]):
        urls = command(
            ["git", "remote", "get-url", "--all", *direction, "origin"], cwd
        ).splitlines()
        if not urls or any(remote_name(u) != fork for u in urls):
            raise ValueError("confidential clone remote does not match private fork")
    if destination and remote_name(destination) != fork:
        raise ValueError("push destination is not the verified private fork")
    return data


if __name__ == "__main__":
    try:
        # Git supplies remote name and actual destination to pre-push.
        if len(sys.argv) != 3:
            raise ValueError("pre-push requires its actual destination")
        verify(destination=sys.argv[2])
    except (ValueError, KeyError, OSError):
        print(
            "Push refused: private-fork identity/access could not be verified.",
            file=sys.stderr,
        )
        sys.exit(1)
