#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Small, explicit issue workflow. See docs/issue-workflow.md; no scheduler."""

from __future__ import annotations
import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import uuid

import board
import codex_review
import review_policy as policy
import security_guard

MARK = "work-issue-checkpoint:v1"
PR_MARK = "work-issue-pr:v1"
MAX_CHECKPOINT_BYTES = 65000  # Below GitHub's comment limit, including all metadata.


Error = policy.Error


def run(args, **kwargs):
    p = subprocess.run(
        args,
        capture_output=True,
        text=True,
        env=codex_review.clean_env(dict(os.environ)),
        **kwargs,
    )
    if p.returncode:
        raise Error(p.stderr.strip() or f"{args[0]} failed")
    return p.stdout.strip()


def git(*args):
    return run(["git", *args])


def atomic(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def directory():
    return (
        Path(git("rev-parse", "--path-format=absolute", "--git-common-dir"))
        / "work-issue"
    )


@contextlib.contextmanager
def locked():
    d = directory()
    d.mkdir(parents=True, exist_ok=True)
    with (d / "operation.lock").open("a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Error("another workflow operation holds this clone lock") from None
        yield


def public_safe(text):
    # A guard against accidental routing, not a semantic vulnerability detector.
    if re.search(
        r"GHSA-[\w-]+|security/advisories/|security-advisories/|security-finding:v1",
        text,
        re.I,
    ):
        raise Error(
            "confidential advisory reference refused by ordinary issue workflow; use work-security"
        )


def issue_number(ref):
    m = re.fullmatch(re.escape(board.REPO) + r"#([1-9][0-9]*)", ref)
    if not m:
        raise Error(f"expected {board.REPO}#NUMBER; wrong or missing repository/issue")
    return int(m[1])


def block(marker, data):
    return "<!-- " + marker + " -->\n```json\n" + json.dumps(data, indent=2) + "\n```"


def parse_block(marker, body):
    found = list(
        re.finditer(
            r"^<!-- " + re.escape(marker) + r" -->[ \t]*\r?\n```json[ \t]*\r?\n",
            body or "",
            re.M,
        )
    )
    if len(found) != 1:
        raise Error("missing or ambiguous workflow evidence")
    try:
        # Markdown fences inside JSON strings are data, not the closing fence.
        remaining = body[found[0].end() :].lstrip()
        value, end = json.JSONDecoder().raw_decode(remaining)
        if not isinstance(value, dict) or not re.match(
            r"[ \t]*(?:\r?\n[ \t]*)+```[ \t]*(?:\r?\n|$)", remaining[end:]
        ):
            raise ValueError("missing closing fence or object")
        return value
    except (ValueError, TypeError):
        raise Error("invalid workflow evidence JSON") from None


def checkpoint_body(state):
    public = {k: v for k, v in state.items() if not k.startswith("_")}
    body = "# Work issue checkpoint\n\n" + block(MARK, public)
    public_safe(body)
    if len(body.encode("utf-8")) > MAX_CHECKPOINT_BYTES:
        # Long-lived ledgers must not lose history merely to remove whitespace.
        body = (
            "# Work issue checkpoint\n\n<!-- "
            + MARK
            + " -->\n```json\n"
            + json.dumps(public, separators=(",", ":"))
            + "\n```"
        )
    if len(body.encode("utf-8")) > MAX_CHECKPOINT_BYTES:
        raise Error(
            "checkpoint too large; shorten checkpoint/triage text, preserve review history"
        )
    if parse_block(MARK, body) != public:
        raise Error("checkpoint serialization did not round trip")
    return body


class GitHub:
    def api(self, path, data=None, method=None, pages=False):
        try:
            security_guard.public_only()
        except ValueError as e:
            raise Error(str(e)) from None
        args = ["gh", "api", path]
        if pages:
            args += ["--paginate", "--slurp"]
        if method:
            args += ["--method", method]
        if data is not None:
            args += ["--input", "-"]
        out = run(args, input=json.dumps(data) if data is not None else None)
        value = json.loads(out or "null")
        if isinstance(value, dict) and value.get("errors"):
            raise Error("GitHub GraphQL request failed")
        return [item for page in value for item in page] if pages else value

    def trusted(self, comment):
        q = """query($id:ID!) { node(id:$id) { ... on IssueComment {
          body author { login } editor { login } lastEditedAt repository { nameWithOwner }
        } } }"""
        d = self.api("graphql", {"query": q, "variables": {"id": comment["node_id"]}})[
            "data"
        ]["node"]
        if (
            not d
            or (d.get("author") or {}).get("login") != board.OWNER
            or d["repository"]["nameWithOwner"] != board.REPO
            or (
                d.get("lastEditedAt")
                and (d.get("editor") or {}).get("login") != board.OWNER
            )
        ):
            raise Error(
                "untrusted comment revision: owner author and latest editor required"
            )
        return {**comment, "body": d["body"]}

    def project(self):
        try:
            return board.project()
        except board.BoardError as e:
            raise Error(str(e)) from None

    def move(self, number, status):
        try:
            board.set_status(number, status)
        except board.BoardError as e:
            raise Error(str(e)) from None

    def pr_write(self, number, title, body, branch, base, draft):
        try:
            security_guard.public_only()
        except ValueError as e:
            raise Error(str(e)) from None
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md") as f:
            f.write(body)
            f.flush()
            args = (
                ["gh", "pr", "edit", str(number), "--base", base]
                if number
                else ["gh", "pr", "create", "--head", branch, "--base", base]
            )
            if draft and not number:
                args += ["--draft"]
            run([*args, "--repo", board.REPO, "--title", title, "--body-file", f.name])
        if number:
            current = json.loads(
                run(
                    [
                        "gh",
                        "pr",
                        "view",
                        str(number),
                        "--repo",
                        board.REPO,
                        "--json",
                        "isDraft",
                    ]
                )
            )["isDraft"]
            if current != draft:
                run(
                    [
                        "gh",
                        "pr",
                        "ready",
                        str(number),
                        "--repo",
                        board.REPO,
                        *(["--undo"] if draft else []),
                    ]
                )


def comments(gh, number):
    return gh.api(f"repos/{board.REPO}/issues/{number}/comments", pages=True)


def remote_state(gh, number):
    candidates = [c for c in comments(gh, number) if MARK in c.get("body", "")]
    if len(candidates) > 1:
        raise Error("multiple checkpoint comments; reconcile before continuing")
    if not candidates:
        return None, None
    c = gh.trusted(candidates[0])
    state = parse_block(MARK, c["body"])
    if (
        state.get("repo") != board.REPO
        or state.get("issue") != number
        or state.get("version") not in (1, 2, 3)
    ):
        raise Error("checkpoint belongs to another task or schema")
    return state, c


def pulls(gh):
    return gh.api(f"repos/{board.REPO}/pulls?state=all&per_page=100", pages=True)


def branch_prs(gh, branch, number):
    existing = [
        p
        for p in pulls(gh)
        if p["state"] == "open"
        and p.get("head", {}).get("ref") == branch
        and (p["head"].get("repo") or {}).get("full_name") == board.REPO
    ]
    if len(existing) > 1:
        raise Error("ambiguous existing PRs")
    if existing and relation(existing[0]["body"], number) not in ("fixes", "part of"):
        raise Error("existing branch PR has a different issue relationship")
    return existing


def relation(body, number):
    ref = rf"(?:#{number}|{re.escape(board.REPO)}#{number}|https://github.com/{re.escape(board.REPO)}/issues/{number})"
    matches = re.findall(rf"^(Fixes|Part of) {ref}\s*$", body or "", re.M | re.I)
    if len(matches) != 1:
        return None
    kind = matches[0].lower()
    closing = re.findall(
        r"\b(?:close[sd]?|fix(?:es|ed)?|resolve[sd]?):?\s+(#[0-9]+|[\w.-]+/[\w.-]+#[0-9]+|https://github\.com/[\w.-]+/[\w.-]+/issues/[0-9]+)",
        body or "",
        re.I,
    )
    if kind == "part of":
        if closing:
            return None
    else:
        canonical = re.findall(
            r"^Fixes (#[0-9]+|[\w.-]+/[\w.-]+#[0-9]+|https://github\.com/[\w.-]+/[\w.-]+/issues/[0-9]+)\s*$",
            body or "",
            re.M | re.I,
        )

        def key(value):
            value = (
                value.lower()
                .removeprefix("https://github.com/")
                .replace("/issues/", "#")
            )
            return board.REPO.lower() + value if value.startswith("#") else value

        closing_keys = [key(value) for value in closing]
        if len(closing_keys) != len(set(closing_keys)) or set(closing_keys) != {
            key(value) for value in canonical
        }:
            return None
        if sum(bool(re.fullmatch(ref, value, re.I)) for value in closing) != 1:
            return None
    return kind


def fresh_base(base):
    if not re.fullmatch(r"origin/[A-Za-z0-9_./-]+", base) or ".." in base:
        raise Error("base must be an origin branch")
    codex_review.behind(base, env=codex_review.clean_env(dict(os.environ)))
    return git("rev-parse", base)


LICENSE_HEADER = (
    b"# SPDX-License-Identifier: Apache-2.0\n# Copyright 2026 The boxcar Authors\n"
)


def license_continuity(before, head, base, gh=None):
    """Recompute the narrow content proof; never execute candidate files.

    CI uses GitHub Git objects, not its trusted-main checkout's working tree.
    Exact bytes, modes and paths matter; this is not a semantic diff heuristic.
    """
    if not all(re.fullmatch(r"[0-9a-f]{40,64}", s or "") for s in (before, head, base)):
        raise Error("continuity requires immutable revisions")
    if before == head:
        raise Error("unchanged head needs no continuity record")
    if gh:
        comparison = gh.api(f"repos/{board.REPO}/compare/{before}...{head}")
        if (
            comparison.get("status") != "ahead"
            or comparison.get("merge_base_commit", {}).get("sha") != before
        ):
            raise Error("reviewed head must be an ancestor of continuity head")
    elif git("merge-base", before, head) != before:
        raise Error("reviewed head must be an ancestor of continuity head")

    def tree(sha):
        if gh:
            value = gh.api(f"repos/{board.REPO}/git/trees/{sha}?recursive=1")
            if value.get("truncated") is not False or not isinstance(
                value.get("tree"), list
            ):
                raise Error("complete Git tree unavailable for continuity")
            entries = value["tree"]
        else:
            entries = []
            for row in git("ls-tree", "-rz", "--full-tree", sha).split("\0"):
                if row:
                    fields, path = row.split("\t", 1)
                    mode, kind, oid = fields.split()
                    entries.append(
                        {"path": path, "mode": mode, "type": kind, "sha": oid}
                    )
        selected = [e for e in entries if e["type"] != "tree"]
        result = {e["path"]: [e["mode"], e["type"], e["sha"]] for e in selected}
        if len(result) != len(selected):
            raise Error("ambiguous Git tree")
        return result

    def blob(sha):
        if gh:
            value = gh.api(f"repos/{board.REPO}/git/blobs/{sha}")
            if value.get("encoding") != "base64" or value.get("sha") != sha:
                raise Error("Git blob unavailable for continuity")
            try:
                content = base64.b64decode(
                    "".join(value["content"].split()), validate=True
                )
            except (ValueError, KeyError):
                raise Error("invalid Git blob encoding") from None
        else:
            p = subprocess.run(
                ["git", "cat-file", "blob", sha],
                capture_output=True,
                env=codex_review.clean_env(dict(os.environ)),
            )
            if p.returncode:
                raise Error("Git blob unavailable for continuity")
            content = p.stdout
        if len(content) > 1024 * 1024:
            raise Error("continuity blob exceeds bounded inspection size")
        hashed = (hashlib.sha1 if len(sha) == 40 else hashlib.sha256)(
            b"blob " + str(len(content)).encode() + b"\0" + content
        ).hexdigest()
        if hashed != sha:
            raise Error("Git blob content does not match its object ID")
        return content

    old, new = tree(before), tree(head)
    if old.keys() != new.keys():
        raise Error("continuity cannot add, delete or rename files")
    changed = sorted(path for path in old if old[path] != new[path])
    if not changed or len(changed) > 100:
        raise Error("continuity needs a bounded license-header delta")
    for path in changed:
        a, b = old[path], new[path]
        if (
            not path.endswith(".py")
            or a[:2] != b[:2]
            or a[0] not in ("100644", "100755")
            or a[1] != "blob"
        ):
            raise Error("continuity only permits unchanged regular Python paths/modes")
        source, target = blob(a[2]), blob(b[2])
        if (
            source.startswith(b"\xef\xbb\xbf")
            or b"\0" in source
            or re.search(
                rb"coding[:=][ \t]*[-\w.]+", b"\n".join(source.splitlines()[:2])
            )
        ):
            raise Error("encoding cookies/BOMs/binary files cannot use continuity")
        try:
            source.decode("utf-8")
        except UnicodeError:
            raise Error("continuity requires ordinary UTF-8 Python source") from None
        offset = 0
        if source.startswith(b"#!"):
            offset = source.find(b"\n") + 1
            if not offset:
                raise Error("unterminated shebang cannot use continuity")
        if target != source[:offset] + LICENSE_HEADER + source[offset:]:
            raise Error("continuity delta is not exactly the approved license header")
    return {
        "kind": "license-headers",
        "from_head": before,
        "head": head,
        "base": base,
        "before_tree": policy.digest(old),
        "after_tree": policy.digest(new),
        "files": changed,
    }


def verify_continuity(state, head, base, gh=None, confidential=False):
    reviews = [r for r in state["reviews"] if r["phase"] in ("code", "docs")]
    if state.get("version") == 3 and reviews and reviews[-1]["commit"] != head:
        c = policy.validate_continuity(state, head, base, confidential=confidential)
        if c["proof"] != license_continuity(c["reviewed_head"], head, base, gh):
            raise Error("continuity proof does not match the actual Git objects")


def review_source(receipt, path):
    """Only receipt-bound structured claims may be transferred into review context."""
    try:
        payload = json.loads(path.read_text())
    except (ValueError, OSError):
        raise Error("prior source report is missing or incomplete") from None
    result = payload.get("result") if isinstance(payload, dict) else None
    expected = {
        "head": receipt["commit"],
        "base": receipt["base_sha"],
        "merge_base": receipt.get("merge_base"),
    }
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("findings"), list)
        or not all(isinstance(f, dict) for f in result["findings"])
        or not isinstance(payload.get("codex"), dict)
        or payload.get("codex", {}).get("status") != 0
        or payload.get("parseError")
        or result.get("verdict") != receipt["outcome"]
        or not receipt.get("result_digest")
        or policy.digest(result) != receipt["result_digest"]
        or receipt.get("inputs") != expected
        or payload.get("inputs") != expected
    ):
        raise Error(
            "prior source result/inputs do not match its receipt; recover the original report or reconcile through a new initial review"
        )
    # Unbound transcript/metadata fields must not masquerade as authenticated claims.
    return {"result": result, "inputs": expected}


completed = policy.count
budget = policy.budget
approved = policy.approved


def exception(gh, number, head, base):
    expected = f"work-issue exception {head} {base}"
    for c in comments(gh, number):
        if expected in c.get("body", "").splitlines():
            if expected in gh.trusted(c)["body"].splitlines():
                return True
    return False


def finish(number, gh):
    gh.api(f"repos/{board.REPO}/issues/{number}")
    for p in pulls(gh):
        if (
            relation(p.get("body"), number) != "fixes"
            or p["base"]["ref"] != "main"
            or not p.get("merged_at")
        ):
            continue
        sha = p.get("merge_commit_sha")
        if not sha:
            continue
        comparison = gh.api(f"repos/{board.REPO}/compare/{sha}...main")
        if comparison["status"] in ("ahead", "identical"):
            gh.move(number, "Done")
            return p["number"]
    raise Error(
        "no finishing PR whose merge commit reached main; partial/stacked/open PRs do not complete"
    )


class Task:
    def __init__(self, number, gh=None):
        self.number = number
        self.gh = gh or GitHub()
        self.directory = directory()
        self.path = self.directory / f"{number}.json"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.state = json.loads(self.path.read_text()) if self.path.exists() else None

    def save(self):
        # Reject invalid publication intents before they can wedge later recovery.
        checkpoint_body(self.state)
        atomic(self.path, self.state)

    def public_state(self):
        return {k: v for k, v in self.state.items() if not k.startswith("_")}

    def acknowledge(self, public, comment):
        self.state["_remote_revision"] = public["revision"]
        self.state["_comment"] = comment["html_url"]
        # A separate snapshot detects unpublished edits on a returning machine.
        self.state["_published"] = json.loads(json.dumps(public))
        self.save()

    def publish(self):
        remote, c = remote_state(self.gh, self.number)
        revision = remote["revision"] if remote else None
        public = self.public_state()
        if remote == public:
            self.acknowledge(public, c)
            return
        if revision != self.state.get("_remote_revision"):
            raise Error(
                "checkpoint changed in another clone; reconcile without overwriting history"
            )
        self.state["revision"] = str(uuid.uuid4())
        self.save()
        public = self.public_state()
        body = checkpoint_body(self.state)
        path = (
            f"repos/{board.REPO}/issues/comments/{c['id']}"
            if c
            else f"repos/{board.REPO}/issues/{self.number}/comments"
        )
        try:
            self.gh.api(path, {"body": body}, method="PATCH" if c else "POST")
        except Error:
            check, _ = remote_state(self.gh, self.number)
            if check != public:
                raise
        check, c = remote_state(self.gh, self.number)
        if check != public:
            raise Error("checkpoint publication not verified")
        self.acknowledge(check, c)

    def own(self, session):
        if not self.state or self.state.get("owner") != {
            "session": session,
            "clone": self.clone(),
        }:
            raise Error(
                "task owned by another session/clone; explicit release/handoff required"
            )
        # Every operation reconciles its predecessor before changing the saved intent.
        self.publish()

    def clone(self):
        p = self.directory / "clone.json"
        if not p.exists():
            atomic(p, {"id": str(uuid.uuid4())})
        return json.loads(p.read_text())["id"]

    def start(self, session, here=False, base=None):
        url = git("remote", "get-url", "origin")
        expected = [f"https://github.com/{board.REPO}", f"git@github.com:{board.REPO}"]
        if url.removesuffix(".git") not in expected:
            raise Error(
                "local origin is the wrong repository; private work uses work-security"
            )
        issue = self.gh.api(f"repos/{board.REPO}/issues/{self.number}")
        if issue.get("pull_request") or issue["state"] != "open":
            raise Error("expected an open issue, not a PR or closed task")
        public_safe(issue.get("body") or "")
        self.gh.project()
        if self.gh.api("user")["login"] != board.OWNER:
            raise Error(
                "this workflow requires owner-issued checkpoints; authenticated identity is not the owner"
            )
        remote, _ = remote_state(self.gh, self.number)
        if self.state:
            # Check provenance even when the local state has unpublished work.
            remote_revision = remote["revision"] if remote else None
            if remote_revision not in (
                self.state.get("_remote_revision"),
                self.state["revision"],
            ):
                if (
                    not remote
                    or self.state.get("owner")
                    or remote.get("owner")
                    or self.public_state() != self.state.get("_published")
                    or remote["branch"] != self.state["branch"]
                ):
                    raise Error("remote checkpoint changed; reconcile local history")
                if not {r["id"] for r in self.state["reviews"]}.issubset(
                    {r["id"] for r in remote["reviews"]}
                ):
                    raise Error(
                        "remote checkpoint lost review history; reconcile before continuing"
                    )
                self.state = remote
                self.state["_remote_revision"] = remote_revision
            # Reconcile a mutation accepted remotely before changing its saved intent.
            if remote_revision == self.state["revision"]:
                self.publish()
        elif remote:
            self.state = remote
            self.state["_remote_revision"] = remote["revision"]
        else:
            related = [
                p
                for p in pulls(self.gh)
                if relation(p.get("body"), self.number) and p["state"] == "open"
            ]
            branches = {
                p["head"]["ref"]
                for p in related
                if p["head"]["repo"]["full_name"] == board.REPO
            }
            if len(branches) > 1:
                raise Error(
                    "multiple active task branches; choose with the owner before starting"
                )
            branch = next(iter(branches)) if branches else f"issue-{self.number}"
            if here:
                current = git("branch", "--show-current")
                if branches and current != branch:
                    raise Error("existing PR uses another branch; resume its worktree")
                branch = current
            self.state = {
                "version": 2,
                "policy_version": 2,
                "findings": {},
                "migration": {"from": None, "history": {}},
                "repo": board.REPO,
                "issue": self.number,
                "revision": str(uuid.uuid4()),
                "branch": branch,
                "base": base or "origin/main",
                "owner": None,
                "reviews": [],
                "authorizations": [],
                "checkpoint": {
                    "completed": "",
                    "verification": "",
                    "blockers": "",
                    "next": "Read issue context and linked plans",
                },
            }
        if self.state.get("owner"):
            self.own(session)
        if base is not None and base != self.state["base"]:
            raise Error(
                "existing task has a different base; use the base command in its worktree"
            )
        branch = self.state["branch"]
        if not branch or branch == "main":
            raise Error("use a task branch, not main or detached HEAD")
        # Released local ownership does not free a branch with another task's open PR.
        branch_prs(self.gh, branch, self.number)
        for p in self.directory.glob("[0-9]*.json"):
            if not p.stem.isdecimal():
                continue
            other = json.loads(p.read_text())
            if (
                other["issue"] != self.number
                and other["branch"] == branch
                and other.get("owner")
            ):
                raise Error("branch already belongs to another issue")
        self.state["owner"] = {"session": session, "clone": self.clone()}
        self.save()
        target = None
        for record in git("worktree", "list", "--porcelain").split("\n\n"):
            lines = record.splitlines()
            if f"branch refs/heads/{branch}" in lines:
                target = lines[0].removeprefix("worktree ")
        if target is None:
            target = str(self.directory / "worktrees" / str(self.number))
            existing = git("branch", "--list", branch)
            if not existing:
                run(["git", "fetch", "origin"])
                remote_branch = git("branch", "-r", "--list", f"origin/{branch}")
                git(
                    "branch",
                    branch,
                    f"origin/{branch}" if remote_branch else self.state["base"],
                )
            git("worktree", "add", target, branch)
        self.state["_worktree"] = target
        self.state["commit"] = run(["git", "-C", target, "rev-parse", "HEAD"])
        self.save()
        self.publish()
        finishing = any(
            relation(p.get("body"), self.number) == "fixes" and p["state"] == "open"
            for p in pulls(self.gh)
        )
        self.gh.move(self.number, "In review" if finishing else "In progress")
        if not any(r["status"] == "pending" for r in self.state["reviews"]):
            self.migrate(session)
        return self.state

    def check_tree(self, session):
        self.own(session)
        if git("branch", "--show-current") != self.state["branch"]:
            raise Error("run in the associated task worktree")

    def checkpoint(self, session, data):
        self.check_tree(session)
        if set(data) != {"completed", "verification", "blockers", "next"} or not all(
            isinstance(v, str) for v in data.values()
        ):
            raise Error(
                "checkpoint needs completed, verification, blockers, next strings"
            )
        public_safe(json.dumps(data))
        head = git("rev-parse", "HEAD")
        candidate = {
            **self.state,
            "checkpoint": data,
            "commit": head,
            "verification_commit": head,
            "verification_base": fresh_base(self.state["base"]),
            "verification_dirty": bool(git("status", "--porcelain")),
        }
        checkpoint_body(candidate)
        self.state = candidate
        self.save()
        self.publish()

    def set_base(self, session, base):
        self.check_tree(session)
        if any(r["status"] == "pending" for r in self.state["reviews"]):
            raise Error("recover pending review before changing base")
        fresh_base(base)
        if base != self.state["base"]:
            self.state["base"] = base
            self.state["verification_base"] = None
            self.save()
            self.publish()

    def release(self, session):
        if (
            self.state
            and self.state.get("owner") is None
            and self.state.get("_released_by")
            == {"session": session, "clone": self.clone()}
        ):
            self.publish()
            return
        self.own(session)
        if any(r["status"] == "pending" for r in self.state["reviews"]):
            raise Error("recover pending review before release")
        self.publish()  # durable handoff barrier before releasing ownership
        self.state["_released_by"] = self.state["owner"]
        self.state["owner"] = None
        self.save()
        self.publish()

    def migrate(self, session):
        self.own(session)
        if self.state["version"] in (2, 3):
            return
        candidate = policy.migrate(self.state)
        backup = self.directory / f"{self.number}.v1-backup.json"
        if not backup.exists():
            atomic(backup, self.state)
        self.state = candidate
        self.save()
        self.publish()

    def deliverable(self, session, data, comment=None, preview=False):
        if set(data) != {"id", "outcome", "acceptance"}:
            raise Error("deliverable needs id, outcome and acceptance")
        public_safe(json.dumps(data))
        if preview:
            if (
                not self.state
                or self.state.get("owner")
                != {
                    "session": session,
                    "clone": self.clone(),
                }
                or git("branch", "--show-current") != self.state["branch"]
            ):
                raise Error("preview requires the owned task worktree")
            remote, _ = remote_state(self.gh, self.number)
            if remote != self.public_state():
                raise Error("reconcile unpublished or remote state before preview")
        else:
            self.check_tree(session)
        existing = next(
            (d for d in self.state.get("deliverables", []) if d["id"] == data["id"]),
            None,
        )
        candidate = policy.begin_deliverable(
            self.state,
            data["id"],
            data["outcome"],
            data["acceptance"],
            comment or (existing["comment"] if existing else 1),
        )
        d = candidate["deliverables"][-1]
        ordinal = len(candidate["deliverables"])
        line = f"work-issue deliverable {board.REPO}#{self.number} {ordinal} {d['binding']}"
        if preview:
            return line
        if comment is None:
            raise Error(
                "record the real owner instruction and exact preview line, then supply --comment"
            )
        check = lambda ph, rd, c, kind, binding=None: authorize_check(
            self.gh, self.number, ph, rd, c, kind, binding
        )
        policy.check_ledger(self.state, check)
        authorize_check(
            self.gh,
            self.number,
            "deliverable",
            ordinal,
            comment,
            "deliverable",
            d["binding"],
        )
        policy.check_ledger(candidate, check)
        checkpoint_body(candidate)
        self.state = candidate
        self.save()
        self.publish()
        return line

    def carry(self, session, receipt_id, data):
        self.check_tree(session)
        if set(data) != {"findings", "rationale"}:
            raise Error("carry needs findings and rationale")
        public_safe(json.dumps(data))
        head, base = git("rev-parse", "HEAD"), fresh_base(self.state["base"])
        r = policy.receipt(self.state, receipt_id)
        if git("status", "--porcelain") or (r["commit"], r["base_sha"]) != (head, base):
            raise Error("carry requires the actual clean reviewed head and target")
        candidate = json.loads(json.dumps(self.state))
        policy.carry_forward(candidate, receipt_id, data["findings"], data["rationale"])
        checkpoint_body(candidate)
        self.state = candidate
        self.save()
        self.publish()

    def continuity(self, session, receipt_id):
        self.check_tree(session)
        if git("status", "--porcelain"):
            raise Error("commit all changes before continuity validation")
        head, base = git("rev-parse", "HEAD"), fresh_base(self.state["base"])
        r = policy.receipt(self.state, receipt_id)
        if r["base_sha"] != base:
            raise Error("changed target requires integration review")
        proof = license_continuity(r["commit"], head, base)
        candidate = json.loads(json.dumps(self.state))
        policy.record_continuity(candidate, receipt_id, head, base, proof)
        checkpoint_body(candidate)
        self.state = candidate
        self.save()
        self.publish()

    def authorize(self, session, phase, round_, comment, kind="authorize"):
        self.own(session)
        failed_ids = [
            r["id"]
            for r in self.state["reviews"]
            if r["phase"] == phase and r["status"] == "failed"
        ]
        binding = policy.digest(failed_ids) if kind == "retry" else None
        deliverable = policy.active_deliverable(self.state)
        if deliverable and kind in ("authorize", "ceiling"):
            binding = deliverable["binding"]
        authorize_check(self.gh, self.number, phase, round_, comment, kind, binding)
        a = {"phase": phase, "round": round_, "comment": comment}
        if deliverable and kind in ("authorize", "ceiling"):
            a.update(deliverable=deliverable["id"], binding=binding)
        if kind == "ceiling":
            if round_ < completed(self.state, phase):
                raise Error("ceiling cannot erase completed reviews")
            target = policy.active_deliverable(self.state)
            if target is None:
                target = self.state
            target.setdefault("ceilings", {})[phase] = a
        elif kind == "retry":
            if round_ != completed(self.state, phase) + 1:
                raise Error("retry authorization must name the next completed round")
            a.update(failed_ids=failed_ids, binding=binding)
            history = self.state.setdefault("retry_history", [])
            if a not in history:
                history.append(a)
            self.state.setdefault("retry_authorizations", {})[phase] = a
        elif a not in self.state["authorizations"]:
            self.state["authorizations"].append(a)
        self.save()
        self.publish()

    def dispose(self, session, fid, data):
        self.check_tree(session)
        self.migrate(session)
        public_safe(json.dumps(data))
        head, base = git("rev-parse", "HEAD"), fresh_base(self.state["base"])
        candidate = json.loads(json.dumps(self.state))
        event = policy.disposition(candidate, fid, data, head, base)
        if event["status"] == "excepted":
            finding_exception(self.gh, self.number, fid, event["comment"], head, base)
        checkpoint_body(candidate)
        self.state = candidate
        self.save()
        self.publish()

    def integrate(self, session, receipt_id, rationale, material=False):
        self.check_tree(session)
        if git("status", "--porcelain"):
            raise Error("commit all changes before integration validation")
        public_safe(rationale)
        head, base = git("rev-parse", "HEAD"), fresh_base(self.state["base"])
        merge_base = git("merge-base", head, base)
        if merge_base != base:
            raise Error(
                "current target is not incorporated; integrate it, verify affected behavior and review the result"
            )
        verification_current(self.state, head, base)
        candidate = {
            **self.state,
            "integration": {
                "head": head,
                "base": base,
                "merge_base": merge_base,
                "receipt": receipt_id,
                "rationale": rationale,
                "material_change": material,
            },
        }
        readiness(candidate, head, base, self.gh, self.number)
        self.state = candidate
        self.save()
        self.publish()

    def review(
        self,
        session,
        phase,
        focus,
        scope="initial",
        prior=None,
        verifies=None,
        rationale="",
        material=False,
        comparison=None,
    ):
        self.check_tree(session)
        self.migrate(session)
        if git("status", "--porcelain"):
            raise Error("commit all changes before review")
        round_ = budget(self.state, phase)
        auth = policy.authorization(self.state, phase, round_)
        if auth:
            authorize_check(
                self.gh,
                self.number,
                phase,
                round_,
                auth["comment"],
                binding=auth.get("binding"),
            )
        scope_state = policy.active_deliverable(self.state)
        ceiling = (
            (scope_state if scope_state is not None else self.state)
            .get("ceilings", {})
            .get(phase)
        )
        if ceiling:
            authorize_check(
                self.gh,
                self.number,
                phase,
                ceiling["round"],
                ceiling["comment"],
                "ceiling",
                ceiling.get("binding"),
            )
        # Validate all previous counts before spending, including historical exceptions.
        policy.check_ledger(
            self.state,
            lambda ph, rd, c, kind, binding=None: authorize_check(
                self.gh, self.number, ph, rd, c, kind, binding
            ),
        )
        if phase == "docs" and any(
            Path(p).suffix not in (".md", ".txt")
            for p in git(
                "diff", "--no-renames", "--name-only", self.state["base"] + "...HEAD"
            ).splitlines()
        ):
            raise Error("executable changes require the code phase, not docs")
        if comparison and phase != "plan":
            raise Error(
                "a custom comparison commit is only supported for plan-only review"
            )
        base_sha = fresh_base(self.state["base"])
        if comparison:
            base_sha = git("rev-parse", "--verify", comparison + "^{commit}")
        head = git("rev-parse", "HEAD")
        r = {
            "id": str(uuid.uuid4()),
            "phase": phase,
            "commit": head,
            "base": comparison or self.state["base"],
            "base_sha": base_sha,
            "merge_base": git("merge-base", head, base_sha),
            "status": "pending",
            "outcome": "pending",
            **policy.review_fields(self.state, phase),
            "scope": scope,
            "prior": prior or [],
            "verifies": verifies or [],
            "rationale": rationale,
            "material_change": material,
        }
        if r["policy_version"] == 3:
            r["finding_context"] = policy.capture_findings(self.state, r["verifies"])
        if policy.failed_attempts(self.state, phase)[1] >= 2:
            grant = self.state["retry_authorizations"][phase]
            # A cached grant is not current permission. Validate the selected
            # comment revision before recording/spending this new attempt.
            authorize_check(
                self.gh,
                self.number,
                phase,
                round_,
                grant["comment"],
                "retry",
                grant["binding"],
            )
            r["retry"] = dict(grant)
        public_safe(json.dumps(r))
        policy.validate_scope(
            self.state,
            r,
            lambda ph, rd, c, kind, binding=None: authorize_check(
                self.gh, self.number, ph, rd, c, kind, binding
            ),
        )
        if scope not in policy.SCOPES or (material and scope != "initial"):
            raise Error("material changes require initial scope; unknown scope refused")
        if scope != "initial" and (not r["prior"] or not rationale.strip()):
            raise Error(
                "focused review needs prior receipts and a continuity rationale"
            )
        if any(fid not in self.state["findings"] for fid in r["verifies"]):
            raise Error("unknown finding to verify")
        report = self.directory / (r["id"] + ".json")
        context = self.directory / (r["id"] + ".context.json")
        # Restricted context is not copied into the public checkpoint or PR.
        previous_context = []
        required_sources = {
            source[0]
            for fid in r["verifies"]
            for source in self.state["findings"][fid]["sources"]
        }
        if r["policy_version"] == 3 and not required_sources.issubset(r["prior"]):
            raise Error(
                "include every source receipt before verifying carried findings"
            )
        for ident in r["prior"]:
            path = self.directory / (ident + ".json")
            if (scope != "initial" or ident in required_sources) and not path.exists():
                raise Error(
                    "prior raw report unavailable; recover it privately before verifying its findings"
                )
            previous_context.append(
                {
                    "receipt": policy.receipt(self.state, ident),
                    "report": review_source(policy.receipt(self.state, ident), path)
                    if path.exists()
                    else "unavailable; recover privately or broaden review",
                }
            )
        atomic(
            context,
            {
                "prior": previous_context,
                "findings": {fid: self.state["findings"][fid] for fid in r["verifies"]},
            },
        )
        self.state["reviews"].append(r)
        self.save()
        self.publish()
        instruction = review_focus(r, focus, context)
        with report.open("w") as f:
            os.chmod(report, 0o600)
            p = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("codex_review.py")),
                    "--json",
                    "--head",
                    head,
                    "--base",
                    base_sha,
                    "--scope",
                    "branch",
                    instruction,
                ],
                stdout=f,
                stderr=subprocess.DEVNULL,
                env=codex_review.clean_env(dict(os.environ)),
                umask=0o077,
            )
            f.flush()
            os.fsync(f.fileno())
        self.recover(session, failed=p.returncode != 0)
        return report

    def recover(self, session, failed=False):
        self.own(session)
        pending = [r for r in self.state["reviews"] if r["status"] == "pending"]
        if len(pending) != 1:
            raise Error("expected one pending attempt; already recovered or ambiguous")
        r = pending[0]
        report = self.directory / (r["id"] + ".json")
        try:
            payload = json.loads(report.read_text())
        except (ValueError, FileNotFoundError):
            payload = {}
        result = payload.get("result") or {}
        if (
            payload.get("codex", {}).get("status") == 0
            and result.get("verdict") in ("approve", "needs-attention")
            and isinstance(result.get("findings"), list)
            and all(isinstance(f, dict) for f in result.get("findings", []))
            and not payload.get("parseError")
            and (
                r.get("policy_version", 1) == 1
                or payload.get("inputs")
                == {
                    "head": r["commit"],
                    "base": r["base_sha"],
                    "merge_base": r["merge_base"],
                }
            )
        ):
            r.update(
                status="completed",
                outcome=result["verdict"],
                round=completed(self.state, r["phase"]) + 1,
            )
            if r.get("policy_version") in (2, 3):
                r["finding_count"] = len(result["findings"])
                r["inputs"] = payload["inputs"]
                policy.register_result(self.state, r, result)
            else:
                r["unresolved"] = len(result["findings"])
        elif failed:
            r.update(status="failed", outcome="unavailable")
        else:
            raise Error(
                "no complete structured result; confirm invocation stopped before recover --failed"
            )
        self.save()
        self.publish()

    def submit(self, session, title, body, kind="fixes", pending=False):
        self.check_tree(session)
        if git("status", "--porcelain"):
            raise Error("commit all changes before submit")
        public_safe(title + "\n" + body)
        head = git("rev-parse", "HEAD")
        base_sha = fresh_base(self.state["base"])
        if not pending:
            readiness(self.state, head, base_sha, self.gh, self.number)
        expected = "fixes" if kind == "fixes" else "part of"
        if relation(body, self.number) not in (None, expected):
            raise Error("PR issue relationship contradicts --relation")
        self.publish()
        token = {
            "repo": board.REPO,
            "issue": self.number,
            "relation": expected,
            "head": head,
            "base": base_sha,
            "checkpoint": self.state["_comment"],
            "pending": pending,
        }
        if relation(body, self.number) is None:
            body = (
                ("Fixes" if kind == "fixes" else "Part of")
                + f" #{self.number}\n\n"
                + body
            )
        # Validate the assembled body before push/PR mutation, including inline
        # and noncanonical GitHub closing keywords in the caller's prose.
        if relation(body, self.number) != expected:
            raise Error("assembled PR body has an invalid issue relationship")
        body += "\n\n" + block(PR_MARK, token)
        if pending:
            body += "\n\nReview decision pending; this draft has unreviewed or unresolved work.\n"
        branch = self.state["branch"]
        base = self.state["base"].removeprefix("origin/")

        def candidates():
            return branch_prs(self.gh, branch, self.number)

        existing = candidates()
        number = existing[0]["number"] if existing else None
        # A push changes an existing PR immediately; validate its ownership first.
        run(["git", "push", "--set-upstream", "origin", branch])
        try:
            self.gh.pr_write(number, title, body, branch, base, pending)
        except Error:
            observed = candidates()
            if len(observed) != 1 or observed[0]["body"] != body:
                raise
        observed = candidates()
        if (
            len(observed) != 1
            or observed[0]["body"] != body
            or observed[0]["base"]["ref"] != base
            or observed[0]["draft"] != pending
            or observed[0]["head"]["sha"] != head
        ):
            raise Error("PR write not verified")
        self.gh.move(self.number, "In review" if kind == "fixes" else "In progress")
        return observed[0]["html_url"]


def verification_current(state, head, base):
    if (
        not state.get("checkpoint", {}).get("verification", "").strip()
        or state.get("verification_commit") != head
        or state.get("verification_base") != base
        or state.get("verification_dirty")
    ):
        raise Error(
            "verification is missing or stale; checkpoint actual results for the exact committed revision and fetched target"
        )


def validate_pr(number, gh):
    p = gh.api(f"repos/{board.REPO}/pulls/{number}")
    head = p["head"]["sha"]
    base = p["base"]["sha"]
    if exception(gh, number, head, base):
        return "owner exception for this revision/base"
    evidence = parse_block(PR_MARK, p["body"])
    n = evidence.get("issue")
    if (
        evidence.get("repo") != board.REPO
        or not isinstance(n, int)
        or evidence.get("head") != head
        or evidence.get("base") != base
    ):
        raise Error("PR evidence is stale or belongs to another task")
    if relation(p["body"], n) != evidence.get("relation"):
        raise Error("invalid issue relationship")
    issue = gh.api(f"repos/{board.REPO}/issues/{n}")
    if issue.get("pull_request"):
        raise Error("relationship points to a PR, not an issue")
    s, c = remote_state(gh, n)
    if (
        not s
        or s["branch"] != p["head"]["ref"]
        or c["html_url"] != evidence.get("checkpoint")
    ):
        raise Error("checkpoint missing or replaced")
    if evidence.get("pending") or not approved(s, head, base):
        raise Error("review missing, stale, failed or unresolved")
    implementation = [r for r in s["reviews"] if r["phase"] in ("code", "docs")]
    if implementation and implementation[-1]["phase"] == "docs":
        files = gh.api(
            f"repos/{board.REPO}/pulls/{number}/files?per_page=100", pages=True
        )
        if any(
            Path(f[name]).suffix not in (".md", ".txt")
            for f in files
            for name in ("filename", "previous_filename")
            if name in f
        ):
            raise Error("executable PR changes require code review, not docs")
    readiness(s, head, base, gh, n, remote=True)
    if s.get("version") in (2, 3):
        comparison = gh.api(f"repos/{board.REPO}/compare/{base}...{head}")
        if (
            comparison.get("status") not in ("ahead", "identical")
            or comparison.get("merge_base_commit", {}).get("sha") != base
        ):
            raise Error("live target is not incorporated into the reviewed head")
    return "issue and review contract verified"


def authorize_check(gh, n, phase, round_, comment, kind="authorize", binding=None):
    c = next((c for c in comments(gh, n) if c["id"] == comment), None)
    expected = (
        f"work-issue deliverable {board.REPO}#{n} {round_} {binding}"
        if kind == "deliverable"
        else f"work-issue {kind} {board.REPO}#{n} {phase} {round_}"
        + (f" {binding}" if binding else "")
    )
    if not c or expected not in gh.trusted(c)["body"].splitlines():
        raise Error("missing exact owner authorization")


def finding_exception(gh, n, fid, comment, head, base):
    c = next((c for c in comments(gh, n) if c["id"] == comment), None)
    expected = f"work-issue finding-exception {board.REPO}#{n} {fid} {head} {base}"
    if not c or expected not in gh.trusted(c)["body"].splitlines():
        raise Error("missing exact owner finding exception")


def readiness(state, head, base, gh, number, remote=False):
    verification_current(state, head, base)
    policy.check_ledger(
        state,
        lambda ph, rd, c, kind, binding=None: authorize_check(
            gh, number, ph, rd, c, kind, binding
        ),
    )
    if not approved(state, head, base):
        raise Error("review missing, stale, failed, unclassified or blocking")
    verify_continuity(state, head, base, gh if remote else None)
    if state.get("version") in (2, 3):
        policy.integration_current(state, head, base)
        if not policy.findings_ready(
            state,
            head,
            base,
            lambda fid, c, h, b: finding_exception(gh, number, fid, c, h, b),
        ):
            raise Error("finding disposition is unresolved")


def review_focus(r, focus, context):
    scopes = {
        "initial": "Review the complete logical change, requirements, surrounding code and important invariants.",
        "follow-up": "Focused follow-up: verify prior findings, intervening fixes, their tests and affected behavior/callers. Do not restart an unrestricted architectural review. Identify any new serious defect you discover.",
        "integration": "Integration review: examine target-branch changes, conflict resolutions, callers, dependencies, configuration and shared invariants since the referenced receipts. Unchanged patches alone do not prove equivalent behavior.",
    }
    return (
        f"Phase: {r['phase']}. Scope: {r['scope']}. {scopes[r['scope']]} "
        f"Immutable inputs: head={r['commit']} comparison={r['base_sha']} merge-base={r['merge_base']}. "
        f"Read restricted prior context at {context}. Prior receipts: {r['prior']}; finding IDs: {r['verifies']}. "
        "Preserve a repeated finding's opaque F- ID in its title. Distinguish blocking defects from optional improvements; provide evidence, consequences, severity and confidence separately. "
        "Report missing critical context rather than inventing an approval. This branch review does not assert current integration readiness. "
        f"Continuity rationale: {r['rationale']}. Focus: {focus}"
    )


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="action", required=True)
    for name in [
        "start",
        "base",
        "checkpoint",
        "release",
        "review",
        "recover",
        "triage",
        "authorize",
        "ceiling",
        "retry",
        "migrate",
        "deliverable",
        "carry",
        "continuity",
        "dispose",
        "integrate",
        "submit",
        "complete",
    ]:
        s = sub.add_parser(name)
        s.add_argument("issue")
        if name != "complete":
            s.add_argument("--session", required=True)
        if name == "start":
            s.add_argument("--here", action="store_true")
            s.add_argument("--base")
        if name == "base":
            s.add_argument("--base", required=True)
        if name in ("checkpoint", "triage", "dispose", "deliverable", "carry"):
            s.add_argument("--file", type=Path, required=True)
        if name == "deliverable":
            group = s.add_mutually_exclusive_group(required=True)
            group.add_argument("--comment", type=int)
            group.add_argument("--preview", action="store_true")
        if name in ("carry", "continuity"):
            s.add_argument("--receipt", required=True)
        if name == "review":
            s.add_argument("--phase", choices=["docs", "plan", "code"], required=True)
            s.add_argument("--focus", required=True)
            s.add_argument("--scope", choices=policy.SCOPES, default="initial")
            s.add_argument("--prior", action="append", default=[])
            s.add_argument("--verifies", action="append", default=[])
            s.add_argument("--rationale", default="")
            s.add_argument("--material-change", action="store_true")
            s.add_argument(
                "--comparison", help="immutable comparison commit for plan-only review"
            )
        if name == "dispose":
            s.add_argument("--finding", required=True)
        if name == "integrate":
            s.add_argument("--receipt", required=True)
            s.add_argument("--rationale", required=True)
            s.add_argument("--material-change", action="store_true")
        if name == "recover":
            s.add_argument("--failed", action="store_true")
        if name in ("authorize", "ceiling", "retry"):
            s.add_argument("--phase", choices=["docs", "plan", "code"], required=True)
            s.add_argument("--round", type=int, required=True)
            s.add_argument("--comment", type=int, required=True)
        if name == "submit":
            s.add_argument("--title", required=True)
            s.add_argument("--body-file", type=Path, required=True)
            s.add_argument("--relation", choices=["fixes", "part"], default="fixes")
            s.add_argument("--pending", action="store_true")
    s = sub.add_parser("ci")
    s.add_argument("--pr", type=int, required=True)
    a = p.parse_args(argv)
    try:
        if a.action == "ci":
            print(validate_pr(a.pr, GitHub()))
            return 0
        n = issue_number(a.issue)
        with locked():
            if a.action == "complete":
                print(f"completed by PR #{finish(n, GitHub())}")
                return 0
            t = Task(n)
            if a.action == "start":
                state = t.start(a.session, a.here, a.base)
                print(
                    json.dumps(
                        {
                            "worktree": state["_worktree"],
                            "checkpoint": state["_comment"],
                            "issue": t.gh.api(f"repos/{board.REPO}/issues/{n}"),
                            "discussion": comments(t.gh, n),
                            "related_prs": [
                                x for x in pulls(t.gh) if relation(x.get("body"), n)
                            ],
                        },
                        indent=2,
                    )
                )
            elif a.action == "base":
                t.set_base(a.session, a.base)
            elif a.action == "checkpoint":
                t.checkpoint(a.session, json.loads(a.file.read_text()))
            elif a.action == "release":
                t.release(a.session)
            elif a.action == "review":
                print(
                    "Private local report:",
                    t.review(
                        a.session,
                        a.phase,
                        a.focus,
                        a.scope,
                        a.prior,
                        a.verifies,
                        a.rationale,
                        a.material_change,
                        a.comparison,
                    ),
                )
            elif a.action == "recover":
                t.recover(a.session, a.failed)
            elif a.action == "submit":
                print(
                    t.submit(
                        a.session,
                        a.title,
                        a.body_file.read_text(),
                        a.relation,
                        a.pending,
                    )
                )
            elif a.action == "triage":
                t.own(a.session)
                note = a.file.read_text()
                public_safe(note)
                if not note.strip():
                    raise Error("triage disposition must not be empty")
                t.state["triage"] = note
                t.save()
                t.publish()
            elif a.action in ("authorize", "ceiling", "retry"):
                t.authorize(a.session, a.phase, a.round, a.comment, a.action)
            elif a.action == "migrate":
                t.migrate(a.session)
            elif a.action == "deliverable":
                print(
                    t.deliverable(
                        a.session, json.loads(a.file.read_text()), a.comment, a.preview
                    )
                )
            elif a.action == "carry":
                t.carry(a.session, a.receipt, json.loads(a.file.read_text()))
            elif a.action == "continuity":
                t.continuity(a.session, a.receipt)
            elif a.action == "dispose":
                t.dispose(a.session, a.finding, json.loads(a.file.read_text()))
            elif a.action == "integrate":
                t.integrate(a.session, a.receipt, a.rationale, a.material_change)
        return 0
    except (
        Error,
        board.BoardError,
        codex_review.BaseUnknown,
        OSError,
        ValueError,
        KeyError,
        TypeError,
    ) as e:
        print(f"work-issue: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
