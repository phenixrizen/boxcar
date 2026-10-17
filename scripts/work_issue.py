#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Small, explicit issue workflow. See docs/issue-workflow.md; no scheduler."""

from __future__ import annotations
import argparse
import contextlib
import fcntl
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

MARK = "work-issue-checkpoint:v1"
PR_MARK = "work-issue-pr:v1"
MAX_CHECKPOINT_BYTES = 60000  # Below GitHub's comment limit, including all metadata.


class Error(Exception):
    pass


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
        raise Error(
            "checkpoint too large; shorten checkpoint/triage text, preserve review history"
        )
    if parse_block(MARK, body) != public:
        raise Error("checkpoint serialization did not round trip")
    return body


class GitHub:
    def api(self, path, data=None, method=None, pages=False):
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
        or state.get("version") != 1
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
        r"\b(?:close[sd]?|fix(?:es|ed)?|resolve[sd]?):?\s+(?:#[0-9]+|[\w.-]+/[\w.-]+#[0-9]+|https://github\.com/[\w.-]+/[\w.-]+/issues/[0-9]+)",
        body or "",
        re.I,
    )
    if len(closing) != (1 if kind == "fixes" else 0):
        return None
    return kind


def fresh_base(base):
    if not re.fullmatch(r"origin/[A-Za-z0-9_./-]+", base) or ".." in base:
        raise Error("base must be an origin branch")
    if codex_review.behind(base, env=codex_review.clean_env(dict(os.environ))):
        raise Error("branch is behind its current base; rebase and verify first")
    return git("rev-parse", base)


def completed(state, phase):
    return sum(
        r["status"] == "completed" and r["phase"] == phase
        for r in state.get("reviews", [])
    )


def budget(state, phase):
    if any(r["status"] == "pending" for r in state.get("reviews", [])):
        raise Error("pending review: recover it before another invocation")
    count = completed(state, phase)
    if phase == "code" and count >= 3 and not state.get("triage"):
        third = [
            r
            for r in state["reviews"]
            if r["phase"] == "code" and r["status"] == "completed"
        ][2]
        if third["outcome"] != "approve":
            raise Error("third code review requires triage checkpoint")
    limit = {"docs": 1, "plan": 2, "code": 5}[phase]
    if count >= limit and not any(
        a["phase"] == phase and a["round"] == count + 1
        for a in state.get("authorizations", [])
    ):
        raise Error(
            f"{phase} budget exhausted; owner decision required for round {count + 1}"
        )


def approved(state, head, base):
    reviews = [r for r in state.get("reviews", []) if r["phase"] in ("code", "docs")]
    return bool(
        reviews
        and reviews[-1].get("valid", True)
        and reviews[-1]["status"] == "completed"
        and reviews[-1]["outcome"] == "approve"
        and reviews[-1]["unresolved"] == 0
        and reviews[-1]["commit"] == head
        and reviews[-1]["base_sha"] == base
    )


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
                "version": 1,
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
            "verification_base": git("rev-parse", self.state["base"]),
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
            for receipt in self.state["reviews"]:
                receipt["valid"] = False
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

    def review(self, session, phase, focus):
        self.check_tree(session)
        if git("status", "--porcelain"):
            raise Error("commit all changes before review")
        budget(self.state, phase)
        if phase == "docs" and any(
            Path(p).suffix not in (".md", ".txt")
            for p in git(
                "diff", "--name-only", self.state["base"] + "...HEAD"
            ).splitlines()
        ):
            raise Error("executable changes require the code phase, not docs")
        base = self.state["base"]
        base_sha = fresh_base(base)
        r = {
            "id": str(uuid.uuid4()),
            "phase": phase,
            "commit": git("rev-parse", "HEAD"),
            "base": base,
            "base_sha": base_sha,
            "status": "pending",
            "outcome": "pending",
            "unresolved": 0,
        }
        self.state["reviews"].append(r)
        self.save()
        self.publish()
        report = self.directory / (r["id"] + ".json")
        with report.open("w") as f:
            os.chmod(report, 0o600)
            p = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("codex_review.py")),
                    "--json",
                    "--base",
                    base,
                    "--scope",
                    "branch",
                    focus,
                ],
                stdout=f,
                stderr=subprocess.DEVNULL,
                env=codex_review.clean_env(dict(os.environ)),
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
            and not payload.get("parseError")
        ):
            r.update(
                status="completed",
                outcome=result["verdict"],
                unresolved=len(result["findings"]),
                round=completed(self.state, r["phase"]) + 1,
            )
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
        verification_current(self.state, head, base_sha)
        if not approved(self.state, head, base_sha) and not pending:
            raise Error(
                "current head/base lacks approval; review or submit --pending for an owner decision"
            )
        expected = "fixes" if kind == "fixes" else "part of"
        if relation(body, self.number) not in (None, expected):
            raise Error("PR issue relationship contradicts --relation")
        # Avoid quietly accepting contradictory completion declarations elsewhere.
        if (
            re.search(r"^\s*(?:fixes|closes|resolves|part of)\b", body, re.M | re.I)
            and relation(body, self.number) != expected
        ):
            raise Error("supply only the selected task relationship")
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
            "verification is missing or stale; checkpoint actual results after committing and rebasing"
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
    verification_current(s, head, base)
    for phase, limit in [("docs", 1), ("plan", 2), ("code", 5)]:
        done = [
            r
            for r in s["reviews"]
            if r["phase"] == phase and r["status"] == "completed"
        ]
        if [r["round"] for r in done] != list(range(1, len(done) + 1)):
            raise Error("inconsistent review counts")
        for round_ in range(limit + 1, len(done) + 1):
            auth = [
                a
                for a in s.get("authorizations", [])
                if a["phase"] == phase and a["round"] == round_
            ]
            if not auth:
                raise Error("review budget exceeded without owner authorization")
            authorize_check(gh, n, phase, round_, auth[0]["comment"])
    if completed(s, "code") > 3 and not s.get("triage"):
        third = [
            r
            for r in s["reviews"]
            if r["phase"] == "code" and r["status"] == "completed"
        ][2]
        if third["outcome"] != "approve":
            raise Error("third-round triage missing")
    return "issue and review contract verified"


def authorize_check(gh, n, phase, round_, comment):
    c = next((c for c in comments(gh, n) if c["id"] == comment), None)
    if (
        not c
        or f"work-issue authorize {board.REPO}#{n} {phase} {round_}"
        not in gh.trusted(c)["body"].splitlines()
    ):
        raise Error("missing exact owner authorization")


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
        if name in ("checkpoint", "triage"):
            s.add_argument("--file", type=Path, required=True)
        if name == "review":
            s.add_argument("--phase", choices=["docs", "plan", "code"], required=True)
            s.add_argument("--focus", required=True)
        if name == "recover":
            s.add_argument("--failed", action="store_true")
        if name == "authorize":
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
                print("Private local report:", t.review(a.session, a.phase, a.focus))
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
            elif a.action == "authorize":
                t.own(a.session)
                authorize_check(t.gh, n, a.phase, a.round, a.comment)
                t.state["authorizations"].append(
                    {"phase": a.phase, "round": a.round, "comment": a.comment}
                )
                t.save()
                t.publish()
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
