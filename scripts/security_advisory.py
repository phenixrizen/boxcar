#!/usr/bin/env python3
"""Private advisory operations. See docs/security-workflow.md. No publish/CVE API."""

from __future__ import annotations
import argparse
import contextlib
import copy
import datetime
import difflib
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

import board
import review_policy as policy
import security_guard as guard

Error = policy.Error
MARK = "<!-- security-finding:v1 -->"
GHSA = r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}"
STATES = (
    "New",
    "Investigating",
    "Confirmed",
    "Approved for remediation",
    "Fixing",
    "Awaiting verification",
    "Fixed, awaiting disclosure",
    "Closed",
)
ECOSYSTEMS = (
    "rubygems",
    "npm",
    "pip",
    "maven",
    "nuget",
    "composer",
    "go",
    "rust",
    "erlang",
    "actions",
    "pub",
    "other",
    "swift",
)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def ident(value):
    if not isinstance(value, str) or not re.fullmatch(GHSA, value):
        raise Error("invalid advisory identifier")
    return value


def secure_path(value, directory=False):
    p = Path(value).expanduser().absolute()
    if any(x.is_symlink() for x in (p, *p.parents)):
        raise Error("private paths must not contain symlinks")
    for parent in (p if directory else p.parent, *p.parents):
        if (parent / ".git").exists():
            raise Error("confidential files must live outside Git working trees")
    parent = p if directory else p.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (
        parent.stat().st_uid != os.getuid()
        or stat.S_IMODE(parent.stat().st_mode) & 0o077
    ):
        raise Error("private directory must be owner-only (0700)")
    if p.exists() and (
        p.stat().st_uid != os.getuid() or stat.S_IMODE(p.stat().st_mode) & 0o077
    ):
        raise Error("private file must be owner-only (0600)")
    return p


def atomic(path, value):
    path = secure_path(path)
    fd, tmp = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(value, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_file(path):
    try:
        return json.loads(secure_path(path).read_text())
    except (OSError, ValueError):
        raise Error("cannot read restricted JSON input") from None


def metadata(record, required=True):
    body = record.get("description") or ""
    if MARK not in body and not required:
        return None
    if body.count(MARK) != 1:
        raise Error("missing or ambiguous advisory metadata; inspect privately")
    prose, block = body.split(MARK)
    match = re.fullmatch(r"\n```json\n(.*)\n```\s*", block, re.S)
    try:
        data = json.loads(match[1]) if match else None
        if (
            not data
            or data["schema"] != 1
            or data["repository"] != board.REPO
            or data["status"] not in STATES
        ):
            raise ValueError()
    except (ValueError, KeyError, TypeError):
        raise Error("unsupported or malformed advisory metadata") from None
    return data


def description(prose, meta):
    if MARK in prose:
        raise Error("reserved metadata marker in technical prose")
    result = (
        prose.rstrip()
        + "\n\n"
        + MARK
        + "\n```json\n"
        + json.dumps(meta, indent=2)
        + "\n```"
    )
    if len(result.encode()) > 60000:
        raise Error(
            "advisory description limit reached; retain history and seek a private archival decision"
        )
    return result


class APIError(Error):
    def __init__(self, status=None):
        self.status = status
        guidance = {
            401: "GitHub authentication failed; authorize gh independently",
            403: "GitHub denied access or rate limited: check repository role and Repository security advisories permission (read/write); fork creation also needs Administration write",
            404: "GitHub record unavailable: verify repository/advisory identity and unpublished-advisory read permission",
            422: "GitHub rejected advisory metadata; inspect required fields privately; do not invent package metadata",
        }.get(
            status,
            "GitHub response unavailable; mutation outcome may be unknown; recover before retrying",
        )
        super().__init__(guidance)


class API:
    def request(self, path, data=None, method="GET", pages=False):
        # No caller-supplied routes. Mutations only reach these three forms.
        base = f"repos/{board.REPO}/security-advisories"
        permitted = path == base or re.fullmatch(
            re.escape(base) + "/" + GHSA + "(?:/forks)?", path
        )
        if method != "GET" and (not permitted or method not in ("POST", "PATCH")):
            raise Error("unsupported advisory mutation route")
        if data is not None and any(
            k in data for k in ("cve_id", "collaborating_users", "collaborating_teams")
        ):
            raise Error("publication, CVE and collaborator operations are unavailable")
        if data and "state" in data and data["state"] != "closed":
            raise Error("publication and reopening are unavailable")
        args = [
            "gh",
            "api",
            "--hostname",
            "github.com",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            "X-GitHub-Api-Version: 2026-03-10",
            "--method",
            method,
            path,
        ]
        if pages:
            args += ["--paginate", "--slurp"]
        if data is not None:
            args += ["--input", "-"]
        p = subprocess.run(
            args,
            input=json.dumps(data) if data is not None else None,
            capture_output=True,
            text=True,
            env=guard.environment(),
        )
        if p.returncode:
            match = re.search(r"HTTP (\d{3})", p.stderr)
            raise APIError(int(match[1]) if match else None)
        try:
            value = json.loads(p.stdout)
            return [item for page in value for item in page] if pages else value
        except (ValueError, TypeError):
            raise APIError() from None


class Advisory:
    def __init__(self, repo=board.REPO, api=None, directory=None):
        if repo != board.REPO:
            raise Error("wrong repository; run the helper from the affected repository")
        self.api = api or API()
        self.base = f"repos/{repo}/security-advisories"
        self.directory = secure_path(
            directory or Path.home() / ".local/state/repository-advisories" / repo, True
        )
        self.journal = self.directory / "pending.json"
        self.anchor = self.directory / "trust.json"

    @contextlib.contextmanager
    def locked(self):
        p = secure_path(self.directory / "operation.lock")
        fd = os.open(p, os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "a") as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error(
                    "another advisory operation holds this local state lock"
                ) from None
            yield

    def owner(self):
        user = self.api.request("user")
        repo = self.api.request("repos/" + board.REPO)
        if user.get("login") != board.OWNER or not repo.get("permissions", {}).get(
            "admin"
        ):
            raise Error(
                "full inventory/mutations require the authenticated repository owner with administration rights; collaborator named-read is separate"
            )

    def list(self):
        self.owner()
        return self.api.request(self.base + "?per_page=100", pages=True)

    def read(self, ghsa, editable=False):
        record = self.api.request(self.base + "/" + ident(ghsa))
        if (
            record.get("ghsa_id") != ghsa
            or record.get("repository", {}).get("full_name", board.REPO) != board.REPO
        ):
            raise Error("GitHub returned another advisory/repository")
        if editable and record.get("state") != "draft":
            raise Error(
                "only native draft advisories may be changed; closed/published records are read-only"
            )
        return record

    def pending(self):
        return read_file(self.journal) if self.journal.exists() else None

    def clear_pending(self, record):
        intent = self.pending()
        if intent and intent.get("trusted"):
            anchors = read_file(self.anchor) if self.anchor.exists() else {}
            atomic(self.directory / (record["ghsa_id"] + ".trusted.json"), record)
            anchors[record["ghsa_id"]] = policy.digest(record)
            atomic(self.anchor, anchors)
        if intent:
            atomic(
                self.directory / (intent["id"] + ".journal.json"),
                {**intent, "acknowledged": True},
            )
            self.journal.unlink()
        return record

    def trusted(self, record):
        anchors = read_file(self.anchor) if self.anchor.exists() else {}
        if anchors.get(record["ghsa_id"]) != policy.digest(record):
            raise Error(
                "owner provenance unavailable or advisory edited out of band; owner must inspect and reconfirm this exact snapshot before remediation/review"
            )

    def recover(self):
        self.owner()
        intent = self.pending()
        if not intent:
            raise Error("no pending advisory operation")
        if intent["kind"] == "create":
            matches = [
                r
                for r in self.list()
                if (metadata(r, False) or {}).get("key") == intent["key"]
            ]
            if len(matches) != 1:
                raise Error(
                    "unknown create outcome; retain journal and reconcile privately; no repeated POST"
                )
            record = self.read(matches[0]["ghsa_id"])
        else:
            record = self.read(intent["ghsa"])
        m = metadata(record)
        if "before" in intent:
            ignored = {"description", "state", "updated_at"}
            if intent["kind"] == "fork":
                ignored.add("private_fork")
            if intent.get("expected_state") == "closed":
                ignored.add("closed_at")
            if {k: v for k, v in record.items() if k not in ignored} != {
                k: v for k, v in intent["before"].items() if k not in ignored
            }:
                raise Error(
                    "other advisory fields changed during publication; reconcile privately before trusting this revision"
                )
        if intent["kind"] == "fork":
            if (
                record.get("state") != "draft"
                or record.get("description") != intent["before"]["description"]
            ):
                raise Error(
                    "advisory control state changed during fork provisioning; restore/reconcile the recorded snapshot privately before recovery"
                )
            if not record.get("private_fork"):
                raise Error(
                    "private fork request pending/unknown; retry retrieval, not POST"
                )
            full = record["private_fork"].get("full_name", "")
            if not re.fullmatch(r"[\w.-]+/[\w.-]+", full):
                raise Error("invalid provisioned fork identity")
            fork = self.api.request("repos/" + full)
            if fork.get("full_name") != full or fork.get("private") is not True:
                raise Error("provisioned fork privacy is unverified")
        elif (
            record.get("description") != intent["payload"]["description"]
            or record["state"] != intent["expected_state"]
        ):
            raise Error(
                "pending write is not the exact verified revision; reconcile privately before another mutation"
            )
        if m.get("repository") != board.REPO:
            raise Error("invalid pending advisory identity")
        return self.clear_pending(record)

    def send(self, intent):
        if self.pending():
            raise Error("pending advisory operation; recover before another write")
        atomic(self.journal, intent)
        try:
            self.api.request(intent["path"], intent.get("payload"), intent["method"])
        except APIError as e:
            # Explicit rejecting status is distinct from a lost acknowledgement.
            if e.status in (400, 401, 403, 404, 422):
                atomic(
                    self.directory / (intent["id"] + ".journal.json"),
                    {**intent, "rejected": e.status},
                )
                self.journal.unlink()
            raise
        return self.recover()

    def create(self, data):
        self.owner()
        allowed = {
            "key",
            "legacy_ids",
            "summary",
            "description",
            "vulnerabilities",
            "severity",
            "confidence",
            "discovery",
            "status",
            "reviewed_related",
        }
        if not isinstance(data, dict) or set(data) - allowed:
            raise Error(
                "unsupported creation fields; publication/CVE/authorization fields are forbidden"
            )
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{8,100}", data.get("key", "")):
            raise Error("stable create key (8-100 safe characters) required")
        if not all(
            isinstance(data.get(k), str) and data[k].strip()
            for k in ("summary", "description")
        ):
            raise Error("summary and original technical description required")
        vulnerabilities(data.get("vulnerabilities"))
        if data.get("severity") not in (
            None,
            "low",
            "medium",
            "high",
            "critical",
        ) or data.get("status", "New") not in ("New", "Investigating", "Confirmed"):
            raise Error(
                "invalid severity or initial status; migration cannot grant remediation approval"
            )
        ids = data.get("legacy_ids", [])
        if not isinstance(ids, list) or any(
            not isinstance(x, str) or not x for x in ids
        ):
            raise Error("invalid original identifiers")
        records = self.list()
        exact = [
            r for r in records if (metadata(r, False) or {}).get("key") == data["key"]
        ]
        if exact:
            if len(exact) != 1:
                raise Error("ambiguous duplicate creation key; inspect privately")
            record = self.read(exact[0]["ghsa_id"])
            pending = self.pending()
            if pending and (
                pending["kind"] != "create" or pending.get("key") != data["key"]
            ):
                raise Error(
                    "unrelated pending operation; recover it explicitly before retrying this creation"
                )
            if metadata(record).get("source_digest") != policy.digest(
                {k: v for k, v in data.items() if k != "reviewed_related"}
            ):
                raise Error(
                    "creation key reused with changed content; update the existing advisory"
                )
            if pending:
                recovered = self.recover()
                if recovered["ghsa_id"] != record["ghsa_id"]:
                    raise Error(
                        "recovered another advisory; reconcile before continuing migration"
                    )
                return recovered
            return record
        if self.pending():
            raise Error(
                "pending create/write outcome; recover, never blindly repeat POST"
            )
        related = []
        for r in records:
            m = metadata(r, False) or {}
            if set(ids) & set(m.get("legacy_ids", [])):
                raise Error(
                    "original identifier already exists; read/update its advisory"
                )
            if (
                difflib.SequenceMatcher(
                    None, data["summary"].lower(), r.get("summary", "").lower()
                ).ratio()
                >= 0.65
            ):
                related.append(r["ghsa_id"])
        if set(related) - set(data.get("reviewed_related", [])):
            atomic(
                self.directory / "related.json",
                [r for r in records if r["ghsa_id"] in related],
            )
            raise Error(
                "related records require private inspection; see restricted related.json and acknowledge identifiers"
            )
        op = str(uuid.uuid4())
        meta = {
            "schema": 1,
            "repository": board.REPO,
            "revision": op,
            "key": data["key"],
            "legacy_ids": ids,
            "source_digest": policy.digest(
                {k: v for k, v in data.items() if k != "reviewed_related"}
            ),
            "status": data.get("status", "New"),
            "confidence": data.get("confidence"),
            "discovery": data.get("discovery", {}),
            "history": [{"id": op, "at": now(), "kind": "created"}],
            "owner": None,
            "grants": [],
            "ledger": {
                "version": 2,
                "policy_version": 2,
                "reviews": [],
                "findings": {},
                "authorizations": [],
            },
        }
        payload = {
            k: data[k] for k in ("summary", "vulnerabilities", "severity") if k in data
        }
        payload["description"] = description(data["description"], meta)
        return self.send(
            {
                "id": op,
                "kind": "create",
                "key": data["key"],
                "path": self.base,
                "method": "POST",
                "payload": payload,
                "expected_state": "draft",
                "trusted": False,
            }
        )

    def change(self, record, meta, kind, note, close=False, trust=False):
        self.owner()
        current = self.read(record["ghsa_id"], editable=True)
        if policy.digest(current) != policy.digest(record):
            raise Error("advisory changed since read; retrieve and reconcile")
        if self.pending():
            raise Error("pending operation must be recovered first")
        op = str(uuid.uuid4())
        meta = copy.deepcopy(meta)
        meta["revision"] = op
        meta["history"].append({"id": op, "at": now(), "kind": kind, "note": note})
        prose = record["description"].split(MARK)[0]
        payload = {"description": description(prose, meta)}
        if close:
            payload["state"] = "closed"
        return self.send(
            {
                "id": op,
                "kind": kind,
                "before": record,
                "ghsa": record["ghsa_id"],
                "path": self.base + "/" + record["ghsa_id"],
                "method": "PATCH",
                "payload": payload,
                "expected_state": "closed" if close else "draft",
                "trusted": trust,
            }
        )

    def update(self, ghsa, data):
        if (
            set(data) - {"expected", "note", "status"}
            or not data.get("note", "").strip()
        ):
            raise Error(
                "update requires expected snapshot digest and private progress note; protected state cannot be replaced"
            )
        record = self.read(ghsa, True)
        if data.get("expected") != policy.digest(record):
            raise Error("stale update snapshot")
        meta = metadata(record)
        if meta.get("owner"):
            raise Error("active remediation: use its owned checkpoint operation")
        if "status" in data:
            if data["status"] not in ("New", "Investigating", "Confirmed"):
                raise Error(
                    "protected remediation status needs its dedicated operation"
                )
            meta["status"] = data["status"]
        return self.change(record, meta, "progress", data["note"])

    def decision(self, record, data):
        self.owner()
        if (
            data.get("expected") != policy.digest(record)
            or data.get("owner") != board.OWNER
            or not data.get("source", "").strip()
        ):
            raise Error(
                "current owner decision must name the exact snapshot digest and instruction source"
            )

    def authorize(self, ghsa, data):
        record = self.read(ghsa, True)
        self.decision(record, data)
        m = metadata(record)
        if (
            set(data)
            - {"expected", "owner", "source", "scope", "allowances", "reconfirm"}
            or not data.get("scope", "").strip()
            or data.get("reconfirm") is not True
        ):
            raise Error(
                "explicit owner reconfirmation of current scope and complete ledger required"
            )
        if any(r["status"] == "pending" for r in m["ledger"]["reviews"]):
            raise Error(
                "pending review: recover on its original trusted machine before handoff"
            )
        if m.get("owner"):
            self.trusted(record)
            if m["owner"].get("clone") != self.clone_id():
                raise Error(
                    "active owner must release before another clone can reconfirm"
                )
        grant = {
            "id": len(m["grants"]) + 1,
            "owner": board.OWNER,
            "source": data["source"],
            "scope": data["scope"],
            "snapshot": policy.digest(record),
            "at": now(),
            "allowances": data.get("allowances", {}),
        }
        for phase, ceiling in grant["allowances"].items():
            if (
                phase not in ("docs", "plan", "code")
                or type(ceiling) is not int
                or ceiling < policy.count(m["ledger"], phase)
            ):
                raise Error("allowance cannot erase reviews or use an unknown phase")
            for n in range(policy.count(m["ledger"], phase) + 1, ceiling + 1):
                a = {"phase": phase, "round": n, "comment": grant["id"]}
                if not policy.authorization(m["ledger"], phase, n):
                    m["ledger"]["authorizations"].append(a)
            m["ledger"].setdefault("ceilings", {})[phase] = {
                "phase": phase,
                "round": ceiling,
                "comment": grant["id"],
            }
        m["grants"].append(grant)
        m["scope"] = data["scope"]
        m["status"] = "Approved for remediation"
        return self.change(record, m, "owner-authorization", data["source"], trust=True)

    def reconcile(self, ghsa, data):
        """Explicit owner recovery of observed edits, never a silent takeover."""
        record = self.read(ghsa, True)
        self.decision(record, data)
        if (
            set(data) - {"expected", "owner", "source", "reason", "stopped_attempts"}
            or not data.get("reason", "").strip()
        ):
            raise Error(
                "reconciliation needs an explicit owner reason for this inspected snapshot"
            )
        if self.pending():
            raise Error(
                "recover the pending write first; preserve its journal and restore its recorded snapshot privately if necessary"
            )
        path = self.directory / (ghsa + ".trusted.json")
        if not path.exists():
            raise Error(
                "last trusted snapshot unavailable; obtain a private released handoff, not a takeover"
            )
        known = read_file(path)
        anchors = read_file(self.anchor)
        if anchors.get(ghsa) != policy.digest(known):
            raise Error("trusted snapshot does not match local anchor")
        m = metadata(known)
        if m.get("owner") and m["owner"].get("clone") != self.clone_id():
            raise Error("another clone owns the trusted state; it must release first")
        pending = [r["id"] for r in m["ledger"]["reviews"] if r["status"] == "pending"]
        if sorted(data.get("stopped_attempts", [])) != sorted(pending):
            raise Error(
                "owner must confirm each pending invocation stopped before reconciliation"
            )
        # Retain the observed untrusted control state as evidence, not as grants.
        note = {
            "source": data["source"],
            "reason": data["reason"],
            "trusted_snapshot": policy.digest(known),
            "observed_snapshot": policy.digest(record),
            "observed_metadata": metadata(record),
            "stopped_attempts": pending,
        }
        atomic(self.directory / (str(uuid.uuid4()) + ".observed.json"), record)
        return self.change(record, m, "owner-reconciliation", note, trust=True)

    def close(self, ghsa, data):
        record = self.read(ghsa, True)
        self.decision(record, data)
        m = metadata(record)
        if (
            set(data) - {"expected", "owner", "source", "reason"}
            or not data.get("reason", "").strip()
            or m.get("owner")
            or any(r["status"] == "pending" for r in m["ledger"]["reviews"])
        ):
            raise Error("close needs a private reason and no active/pending work")
        m["status"] = "Closed"
        return self.change(
            record,
            m,
            "owner-close",
            {"source": data["source"], "reason": data["reason"]},
            close=True,
        )

    def owned(self, ghsa, session, workspace=True):
        self.owner()
        record = self.read(ghsa, True)
        self.trusted(record)
        m = metadata(record)
        claim = m.get("owner") or {}
        if claim.get("session") != session or claim.get("clone") != self.clone_id():
            raise Error(
                "another session/clone owns this work; obtain an explicit released handoff"
            )
        if not m.get("scope") or not m.get("grants"):
            raise Error("owner remediation scope required")
        if workspace:
            data = guard.verify()
            if (
                data.get("ghsa") != ghsa
                or data.get("repository") != board.REPO
                or data.get("fork")
                != (record.get("private_fork") or {}).get("full_name")
            ):
                raise Error("workspace does not match this advisory private fork")
        return record, m

    def clone_id(self):
        path = self.directory / "clone.json"
        if not path.exists():
            atomic(path, {"id": str(uuid.uuid4())})
        return read_file(path)["id"]

    def work(self, ghsa, session, workspace):
        self.owner()
        if self.pending():
            self.recover()
        record = self.read(ghsa, True)
        self.trusted(record)
        m = metadata(record)
        if (
            not session
            or not m.get("scope")
            or not m.get("grants")
            or m["status"]
            not in ("Approved for remediation", "Fixing", "Awaiting verification")
        ):
            raise Error(
                "current explicit owner scope and actionable remediation status required"
            )
        claim = {"session": session, "clone": self.clone_id()}
        if m.get("owner") and m["owner"] != claim:
            raise Error(
                "active session/clone conflict; release and privately hand off first"
            )
        if not m.get("owner"):
            m["owner"] = claim
            m["status"] = "Fixing"
            record = self.change(
                record,
                m,
                "claim",
                "Explicit local session claim; remote coordination is not atomic.",
                trust=True,
            )
        fork = record.get("private_fork")
        if not fork:
            op = str(uuid.uuid4())
            record = self.send(
                {
                    "id": op,
                    "kind": "fork",
                    "before": record,
                    "ghsa": ghsa,
                    "path": self.base + "/" + ghsa + "/forks",
                    "method": "POST",
                    "payload": {},
                    "trusted": True,
                }
            )
            fork = record.get("private_fork")
        full = (fork or {}).get("full_name", "")
        if not re.fullmatch(r"[\w.-]+/[\w.-]+", full):
            raise Error("private fork is not provisioned")
        remote = self.api.request("repos/" + full)
        if remote.get("private") is not True or remote.get("full_name") != full:
            raise Error("fork privacy could not be verified")
        path = Path(workspace).expanduser().absolute()
        secure_path(path.parent, True)
        if path.is_symlink():
            raise Error("workspace symlinks refused")
        if not path.exists():
            guard.command(
                ["git", "clone", "--", "https://github.com/" + full + ".git", str(path)]
            )
            os.chmod(path, 0o700)
        marker = guard.marker(path)
        if not marker:
            raise Error("isolated private clone required")
        common = marker.parent
        if (path / ".git").resolve() != common:
            raise Error(
                "security work requires a separate clone, not a shared worktree"
            )
        expected = {"repository": board.REPO, "ghsa": ghsa, "fork": full}
        if marker.exists() and json.loads(marker.read_text()) != expected:
            raise Error("workspace belongs to another advisory")
        # Verify the remote before installing any markers/hooks in an existing clone.
        if guard.command(["git", "remote"], path).splitlines() != ["origin"]:
            raise Error("isolated clone must have only private origin")
        for direction in ([], ["--push"]):
            urls = guard.command(
                ["git", "remote", "get-url", "--all", *direction, "origin"], path
            ).splitlines()
            if not urls or any(guard.remote_name(u) != full for u in urls):
                raise Error("private origin mismatch")
        hooks = common / "hooks"
        hooks.mkdir(exist_ok=True)
        custom = subprocess.run(
            ["git", "config", "--get", "core.hooksPath"],
            cwd=path,
            env=guard.environment(),
            capture_output=True,
            text=True,
        )
        if custom.returncode == 0:
            raise Error("custom hooksPath requires private guard reconciliation")
        hook = hooks / "pre-push"
        code = '#!/usr/bin/env python3\nimport runpy,sys\nfrom pathlib import Path\nrunpy.run_path(str(Path(__file__).resolve().parent.parent / "security-guard.py"),run_name="__main__")\n'
        if hook.exists() and hook.read_text() != code:
            raise Error("existing pre-push hook must be reconciled; never overwritten")
        marker.write_text(json.dumps(expected))
        os.chmod(marker, 0o600)
        shutil.copyfile(Path(guard.__file__), common / "security-guard.py")
        os.chmod(common / "security-guard.py", 0o600)
        hook.write_text(code)
        os.chmod(hook, 0o700)
        guard.verify(path)
        record = self.read(ghsa, True)
        self.trusted(record)
        m = metadata(record)
        associated = {
            "fork": full,
            "path": str(path),
            "branch": guard.command(["git", "branch", "--show-current"], path),
        }
        if m.get("workspace") != associated:
            m["workspace"] = associated
            record = self.change(
                record,
                m,
                "workspace",
                "Verified isolated private fork workspace.",
                trust=True,
            )
        return record

    def inputs(self):
        if guard.command(["git", "status", "--porcelain"]):
            raise Error(
                "commit changes before review/verification; branch review excludes working-tree edits"
            )
        # Read the actual current public target without installing a public push remote.
        guard.command(
            [
                "git",
                "fetch",
                "--no-tags",
                "https://github.com/" + board.REPO + ".git",
                "main",
            ]
        )
        head = guard.command(["git", "rev-parse", "HEAD"])
        base = guard.command(["git", "rev-parse", "FETCH_HEAD"])
        return head, base, guard.command(["git", "merge-base", head, base])

    def checkpoint(self, ghsa, session, data):
        if (
            set(data) - {"completed", "verification", "blockers", "next"}
            or any(
                not isinstance(data.get(k), str)
                for k in ("completed", "verification", "blockers", "next")
            )
            or not data["next"].strip()
        ):
            raise Error(
                "checkpoint needs completed work, actual verification, blockers and next action"
            )
        record, m = self.owned(ghsa, session)
        head, base, merge = self.inputs()
        m["checkpoint"] = {
            **data,
            "head": head,
            "base": base,
            "merge_base": merge,
            "at": now(),
            "branch": guard.command(["git", "branch", "--show-current"]),
            "session": session,
        }
        return self.change(record, m, "checkpoint", data, trust=True)

    def release(self, ghsa, session):
        record, m = self.owned(ghsa, session, False)
        if self.pending() or any(
            r["status"] == "pending" for r in m["ledger"]["reviews"]
        ):
            raise Error("recover pending operation/review before handoff")
        m["owner"] = None
        return self.change(
            record,
            m,
            "release",
            "Transfer any unresolved private journals before resuming elsewhere.",
            trust=True,
        )

    def check_auth(self, m, phase, round_, grant_id, kind, binding=None):
        grant = next((g for g in m["grants"] if g["id"] == grant_id), None)
        if not grant or grant["owner"] != board.OWNER or not grant.get("source"):
            raise Error("private owner grant missing")
        if kind == "retry":
            if grant.get("retry") != {
                "phase": phase,
                "round": round_,
                "binding": binding,
            }:
                raise Error("retry authorization does not bind failed attempts")
        elif grant.get("allowances", {}).get(phase, 0) < round_:
            raise Error("private spending exceeds the explicit owner grant")

    def retry(self, ghsa, data):
        record = self.read(ghsa, True)
        self.trusted(record)
        self.decision(record, data)
        m = metadata(record)
        if set(data) - {"expected", "owner", "source", "phase", "binding"} or data.get(
            "phase"
        ) not in ("docs", "plan", "code"):
            raise Error("retry requires phase and exact failed-attempt digest")
        phase = data["phase"]
        failed, _ = policy.failed_attempts(m["ledger"], phase)
        if data.get("binding") != policy.digest(failed):
            raise Error("retry decision is stale")
        grant = {
            "id": len(m["grants"]) + 1,
            "owner": board.OWNER,
            "source": data["source"],
            "at": now(),
            "retry": {
                "phase": phase,
                "round": policy.count(m["ledger"], phase) + 1,
                "binding": data["binding"],
            },
        }
        m["grants"].append(grant)
        auth = {**grant["retry"], "comment": grant["id"], "failed_ids": failed}
        m["ledger"].setdefault("retry_authorizations", {})[phase] = auth
        return self.change(record, m, "retry-authorization", data["source"], trust=True)

    def review(self, ghsa, session, data):
        import work_issue

        record, m = self.owned(ghsa, session)
        s = m["ledger"]
        if set(data) - {
            "phase",
            "scope",
            "focus",
            "prior",
            "verifies",
            "rationale",
            "material_change",
        }:
            raise Error("unsupported private review fields")
        phase = data.get("phase", "code")
        scope = data.get("scope", "initial")
        if (
            phase not in ("docs", "plan", "code")
            or scope not in policy.SCOPES
            or not data.get("focus", "").strip()
        ):
            raise Error("review needs a supported phase/scope and private focus")
        callback = lambda ph, rd, g, kind, binding=None: self.check_auth(
            m, ph, rd, g, kind, binding
        )
        round_ = policy.budget(s, phase)
        policy.check_ledger(s, callback)
        auth = policy.authorization(s, phase, round_)
        if auth:
            callback(phase, round_, auth["comment"], "authorize")
        head, base, merge = self.inputs()
        if phase == "docs" and any(
            Path(p).suffix not in (".md", ".txt")
            for p in guard.command(
                ["git", "diff", "--no-renames", "--name-only", base + "..." + head]
            ).splitlines()
        ):
            raise Error("executable changes require code review")
        r = {
            "id": str(uuid.uuid4()),
            "phase": phase,
            "scope": scope,
            "commit": head,
            "base": "main",
            "base_sha": base,
            "merge_base": merge,
            "policy_version": 2,
            "receipt_version": 2,
            "status": "pending",
            "outcome": "pending",
            "prior": data.get("prior", []),
            "verifies": data.get("verifies", []),
            "rationale": data.get("rationale", ""),
            "material_change": data.get("material_change", False),
        }
        if r["material_change"] and scope != "initial":
            raise Error("material changes need initial review")
        if scope != "initial" and (not r["prior"] or not r["rationale"].strip()):
            raise Error(
                "focused review requires prior receipts and continuity rationale"
            )
        prior = []
        for previous in r["prior"]:
            old = policy.receipt(s, previous)
            if old["phase"] != phase or (
                scope == "follow-up" and old["base_sha"] != base
            ):
                raise Error(
                    "prior phase/base incompatible; use integration or initial review"
                )
            if (
                not old.get("result")
                or policy.digest(old["result"]) != old["result_digest"]
            ):
                raise Error("prior original structured result missing or changed")
            prior.append(old)
        if any(fid not in s["findings"] for fid in r["verifies"]):
            raise Error("unknown prior finding")
        if policy.failed_attempts(s, phase)[1] >= 2:
            r["retry"] = copy.deepcopy(s["retry_authorizations"][phase])
            callback(
                phase, round_, r["retry"]["comment"], "retry", r["retry"]["binding"]
            )
        context = self.directory / (r["id"] + ".context.json")
        atomic(
            context,
            {
                "focus": data["focus"],
                "current_receipt": r,
                "prior": prior,
                "findings": s["findings"],
                "approved_scope": m["scope"],
            },
        )
        s["reviews"].append(r)
        self.change(
            record,
            m,
            "review-start",
            "Pending independent review; no approval until structured output is recovered.",
            trust=True,
        )
        report = self.directory / (r["id"] + ".json")
        instruction = work_issue.review_focus(
            {
                **r,
                "rationale": "Read the private continuity rationale in the restricted context.",
            },
            "Read the private focus and scope from the restricted context file. Do not publish or modify files.",
            context,
        )
        with secure_path(report).open("w") as f:
            os.chmod(report, 0o600)
            p = subprocess.run(
                [
                    sys.executable,
                    str(Path(__file__).with_name("codex_review.py")),
                    "--private",
                    "--json",
                    "--head",
                    head,
                    "--base",
                    base,
                    "--scope",
                    "branch",
                    instruction,
                ],
                stdout=f,
                stderr=subprocess.DEVNULL,
                env=guard.environment(),
                umask=0o077,
            )
            f.flush()
            os.fsync(f.fileno())
        return self.recover_review(ghsa, session, failed=p.returncode != 0)

    def recover_review(self, ghsa, session, failed=False):
        record, m = self.owned(ghsa, session, False)
        s = m["ledger"]
        pending = [r for r in s["reviews"] if r["status"] == "pending"]
        if len(pending) != 1:
            raise Error("expected one pending review; already recovered or ambiguous")
        r = pending[0]
        try:
            payload = read_file(self.directory / (r["id"] + ".json"))
        except Error:
            payload = {}
        result = payload.get("result") or {}
        expected = {
            "head": r["commit"],
            "base": r["base_sha"],
            "merge_base": r["merge_base"],
        }
        if (
            payload.get("codex", {}).get("status") == 0
            and result.get("verdict") in ("approve", "needs-attention")
            and isinstance(result.get("findings"), list)
            and all(isinstance(f, dict) for f in result["findings"])
            and not payload.get("parseError")
            and payload.get("inputs") == expected
        ):
            r.update(
                status="completed",
                outcome=result["verdict"],
                round=policy.count(s, r["phase"]) + 1,
                inputs=expected,
                finding_count=len(result["findings"]),
                result=result,
            )
            policy.register_result(s, r, result)
        elif failed:
            r.update(status="failed", outcome="unavailable")
        else:
            raise Error(
                "missing complete review output; confirm invocation stopped before recovery as failed"
            )
        return self.change(
            record,
            m,
            "review-recovered",
            "Recovered exactly one attempt; historical results preserved.",
            trust=True,
        )

    def tracking(self, state):
        for finding in state["findings"].values():
            for event in finding["history"]:
                if event.get("category") == "independent":
                    ref = event.get("tracking", "")
                    if not ref.startswith(board.REPO + "#"):
                        raise Error(
                            "independent confidential finding must name this repository advisory"
                        )
                    record = self.read(ref.split("#")[1])
                    if record.get("state") not in ("draft", "closed"):
                        raise Error(
                            "private tracking must resolve to a draft/closed advisory"
                        )

    def finding_exception(self, ghsa, data):
        record = self.read(ghsa, True)
        self.trusted(record)
        self.decision(record, data)
        m = metadata(record)
        if (
            set(data)
            - {"expected", "owner", "source", "finding", "head", "base", "reason"}
            or not data.get("reason", "").strip()
        ):
            raise Error("finding exception requires scoped owner reason")
        if data.get("finding") not in m["ledger"]["findings"] or any(
            not re.fullmatch(r"[0-9a-f]{40,64}", data.get(k, ""))
            for k in ("head", "base")
        ):
            raise Error(
                "finding exception must name actual finding and immutable revisions"
            )
        m["grants"].append(
            {
                "id": len(m["grants"]) + 1,
                "owner": board.OWNER,
                "source": data["source"],
                "at": now(),
                "exception": {
                    k: data[k] for k in ("finding", "head", "base", "reason")
                },
            }
        )
        return self.change(record, m, "finding-exception", data["source"], trust=True)

    def check_exception(self, m, fid, grant_id, head, base):
        grant = next((g for g in m["grants"] if g["id"] == grant_id), {})
        e = grant.get("exception", {})
        if (
            grant.get("owner") != board.OWNER
            or not grant.get("source")
            or not e.get("reason")
            or (e.get("finding"), e.get("head"), e.get("base")) != (fid, head, base)
        ):
            raise Error("specific owner finding exception missing/stale")

    def dispose(self, ghsa, session, data):
        record, m = self.owned(ghsa, session)
        head, base, _ = self.inputs()
        data = dict(data)
        fid = data.pop("finding", None)
        if data.get("status") == "excepted":
            self.check_exception(m, fid, data.get("comment"), head, base)
        policy.disposition(m["ledger"], fid, data, head, base, confidential=True)
        self.tracking(m["ledger"])
        return self.change(
            record,
            m,
            "finding-disposition",
            "Evidence and consequences recorded privately.",
            trust=True,
        )

    def verified(self, ghsa, session, data):
        record, m = self.owned(ghsa, session)
        s = m["ledger"]
        head, base, merge = self.inputs()
        if (
            set(data) - {"receipt", "rationale", "material_change"}
            or not data.get("rationale", "").strip()
        ):
            raise Error("integration requires actual receipt and continuity rationale")
        if merge != base:
            raise Error(
                "current main must be integrated and affected behavior verified"
            )
        checkpoint = m.get("checkpoint", {})
        if (
            checkpoint.get("head") != head
            or checkpoint.get("base") != base
            or not checkpoint.get("verification", "").strip()
        ):
            raise Error("actual verification is missing/stale")
        policy.check_ledger(
            s,
            lambda ph, rd, g, kind, binding=None: self.check_auth(
                m, ph, rd, g, kind, binding
            ),
        )
        self.tracking(s)
        if not policy.approved(s, head, base, confidential=True):
            raise Error("private review/findings unresolved or stale")
        if not policy.findings_ready(
            s,
            head,
            base,
            lambda fid, g, h, b: self.check_exception(m, fid, g, h, b),
            confidential=True,
        ):
            raise Error("finding dispositions are unresolved")
        s["integration"] = {"head": head, "base": base, "merge_base": merge, **data}
        policy.integration_current(s, head, base, confidential=True)
        m["status"] = "Fixed, awaiting disclosure"
        return self.change(
            record,
            m,
            "verified",
            "Current tests and independent review recorded; disclosure is NOT authorized.",
            trust=True,
        )


def vulnerabilities(items):
    if not isinstance(items, list) or not items:
        raise Error("at least one accurately identified affected package required")
    for item in items:
        if not isinstance(item, dict) or set(item) - {
            "package",
            "vulnerable_version_range",
            "patched_versions",
            "vulnerable_functions",
        }:
            raise Error("unsupported vulnerability fields")
        p = item.get("package", {})
        if (
            set(p) - {"ecosystem", "name"}
            or p.get("ecosystem") not in ECOSYSTEMS
            or not isinstance(p.get("name"), (str, type(None)))
        ):
            raise Error(
                "real supported package ecosystem required; unknown names/versions may be null"
            )
        for k in ("vulnerable_version_range", "patched_versions"):
            if not isinstance(item.get(k), (str, type(None))):
                raise Error("invalid affected version metadata")


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's usual error can echo private arguments.
        raise Error(
            "invalid arguments; use --help (never pass finding details as arguments)"
        )


def main(argv=None):
    p = Parser(description=__doc__)
    p.add_argument("--repo", default=board.REPO)
    p.add_argument("--state-dir")
    p.add_argument(
        "--out",
        required=True,
        help="restricted output JSON outside Git; records never print to stdout",
    )
    p.add_argument(
        "operation",
        choices=(
            "access",
            "list",
            "read",
            "search",
            "create",
            "update",
            "close",
            "recover",
            "authorize",
            "work",
            "checkpoint",
            "release",
            "review",
            "recover-review",
            "retry",
            "dispose",
            "verified",
            "exception",
            "reconcile",
        ),
    )
    p.add_argument("ghsa", nargs="?")
    p.add_argument(
        "--input", help="restricted JSON request; never inline technical text"
    )
    p.add_argument("--session")
    p.add_argument("--workspace")
    p.add_argument("--failed", action="store_true")
    try:
        args = p.parse_args(argv)
        out = secure_path(args.out)
        client = Advisory(args.repo, directory=args.state_dir)
        data = read_file(args.input) if args.input else {}
        with client.locked():
            op = args.operation
            if op == "access":
                client.list()
                result = {
                    "identity": board.OWNER,
                    "private_inventory": "readable",
                    "write": "not proven until authorized mutation",
                }
            elif op == "list":
                result = client.list()
            elif op == "search":
                if (
                    set(data) != {"query"}
                    or not isinstance(data["query"], str)
                    or not data["query"].strip()
                ):
                    raise Error("search requires restricted JSON query")
                result = [
                    r
                    for r in client.list()
                    if data["query"].casefold() in json.dumps(r).casefold()
                ]
            elif op == "create":
                result = client.create(data)
            elif op == "recover":
                result = client.recover()
            else:
                ident(args.ghsa)
                if op == "read":
                    result = client.read(args.ghsa)
                elif op == "exception":
                    result = client.finding_exception(args.ghsa, data)
                elif op in ("update", "close", "authorize", "retry", "reconcile"):
                    result = getattr(client, op)(args.ghsa, data)
                else:
                    if not args.session:
                        raise Error("session identifier required")
                    if op == "work":
                        if not args.workspace:
                            raise Error("isolated private workspace path required")
                        result = client.work(args.ghsa, args.session, args.workspace)
                    elif op == "release":
                        result = client.release(args.ghsa, args.session)
                    elif op == "recover-review":
                        result = client.recover_review(
                            args.ghsa, args.session, args.failed
                        )
                    else:
                        result = getattr(client, op)(args.ghsa, args.session, data)
            atomic(out, {"snapshot": policy.digest(result), "record": result})
        print("Private operation completed; result written to restricted output.")
        return 0
    except (Error, ValueError, OSError, KeyError, TypeError) as e:
        # Our Error messages are controlled, but unexpected API/schema exceptions are not.
        message = (
            str(e)
            if isinstance(e, Error)
            else "private operation failed; inspect authenticated access/input privately"
        )
        print("security_advisory: " + message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
