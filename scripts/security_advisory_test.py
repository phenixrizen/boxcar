"""Synthetic private workflow tests. Never call real GitHub or create real advisories."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import board
import codex_review
import review_policy as policy
import security_advisory as a
import security_guard as guard
import work_issue

GHSA = "GHSA-2345-6789-cfgh"
OTHER = "GHSA-cfgh-jmpq-rvwx"
HEAD = "a" * 40
BASE = "b" * 40


def seed(key="synthetic-key-1", summary="Synthetic test condition"):
    return {
        "key": key,
        "summary": summary,
        "description": "Synthetic claim only; not a real vulnerability.",
        "legacy_ids": ["TEST-1"],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "go", "name": None},
                "vulnerable_version_range": None,
            }
        ],
        "confidence": "unconfirmed",
        "discovery": {"source": "synthetic test", "date": None},
    }


class FakeAPI:
    def __init__(self):
        self.records = {}
        self.calls = []
        self.user = board.OWNER
        self.admin = True
        self.lose = False
        self.reject = None
        self.fork_ready = True

    def request(self, path, data=None, method="GET", pages=False):
        self.calls.append((path, copy.deepcopy(data), method, pages))
        if path == "user":
            return {"login": self.user}
        if path == "repos/" + board.REPO:
            return {"permissions": {"admin": self.admin}, "full_name": board.REPO}
        if path == "repos/owner/private-fork":
            return {"private": True, "full_name": "owner/private-fork"}
        if "?per_page=" in path:
            return copy.deepcopy(list(self.records.values()))
        if method == "POST" and not path.endswith("/forks"):
            if self.reject:
                raise a.APIError(self.reject)
            name = GHSA if not self.records else OTHER
            record = {
                "ghsa_id": name,
                "state": "draft",
                "repository": {"full_name": board.REPO},
                **copy.deepcopy(data),
            }
            self.records[name] = record
        elif path.endswith("/forks"):
            name = path.split("/")[-2]
            record = self.records[name]
            if self.fork_ready:
                record["private_fork"] = {
                    "full_name": "owner/private-fork",
                    "private": True,
                }
        else:
            name = path.split("/")[-1]
            if name not in self.records:
                raise a.APIError(404)
            record = self.records[name]
            if method == "PATCH":
                if self.reject:
                    raise a.APIError(self.reject)
                record.update(copy.deepcopy(data))
        if method != "GET" and self.lose:
            self.lose = False
            raise a.APIError()
        return copy.deepcopy(record)


class PrivateWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home())
        self.root = Path(self.temp.name)
        self.api = FakeAPI()
        self.client = a.Advisory(api=self.api, directory=self.root / "state")
        self.addCleanup(self.temp.cleanup)

    def create(self):
        return self.client.create(seed())

    def approve(self, record=None):
        record = record or self.create()
        return self.client.authorize(
            record["ghsa_id"],
            {
                "expected": policy.digest(record),
                "owner": board.OWNER,
                "source": "Synthetic owner instruction",
                "scope": "Synthetic bounded correction",
                "reconfirm": True,
            },
        )

    def claimed(self):
        r = self.approve()
        m = a.metadata(r)
        m["owner"] = {"session": "s", "clone": self.client.clone_id()}
        r["private_fork"] = {"full_name": "owner/private-fork", "private": True}
        self.api.records[GHSA] = copy.deepcopy(r)
        # Explicitly account for fake server provisioning before owned test setup.
        a.atomic(self.client.anchor, {GHSA: policy.digest(r)})
        r = self.client.change(r, m, "claim", "Synthetic setup", trust=True)
        return r

    def test_draft_create_retrieval_and_normal_retry_are_idempotent(self):
        one = self.create()
        two = self.create()
        self.assertEqual(one, two)
        self.assertEqual(len(self.api.records), 1)
        self.assertEqual(one["state"], "draft")
        posts = [c for c in self.api.calls if c[2] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertNotIn("state", posts[0][1])
        self.assertNotIn("cve_id", posts[0][1])
        self.assertEqual(a.metadata(one)["status"], "New")
        self.assertEqual(self.client.list(), [one])
        self.assertEqual(self.client.read(GHSA), one)

    def test_changed_key_payload_and_duplicate_original_id_require_update(self):
        self.create()
        changed = seed()
        changed["description"] = "Changed claim"
        with self.assertRaisesRegex(a.Error, "changed content"):
            self.client.create(changed)
        changed["key"] = "different-key"
        with self.assertRaisesRegex(a.Error, "original identifier"):
            self.client.create(changed)

    def test_related_claim_requires_explicit_private_inspection(self):
        self.create()
        data = seed("different-key")
        data["legacy_ids"] = []
        with self.assertRaisesRegex(a.Error, "related records"):
            self.client.create(data)
        self.assertTrue((self.client.directory / "related.json").exists())
        data["reviewed_related"] = [GHSA]
        self.client.create(data)
        self.assertEqual(len(self.api.records), 2)

    def test_lost_create_ack_recovered_without_repost(self):
        self.api.lose = True
        with self.assertRaises(a.APIError):
            self.create()
        self.assertTrue(self.client.pending())
        returning = a.Advisory(api=self.api, directory=self.root / "state")
        self.assertEqual(returning.create(seed())["ghsa_id"], GHSA)
        self.assertIsNone(returning.pending())
        self.assertEqual(sum(c[2] == "POST" for c in self.api.calls), 1)

    def test_unknown_not_observed_create_never_reposts(self):
        self.api.lose = True
        with self.assertRaises(a.APIError):
            self.create()
        self.api.records.clear()
        with self.assertRaisesRegex(a.Error, "pending"):
            self.create()
        with self.assertRaisesRegex(a.Error, "unknown create outcome"):
            self.client.recover()
        self.assertEqual(sum(c[2] == "POST" for c in self.api.calls), 1)

    def test_definite_rejection_retains_audit_without_unknown_pending(self):
        self.api.reject = 422
        with self.assertRaises(a.APIError):
            self.create()
        self.assertIsNone(self.client.pending())
        self.assertEqual(len(list(self.client.directory.glob("*.journal.json"))), 1)
        self.assertFalse(self.api.records)

    def test_update_preserves_original_prose_identity_and_history(self):
        r = self.create()
        old = a.metadata(r)
        r = self.client.update(
            GHSA,
            {
                "expected": policy.digest(r),
                "note": "Synthetic verification attempted; inconclusive.",
                "status": "Investigating",
            },
        )
        new = a.metadata(r)
        self.assertTrue(r["description"].startswith(seed()["description"]))
        self.assertEqual(old["legacy_ids"], new["legacy_ids"])
        self.assertEqual(old["history"], new["history"][:-1])
        self.assertEqual(new["status"], "Investigating")

    def test_stale_and_protected_updates_fail(self):
        r = self.create()
        for data in (
            {"expected": "stale", "note": "test"},
            {
                "expected": policy.digest(r),
                "note": "test",
                "status": "Fixed, awaiting disclosure",
            },
            {"expected": policy.digest(r), "note": "test", "ledger": {}},
        ):
            with self.assertRaises(a.Error):
                self.client.update(GHSA, data)
        self.assertEqual(self.client.read(GHSA), r)

    def test_lost_update_ack_recovered_exactly_once(self):
        r = self.create()
        self.api.lose = True
        with self.assertRaises(a.APIError):
            self.client.update(
                GHSA, {"expected": policy.digest(r), "note": "Synthetic progress"}
            )
        r = self.client.recover()
        self.assertEqual(len(a.metadata(r)["history"]), 2)
        with self.assertRaisesRegex(a.Error, "no pending"):
            self.client.recover()
        self.assertEqual(sum(c[2] == "PATCH" for c in self.api.calls), 1)

    def test_concurrent_change_during_publication_is_not_false_success(self):
        r = self.create()
        m = a.metadata(r)
        self.api.records[GHSA]["summary"] = "Concurrent change"
        with self.assertRaisesRegex(a.Error, "changed since read"):
            self.client.change(r, m, "update", "test")
        self.assertEqual(self.api.records[GHSA]["summary"], "Concurrent change")

    def test_missing_role_and_wrong_repository_fail_before_mutation(self):
        self.api.admin = False
        with self.assertRaisesRegex(a.Error, "administration"):
            self.client.list()
        with self.assertRaises(a.Error):
            self.create()
        with self.assertRaisesRegex(a.Error, "wrong repository"):
            a.Advisory("other/repo", api=self.api, directory=self.root / "wrong")
        self.assertFalse(any(c[2] != "GET" for c in self.api.calls))

    def test_collaborator_can_read_named_advisory_but_not_claim_inventory(self):
        r = self.create()
        self.api.user = "collaborator"
        self.api.admin = False
        self.assertEqual(self.client.read(GHSA), r)
        with self.assertRaises(a.Error):
            self.client.list()

    def test_invalid_identifiers_and_publication_attempts(self):
        for value in ("GHSA-../../oops", "GHSA-1111-1111-1111", "", None):
            with self.assertRaises(a.Error):
                self.client.read(value)
        for field, value in [
            ("state", "published"),
            ("cve_id", "CVE-0000-0000"),
            ("authorizations", []),
        ]:
            with self.assertRaises(a.Error):
                self.client.create({**seed(), field: value})
        self.assertFalse(self.api.records)

    def test_closed_and_published_records_are_read_only(self):
        r = self.create()
        r = self.client.close(
            GHSA,
            {
                "expected": policy.digest(r),
                "owner": board.OWNER,
                "source": "Synthetic owner decision",
                "reason": "Synthetic claim disproven.",
            },
        )
        self.assertEqual(r["state"], "closed")
        self.assertEqual(a.metadata(r)["status"], "Closed")
        self.assertIn("disproven", r["description"])
        for state in ("closed", "published"):
            self.api.records[GHSA]["state"] = state
            self.client.read(GHSA)
            with self.assertRaises(a.Error):
                self.client.update(
                    GHSA,
                    {"expected": policy.digest(self.api.records[GHSA]), "note": "test"},
                )

    def test_fresh_machine_needs_owner_reconfirmation_not_copied_author_field(self):
        r = self.approve()
        other = a.Advisory(api=self.api, directory=self.root / "another-machine")
        self.assertEqual(other.read(GHSA), r)
        with self.assertRaisesRegex(a.Error, "provenance"):
            other.work(GHSA, "new", self.root / "private")
        r = other.authorize(
            GHSA,
            {
                "expected": policy.digest(r),
                "owner": board.OWNER,
                "source": "New explicit owner handoff decision",
                "scope": "Same bounded work",
                "reconfirm": True,
            },
        )
        other.trusted(r)
        self.assertEqual(len(a.metadata(r)["grants"]), 2)

    def test_collaborator_scope_budget_edit_invalidates_owner_trust(self):
        r = self.approve()
        m = a.metadata(r)
        m["scope"] = "Unauthorized expanded scope"
        m["ledger"]["reviews"] = []
        self.api.records[GHSA]["description"] = a.description(seed()["description"], m)
        with self.assertRaisesRegex(a.Error, "provenance"):
            self.client.work(GHSA, "s", self.root / "private")

    def test_ownership_conflict_and_release_handoff(self):
        r = self.claimed()
        with self.assertRaisesRegex(a.Error, "another session"):
            self.client.owned(GHSA, "other", False)
        other = a.Advisory(api=self.api, directory=self.root / "another-machine")
        with self.assertRaisesRegex(a.Error, "provenance"):
            other.authorize(
                GHSA,
                {
                    "expected": policy.digest(r),
                    "owner": board.OWNER,
                    "source": "handoff",
                    "scope": "test",
                    "reconfirm": True,
                },
            )
        self.client.release(GHSA, "s")
        self.assertIsNone(a.metadata(self.client.read(GHSA))["owner"])

    def test_pending_fork_only_polls_on_resume(self):
        self.approve()
        self.api.fork_ready = False
        with self.assertRaisesRegex(a.Error, "fork request pending"):
            self.client.work(GHSA, "s", self.root / "private")
        with self.assertRaisesRegex(a.Error, "fork request pending"):
            self.client.work(GHSA, "s", self.root / "private")
        self.assertEqual(sum(c[0].endswith("/forks") for c in self.api.calls), 1)
        self.api.records[GHSA]["private_fork"] = {
            "full_name": "owner/private-fork",
            "private": True,
        }
        self.client.recover()
        self.assertIsNone(self.client.pending())

    def test_private_files_permissions_and_git_symlinks_rejected(self):
        path = self.root / "record.json"
        a.atomic(path, {"synthetic": "private"})
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(a.Error):
            a.read_file(link)
        repo = self.root / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        with self.assertRaisesRegex(a.Error, "outside Git"):
            a.atomic(repo / "record.json", {})

    def test_local_lock_conflicts(self):
        other = a.Advisory(api=self.api, directory=self.root / "state")
        with self.client.locked():
            with self.assertRaisesRegex(a.Error, "local state lock"):
                with other.locked():
                    pass

    def pending_review(self):
        record = self.claimed()
        m = a.metadata(record)
        r = {
            "id": "attempt-1",
            "phase": "code",
            "status": "pending",
            "outcome": "pending",
            "policy_version": 2,
            "receipt_version": 2,
            "commit": HEAD,
            "base_sha": BASE,
            "merge_base": BASE,
            "scope": "initial",
            "prior": [],
            "verifies": [],
            "rationale": "",
            "material_change": False,
        }
        m["ledger"]["reviews"].append(r)
        self.client.change(record, m, "pending", "synthetic", trust=True)
        return r

    def test_review_recovery_counts_once_survives_handoff_and_retains_original(self):
        r = self.pending_review()
        result = {
            "verdict": "approve",
            "findings": [],
            "summary": "Synthetic review only.",
        }
        a.atomic(
            self.client.directory / (r["id"] + ".json"),
            {
                "codex": {"status": 0},
                "inputs": {"head": HEAD, "base": BASE, "merge_base": BASE},
                "result": result,
            },
        )
        record = self.client.recover_review(GHSA, "s")
        s = a.metadata(record)["ledger"]
        self.assertEqual(policy.count(s, "code"), 1)
        self.assertEqual(s["reviews"][0]["result"], result)
        with self.assertRaises(a.Error):
            self.client.recover_review(GHSA, "s")
        returning = a.Advisory(api=self.api, directory=self.root / "state")
        self.assertEqual(
            policy.count(a.metadata(returning.read(GHSA))["ledger"], "code"), 1
        )
        self.assertTrue(policy.approved(s, HEAD, BASE, confidential=True))
        self.assertFalse(policy.approved(s, "c" * 40, BASE, confidential=True))

    def test_missing_or_mismatched_output_cannot_approve_or_count(self):
        r = self.pending_review()
        with self.assertRaisesRegex(a.Error, "missing complete"):
            self.client.recover_review(GHSA, "s")
        a.atomic(
            self.client.directory / (r["id"] + ".json"),
            {
                "codex": {"status": 0},
                "result": {"verdict": "approve", "findings": []},
                "inputs": {"head": "c" * 40, "base": BASE, "merge_base": BASE},
            },
        )
        record = self.client.recover_review(GHSA, "s", True)
        s = a.metadata(record)["ledger"]
        self.assertEqual(policy.count(s, "code"), 0)
        self.assertEqual(s["reviews"][0]["status"], "failed")

    def test_pending_review_cannot_release_or_reauthorize(self):
        self.pending_review()
        with self.assertRaisesRegex(a.Error, "pending"):
            self.client.release(GHSA, "s")
        r = self.client.read(GHSA)
        with self.assertRaisesRegex(a.Error, "pending"):
            self.approve(r)

    def test_private_independent_tracking_replays_but_public_issue_is_refused(self):
        s = {
            "findings": {
                "F-123456789abc": {
                    "id": "F-123456789abc",
                    "sources": [["review", 0]],
                    "history": [],
                    "severity": "low",
                }
            }
        }
        data = {
            "category": "independent",
            "status": "deferred",
            "tracking": board.REPO + "#" + GHSA,
            "evidence": "Synthetic independent evidence",
            "consequence": "No dependency on current work.",
        }
        policy.disposition(s, "F-123456789abc", data, HEAD, BASE, confidential=True)
        self.assertTrue(policy.findings_ready(s, HEAD, BASE, confidential=True))
        with self.assertRaises(policy.Error):
            policy.findings_ready(s, HEAD, BASE)
        with self.assertRaises(policy.Error):
            policy.disposition(
                s,
                "F-123456789abc",
                {**data, "tracking": "#123"},
                HEAD,
                BASE,
                confidential=True,
            )

    def test_public_helpers_and_direct_review_refuse_confidential_workspace(self):
        old = Path.cwd()
        repo = self.root / "private"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / ".git" / guard.MARKER).write_text("{}")
        try:
            os.chdir(repo)
            with mock.patch("subprocess.run") as run:
                with self.assertRaises(work_issue.Error):
                    work_issue.GitHub().api("user")
                with self.assertRaises(board.BoardError):
                    board.gh(["api", "user"])
                with self.assertRaises(work_issue.Error):
                    work_issue.GitHub().pr_write(
                        1, "title", "body", "branch", "main", True
                    )
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(codex_review.main(["focus"]), 2)
                run.assert_not_called()
        finally:
            os.chdir(old)

    def test_api_errors_are_sanitized_and_no_write_routes_publish(self):
        for code in (401, 403, 404, 422):
            response = subprocess.CompletedProcess(
                [], 1, "private response", "SECRET synthetic claim HTTP " + str(code)
            )
            with mock.patch("subprocess.run", return_value=response):
                with self.assertRaises(a.APIError) as caught:
                    a.API().request("user")
            self.assertNotIn("SECRET", str(caught.exception))
        with mock.patch("subprocess.run") as run:
            for path, data in [
                (
                    "repos/" + board.REPO + "/security-advisories/" + GHSA,
                    {"state": "published"},
                ),
                ("repos/" + board.REPO + "/issues", {"title": "private"}),
            ]:
                with self.assertRaises(a.Error):
                    a.API().request(path, data, "POST")
            run.assert_not_called()

    def test_long_lived_ordinary_checkpoint_compacts_without_lost_history(self):
        state = {
            "reviews": [{"id": i, "detail": {"result": "test"}} for i in range(1000)]
        }
        self.assertGreater(
            len(work_issue.block(work_issue.MARK, state)),
            work_issue.MAX_CHECKPOINT_BYTES,
        )
        body = work_issue.checkpoint_body(state)
        self.assertLess(len(body), work_issue.MAX_CHECKPOINT_BYTES)
        self.assertEqual(work_issue.parse_block(work_issue.MARK, body), state)

    def test_cli_invalid_private_argument_never_echoes_it(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(
                a.main(["--out", str(self.root / "output.json"), "publish-SECRET"]), 1
            )
        self.assertNotIn("SECRET", err.getvalue())

    def test_review_scopes_and_budgets_reach_real_wrapper_boundary(self):
        self.claimed()
        calls = []

        def reviewer(args, **kwargs):
            calls.append(args)
            kwargs["stdout"].write(
                json.dumps(
                    {
                        "codex": {"status": 0},
                        "inputs": {"head": HEAD, "base": BASE, "merge_base": BASE},
                        "result": {
                            "verdict": "approve",
                            "findings": [],
                            "summary": "Synthetic review",
                        },
                    }
                )
            )
            return subprocess.CompletedProcess(args, 0)

        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(self.client, "inputs", return_value=(HEAD, BASE, BASE)),
            mock.patch("subprocess.run", side_effect=reviewer),
        ):
            record = self.client.review(
                GHSA,
                "s",
                {
                    "phase": "code",
                    "scope": "initial",
                    "focus": "Synthetic private focus",
                },
            )
            prior = a.metadata(record)["ledger"]["reviews"][-1]["id"]
            record = self.client.review(
                GHSA,
                "s",
                {
                    "phase": "code",
                    "scope": "follow-up",
                    "focus": "Synthetic verification",
                    "prior": [prior],
                    "rationale": "Bounded correction",
                },
            )
            prior = a.metadata(record)["ledger"]["reviews"][-1]["id"]
            self.client.review(
                GHSA,
                "s",
                {
                    "phase": "code",
                    "scope": "integration",
                    "focus": "Synthetic integration",
                    "prior": [prior],
                    "rationale": "Target callers inspected",
                },
            )
            with self.assertRaisesRegex(a.Error, "budget exhausted"):
                self.client.review(
                    GHSA, "s", {"phase": "code", "focus": "No permission"}
                )
            self.assertEqual(len(calls), 3)
            record = self.client.read(GHSA)
            self.client.authorize(
                GHSA,
                {
                    "expected": policy.digest(record),
                    "owner": board.OWNER,
                    "source": "Explicit synthetic round four grant",
                    "scope": "Synthetic bounded correction",
                    "reconfirm": True,
                    "allowances": {"code": 4},
                },
            )
            record = self.client.review(
                GHSA,
                "s",
                {
                    "phase": "code",
                    "scope": "initial",
                    "focus": "Synthetic authorized fourth round",
                },
            )
            self.assertEqual(policy.count(a.metadata(record)["ledger"], "code"), 4)
            with self.assertRaisesRegex(a.Error, "allowance exhausted"):
                self.client.review(
                    GHSA, "s", {"phase": "code", "focus": "No permission"}
                )
        for args, scope in zip(
            calls, ["initial", "follow-up", "integration", "initial"]
        ):
            self.assertIn("--private", args)
            self.assertIn("--json", args)
            self.assertEqual(args[args.index("--scope") + 1], "branch")
            self.assertIn("Scope: " + scope, args[-1])
            self.assertNotIn("Synthetic private focus", args[-1])

    def test_verification_needs_actual_current_integration_and_keeps_draft(self):
        r = self.pending_review()
        a.atomic(
            self.client.directory / (r["id"] + ".json"),
            {
                "codex": {"status": 0},
                "inputs": {"head": HEAD, "base": BASE, "merge_base": BASE},
                "result": {"verdict": "approve", "findings": []},
            },
        )
        self.client.recover_review(GHSA, "s")
        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        decision = {
            "receipt": r["id"],
            "rationale": "Synthetic target integration verified",
        }
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(self.client, "inputs", return_value=(HEAD, BASE, BASE)),
        ):
            with self.assertRaisesRegex(a.Error, "verification is missing"):
                self.client.verified(GHSA, "s", decision)
            with mock.patch.object(guard, "command", return_value="remediation"):
                self.client.checkpoint(
                    GHSA,
                    "s",
                    {
                        "completed": "Synthetic correction",
                        "verification": "Synthetic tests passed",
                        "blockers": "",
                        "next": "Owner disclosure decision",
                    },
                )
            with mock.patch.object(
                self.client, "inputs", return_value=(HEAD, BASE, "c" * 40)
            ):
                with self.assertRaisesRegex(a.Error, "main must be integrated"):
                    self.client.verified(GHSA, "s", decision)
            record = self.client.verified(GHSA, "s", decision)
        self.assertEqual(record["state"], "draft")
        self.assertEqual(a.metadata(record)["status"], "Fixed, awaiting disclosure")
        self.assertFalse(
            any(c[1] and c[1].get("state") == "published" for c in self.api.calls)
        )

    def test_private_clone_reuse_and_push_destination_check_with_real_git(self):
        self.approve()
        workspace = self.root / "workspace"
        subprocess.run(["git", "init", "-q", str(workspace)], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(workspace),
                "remote",
                "add",
                "origin",
                "https://github.com/owner/private-fork.git",
            ],
            check=True,
        )
        original = guard.command

        def command(args, cwd=None):
            if args[0] == "gh":
                return json.dumps({"full_name": "owner/private-fork", "private": True})
            return original(args, cwd)

        with mock.patch.object(guard, "command", side_effect=command):
            one = self.client.work(GHSA, "s", workspace)
            two = self.client.work(GHSA, "s", workspace)
            self.assertEqual(one, two)
            self.assertTrue(guard.confidential(workspace))
            guard.verify(workspace, destination="git@github.com:owner/private-fork.git")
            with self.assertRaises(ValueError):
                guard.verify(
                    workspace, destination="https://github.com/" + board.REPO + ".git"
                )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(workspace),
                    "remote",
                    "set-url",
                    "--push",
                    "origin",
                    "https://github.com/" + board.REPO + ".git",
                ],
                check=True,
            )
            with self.assertRaises(ValueError):
                guard.verify(workspace)
        self.assertEqual(sum(c[0].endswith("/forks") for c in self.api.calls), 1)
        self.assertTrue((workspace / ".git/hooks/pre-push").stat().st_mode & 0o100)

    def test_private_finding_exception_is_owner_scoped_and_revision_bound(self):
        r = self.claimed()
        m = a.metadata(r)
        fid = "F-123456789abc"
        m["ledger"]["findings"][fid] = {
            "id": fid,
            "sources": [["synthetic", 0]],
            "history": [],
            "severity": "high",
        }
        r = self.client.change(r, m, "setup", "Synthetic finding", trust=True)
        r = self.client.finding_exception(
            GHSA,
            {
                "expected": policy.digest(r),
                "owner": board.OWNER,
                "source": "Synthetic explicit scoped exception",
                "reason": "Synthetic bounded reason",
                "finding": fid,
                "head": HEAD,
                "base": BASE,
            },
        )
        m = a.metadata(r)
        grant = m["grants"][-1]["id"]
        self.client.check_exception(m, fid, grant, HEAD, BASE)
        with self.assertRaisesRegex(a.Error, "stale"):
            self.client.check_exception(m, fid, grant, "c" * 40, BASE)

    def test_api_pagination_structured_stdin_and_private_environment(self):
        response = subprocess.CompletedProcess(
            [], 0, json.dumps([[{"synthetic": 1}], [{"synthetic": 2}]]), ""
        )
        with (
            mock.patch.dict(os.environ, {"GH_DEBUG": "api", "GIT_TRACE": "1"}),
            mock.patch("subprocess.run", return_value=response) as run,
        ):
            result = a.API().request(
                "repos/" + board.REPO + "/security-advisories?per_page=100", pages=True
            )
            args = run.call_args.args[0]
            self.assertIn("--paginate", args)
            self.assertIn("--slurp", args)
            self.assertNotIn("GH_DEBUG", run.call_args.kwargs["env"])
            self.assertNotIn("GIT_TRACE", run.call_args.kwargs["env"])
            self.assertEqual(len(result), 2)
        response = subprocess.CompletedProcess([], 0, "{}", "")
        with mock.patch("subprocess.run", return_value=response) as run:
            a.API().request(
                "repos/" + board.REPO + "/security-advisories",
                {"description": "Synthetic multiline\ntext"},
                "POST",
            )
            self.assertEqual(
                json.loads(run.call_args.kwargs["input"])["description"],
                "Synthetic multiline\ntext",
            )
            self.assertNotIn("Synthetic", str(run.call_args.args[0]))


if __name__ == "__main__":
    unittest.main()
