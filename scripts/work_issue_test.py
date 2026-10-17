# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Behavioral tests for the issue workflow, with real Git and fake GitHub."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import work_issue as w
import board


class FakeGitHub:
    def __init__(self):
        self.issue = {
            "number": 43,
            "node_id": "I43",
            "state": "open",
            "body": "Acceptance criteria",
            "title": "Task",
            "repository_url": "https://api.github.com/repos/" + board.REPO,
        }
        self.notes = []
        self.pulls = []
        self.fail_project = False
        self.lose_comment = False
        self.lose_pr = False
        self.moves = []

    def api(self, path, data=None, method=None, pages=False):
        if path == "user":
            return {"login": board.OWNER}
        if path.endswith("/issues/43"):
            return copy.deepcopy(self.issue)
        if path.endswith("/issues/999"):
            raise w.Error("HTTP 404: Not Found")
        if path.endswith("/comments") and data is None:
            return copy.deepcopy(self.notes)
        if "/issues/comments/" in path and data:
            item = next(
                c for c in self.notes if str(c["id"]) == path.rsplit("/", 1)[-1]
            )
            item["body"] = data["body"]
            if self.lose_comment:
                self.lose_comment = False
                raise w.Error("response lost")
            return copy.deepcopy(item)
        if path.endswith("/comments") and data:
            item = {
                "id": len(self.notes) + 1,
                "node_id": "C" + str(len(self.notes) + 1),
                "body": data["body"],
                "html_url": "https://github.com/"
                + board.REPO
                + "/issues/43#issuecomment-"
                + str(len(self.notes) + 1),
                "user": {"login": board.OWNER},
                "editor": board.OWNER,
            }
            self.notes.append(item)
            if self.lose_comment:
                self.lose_comment = False
                raise w.Error("response lost")
            return copy.deepcopy(item)
        if "/pulls?" in path:
            return copy.deepcopy(self.pulls)
        if "/pulls/" in path:
            return copy.deepcopy(
                next(
                    p for p in self.pulls if p["number"] == int(path.rsplit("/", 1)[-1])
                )
            )
        if "/compare/" in path:
            return {
                "status": "ahead",
                "merge_base_commit": {
                    "sha": path.split("/compare/")[1].split("...")[0]
                },
            }
        raise AssertionError((path, data))

    def trusted(self, c):
        if c["user"]["login"] != board.OWNER or c.get("editor") != board.OWNER:
            raise w.Error("untrusted comment revision")
        return c

    def project(self):
        if self.fail_project:
            raise w.Error("Project access denied")
        return {"id": "P"}

    def move(self, n, status):
        self.project()
        self.moves.append(status)

    def pr_write(self, number, title, body, branch, base, draft):
        if number:
            self.pulls[0]["body"] = body
            self.pulls[0]["draft"] = draft
        else:
            self.pulls.append(
                {
                    "number": 88,
                    "state": "open",
                    "merged_at": None,
                    "body": body,
                    "html_url": "https://github.com/" + board.REPO + "/pull/88",
                    "draft": draft,
                    "head": {
                        "ref": branch,
                        "sha": w.git("rev-parse", "HEAD"),
                        "repo": {"full_name": board.REPO},
                    },
                    "base": {"ref": base, "sha": w.git("rev-parse", "origin/main")},
                }
            )
        if self.lose_pr:
            self.lose_pr = False
            raise w.Error("response lost")


class Workflow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old = Path.cwd()
        self.addCleanup(os.chdir, self.old)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        os.chdir(self.root)

        def g(*a):
            subprocess.run(["git", *a], check=True, capture_output=True)

        g("init", "-q", "-b", "main")
        g("config", "user.name", "test")
        g("config", "user.email", "test@example.com")
        (self.root / "file").write_text("base")
        g("add", ".")
        g("commit", "-qm", "base")
        g("remote", "add", "origin", "https://github.com/" + board.REPO + ".git")
        g("update-ref", "refs/remotes/origin/main", "HEAD")
        g("switch", "-qc", "issue-43")
        self.gh = FakeGitHub()
        self.ref = board.REPO + "#43"
        self.ctx = w.Task(43, self.gh)
        self.fetch = mock.patch.object(
            w, "fresh_base", return_value=w.git("rev-parse", "origin/main")
        )
        self.fetch.start()
        self.addCleanup(self.fetch.stop)

    def start(self, session="one"):
        return self.ctx.start(session, here=True)

    def test_repeated_start_reuses_branch_comment_and_claim(self):
        a = self.start()
        b = self.start()
        self.assertEqual(a["branch"], b["branch"])
        self.assertEqual(len(self.gh.notes), 1)
        self.assertEqual(w.git("branch", "--list").count("issue-43"), 1)

    def test_wrong_repository_and_missing_issue(self):
        with self.assertRaises(w.Error):
            w.issue_number("someone/else#43")
        with self.assertRaises(w.Error):
            w.Task(999, self.gh).start("one", here=True)
        self.assertEqual(self.gh.notes, [])

    def test_missing_project_permission_never_claims_success(self):
        self.gh.fail_project = True
        with self.assertRaisesRegex(w.Error, "Project"):
            self.start()
        self.assertEqual(self.gh.moves, [])
        self.assertEqual(self.gh.notes, [])

    def test_session_conflict_and_same_branch_conflict(self):
        self.start()
        with self.assertRaisesRegex(w.Error, "owned"):
            self.start("two")
        p = self.ctx.directory / "44.json"
        data = copy.deepcopy(self.ctx.state)
        data["issue"] = 44
        w.atomic(p, data)
        with self.assertRaisesRegex(w.Error, "branch"):
            self.start()

    def test_lost_comment_response_reconciles_without_duplicate(self):
        self.gh.lose_comment = True
        self.start()
        self.start()
        self.assertEqual(len(self.gh.notes), 1)

    def test_later_session_recovers_checkpoint_and_review_counts(self):
        self.start()
        self.ctx.state["reviews"] = [self.receipt("code", 1)]
        self.ctx.checkpoint(
            "one",
            {
                "completed": "done",
                "verification": "unit tests passed",
                "blockers": "none",
                "next": "review",
            },
        )
        self.ctx.release("one")
        self.ctx.path.unlink()
        later = w.Task(43, self.gh)
        later.start("two", here=True)
        self.assertEqual(later.state["checkpoint"]["next"], "review")
        self.assertEqual(w.completed(later.state, "code"), 1)

    def receipt(self, phase="code", number=1, outcome="approve"):
        r = {
            "id": str(number),
            "phase": phase,
            "commit": w.git("rev-parse", "HEAD"),
            "base": "origin/main",
            "base_sha": w.git("rev-parse", "origin/main"),
            "status": "completed",
            "outcome": outcome,
            "unresolved": 0 if outcome == "approve" else 1,
            "round": number,
            "policy_version": 2,
            "receipt_version": 2,
            "scope": "initial",
            "prior": [],
            "verifies": [],
            "rationale": "",
            "merge_base": w.git("merge-base", "HEAD", "origin/main"),
        }
        r["inputs"] = {
            "head": r["commit"],
            "base": r["base_sha"],
            "merge_base": r["merge_base"],
        }
        w.policy.register_result(
            self.ctx.state, r, {"verdict": outcome, "findings": []}
        )
        return r

    def test_changed_revision_or_base_invalidates_review_not_count(self):
        self.start()
        self.ctx.state["reviews"] = [self.receipt()]
        self.assertTrue(
            w.approved(
                self.ctx.state,
                w.git("rev-parse", "HEAD"),
                w.git("rev-parse", "origin/main"),
            )
        )
        self.assertFalse(
            w.approved(self.ctx.state, "0" * 40, w.git("rev-parse", "origin/main"))
        )
        self.assertFalse(
            w.approved(self.ctx.state, w.git("rev-parse", "HEAD"), "0" * 40)
        )
        self.assertEqual(w.completed(self.ctx.state, "code"), 1)

    def test_phase_budgets_require_permission_after_three(self):
        self.start()
        for phase, limit in [("docs", 1), ("plan", 2), ("code", 5)]:
            self.ctx.state["reviews"] = [
                self.receipt(phase, n, "needs-attention") for n in range(1, limit + 1)
            ]
            with self.assertRaises(w.Error):
                w.budget(self.ctx.state, phase)
        self.ctx.state["reviews"] = [
            self.receipt("code", n, "needs-attention") for n in range(1, 4)
        ]
        with self.assertRaisesRegex(w.Error, "authorization"):
            w.budget(self.ctx.state, "code")
        self.ctx.state["triage"] = "Findings sorted with tests and follow-up issues"
        with self.assertRaisesRegex(w.Error, "authorization"):
            w.budget(self.ctx.state, "code")
        self.ctx.state["authorizations"] = [{"phase": "code", "round": 4, "comment": 9}]
        w.budget(self.ctx.state, "code")

    def test_failed_review_is_not_completed_or_approved(self):
        self.start()
        r = self.receipt()
        r.update(status="failed", outcome="unavailable")
        self.ctx.state["reviews"] = [r]
        self.assertEqual(w.completed(self.ctx.state, "code"), 0)
        self.assertFalse(w.approved(self.ctx.state, r["commit"], r["base_sha"]))

    def test_unpublished_history_blocks_release(self):
        self.start()
        self.ctx.state["reviews"] = [self.receipt()]
        with mock.patch.object(self.ctx, "publish", side_effect=w.Error("offline")):
            with self.assertRaises(w.Error):
                self.ctx.release("one")
        self.assertIsNotNone(self.ctx.state["owner"])

    def test_pending_review_blocks_release_and_another_review(self):
        self.start()
        r = self.receipt()
        r["status"] = "pending"
        self.ctx.state["reviews"] = [r]
        with self.assertRaises(w.Error):
            self.ctx.release("one")
        with self.assertRaises(w.Error):
            w.budget(self.ctx.state, "code")

    def test_atomic_replace_failure_preserves_previous_state(self):
        p = Path("state.json")
        w.atomic(p, {"round": 3})
        with mock.patch.object(os, "replace", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                w.atomic(p, {"round": 4})
        self.assertEqual(json.loads(p.read_text()), {"round": 3})

    def test_unauthorized_edit_of_checkpoint_is_rejected(self):
        self.start()
        self.gh.notes[0]["editor"] = "someone-else"
        with self.assertRaisesRegex(w.Error, "untrusted"):
            w.Task(43, self.gh).start("one", here=True)

    def test_partial_and_stacked_prs_cannot_complete(self):
        p = {
            "number": 88,
            "body": "Part of #43",
            "merged_at": "today",
            "merge_commit_sha": "a" * 40,
            "base": {"ref": "main"},
        }
        self.gh.pulls = [p]
        with self.assertRaises(w.Error):
            w.finish(43, self.gh)
        p["body"] = "Fixes #43"
        p["base"]["ref"] = "parent"
        with self.assertRaises(w.Error):
            w.finish(43, self.gh)
        p["base"]["ref"] = "main"
        p["merged_at"] = None
        with self.assertRaises(w.Error):
            w.finish(43, self.gh)
        p["merged_at"] = "today"
        w.finish(43, self.gh)
        self.assertEqual(self.gh.moves[-1], "Done")

    def test_completion_rejects_merge_not_on_main(self):
        self.gh.pulls = [
            {
                "number": 88,
                "body": "Fixes #43",
                "merged_at": "today",
                "merge_commit_sha": "a" * 40,
                "base": {"ref": "main"},
            }
        ]
        original = self.gh.api
        self.gh.api = lambda path, **kw: (
            {"status": "diverged"} if "/compare/" in path else original(path, **kw)
        )
        with self.assertRaises(w.Error):
            w.finish(43, self.gh)

    def test_private_exception_has_no_sensitive_output(self):
        c = {
            "id": 1,
            "body": "work-issue exception " + ("a" * 40) + " " + ("b" * 40),
            "user": {"login": board.OWNER},
            "editor": board.OWNER,
        }
        self.gh.notes = [c]
        self.assertTrue(w.exception(self.gh, 88, "a" * 40, "b" * 40))
        self.assertFalse(w.exception(self.gh, 88, "c" * 40, "b" * 40))
        c["editor"] = "someone-else"
        with self.assertRaises(w.Error):
            w.exception(self.gh, 88, "a" * 40, "b" * 40)

    def ready(self):
        self.start()
        self.ctx.state["reviews"] = [self.receipt()]
        self.ctx.checkpoint(
            "one",
            {
                "completed": "done",
                "verification": "44 tests passed",
                "blockers": "none",
                "next": "submit",
            },
        )

        self.ctx.integrate(
            "one", "1", "Current target incorporated; affected unit checks passed."
        )

    def test_lost_pr_response_and_repeat_submit_reuse_one_pr(self):
        self.ready()
        self.gh.lose_pr = True
        original = w.run

        def command(args, **kw):
            return "" if args[:2] == ["git", "push"] else original(args, **kw)

        with mock.patch.object(w, "run", side_effect=command):
            one = self.ctx.submit("one", "Test change", "What changed and validation")
            two = self.ctx.submit("one", "Test change", "What changed and validation")
        self.assertEqual(one, two)
        self.assertEqual(len(self.gh.pulls), 1)
        self.assertEqual(
            w.validate_pr(88, self.gh), "issue and review contract verified"
        )
        self.gh.pulls[0]["head"]["sha"] = "0" * 40
        with self.assertRaisesRegex(w.Error, "stale"):
            w.validate_pr(88, self.gh)

    def test_partial_submit_stays_in_progress(self):
        self.ready()
        original = w.run
        with mock.patch.object(
            w,
            "run",
            side_effect=lambda a, **kw: (
                "" if a[:2] == ["git", "push"] else original(a, **kw)
            ),
        ):
            self.ctx.submit("one", "Partial", "Implemented one piece", kind="part")
        self.assertEqual(self.gh.moves[-1], "In progress")
        self.assertIn("Part of #43", self.gh.pulls[0]["body"])

    def test_real_pr_adapter_reconciles_draft_transitions(self):
        for current, requested in [(True, False), (False, True), (True, True)]:

            def command(args, **kwargs):
                if args[:3] == ["gh", "pr", "view"]:
                    return json.dumps({"isDraft": current})
                return ""

            with mock.patch.object(w, "run", side_effect=command) as run:
                w.GitHub().pr_write(88, "Change", "Body", "issue-43", "main", requested)
                transitions = [
                    call.args[0]
                    for call in run.call_args_list
                    if call.args[0][:3] == ["gh", "pr", "ready"]
                ]
                self.assertEqual(len(transitions), int(current != requested))
                if transitions:
                    self.assertEqual("--undo" in transitions[0], requested)

    def test_pending_and_approved_resubmissions_reuse_pr_and_check_draft(self):
        self.ready()
        original = w.run
        with mock.patch.object(
            w,
            "run",
            side_effect=lambda a, **kw: (
                "" if a[:2] == ["git", "push"] else original(a, **kw)
            ),
        ):
            for pending in [True, False, True]:
                self.gh.lose_pr = True  # State change accepted, acknowledgement lost.
                self.ctx.submit("one", "Change", "Implemented", pending=pending)
                self.assertEqual(self.gh.pulls[0]["draft"], pending)
                self.assertEqual(len(self.gh.pulls), 1)
            write = self.gh.pr_write

            def wrong_draft(*args):
                write(*args)
                self.gh.pulls[0]["draft"] = True

            with mock.patch.object(self.gh, "pr_write", side_effect=wrong_draft):
                with self.assertRaisesRegex(w.Error, "verified"):
                    self.ctx.submit("one", "Change", "Implemented", pending=False)

    def test_released_branch_with_unrelated_open_pr_cannot_be_adopted(self):
        self.ready()
        self.gh.pr_write(None, "A", "Fixes #43", "issue-43", "main", False)
        self.ctx.release("one")
        other = FakeGitHub()
        other.pulls = self.gh.pulls
        api = other.api
        other.api = lambda path, *args, **kwargs: (
            {**other.issue, "number": 44}
            if path.endswith("/issues/44")
            else api(path, *args, **kwargs)
        )
        task = w.Task(44, other)
        with self.assertRaisesRegex(w.Error, "different issue"):
            task.start("two", here=True)
        self.assertFalse(task.path.exists())
        self.assertEqual(other.notes, [])

    def test_submit_checks_foreign_or_ambiguous_pr_before_any_push(self):
        self.ready()
        self.gh.pr_write(None, "A", "Fixes #44", "issue-43", "main", False)
        original = w.run
        with mock.patch.object(
            w,
            "run",
            side_effect=lambda a, **kw: (
                "" if a[:2] == ["git", "push"] else original(a, **kw)
            ),
        ) as run:
            with self.assertRaisesRegex(w.Error, "different issue"):
                self.ctx.submit("one", "Change", "Implemented")
            self.gh.pulls[0]["body"] = "Fixes #43"
            self.gh.pulls.append({**copy.deepcopy(self.gh.pulls[0]), "number": 89})
            with self.assertRaisesRegex(w.Error, "ambiguous"):
                self.ctx.submit("one", "Change", "Implemented")
            self.assertFalse(
                any(c.args[0][:2] == ["git", "push"] for c in run.call_args_list)
            )

    def test_oversized_checkpoint_rejected_before_save_and_can_be_corrected(self):
        self.start()
        before = self.ctx.path.read_text()
        with self.assertRaisesRegex(w.Error, "too large"):
            self.ctx.checkpoint(
                "one",
                {
                    "completed": "",
                    "verification": "a" * 70000,
                    "blockers": "",
                    "next": "",
                },
            )
        self.assertEqual(before, self.ctx.path.read_text())
        later = w.Task(43, self.gh)
        later.checkpoint(
            "one",
            {
                "completed": "",
                "verification": "short results",
                "blockers": "",
                "next": "review",
            },
        )
        later.release("one")
        self.assertIsNone(w.remote_state(self.gh, 43)[0]["owner"])

    def test_total_checkpoint_limit_includes_triage_and_review_history(self):
        self.ready()
        before = self.ctx.path.read_text()
        self.ctx.state["triage"] = "a" * 70000
        with self.assertRaisesRegex(w.Error, "too large"):
            self.ctx.save()
        self.assertEqual(before, self.ctx.path.read_text())
        later = w.Task(43, self.gh)
        later.release("one")
        self.assertEqual(w.completed(later.state, "code"), 1)

    def test_completed_review_recovery_is_counted_once(self):
        self.start()
        r = self.receipt()
        r["id"] = "attempt"
        r["status"] = "pending"
        self.ctx.state["reviews"] = [r]
        w.atomic(
            self.ctx.directory / "attempt.json",
            {
                "codex": {"status": 0},
                "inputs": r["inputs"],
                "result": {"verdict": "approve", "findings": []},
            },
        )
        self.ctx.recover("one")
        self.assertEqual(w.completed(self.ctx.state, "code"), 1)
        with self.assertRaises(w.Error):
            self.ctx.recover("one")
        self.assertEqual(w.completed(self.ctx.state, "code"), 1)

    def test_remote_checkpoint_conflict_never_overwrites(self):
        self.start()
        data = w.parse_block(w.MARK, self.gh.notes[0]["body"])
        data["revision"] = "another-machine"
        self.gh.notes[0]["body"] = w.block(w.MARK, data)
        with self.assertRaisesRegex(w.Error, "another clone"):
            self.ctx.publish()
        self.assertEqual(
            w.parse_block(w.MARK, self.gh.notes[0]["body"])["revision"],
            "another-machine",
        )

    def test_an_extra_round_requires_scoped_owner_comment(self):
        self.start()
        self.ctx.state["reviews"] = [self.receipt("docs", 1)]
        with self.assertRaises(w.Error):
            w.budget(self.ctx.state, "docs")
        c = {
            "id": 25,
            "body": f"work-issue authorize {board.REPO}#43 docs 2",
            "user": {"login": board.OWNER},
            "editor": board.OWNER,
        }
        self.gh.notes.append(c)
        w.authorize_check(self.gh, 43, "docs", 2, 25)
        self.ctx.state["authorizations"] = [
            {"phase": "docs", "round": 2, "comment": 25}
        ]
        w.budget(self.ctx.state, "docs")
        with self.assertRaises(w.Error):
            w.authorize_check(self.gh, 43, "code", 6, 25)

    def test_advisory_reference_is_rejected_before_publication(self):
        self.start()
        with self.assertRaisesRegex(w.Error, "confidential"):
            self.ctx.checkpoint(
                "one",
                {
                    "completed": "GHSA-xxxx-yyyy-zzzz",
                    "verification": "",
                    "blockers": "",
                    "next": "",
                },
            )
        self.assertNotIn("GHSA-", self.gh.notes[0]["body"])

    def test_actual_adapter_checks_latest_editor(self):
        client = w.GitHub()
        c = {"node_id": "C", "body": "old"}
        node = {
            "author": {"login": board.OWNER},
            "editor": {"login": "other"},
            "lastEditedAt": "today",
            "repository": {"nameWithOwner": board.REPO},
            "body": "current",
        }
        with mock.patch.object(client, "api", return_value={"data": {"node": node}}):
            with self.assertRaises(w.Error):
                client.trusted(c)
            node["editor"] = {"login": board.OWNER}
            self.assertEqual(client.trusted(c)["body"], "current")
            node["editor"] = None
            with self.assertRaises(w.Error):
                client.trusted(c)
            node["lastEditedAt"] = None
            self.assertEqual(client.trusted(c)["body"], "current")

    def test_new_session_discovers_existing_task_pr(self):
        self.gh.pulls = [
            {
                "number": 88,
                "state": "open",
                "body": "Fixes #43",
                "head": {"ref": "existing-task", "repo": {"full_name": board.REPO}},
            }
        ]
        with self.assertRaisesRegex(w.Error, "another branch"):
            self.start()
        self.assertFalse(self.ctx.path.exists())

    def test_resume_does_not_demote_finishing_pr(self):
        self.start()
        self.gh.pulls = [{"body": "Fixes #43", "state": "open"}]
        self.start()
        self.assertEqual(self.gh.moves[-1], "In review")

    def test_numeric_prefix_review_log_is_not_an_issue(self):
        self.start()
        w.atomic(
            self.ctx.directory / "1c000000-0000-4000-8000-000000000000.json",
            {"result": {}},
        )
        self.start()

    def test_release_lost_ack_and_readback_recovers(self):
        self.start()
        original = self.ctx.publish
        calls = 0

        def publish():
            nonlocal calls
            calls += 1
            if calls == 2:
                # Remote accepted the released revision, local acknowledgement was lost.
                original()
                self.ctx.state["_remote_revision"] = "old-ack"
                self.ctx.save()
                raise w.Error("readback offline")
            original()

        with mock.patch.object(self.ctx, "publish", side_effect=publish):
            with self.assertRaises(w.Error):
                self.ctx.release("one")
        later = w.Task(43, self.gh)
        later.release("one")
        later.start("two", here=True)
        self.assertEqual(later.state["owner"]["session"], "two")

    def test_partial_rejects_all_github_closing_keywords(self):
        for closing in [
            "Closes #43",
            "Resolved #43",
            "Fix #43",
            f"fixes {board.REPO}#43",
            "Fixes #999",
        ]:
            self.assertIsNone(w.relation("Part of #43\n\n" + closing, 43), closing)
        self.assertIsNone(w.relation("Fixes #43\n\nCloses #999", 43))

    def test_verification_binding_is_not_refreshed_by_resume(self):
        self.ready()
        old = self.ctx.state["verification_commit"]
        (self.root / "file").write_text("changed")
        w.git("add", "file")
        w.git("commit", "-qm", "change")
        self.start()
        self.assertEqual(self.ctx.state["verification_commit"], old)
        self.ctx.state["reviews"] = [self.receipt()]
        with self.assertRaisesRegex(w.Error, "verification"):
            self.ctx.submit("one", "Change", "Implemented")

    def test_explicit_base_transition_keeps_counts_and_invalidates_evidence(self):
        self.ready()
        self.ctx.state["base"] = "origin/parent"
        self.ctx.save()
        self.ctx.set_base("one", "origin/main")
        self.assertEqual(self.ctx.state["base"], "origin/main")
        self.assertEqual(w.completed(self.ctx.state, "code"), 1)
        # Identical immutable inputs retain review evidence; retargeting still
        # clears verification and requires a new integration checkpoint.
        self.assertTrue(
            w.approved(
                self.ctx.state,
                w.git("rev-parse", "HEAD"),
                w.git("rev-parse", "origin/main"),
            )
        )
        with self.assertRaisesRegex(w.Error, "verification"):
            w.verification_current(
                self.ctx.state,
                w.git("rev-parse", "HEAD"),
                w.git("rev-parse", "origin/main"),
            )

    def test_handoff_recovers_from_a_separate_clone(self):
        self.ready()
        self.ctx.release("one")
        clone = Path(self.tmp.name) / "other-machine"
        w.run(["git", "clone", "-q", str(self.root), str(clone)])
        os.chdir(clone)
        w.git(
            "remote", "set-url", "origin", "https://github.com/" + board.REPO + ".git"
        )
        later = w.Task(43, self.gh)
        later.start("new-session", here=True)
        self.assertNotEqual(later.clone(), self.ctx.clone())
        self.assertEqual(w.completed(later.state, "code"), 1)
        self.assertEqual(later.state["checkpoint"]["verification"], "44 tests passed")

    def handoff_back(self):
        self.ready()
        self.ctx.release("one")
        clone = Path(self.tmp.name) / "other-machine"
        w.run(["git", "clone", "-q", str(self.root), str(clone)])
        os.chdir(clone)
        w.git(
            "remote", "set-url", "origin", "https://github.com/" + board.REPO + ".git"
        )
        later = w.Task(43, self.gh)
        later.start("two", here=True)
        later.state["reviews"].append(self.receipt("code", 2))
        later.checkpoint(
            "two",
            {
                "completed": "Second machine finished its part",
                "verification": "Synthetic tests passed",
                "blockers": "none",
                "next": "Return to first machine",
            },
        )
        later.release("two")
        os.chdir(self.root)
        return w.Task(43, self.gh)

    def test_return_handoff_keeps_remote_history(self):
        returned = self.handoff_back()
        returned.start("three", here=True)
        self.assertEqual(w.completed(returned.state, "code"), 2)
        self.assertEqual(
            returned.state["checkpoint"]["next"], "Return to first machine"
        )
        self.assertEqual(returned.state["owner"]["session"], "three")
        self.assertEqual(len(self.gh.notes), 1)

    def test_return_handoff_refuses_unpublished_local_changes(self):
        returned = self.handoff_back()
        returned.state["checkpoint"]["next"] = "Unpublished work"
        returned.save()
        before = copy.deepcopy(self.gh.notes)
        with self.assertRaisesRegex(w.Error, "reconcile"):
            returned.start("three", here=True)
        self.assertEqual(before, self.gh.notes)

    def test_return_handoff_refuses_erased_review_history(self):
        returned = self.handoff_back()
        remote = w.parse_block(w.MARK, self.gh.notes[0]["body"])
        remote["reviews"] = []
        self.gh.notes[0]["body"] = w.block(w.MARK, remote)
        with self.assertRaisesRegex(w.Error, "history"):
            returned.start("three", here=True)

    def test_fenced_text_survives_checkpoint_correction_and_release(self):
        self.start()
        data = {
            "completed": "done",
            "verification": "```text\n72 tests passed\n```",
            "blockers": "",
            "next": "review",
        }
        self.ctx.checkpoint("one", data)
        self.ctx.state["triage"] = "```text\nfindings reproduced\n```"
        self.ctx.save()
        self.ctx.publish()
        data["verification"] = "Corrected: 73 tests passed"
        self.ctx.checkpoint("one", data)
        self.ctx.release("one")
        remote, _ = w.remote_state(self.gh, 43)
        self.assertEqual(remote["checkpoint"], data)
        self.assertIn("```text", remote["triage"])
        self.assertIsNone(remote["owner"])

    def test_malformed_or_ambiguous_evidence_is_refused(self):
        for body in [
            w.block(w.MARK, []),
            w.block(w.MARK, {})[:-3],
            w.block(w.MARK, {}) + "\n" + w.block(w.MARK, {}),
        ]:
            with self.assertRaises(w.Error):
                w.parse_block(w.MARK, body)

    def test_retarget_updates_existing_pr_instead_of_creating_another(self):
        self.ready()
        original = w.run
        with mock.patch.object(
            w,
            "run",
            side_effect=lambda a, **kw: (
                "" if a[:2] == ["git", "push"] else original(a, **kw)
            ),
        ):
            self.ctx.submit("one", "Change", "Implemented")
            self.gh.pulls[0]["base"]["ref"] = "parent"
            write = self.gh.pr_write

            def retarget(number, title, body, branch, base, draft):
                write(number, title, body, branch, base, draft)
                self.gh.pulls[0]["base"]["ref"] = base

            with mock.patch.object(self.gh, "pr_write", side_effect=retarget):
                self.ctx.submit("one", "Change", "Implemented")
        self.assertEqual(len(self.gh.pulls), 1)
        self.assertEqual(self.gh.pulls[0]["base"]["ref"], "main")

    def test_colon_closing_forms_rejected_by_submit_and_ci(self):
        self.ready()
        original = w.run
        for keyword in [
            "close",
            "closes",
            "closed",
            "fix",
            "fixes",
            "fixed",
            "resolve",
            "resolves",
            "resolved",
        ]:
            body = "Part of #43\n\n" + keyword + ": #43"
            self.assertIsNone(w.relation(body, 43))
            with self.assertRaises(w.Error):
                self.ctx.submit("one", "Partial", body, kind="part")
        with mock.patch.object(
            w,
            "run",
            side_effect=lambda a, **kw: (
                "" if a[:2] == ["git", "push"] else original(a, **kw)
            ),
        ):
            self.ctx.submit("one", "Partial", "Part of #43", kind="part")
        self.gh.pulls[0]["body"] += "\nCloses: #43"
        with self.assertRaisesRegex(w.Error, "relationship"):
            w.validate_pr(88, self.gh)

    def test_recover_reconciles_accepted_pending_publication_first(self):
        self.start()
        r = self.receipt()
        r["status"] = "pending"
        r["id"] = "not-launched"
        self.ctx.state["reviews"] = [r]
        self.ctx.save()
        # Simulate the new revision accepted remotely without the local acknowledgement.
        self.ctx.publish()
        self.ctx.state["_remote_revision"] = "old-ack"
        self.ctx.save()
        later = w.Task(43, self.gh)
        later.recover("one", failed=True)
        self.assertEqual(later.state["reviews"][-1]["status"], "failed")
        later.start("one", here=True)
        later.release("one")
        self.assertIsNone(w.remote_state(self.gh, 43)[0]["owner"])

    def test_default_start_creates_exactly_one_worktree(self):
        w.git("branch", "-m", "unrelated")
        original = w.run
        with mock.patch.object(
            w,
            "run",
            side_effect=lambda a, **kw: (
                "" if a[:2] == ["git", "fetch"] else original(a, **kw)
            ),
        ):
            one = self.ctx.start("one")["_worktree"]
            two = self.ctx.start("one")["_worktree"]
        self.assertEqual(one, two)
        self.assertTrue(Path(one).is_dir())
        self.assertEqual(
            w.git("worktree", "list", "--porcelain").count(
                "branch refs/heads/issue-43"
            ),
            1,
        )

    def test_another_process_cannot_enter_the_clone_operation_lock(self):
        import sys

        program = "import sys;sys.path.insert(0,sys.argv[1]);import work_issue as w\nwith w.locked(): print('entered')"
        with w.locked():
            child = subprocess.run(
                [sys.executable, "-c", program, str(Path(w.__file__).parent)],
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(child.returncode, 0)
        self.assertIn("another workflow operation", child.stderr)
        with w.locked():
            pass


if __name__ == "__main__":
    unittest.main()
