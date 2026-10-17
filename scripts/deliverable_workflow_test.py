# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Deliverable command and trusted CI parity using synthetic GitHub and real Git."""

import base64
import copy
import subprocess
import unittest
from unittest import mock

import work_issue as w
import work_issue_test as fixtures
import review_policy_test as reviews


class DeliverableWorkflow(unittest.TestCase):
    setUp = fixtures.Workflow.setUp
    start = fixtures.Workflow.start
    review = reviews.PolicyWorkflow.review
    checkpoint = reviews.PolicyWorkflow.checkpoint
    dispose = reviews.PolicyWorkflow.dispose
    finding = reviews.PolicyWorkflow.finding

    def commit(self, content, path="program.py"):
        (self.root / path).write_bytes(content)
        w.git("add", path)
        w.git("commit", "-qm", "synthetic change")

    def grant(self, ident="delivery"):
        data = {
            "id": ident,
            "outcome": "Synthetic outcome",
            "acceptance": "Regression passes",
        }
        before = copy.deepcopy(self.gh.notes)
        line = self.ctx.deliverable("one", data, preview=True)
        self.assertEqual(before, self.gh.notes)
        c = self.gh.api(
            f"repos/{w.board.REPO}/issues/43/comments", {"body": line}, method="POST"
        )
        self.ctx.deliverable("one", data, c["id"])
        return data, c["id"]

    def test_scope_grant_provenance_idempotency_and_handoff(self):
        self.start()
        data, comment = self.grant()
        r, _ = self.review()
        self.ctx.deliverable("one", data, comment)
        self.assertEqual(w.completed(self.ctx.state, "code"), 1)
        self.assertEqual(w.policy.deliverable_count(self.ctx.state, "code"), 1)
        self.assertEqual(len(self.ctx.state["deliverables"]), 1)
        renamed = {**data, "id": "renamed"}
        with self.assertRaisesRegex(w.Error, "authorization"):
            self.ctx.deliverable("one", renamed, comment)
        self.ctx.release("one")
        self.ctx.path.unlink()
        other = w.Task(43, self.gh)
        other.start("two", here=True)
        self.assertEqual(other.state["reviews"], [r])
        self.assertEqual(w.policy.budget(other.state, "code"), 2)
        self.assertEqual(other.state["active_deliverable"], data["id"])
        self.gh.notes[-1]["editor"] = "another-user"
        with self.assertRaisesRegex(w.Error, "untrusted"):
            w.policy.check_ledger(
                other.state,
                lambda ph, rd, c, kind, binding=None: w.authorize_check(
                    self.gh, 43, ph, rd, c, kind, binding
                ),
            )

    def test_lost_scope_publication_recovers_exactly_once(self):
        self.start()
        data = {
            "id": "delivery",
            "outcome": "Synthetic outcome",
            "acceptance": "Regression passes",
        }
        line = self.ctx.deliverable("one", data, preview=True)
        c = self.gh.api(
            f"repos/{w.board.REPO}/issues/43/comments", {"body": line}, method="POST"
        )
        self.gh.lose_comment = True
        self.ctx.deliverable("one", data, c["id"])
        self.ctx.deliverable("one", data, c["id"])
        self.assertEqual(len(self.ctx.state["deliverables"]), 1)
        self.assertEqual(len(self.gh.notes), 2)

    def test_batch_carry_uses_reviewed_dispositions_and_never_resolves_blocker(self):
        self.start()
        self.grant()
        first, fid = self.finding()
        self.dispose(fid)
        history = copy.deepcopy(self.ctx.state["findings"][fid]["history"])
        self.commit(b"print(1)\n")
        follow, _ = self.review(scope="follow-up", prior=[first["id"]], verifies=[fid])
        self.assertFalse(
            w.approved(self.ctx.state, follow["commit"], follow["base_sha"])
        )
        self.ctx.carry(
            "one",
            follow["id"],
            {
                "findings": [fid],
                "rationale": "Prior regression and affected behavior independently verified.",
            },
        )
        self.assertEqual(self.ctx.state["findings"][fid]["history"], history)
        self.checkpoint()
        self.ctx.integrate(
            "one", follow["id"], "Current target and reviewed fixes verified."
        )
        w.readiness(self.ctx.state, follow["commit"], follow["base_sha"], self.gh, 43)
        self.dispose(fid, status="fixed-unverified")
        with self.assertRaises(w.Error):
            self.ctx.carry(
                "one",
                follow["id"],
                {"findings": [fid], "rationale": "Cannot resolve by carrying."},
            )
        self.assertFalse(
            w.approved(self.ctx.state, follow["commit"], follow["base_sha"])
        )

    def object_api(self, corrupt=False, truncated=False):
        original = self.gh.api

        def api(path, *args, **kwargs):
            if "/git/trees/" in path:
                sha = path.split("/git/trees/")[1].split("?")[0]
                tree = []
                for row in w.git("ls-tree", "-rz", "--full-tree", sha).split("\0"):
                    if not row:
                        continue
                    meta, name = row.split("\t", 1)
                    mode, kind, oid = meta.split()
                    tree.append({"path": name, "mode": mode, "type": kind, "sha": oid})
                return {"sha": sha, "tree": tree, "truncated": truncated}
            if "/git/blobs/" in path:
                sha = path.rsplit("/", 1)[-1]
                blob = subprocess.run(
                    ["git", "cat-file", "blob", sha], capture_output=True, check=True
                ).stdout
                return {
                    "sha": sha,
                    "encoding": "base64",
                    "content": base64.b64encode(
                        blob + (b"changed" if corrupt else b"")
                    ).decode(),
                }
            return original(path, *args, **kwargs)

        return mock.patch.object(self.gh, "api", side_effect=api)

    def test_initial_verification_cannot_carry_missing_source_report(self):
        self.start()
        first, fid = self.finding()
        self.dispose(fid)
        self.grant()
        (self.ctx.directory / (first["id"] + ".json")).unlink()
        before = copy.deepcopy(self.ctx.state["reviews"])
        with self.assertRaisesRegex(w.Error, "every source receipt"):
            self.ctx.review("one", "code", "Verify identified claims", verifies=[fid])
        with self.assertRaisesRegex(w.Error, "prior raw report unavailable"):
            self.ctx.review(
                "one",
                "code",
                "Verify identified claims",
                scope="initial",
                prior=[first["id"]],
                verifies=[fid],
                material=True,
            )
        self.assertEqual(before, self.ctx.state["reviews"])

    def test_license_continuity_and_ci_use_same_real_objects(self):
        self.start()
        original = b"#!/usr/bin/env python3\nprint(1)\n"
        self.commit(original)
        self.grant()
        r, _ = self.review()
        original_receipt = copy.deepcopy(r)
        self.commit(b"#!/usr/bin/env python3\n" + w.LICENSE_HEADER + b"print(1)\n")
        head, base = w.git("rev-parse", "HEAD"), r["base_sha"]
        self.assertFalse(w.approved(self.ctx.state, head, base))
        self.ctx.continuity("one", r["id"])
        self.assertEqual(original_receipt, self.ctx.state["reviews"][-1])
        self.checkpoint()
        self.ctx.integrate(
            "one", r["id"], "Exact license header insertion and current tests verified."
        )
        evidence = {
            "repo": w.board.REPO,
            "issue": 43,
            "relation": "part of",
            "head": head,
            "base": base,
            "checkpoint": self.ctx.state["_comment"],
            "pending": False,
        }
        self.gh.pr_write(
            None,
            "Synthetic change",
            "Part of #43\n\n" + w.block(w.PR_MARK, evidence),
            "issue-43",
            "main",
            False,
        )
        with self.object_api():
            self.assertEqual(
                w.license_continuity(r["commit"], head, base),
                w.license_continuity(r["commit"], head, base, self.gh),
            )
            self.assertEqual(
                w.validate_pr(88, self.gh), "issue and review contract verified"
            )
        with (
            self.object_api(corrupt=True),
            self.assertRaisesRegex(w.Error, "object ID"),
        ):
            w.validate_pr(88, self.gh)
        with (
            self.object_api(truncated=True),
            self.assertRaisesRegex(w.Error, "complete Git tree"),
        ):
            w.validate_pr(88, self.gh)
        self.ctx.state["continuity"]["proof"]["files"] = ["not-the-actual-delta.py"]
        with self.assertRaisesRegex(w.Error, "actual Git objects"):
            w.readiness(self.ctx.state, head, base, self.gh, 43)

    def test_encoding_cookie_bom_executable_and_mode_changes_rejected_locally_and_in_ci(
        self,
    ):
        self.start()
        base = w.git("rev-parse", "origin/main")
        cases = [
            (
                b'# coding: latin-1\nvalue="\xc3\xa9"\n',
                w.LICENSE_HEADER + b'# coding: latin-1\nvalue="\xc3\xa9"\n',
            ),
            (
                b'#!/usr/bin/python3\n# coding: latin-1\nvalue="\xc3\xa9"\n',
                b"#!/usr/bin/python3\n"
                + w.LICENSE_HEADER
                + b'# coding: latin-1\nvalue="\xc3\xa9"\n',
            ),
            (b"\xef\xbb\xbfprint(1)\n", w.LICENSE_HEADER + b"\xef\xbb\xbfprint(1)\n"),
            (b"print(1)\n", w.LICENSE_HEADER + b"print(2)\n"),
        ]
        for source, target in cases:
            with self.subTest(source=source):
                self.commit(source)
                old = w.git("rev-parse", "HEAD")
                self.commit(target)
                head = w.git("rev-parse", "HEAD")
                with self.assertRaises(w.Error):
                    w.license_continuity(old, head, base)
                with self.object_api(), self.assertRaises(w.Error):
                    w.license_continuity(old, head, base, self.gh)
        self.commit(b"print(3)\n")
        old = w.git("rev-parse", "HEAD")
        (self.root / "program.py").chmod(0o755)
        self.commit(w.LICENSE_HEADER + b"print(3)\n")
        head = w.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(w.Error, "paths/modes"):
            w.license_continuity(old, head, base)
        with self.object_api(), self.assertRaisesRegex(w.Error, "paths/modes"):
            w.license_continuity(old, head, base, self.gh)

    def test_added_files_docs_and_renames_do_not_inherit_approval(self):
        self.start()
        base = w.git("rev-parse", "origin/main")
        self.commit(b"print(1)\n")
        old = w.git("rev-parse", "HEAD")
        self.commit(b"new documentation\n", "README.md")
        with self.assertRaisesRegex(w.Error, "add, delete or rename"):
            w.license_continuity(old, w.git("rev-parse", "HEAD"), base)
        old = w.git("rev-parse", "HEAD")
        w.git("mv", "program.py", "renamed.py")
        w.git("commit", "-qm", "rename")
        with self.assertRaises(w.Error):
            w.license_continuity(old, w.git("rev-parse", "HEAD"), base)


if __name__ == "__main__":
    unittest.main()
