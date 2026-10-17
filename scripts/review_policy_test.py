# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Policy transitions with synthetic findings, fake GitHub and real Git inputs."""

import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

import codex_review
import review_policy as policy
import work_issue as w
import work_issue_test as fixtures


class PolicyWorkflow(unittest.TestCase):
    setUp = fixtures.Workflow.setUp
    start = fixtures.Workflow.start
    ready = fixtures.Workflow.ready
    receipt = fixtures.Workflow.receipt

    def review(
        self, scope="initial", prior=None, verifies=None, result=None, material=False
    ):
        original = subprocess.run
        result = result or {"verdict": "approve", "findings": []}
        seen = []

        def invoke(args, **kw):
            if len(args) > 1 and str(args[1]).endswith("codex_review.py"):
                seen.append(args)
                r = self.ctx.state["reviews"][-1]
                payload = {
                    "codex": {"status": 0},
                    "result": result,
                    "inputs": {
                        "head": r["commit"],
                        "base": r["base_sha"],
                        "merge_base": r["merge_base"],
                    },
                }
                kw["stdout"].write(json.dumps(payload))
                return subprocess.CompletedProcess(args, 0)
            return original(args, **kw)

        with mock.patch.object(subprocess, "run", side_effect=invoke):
            self.ctx.review(
                "one",
                "code",
                "synthetic workflow behavior",
                scope,
                prior,
                verifies,
                "Bounded change; review affected behavior and tests.",
                material,
            )
        return self.ctx.state["reviews"][-1], seen[0]

    def checkpoint(self):
        self.ctx.checkpoint(
            "one",
            {
                "completed": "synthetic change",
                "verification": "affected regression suite passed",
                "blockers": "",
                "next": "integration validation",
            },
        )

    def finding(self, severity="medium"):
        r, _ = self.review(
            result={
                "verdict": "needs-attention",
                "findings": [
                    {
                        "severity": severity,
                        "confidence": 0.4,
                        "title": "Synthetic claim",
                        "body": "Synthetic evidence only",
                    }
                ],
            }
        )
        return r, r["finding_ids"][0]

    def dispose(self, fid, category="blocking", status="verified", **extra):
        self.ctx.dispose(
            "one",
            fid,
            {
                "category": category,
                "status": status,
                "evidence": "Synthetic test and code trace establish the disposition.",
                "consequence": "Acceptance invariant is satisfied for these inputs.",
                **extra,
            },
        )

    def commit(self, text="fix"):
        (self.root / "file").write_text(text)
        w.git("add", "file")
        w.git("commit", "-qm", text)

    def test_nonblocking_findings_do_not_require_another_round(self):
        self.start()
        r, fid = self.finding()
        self.dispose(fid, "nonblocking", "deferred")
        self.checkpoint()
        self.ctx.integrate(
            "one", r["id"], "Optional refinement does not affect required behavior."
        )
        w.readiness(self.ctx.state, r["commit"], r["base_sha"], self.gh, 43)
        self.assertEqual(r["outcome"], "needs-attention")
        self.assertEqual(w.completed(self.ctx.state, "code"), 1)
        self.assertNotIn("Synthetic claim", w.checkpoint_body(self.ctx.state))
        self.assertNotIn("Synthetic evidence only", w.checkpoint_body(self.ctx.state))

    def test_blocker_and_high_impact_concern_cannot_be_relabelled_away(self):
        self.start()
        r, fid = self.finding("high")
        with self.assertRaisesRegex(w.Error, "reclassification"):
            self.dispose(fid, "nonblocking", "deferred")
        self.dispose(fid, "concern", "investigate")
        with self.assertRaisesRegex(w.Error, "reclassification"):
            self.dispose(fid, "independent", "deferred", tracking="#42")
        self.assertFalse(w.approved(self.ctx.state, r["commit"], r["base_sha"]))
        self.dispose(fid, "concern", "refuted")
        self.assertTrue(w.approved(self.ctx.state, r["commit"], r["base_sha"]))

    def test_fixed_unverified_and_empty_evidence_are_not_approval(self):
        self.start()
        r, fid = self.finding()
        self.dispose(fid, status="fixed-unverified")
        self.assertFalse(w.approved(self.ctx.state, r["commit"], r["base_sha"]))
        with self.assertRaisesRegex(w.Error, "evidence"):
            self.ctx.dispose(
                "one",
                fid,
                {
                    "category": "blocking",
                    "status": "verified",
                    "evidence": "",
                    "consequence": "fine",
                },
            )

    def test_initial_fix_followup_ready_in_two_reviews(self):
        self.start()
        first, fid = self.finding()
        self.dispose(fid, status="fixed-unverified")
        self.commit()
        self.dispose(fid)
        second, args = self.review("follow-up", [first["id"]], [fid])
        self.assertIn("Scope: follow-up", args[-1])
        self.assertIn(first["id"], args[-1])
        self.assertIn(fid, args[-1])
        self.assertNotIn("--follow-up", args)
        self.checkpoint()
        self.ctx.integrate(
            "one", second["id"], "Bounded fix verified against unchanged target."
        )
        w.readiness(self.ctx.state, second["commit"], second["base_sha"], self.gh, 43)
        self.assertEqual(w.completed(self.ctx.state, "code"), 2)
        self.assertEqual(first["outcome"], "needs-attention")

    def test_repeated_finding_retains_id_and_reopens_investigation(self):
        self.start()
        first, fid = self.finding()
        self.dispose(fid)
        result = {
            "verdict": "needs-attention",
            "findings": [
                {
                    "title": fid + " still applies",
                    "severity": "medium",
                    "confidence": 0.9,
                }
            ],
        }
        second, _ = self.review("follow-up", [first["id"]], [fid], result)
        self.assertEqual(second["finding_ids"], [fid])
        self.assertEqual(len(self.ctx.state["findings"][fid]["sources"]), 2)
        self.assertFalse(
            w.approved(self.ctx.state, second["commit"], second["base_sha"])
        )
        self.ctx.release("one")
        self.ctx.path.unlink()
        later = w.Task(43, self.gh)
        later.start("two", here=True)
        self.assertEqual(later.state["findings"], self.ctx.state["findings"])

    def test_behind_branch_reviews_without_integration_approval(self):
        self.start()
        base = w.git("rev-parse", "HEAD")
        w.git("switch", "-qc", "target")
        self.commit("target change")
        target = w.git("rev-parse", "HEAD")
        w.git("update-ref", "refs/remotes/origin/main", target)
        w.git("switch", "-q", "issue-43")
        with mock.patch.object(w, "fresh_base", return_value=target):
            r, _ = self.review()
            self.assertEqual(r["merge_base"], base)
            self.assertEqual(r["base_sha"], target)
            self.checkpoint()
            with self.assertRaisesRegex(w.Error, "not incorporated"):
                self.ctx.integrate("one", r["id"], "Cannot claim integration")
        self.assertNotIn("integration", self.ctx.state)

    def test_changed_target_requires_integration_scope_and_actual_inputs(self):
        self.start()
        first, _ = self.review()
        self.commit("target")
        target = w.git("rev-parse", "HEAD")
        w.git("update-ref", "refs/remotes/origin/main", target)
        with mock.patch.object(w, "fresh_base", return_value=target):
            with self.assertRaisesRegex(w.Error, "target changed"):
                self.review("follow-up", [first["id"]])
            second, args = self.review("integration", [first["id"]])
            self.assertIn("Scope: integration", args[-1])
            self.assertEqual(second["inputs"]["base"], target)
            self.checkpoint()
            self.ctx.integrate(
                "one", second["id"], "Target callers and configuration checked."
            )
            policy.integration_current(self.ctx.state, target, target)
            with self.assertRaisesRegex(w.Error, "stale"):
                policy.integration_current(self.ctx.state, "a" * 40, target)
        self.assertEqual(first["commit"], first["inputs"]["head"])

    def test_material_change_and_missing_prior_context_require_initial(self):
        self.start()
        first, args = self.review()
        self.assertIn("Scope: initial", args[-1])
        with self.assertRaisesRegex(w.Error, "material"):
            self.review("follow-up", [first["id"]], material=True)
        (self.ctx.directory / (first["id"] + ".json")).unlink()
        with self.assertRaisesRegex(w.Error, "unavailable"):
            self.review("follow-up", [first["id"]])
        self.assertEqual(w.completed(self.ctx.state, "code"), 1)

    def test_unexplained_revision_invalidates_dispositions_and_integration(self):
        self.start()
        r, fid = self.finding()
        self.dispose(fid)
        self.checkpoint()
        self.ctx.integrate("one", r["id"], "Exact input checked.")
        self.commit()
        head = w.git("rev-parse", "HEAD")
        self.assertFalse(policy.findings_ready(self.ctx.state, head, r["base_sha"]))
        with self.assertRaisesRegex(w.Error, "stale"):
            policy.integration_current(self.ctx.state, head, r["base_sha"])

    def test_v1_migration_preserves_history_counts_and_no_forged_permissions(self):
        self.start()
        old = {
            "id": "old",
            "phase": "code",
            "commit": w.git("rev-parse", "HEAD"),
            "base": "origin/main",
            "base_sha": w.git("rev-parse", "origin/main"),
            "status": "completed",
            "outcome": "needs-attention",
            "unresolved": 2,
            "round": 1,
        }
        self.ctx.state.update(version=1, reviews=[old], authorizations=[])
        self.ctx.save()
        self.ctx.publish()
        self.ctx.migrate("one")
        self.assertEqual(self.ctx.state["reviews"], [old])
        self.assertEqual(len(self.ctx.state["findings"]), 2)
        self.assertFalse(
            policy.findings_ready(self.ctx.state, old["commit"], old["base_sha"])
        )
        self.assertEqual(self.ctx.state["authorizations"], [])
        policy.check_ledger(
            self.ctx.state, lambda *args: self.fail("forged permission")
        )
        self.ctx.release("one")
        self.ctx.path.unlink()
        later = w.Task(43, self.gh)
        later.start("two", here=True)
        self.assertEqual(later.state["reviews"], [old])
        later.state["reviews"][0]["outcome"] = "approve"
        with self.assertRaisesRegex(w.Error, "historical"):
            policy.check_ledger(later.state, lambda *args: None)

    def test_migration_lost_response_reconciles_and_pending_must_recover(self):
        self.start()
        self.ctx.state["version"] = 1
        self.ctx.save()
        self.ctx.publish()
        self.gh.lose_comment = True
        self.ctx.migrate("one")
        self.ctx.migrate("one")
        self.assertEqual(len(self.gh.notes), 1)
        legacy = {"version": 1, "reviews": [{"id": "p", "status": "pending"}]}
        with self.assertRaisesRegex(w.Error, "pending"):
            policy.migrate(legacy)

    def test_policy_one_rounds_four_five_remain_historical(self):
        self.start()
        old = []
        for i in range(1, 6):
            r = self.receipt(number=i)
            for key in (
                "policy_version",
                "receipt_version",
                "scope",
                "prior",
                "verifies",
                "rationale",
                "merge_base",
                "inputs",
                "finding_ids",
                "result_digest",
            ):
                r.pop(key, None)
            old.append(r)
        state = policy.migrate(
            {**self.ctx.state, "version": 1, "reviews": old, "authorizations": []}
        )
        policy.check_ledger(
            state, lambda *args: self.fail("retrospective authorization requested")
        )
        self.assertEqual(policy.count(state, "code"), 5)
        with self.assertRaisesRegex(w.Error, "round 6"):
            policy.budget(state, "code")
        self.assertEqual(state["reviews"], old)

    def test_local_and_ci_budget_rules_agree_and_triage_is_not_permission(self):
        self.start()
        self.ctx.state["reviews"] = [self.receipt(number=i) for i in range(1, 4)]
        self.ctx.state["triage"] = "not an authorization"
        with self.assertRaisesRegex(w.Error, "authorization"):
            policy.budget(self.ctx.state, "code")
        self.ctx.state["reviews"].append(self.receipt(number=4))
        with self.assertRaisesRegex(w.Error, "authorization"):
            policy.check_ledger(self.ctx.state, lambda *args: None)
        self.ctx.state["authorizations"] = [
            {"phase": "code", "round": 4, "comment": 99}
        ]
        seen = []
        policy.check_ledger(self.ctx.state, lambda *args: seen.append(args))
        self.assertEqual(seen, [("code", 4, 99, "authorize")])

    def test_scoped_ceiling_prevents_spending_unused_generic_budget(self):
        self.start()
        self.ctx.state["reviews"] = [self.receipt(number=1), self.receipt(number=2)]
        self.ctx.state["ceilings"] = {
            "code": {"phase": "code", "round": 2, "comment": 99}
        }
        with self.assertRaisesRegex(w.Error, "scoped allowance"):
            policy.budget(self.ctx.state, "code")
        self.ctx.state["reviews"].append(self.receipt(number=3))
        with self.assertRaisesRegex(w.Error, "allowance"):
            policy.check_ledger(self.ctx.state, lambda *args: None)

    def test_failed_attempts_are_bounded_and_missing_output_never_approves(self):
        self.start()
        for i in range(2):
            r = self.receipt(number=i + 1)
            r.update(id="fail" + str(i), status="pending")
            self.ctx.state["reviews"].append(r)
            self.ctx.save()
            self.ctx.publish()
            with self.assertRaisesRegex(w.Error, "no complete"):
                self.ctx.recover("one")
            self.ctx.recover("one", failed=True)
        self.assertEqual(w.completed(self.ctx.state, "code"), 0)
        with self.assertRaisesRegex(w.Error, "failed attempts"):
            policy.budget(self.ctx.state, "code")

    def test_wrong_input_report_is_not_a_completed_review(self):
        self.start()
        r = self.receipt()
        r.update(status="pending", id="bad-inputs")
        self.ctx.state["reviews"] = [r]
        self.ctx.save()
        self.ctx.publish()
        w.atomic(
            self.ctx.directory / "bad-inputs.json",
            {
                "codex": {"status": 0},
                "result": {"verdict": "approve", "findings": []},
                "inputs": {**r["inputs"], "head": "a" * 40},
            },
        )
        with self.assertRaisesRegex(w.Error, "no complete"):
            self.ctx.recover("one")
        self.ctx.recover("one", failed=True)
        self.assertEqual(w.completed(self.ctx.state, "code"), 0)

    def test_pending_draft_can_precede_verification_and_review(self):
        self.start()
        original = w.run
        with mock.patch.object(
            w,
            "run",
            side_effect=lambda a, **kw: (
                "" if a[:2] == ["git", "push"] else original(a, **kw)
            ),
        ):
            self.ctx.submit("one", "Draft", "Work underway", kind="part", pending=True)
        self.assertTrue(self.gh.pulls[0]["draft"])
        with self.assertRaisesRegex(w.Error, "review"):
            w.validate_pr(88, self.gh)

    def test_public_finding_exception_requires_exact_owner_and_inputs(self):
        self.start()
        r, fid = self.finding()
        with self.assertRaisesRegex(w.Error, "exception"):
            self.dispose(fid, status="excepted", comment=99)
        self.gh.notes.append(
            {
                "id": 99,
                "body": f"work-issue finding-exception {w.board.REPO}#43 {fid} {r['commit']} {r['base_sha']}",
                "user": {"login": w.board.OWNER},
                "editor": w.board.OWNER,
            }
        )
        self.dispose(fid, status="excepted", comment=99)
        self.checkpoint()
        self.ctx.integrate("one", r["id"], "Exact exception checked.")
        self.gh.notes[-1]["editor"] = "someone-else"
        with self.assertRaisesRegex(w.Error, "untrusted"):
            w.readiness(self.ctx.state, r["commit"], r["base_sha"], self.gh, 43)

    def test_dispositions_and_raw_reports_never_appear_as_ci_artifacts(self):
        self.start()
        r, _ = self.finding()
        self.assertEqual(
            (self.ctx.directory / (r["id"] + ".json")).stat().st_mode & 0o777, 0o600
        )
        workflow = (
            Path(w.__file__).parent.parent / ".github/workflows/issue-contract.yml"
        ).read_text()
        self.assertIn("ref: main", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("pull_request.head", workflow)

    def test_wrapper_snapshot_pins_head_even_if_original_branch_moves(self):
        self.start()
        before = w.git("rev-parse", "HEAD")
        with codex_review.snapshot(before) as tree:
            self.commit("later")
            actual = w.run(["git", "-C", str(tree), "rev-parse", "HEAD"])
            self.assertEqual(actual, before)
            self.assertEqual((tree / "file").read_text(), "base")
        self.assertNotEqual(w.git("rev-parse", "HEAD"), before)

    def test_fresh_base_retains_fetch_failure_and_allows_behind(self):
        self.fetch.stop()
        with mock.patch.object(codex_review, "behind", return_value=2):
            self.assertEqual(
                w.fresh_base("origin/main"), w.git("rev-parse", "origin/main")
            )
        with mock.patch.object(
            codex_review, "behind", side_effect=codex_review.BaseUnknown("fetch failed")
        ):
            with self.assertRaises(codex_review.BaseUnknown):
                w.fresh_base("origin/main")

    def test_repeated_claim_escalation_preserves_observations_and_blocks_deferral(self):
        self.start()
        first, fid = self.finding()
        self.dispose(fid, "nonblocking", "deferred")
        original = dict(self.ctx.state["findings"][fid]["history"][0])
        second, _ = self.review(
            "follow-up",
            [first["id"]],
            [fid],
            {
                "verdict": "needs-attention",
                "findings": [
                    {
                        "title": fid + " escalated synthetic concern",
                        "severity": "high",
                        "confidence": 0.7,
                    }
                ],
            },
        )
        f = self.ctx.state["findings"][fid]
        self.assertEqual([o["severity"] for o in f["observations"]], ["medium", "high"])
        self.assertEqual([o["confidence"] for o in f["observations"]], [0.4, 0.7])
        self.assertEqual(f["history"][0], original)
        with self.assertRaisesRegex(w.Error, "reclassification"):
            self.dispose(fid, "nonblocking", "deferred")
        self.assertFalse(
            w.approved(self.ctx.state, second["commit"], second["base_sha"])
        )
        self.dispose(fid, "concern", "refuted")
        self.assertTrue(
            w.approved(self.ctx.state, second["commit"], second["base_sha"])
        )

    def test_retry_grant_cannot_be_rebound_to_additional_failures(self):
        self.start()
        for i in range(2):
            r = self.receipt(number=i + 1)
            r.update(id="failure" + str(i), status="failed", outcome="unavailable")
            self.ctx.state["reviews"].append(r)
        self.ctx.save()
        self.ctx.publish()
        ids, _ = policy.failed_attempts(self.ctx.state, "code")
        binding = policy.digest(ids)
        self.gh.notes.append(
            {
                "id": 99,
                "body": f"work-issue retry {w.board.REPO}#43 code 1 {binding}",
                "user": {"login": w.board.OWNER},
                "editor": w.board.OWNER,
            }
        )
        self.ctx.authorize("one", "code", 1, 99, "retry")
        first_grant = dict(self.ctx.state["retry_authorizations"]["code"])
        self.ctx.authorize("one", "code", 1, 99, "retry")
        self.assertEqual(len(self.ctx.state["retry_history"]), 1)
        r = self.receipt()
        r.update(
            id="failure2", status="failed", outcome="unavailable", retry=first_grant
        )
        self.ctx.state["reviews"].append(r)
        self.ctx.save()
        self.ctx.publish()
        with self.assertRaisesRegex(w.Error, "authorization"):
            self.ctx.authorize("one", "code", 1, 99, "retry")
        with self.assertRaisesRegex(w.Error, "failed attempts"):
            policy.budget(self.ctx.state, "code")
        # The old invocation was authorized; a fourth one cannot reuse its grant.
        check = lambda ph, rd, c, kind, binding=None: w.authorize_check(
            self.gh, 43, ph, rd, c, kind, binding
        )
        policy.check_ledger(self.ctx.state, check)
        fourth = self.receipt()
        fourth.update(id="fourth", retry=first_grant)
        self.ctx.state["reviews"].append(fourth)
        with self.assertRaisesRegex(w.Error, "reused"):
            policy.check_ledger(self.ctx.state, check)
        fourth["retry"] = {
            **first_grant,
            "failed_ids": ids + ["failure2"],
            "binding": policy.digest(ids + ["failure2"]),
        }
        with self.assertRaisesRegex(w.Error, "authorization"):
            policy.check_ledger(self.ctx.state, check)

    def test_retry_invocation_and_ci_use_the_exact_bound_grant(self):
        self.start()
        for i in range(2):
            r = self.receipt()
            r.update(id="failed" + str(i), status="failed", outcome="unavailable")
            self.ctx.state["reviews"].append(r)
        self.ctx.save()
        self.ctx.publish()
        ids, _ = policy.failed_attempts(self.ctx.state, "code")
        self.gh.notes.append(
            {
                "id": 99,
                "body": f"work-issue retry {w.board.REPO}#43 code 1 {policy.digest(ids)}",
                "user": {"login": w.board.OWNER},
                "editor": w.board.OWNER,
            }
        )
        self.ctx.authorize("one", "code", 1, 99, "retry")
        r, _ = self.review()
        self.assertEqual(r["retry"]["failed_ids"], ids)
        self.checkpoint()
        self.ctx.integrate("one", r["id"], "Successful bounded retry checked.")
        w.readiness(self.ctx.state, r["commit"], r["base_sha"], self.gh, 43)

    def test_initial_plan_cannot_replace_material_initial_code_review(self):
        self.start()
        first, _ = self.review()
        self.commit()
        second, _ = self.review("follow-up", [first["id"]])
        plan = self.receipt("plan")
        plan["id"] = "plan-current"
        self.ctx.state["reviews"].append(plan)
        self.checkpoint()
        with self.assertRaisesRegex(w.Error, "implementation"):
            self.ctx.integrate(
                "one", plan["id"], "Material behavior changed.", material=True
            )
        with self.assertRaisesRegex(w.Error, "initial"):
            self.ctx.integrate(
                "one", second["id"], "Material behavior changed.", material=True
            )
        third, _ = self.review(material=True)
        self.checkpoint()
        self.ctx.integrate(
            "one",
            third["id"],
            "Renewed initial code review covers material change.",
            material=True,
        )

    def test_pending_plan_prevents_readiness_of_earlier_code_receipt(self):
        self.ready()
        r = self.receipt("plan")
        r.update(id="pending-plan", status="pending")
        self.ctx.state["reviews"].append(r)
        self.assertFalse(w.approved(self.ctx.state, r["commit"], r["base_sha"]))

    def test_invalid_assembled_relationship_never_pushes_or_creates_pr(self):
        self.start()
        original = w.run
        for body in [
            "Fix #43",
            "This step fixes #999.",
            "Closed: #43",
            "Resolve #43",
            "Part of #43\nFixes #44",
        ]:
            with (
                mock.patch.object(
                    w,
                    "run",
                    side_effect=lambda a, **kw: (
                        "" if a[:2] == ["git", "push"] else original(a, **kw)
                    ),
                ) as command,
                mock.patch.object(self.gh, "pr_write") as write,
            ):
                with self.assertRaisesRegex(w.Error, "relationship"):
                    self.ctx.submit("one", "Partial", body, kind="part", pending=True)
                self.assertFalse(
                    any(
                        c.args[0][:2] == ["git", "push"] for c in command.call_args_list
                    )
                )
                write.assert_not_called()
        self.assertEqual(self.gh.pulls, [])

    def test_final_stacked_pr_can_finish_each_carried_issue(self):
        self.ready()
        original = w.run
        with mock.patch.object(
            w,
            "run",
            side_effect=lambda a, **kw: (
                "" if a[:2] == ["git", "push"] else original(a, **kw)
            ),
        ):
            self.ctx.submit("one", "Final stack", "Fixes #43\nFixes #44")
        p = self.gh.pulls[0]
        p["merged_at"] = "today"
        p["merge_commit_sha"] = w.git("rev-parse", "HEAD")
        api = self.gh.api
        with mock.patch.object(
            self.gh,
            "api",
            side_effect=lambda path, *a, **kw: (
                {**self.gh.issue, "number": 44}
                if path.endswith("/issues/44")
                else api(path, *a, **kw)
            ),
        ):
            self.assertEqual(w.finish(43, self.gh), 88)
            self.assertEqual(w.finish(44, self.gh), 88)
        self.assertEqual(
            w.validate_pr(88, self.gh), "issue and review contract verified"
        )
        self.assertIsNone(w.relation("Fixes #43\nFixed #43\nFixes #44", 43))

    def test_released_v1_returning_clone_adopts_remote_migration(self):
        self.start()
        self.ctx.state["version"] = 1
        self.ctx.save()
        self.ctx.publish()
        self.ctx.release("one")
        old_state = json.loads(self.ctx.path.read_text())
        # Another authorized session migrates the released remote checkpoint.
        later = w.Task(43, self.gh)
        later.start("two", here=True)
        later.release("two")
        w.atomic(self.ctx.path, old_state)
        returning = w.Task(43, self.gh)
        returning.start("three", here=True)
        self.assertEqual(returning.state["version"], 2)
        self.assertEqual(returning.state["reviews"], old_state["reviews"])

    def test_ci_rejects_docs_phase_for_executable_changes(self):
        self.ready()
        self.ctx.state["reviews"][-1]["phase"] = "docs"
        self.ctx.save()
        self.ctx.publish()
        r = self.ctx.state["reviews"][-1]
        token = {
            "repo": w.board.REPO,
            "issue": 43,
            "relation": "fixes",
            "head": r["commit"],
            "base": r["base_sha"],
            "checkpoint": self.ctx.state["_comment"],
            "pending": False,
        }
        self.gh.pr_write(
            None,
            "Change",
            "Fixes #43\n\n" + w.block(w.PR_MARK, token),
            "issue-43",
            "main",
            False,
        )
        api = self.gh.api
        with mock.patch.object(
            self.gh,
            "api",
            side_effect=lambda path, *a, **kw: (
                [{"filename": "scripts/helper.py"}]
                if "/files?" in path
                else api(path, *a, **kw)
            ),
        ):
            with self.assertRaisesRegex(w.Error, "executable"):
                w.validate_pr(88, self.gh)


if __name__ == "__main__":
    unittest.main()
