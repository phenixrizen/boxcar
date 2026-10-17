# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Policy transitions with synthetic findings, fake GitHub and real Git inputs."""

import copy
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

    def test_policy_two_rejects_cross_phase_sources_before_invocation(self):
        self.start()
        plan = self.receipt("plan")
        plan["outcome"] = "needs-attention"
        self.ctx.state["reviews"].append(plan)
        policy.register_result(
            self.ctx.state,
            plan,
            {
                "verdict": "needs-attention",
                "findings": [{"title": "Synthetic plan claim", "severity": "medium"}],
            },
        )
        self.ctx.save()
        self.ctx.publish()
        with self.assertRaisesRegex(policy.Error, "another phase"):
            self.review("initial", [plan["id"]], plan["finding_ids"])
        self.assertEqual(self.ctx.state["reviews"], [plan])
        self.assertEqual(policy.count(self.ctx.state, "code"), 0)

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

    def test_revoked_retry_permission_prevents_any_new_attempt_or_invocation(self):
        self.start()
        for i in range(2):
            r = self.receipt()
            r.update(id="failure" + str(i), status="failed", outcome="unavailable")
            self.ctx.state["reviews"].append(r)
        self.ctx.save()
        self.ctx.publish()
        ids, _ = policy.failed_attempts(self.ctx.state, "code")
        note = {
            "id": 99,
            "body": f"work-issue retry {w.board.REPO}#43 code 1 {policy.digest(ids)}",
            "user": {"login": w.board.OWNER},
            "editor": w.board.OWNER,
        }
        self.gh.notes.append(note)
        self.ctx.authorize("one", "code", 1, 99, "retry")
        original = subprocess.run
        for revocation in ("deleted", "changed", "nonowner-editor"):
            self.gh.notes = [c for c in self.gh.notes if c["id"] != 99]
            if revocation != "deleted":
                self.gh.notes.append(
                    {
                        **note,
                        "body": "revoked" if revocation == "changed" else note["body"],
                        "editor": "someone-else"
                        if revocation == "nonowner-editor"
                        else w.board.OWNER,
                    }
                )

            def guarded(args, **kw):
                if len(args) > 1 and str(args[1]).endswith("codex_review.py"):
                    self.fail("reviewer invoked after authorization revocation")
                return original(args, **kw)

            with mock.patch.object(subprocess, "run", side_effect=guarded):
                with self.assertRaises(w.Error):
                    self.ctx.review("one", "code", "synthetic retry")
            self.assertEqual(len(self.ctx.state["reviews"]), 2)
            self.assertFalse(
                any(r["status"] == "pending" for r in self.ctx.state["reviews"])
            )

    def test_cli_docs_classification_checks_executable_rename_sources(self):
        (self.root / "script.py").write_text('print("synthetic")\n')
        w.git("add", "script.py")
        w.git("commit", "-qm", "executable baseline")
        w.git("update-ref", "refs/remotes/origin/main", "HEAD")
        w.git("mv", "script.py", "script.py.md")
        w.git("commit", "-qm", "rename")
        self.start()
        original = subprocess.run

        def guarded(args, **kw):
            if len(args) > 1 and str(args[1]).endswith("codex_review.py"):
                self.fail("docs reviewer invoked for removed executable")
            return original(args, **kw)

        with mock.patch.object(subprocess, "run", side_effect=guarded):
            with self.assertRaisesRegex(w.Error, "executable"):
                self.ctx.review("one", "docs", "rename classification")
        self.assertEqual(self.ctx.state["reviews"], [])

    def test_ci_docs_classification_checks_executable_rename_sources(self):
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
            "Rename",
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
                [
                    {
                        "filename": "docs/board.py.md",
                        "previous_filename": "scripts/board.py",
                        "status": "renamed",
                    }
                ]
                if "/files?" in path
                else api(path, *a, **kw)
            ),
        ):
            with self.assertRaisesRegex(w.Error, "executable"):
                w.validate_pr(88, self.gh)


class DeliverablePolicy(unittest.TestCase):
    """Pure ledger tests; synthetic claims never need GitHub or a model."""

    def setUp(self):
        self.state = {"version": 2, "reviews": [], "findings": {}, "authorizations": []}
        self.grants = {}

    def grant_check(self, phase, round_, comment, kind, binding=None):
        self.assertEqual(self.grants[comment], (phase, round_, kind, binding))

    def begin(self, ident="change", comment=10):
        self.state = policy.begin_deliverable(
            self.state, ident, "One coherent outcome", "Affected tests pass", comment
        )
        d = self.state["deliverables"][-1]
        self.grants[comment] = (
            "deliverable",
            len(self.state["deliverables"]),
            "deliverable",
            d["binding"],
        )
        return d

    def add(
        self,
        phase="code",
        scope=None,
        head="a" * 40,
        base="b" * 40,
        result=None,
        material=False,
        prior=None,
    ):
        prior_phase = [
            r
            for r in self.state["reviews"]
            if r["phase"] == phase and r["status"] == "completed"
        ]
        same = [
            r
            for r in prior_phase
            if r.get("deliverable") == self.state.get("active_deliverable")
        ]
        scope = scope or ("follow-up" if same else "initial")
        result = result or {"verdict": "approve", "findings": []}
        r = {
            "id": "attempt-" + str(len(self.state["reviews"]) + 1),
            "phase": phase,
            "status": "completed",
            "round": policy.count(self.state, phase) + 1,
            "scope": scope,
            "commit": head,
            "base_sha": base,
            "merge_base": base,
            "inputs": {"head": head, "base": base, "merge_base": base},
            "outcome": result["verdict"],
            "rationale": "Relevant behavior and fixes checked.",
            "prior": prior if prior is not None else [r["id"] for r in prior_phase],
            "verifies": list(self.state["findings"]),
            "material_change": material,
            **policy.review_fields(self.state, phase),
        }
        self.state["reviews"].append(r)
        policy.register_result(self.state, r, result)
        return r

    def finding(self, severity="medium"):
        r = self.add(
            result={
                "verdict": "needs-attention",
                "findings": [
                    {
                        "title": "Synthetic behavior claim",
                        "severity": severity,
                        "confidence": 0.5,
                    }
                ],
            }
        )
        return r, r["finding_ids"][0]

    def settle(self, fid, category="blocking", status="verified", **extra):
        r = self.state["reviews"][-1]
        return policy.disposition(
            self.state,
            fid,
            {
                "category": category,
                "status": status,
                "evidence": "Synthetic regression and code trace.",
                "consequence": "Acceptance requirement remains satisfied.",
                **extra,
            },
            r["commit"],
            r["base_sha"],
        )

    def test_delivery_budget_preserves_lifetime_history_and_scoped_counts(self):
        for number in range(1, 6):
            self.add()
            if number > 3:
                self.state["authorizations"].append(
                    {"phase": "code", "round": number, "comment": number}
                )
                self.grants[number] = ("code", number, "authorize", None)
        previous = copy.deepcopy(self.state["reviews"])
        self.begin()
        for number in range(6, 9):
            self.assertEqual(policy.budget(self.state, "code"), number)
            r = self.add()
            self.assertEqual(r["deliverable_round"], number - 5)
        self.assertEqual(self.state["reviews"][:5], previous)
        policy.check_ledger(self.state, self.grant_check)
        with self.assertRaisesRegex(policy.Error, "round 9"):
            policy.budget(self.state, "code")
        self.add()
        with self.assertRaisesRegex(policy.Error, "authorization"):
            policy.check_ledger(self.state, self.grant_check)

    def test_docs_plans_have_independent_deliverable_ceilings(self):
        self.begin()
        for phase, limit in (("docs", 1), ("plan", 2), ("code", 3)):
            for _ in range(limit):
                policy.budget(self.state, phase)
                self.add(phase)
            with self.assertRaisesRegex(policy.Error, "authorization"):
                policy.budget(self.state, phase)
        policy.check_ledger(self.state, self.grant_check)

    def test_resume_branch_rebase_and_renaming_do_not_reset_budget(self):
        self.begin()
        for _ in range(3):
            self.add()
        before = copy.deepcopy(self.state)
        self.state = policy.begin_deliverable(
            self.state, "change", "One coherent outcome", "Affected tests pass", 10
        )
        self.assertEqual(self.state, before)
        for key, value in (
            ("branch", "other"),
            ("session", "new"),
            ("base_sha", "c" * 40),
        ):
            self.state[key] = value
            with self.assertRaisesRegex(policy.Error, "authorization"):
                policy.budget(self.state, "code")
        with self.assertRaisesRegex(policy.Error, "already used"):
            policy.begin_deliverable(
                self.state, "change", "Renamed outcome", "Affected tests pass", 10
            )
        renamed = policy.begin_deliverable(
            self.state, "renamed", "One coherent outcome", "Affected tests pass", 10
        )
        with self.assertRaises(AssertionError):
            policy.check_ledger(renamed, self.grant_check)

    def test_new_authorized_delivery_does_not_drop_old_blockers(self):
        self.begin()
        first, fid = self.finding("high")
        self.settle(fid, "concern", "investigate")
        original = copy.deepcopy(self.state["findings"])
        self.begin("another-outcome", 11)
        current = self.add()
        self.assertEqual(policy.count(self.state, "code"), 2)
        self.assertEqual(current["deliverable_round"], 1)
        self.assertEqual(self.state["findings"], original)
        self.assertFalse(
            policy.approved(self.state, current["commit"], current["base_sha"])
        )
        policy.check_ledger(self.state, self.grant_check)
        self.assertEqual(first["outcome"], "needs-attention")

    def test_boundary_digest_prevents_rewriting_previous_deliverable(self):
        self.begin()
        self.add()
        self.begin("next", 11)
        self.add()
        policy.check_ledger(self.state, self.grant_check)
        self.state["reviews"][0]["rationale"] = "Rewritten historical review"
        with self.assertRaisesRegex(policy.Error, "boundary changed"):
            policy.check_ledger(self.state, self.grant_check)

    def test_v1_migration_hashes_and_unclassified_findings_survive(self):
        legacy = {
            "id": "legacy",
            "phase": "code",
            "status": "completed",
            "round": 1,
            "outcome": "needs-attention",
            "unresolved": 2,
        }
        self.state.update(version=1, reviews=[legacy])
        self.begin()
        self.assertEqual(
            self.state["migration"]["history"]["legacy"], policy.digest(legacy)
        )
        self.assertEqual(
            self.state["deliverable_migration"]["history"]["legacy"],
            policy.digest(legacy),
        )
        self.assertEqual(self.state["reviews"], [legacy])
        self.assertEqual(len(self.state["findings"]), 2)
        policy.check_ledger(self.state, self.grant_check)
        self.assertFalse(policy.findings_ready(self.state, "a" * 40, "b" * 40))
        self.state["reviews"][0]["outcome"] = "approve"
        with self.assertRaisesRegex(policy.Error, "historical"):
            policy.check_ledger(self.state, self.grant_check)

    def test_old_ceiling_is_not_applied_to_new_deliverable_but_is_preserved(self):
        self.add()
        self.state["ceilings"] = {"code": {"round": 1, "comment": 9}}
        self.grants[9] = ("code", 1, "ceiling", None)
        self.begin()
        self.assertEqual(policy.budget(self.state, "code"), 2)
        self.add()
        policy.check_ledger(self.state, self.grant_check)
        self.assertEqual(self.state["ceilings"]["code"]["round"], 1)

    def test_later_narrow_deliverable_ceiling_limits_default_allowance(self):
        d = self.begin()
        self.add()
        d["ceilings"] = {"code": {"round": 1, "comment": 9}}
        self.grants[9] = ("code", 1, "ceiling", None)
        policy.check_ledger(self.state, self.grant_check)
        with self.assertRaisesRegex(policy.Error, "scoped allowance"):
            policy.budget(self.state, "code")
        self.add()
        with self.assertRaisesRegex(policy.Error, "allowance exceeded"):
            policy.check_ledger(self.state, self.grant_check)
        self.begin("new-deliverable", 11)
        with self.assertRaisesRegex(policy.Error, "allowance exceeded"):
            policy.check_ledger(self.state, self.grant_check)

    def test_material_renewal_requires_exact_owner_grant_without_reset(self):
        self.begin()
        self.add()
        renewed = self.add(scope="initial", material=True)
        with self.assertRaisesRegex(policy.Error, "authorization"):
            policy.validate_scope(self.state, renewed)
        self.state["authorizations"].append(
            {"phase": "code", "round": 2, "comment": 12}
        )
        self.grants[12] = ("code", 2, "authorize", None)
        policy.validate_scope(self.state, renewed, self.grant_check)
        policy.check_ledger(self.state, self.grant_check)
        self.assertEqual(policy.budget(self.state, "code"), 3)
        with self.assertRaisesRegex(policy.Error, "revoked"):
            policy.validate_scope(
                self.state,
                renewed,
                lambda *args: (_ for _ in ()).throw(policy.Error("revoked")),
            )

    def test_failed_attempts_do_not_count_or_erase_retry_limits(self):
        self.begin()
        for _ in range(2):
            r = self.add()
            r.update(status="failed", outcome="unavailable")
        self.assertEqual(policy.count(self.state, "code"), 0)
        self.assertEqual(policy.deliverable_count(self.state, "code"), 0)
        with self.assertRaisesRegex(policy.Error, "failed attempts"):
            policy.budget(self.state, "code")
        policy.check_ledger(self.state, self.grant_check)
        self.state["reviews"][-1]["status"] = "pending"
        with self.assertRaisesRegex(policy.Error, "pending"):
            policy.begin_deliverable(self.state, "next", "Another outcome", "Tests", 11)

    def test_migration_cannot_infer_original_context_for_historical_review(self):
        first, fid = self.finding()
        self.settle(fid)
        historical = self.add(head="c" * 40)
        before = copy.deepcopy(self.state["reviews"])
        self.begin()
        with self.assertRaisesRegex(policy.Error, "policy 3 review"):
            policy.carry_forward(
                self.state,
                historical["id"],
                [fid],
                "Migration cannot prove missing source context.",
            )
        self.assertEqual(self.state["reviews"], before)
        finding = self.state["findings"][fid]
        forged = {
            "receipt": historical["id"],
            "head": historical["commit"],
            "base": historical["base_sha"],
            "rationale": "Historical context not established.",
            "findings": {
                fid: {
                    "disposition": policy.digest(finding["history"][-1]),
                    "sources": policy.digest(finding["sources"]),
                }
            },
        }
        forged["id"] = policy.digest(forged)
        self.state["carry_forwards"] = [forged]
        with self.assertRaisesRegex(policy.Error, "policy 3 review"):
            policy.approved(self.state, historical["commit"], historical["base_sha"])
        self.state.pop("carry_forwards")
        current = self.add(head="c" * 40, prior=[first["id"], historical["id"]])
        policy.carry_forward(
            self.state,
            current["id"],
            [fid],
            "New review explicitly receives original reports.",
        )
        self.assertTrue(
            policy.approved(self.state, current["commit"], current["base_sha"])
        )

    def test_batch_carry_forward_preserves_dispositions_and_survives_handoff(self):
        self.begin()
        first, fid = self.finding()
        self.settle(fid)
        old = copy.deepcopy(self.state["findings"])
        current = self.add(head="c" * 40)
        self.assertFalse(
            policy.approved(self.state, current["commit"], current["base_sha"])
        )
        batch = policy.carry_forward(
            self.state, current["id"], [fid], "Verified bounded fix and callers."
        )
        self.assertEqual(
            policy.carry_forward(
                self.state, current["id"], [fid], "Verified bounded fix and callers."
            ),
            batch,
        )
        self.assertEqual(len(self.state["carry_forwards"]), 1)
        self.assertEqual(self.state["findings"], old)
        self.assertTrue(
            policy.approved(
                json.loads(json.dumps(self.state)),
                current["commit"],
                current["base_sha"],
            )
        )
        self.assertFalse(policy.approved(self.state, "d" * 40, current["base_sha"]))
        self.assertEqual(first["outcome"], "needs-attention")

    def test_carry_cannot_resolve_concerns_or_unknown_legacy_findings(self):
        for status in ("investigate", "fixed-unverified"):
            self.setUp()
            self.begin()
            _, fid = self.finding("high")
            self.settle(fid, "concern", status)
            current = self.add(head="c" * 40)
            with self.assertRaisesRegex(policy.Error, "unresolved"):
                policy.carry_forward(
                    self.state, current["id"], [fid], "Silence is not verification."
                )
            with self.assertRaisesRegex(policy.Error, "reclassification"):
                self.settle(fid, "nonblocking", "deferred")

    def test_carry_requires_original_reports_and_actual_review_context(self):
        self.begin()
        first, fid = self.finding()
        self.settle(fid)
        middle = self.add()
        current = self.add(head="c" * 40, prior=[middle["id"]])
        with self.assertRaisesRegex(policy.Error, "original source"):
            policy.carry_forward(
                self.state, current["id"], [fid], "Missing claim context."
            )
        current["prior"].append(first["id"])
        current["verifies"] = []
        with self.assertRaisesRegex(policy.Error, "explicitly reviewed"):
            policy.carry_forward(self.state, current["id"], [fid], "Missing request.")

    def test_code_carry_can_include_plan_source_without_substituting_plan_review(self):
        self.begin()
        plan = self.add(
            "plan",
            result={
                "verdict": "needs-attention",
                "findings": [
                    {"title": "Synthetic plan verification claim", "severity": "medium"}
                ],
            },
        )
        fid = plan["finding_ids"][0]
        self.settle(fid)
        code = self.add(prior=[plan["id"]], head="c" * 40)
        policy.carry_forward(
            self.state,
            code["id"],
            [fid],
            "Initial code review verified plan requirement.",
        )
        self.assertTrue(policy.approved(self.state, code["commit"], code["base_sha"]))
        followup = self.add(head="d" * 40, prior=[plan["id"]])
        with self.assertRaisesRegex(policy.Error, "own phase"):
            policy.validate_scope(self.state, followup)
        followup["prior"].append(code["id"])
        policy.carry_forward(
            self.state,
            followup["id"],
            [fid],
            "Focused code review includes original plan claim.",
        )
        policy.check_ledger(self.state, self.grant_check)

    def test_repeated_claim_reopens_and_cannot_reuse_earlier_carry(self):
        self.begin()
        first, fid = self.finding()
        self.settle(fid)
        current = self.add(head="c" * 40)
        policy.carry_forward(self.state, current["id"], [fid], "Fix checked.")
        repeated = self.add(
            head="c" * 40,
            result={
                "verdict": "needs-attention",
                "findings": [
                    {"title": fid + " remains reproducible", "severity": "high"}
                ],
            },
        )
        self.assertEqual(repeated["finding_ids"], [fid])
        self.assertFalse(
            policy.approved(self.state, repeated["commit"], repeated["base_sha"])
        )
        with self.assertRaisesRegex(policy.Error, "original source"):
            policy.carry_forward(
                self.state, repeated["id"], [fid], "Cannot carry new occurrence."
            )
        self.assertEqual(first["outcome"], "needs-attention")

    def test_nonblocking_needs_attention_remains_ready_without_issue(self):
        self.begin()
        r, fid = self.finding()
        self.settle(fid, "nonblocking", "deferred")
        self.assertTrue(policy.approved(self.state, r["commit"], r["base_sha"]))
        with self.assertRaisesRegex(policy.Error, "separate issue"):
            self.settle(fid, "independent", "deferred")
        self.assertEqual(policy.deliverable_count(self.state, "code"), 1)

    def test_nonsemantic_continuity_preserves_receipt_and_binds_exact_revision(self):
        self.begin()
        r = self.add()
        original = copy.deepcopy(r)
        head, base = "c" * 40, r["base_sha"]
        proof = {
            "kind": "license-headers",
            "from_head": r["commit"],
            "head": head,
            "base": base,
        }
        policy.record_continuity(self.state, r["id"], head, base, proof)
        self.assertTrue(policy.approved(self.state, head, base))
        self.assertFalse(policy.approved(self.state, "d" * 40, base))
        self.assertEqual(r, original)
        self.state["integration"] = {
            "head": head,
            "base": base,
            "merge_base": base,
            "receipt": r["id"],
            "rationale": "Target incorporated; narrow delta checked.",
        }
        policy.integration_current(self.state, head, base)
        self.state["continuity"]["proof"]["base"] = "d" * 40
        self.assertFalse(policy.approved(self.state, head, base))

    def test_continuity_cannot_bless_unresolved_work_or_revision_exception(self):
        self.begin()
        r, fid = self.finding()
        head, base = "c" * 40, r["base_sha"]
        proof = {
            "kind": "license-headers",
            "from_head": r["commit"],
            "head": head,
            "base": base,
        }
        with self.assertRaisesRegex(policy.Error, "lacks applicable"):
            policy.record_continuity(self.state, r["id"], head, base, proof)
        self.settle(fid, status="excepted", comment=99)
        with self.assertRaisesRegex(policy.Error, "revision-specific"):
            policy.record_continuity(self.state, r["id"], head, base, proof)
        current = self.add(head=head)
        with self.assertRaisesRegex(policy.Error, "revision-specific"):
            policy.carry_forward(
                self.state, current["id"], [fid], "Cannot expand exception."
            )

    def test_missing_review_output_never_becomes_continuity_approval(self):
        self.begin()
        r = self.add()
        r.pop("result_digest")
        with self.assertRaisesRegex(policy.Error, "structured review output"):
            policy.approved(self.state, r["commit"], r["base_sha"])


if __name__ == "__main__":
    unittest.main()
