# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
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
        m["workspace"] = {
            "prepared_for": m["owner"],
            "path": str(Path.cwd()),
            "branch": "synthetic",
            "fork": "owner/private-fork",
        }
        r["private_fork"] = {"full_name": "owner/private-fork", "private": True}
        self.api.records[GHSA] = copy.deepcopy(r)
        # Explicitly account for fake server provisioning before owned test setup.
        a.atomic(self.client.anchor, {GHSA: policy.digest(r)})
        r = self.client.change(r, m, "claim", "Synthetic setup", trust=True)
        return r

    def deliverable(self, record=None, client=None):
        client = client or self.client
        record = record or client.read(GHSA)
        return client.deliverable(
            GHSA,
            {
                "expected": policy.digest(record),
                "owner": board.OWNER,
                "source": "Synthetic selected deliverable instruction",
                "id": "synthetic-deliverable",
                "outcome": "One bounded synthetic correction",
                "acceptance": "Synthetic regression verifies the required outcome",
            },
        )

    def review_output(self, head=HEAD, findings=None):
        def reviewer(args, **kwargs):
            kwargs["stdout"].write(
                json.dumps(
                    {
                        "codex": {"status": 0},
                        "inputs": {"head": head, "base": BASE, "merge_base": BASE},
                        "result": {
                            "verdict": "needs-attention" if findings else "approve",
                            "findings": findings or [],
                            "summary": "Synthetic private review",
                        },
                    }
                )
            )
            return subprocess.CompletedProcess(args, 0)

        return reviewer

    def test_deliverable_requires_trusted_remediation_and_exact_owner_scope(self):
        record = self.create()
        with self.assertRaisesRegex(a.Error, "provenance"):
            self.deliverable(record)
        record = self.approve(record)
        original = copy.deepcopy(a.metadata(record))
        decision = {
            "expected": policy.digest(record),
            "owner": board.OWNER,
            "source": "Synthetic selected deliverable instruction",
            "id": "synthetic-deliverable",
            "outcome": "Synthetic outcome",
            "acceptance": "Synthetic acceptance criteria",
        }
        for changed in (
            {"expected": "stale"},
            {"owner": "another-owner"},
            {"source": ""},
        ):
            with self.assertRaises(a.Error):
                self.client.deliverable(GHSA, {**decision, **changed})
        record = self.deliverable(record)
        current = a.metadata(record)
        self.assertEqual(current["scope"], original["scope"])
        self.assertEqual(current["status"], original["status"])
        self.assertEqual(current["owner"], original["owner"])
        self.assertEqual(current["ledger"]["version"], 3)
        self.assertEqual(len(current["grants"]), len(original["grants"]) + 1)
        self.assertEqual(self.deliverable(record), record)
        changed = {
            **decision,
            "expected": policy.digest(record),
            "outcome": "Changed scope",
        }
        with self.assertRaisesRegex(a.Error, "already used"):
            self.client.deliverable(GHSA, changed)
        missing_scope = a.metadata(record)
        missing_scope.pop("scope")
        record = self.client.change(
            record, missing_scope, "synthetic", "Test only", trust=True
        )
        with self.assertRaisesRegex(a.Error, "authorize remediation"):
            self.deliverable(record)

    def test_deliverable_interrupted_write_recovers_without_duplicate_grant(self):
        record = self.approve()
        self.api.lose = True
        with self.assertRaises(a.APIError):
            self.deliverable(record)
        restored = a.Advisory(api=self.api, directory=self.root / "state")
        record = restored.recover()
        grants = copy.deepcopy(a.metadata(record)["grants"])
        patches = sum(c[2] == "PATCH" for c in self.api.calls)
        self.assertEqual(self.deliverable(record, restored), record)
        self.assertEqual(a.metadata(restored.read(GHSA))["grants"], grants)
        self.assertEqual(sum(c[2] == "PATCH" for c in self.api.calls), patches)
        self.assertEqual(len(a.metadata(record)["ledger"]["deliverables"]), 1)

    def test_deliverable_preserves_lifetime_grants_and_budget_across_handoff(self):
        pending = self.pending_review()
        a.atomic(
            self.client.directory / (pending["id"] + ".json"),
            {
                "codex": {"status": 0},
                "inputs": {"head": HEAD, "base": BASE, "merge_base": BASE},
                "result": {"verdict": "approve", "findings": []},
            },
        )
        record = self.client.recover_review(GHSA, "s")
        record = self.client.authorize(
            GHSA,
            {
                "expected": policy.digest(record),
                "owner": board.OWNER,
                "source": "Synthetic historical cumulative ceiling",
                "scope": "Synthetic bounded correction",
                "reconfirm": True,
                "allowances": {"code": 1},
            },
        )
        original = copy.deepcopy(a.metadata(record)["ledger"])
        record = self.deliverable(record)
        ledger = a.metadata(record)["ledger"]
        self.assertEqual(ledger["reviews"], original["reviews"])
        self.assertEqual(ledger["authorizations"], original["authorizations"])
        self.assertEqual(
            ledger["deliverable_migration"]["ceilings"], original["ceilings"]
        )
        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(self.client, "inputs", return_value=(HEAD, BASE, BASE)),
            mock.patch(
                "subprocess.run", side_effect=self.review_output()
            ) as invocation,
        ):
            previous = None
            for scope in ("initial", "follow-up", "integration"):
                request = {"phase": "code", "scope": scope, "focus": "Synthetic check"}
                if previous:
                    request.update(
                        prior=[previous], rationale="Synthetic bounded change"
                    )
                record = self.client.review(GHSA, "s", request)
                previous = a.metadata(record)["ledger"]["reviews"][-1]["id"]
                if scope == "initial":
                    with self.assertRaises(a.Error):
                        self.client.review(
                            GHSA,
                            "s",
                            {"phase": "code", "focus": "Unbounded broad retry"},
                        )
            self.assertEqual(invocation.call_count, 3)
        ledger = a.metadata(record)["ledger"]
        self.assertEqual(policy.count(ledger, "code"), 4)
        self.assertEqual(policy.deliverable_count(ledger, "code"), 3)
        self.assertEqual(ledger["reviews"][0], original["reviews"][0])
        with self.assertRaisesRegex(a.Error, "exhausted"):
            policy.budget(ledger, "code")
        released = self.client.release(GHSA, "s")
        other = a.Advisory(api=self.api, directory=self.root / "next-machine")
        with self.assertRaisesRegex(a.Error, "provenance"):
            self.deliverable(released, other)
        record = other.authorize(
            GHSA,
            {
                "expected": policy.digest(released),
                "owner": board.OWNER,
                "source": "Synthetic owner released handoff",
                "scope": "Synthetic bounded correction",
                "reconfirm": True,
            },
        )
        self.assertEqual(a.metadata(record)["ledger"], ledger)
        self.assertEqual(self.deliverable(record, other), record)
        with self.assertRaisesRegex(a.Error, "exhausted"):
            policy.budget(a.metadata(record)["ledger"], "code")
        callback = lambda ph, rd, grant, kind, binding=None: other.check_auth(
            a.metadata(record), ph, rd, grant, kind, binding
        )
        policy.check_ledger(ledger, callback)
        with self.assertRaisesRegex(a.Error, "does not bind"):
            other.check_auth(
                a.metadata(record), "deliverable", 1, 3, "deliverable", "altered"
            )

    def test_deliverable_cannot_migrate_pending_review_or_erase_retry_failures(self):
        self.pending_review()
        with self.assertRaisesRegex(a.Error, "pending"):
            self.deliverable()
        record = self.client.recover_review(GHSA, "s", True)
        before = copy.deepcopy(a.metadata(record)["ledger"]["reviews"])
        record = self.deliverable(record)
        ledger = a.metadata(record)["ledger"]
        self.assertEqual(ledger["reviews"], before)
        self.assertEqual(policy.failed_attempts(ledger, "code"), (["attempt-1"], 1))
        self.assertEqual(policy.count(ledger, "code"), 0)

    def test_private_carry_requires_current_review_and_resolved_dispositions(self):
        self.claimed()
        self.deliverable()
        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(
                self.client, "inputs", return_value=(HEAD, BASE, BASE)
            ) as inputs,
        ):
            with mock.patch(
                "subprocess.run",
                side_effect=self.review_output(
                    findings=[
                        {"title": "Synthetic optional refinement", "severity": "low"},
                        {"title": "Synthetic required correction", "severity": "high"},
                    ]
                ),
            ):
                record = self.client.review(
                    GHSA, "s", {"focus": "Synthetic private initial"}
                )
            initial = a.metadata(record)["ledger"]["reviews"][-1]
            optional, blocker = initial["finding_ids"]
            record = self.client.dispose(
                GHSA,
                "s",
                {
                    "finding": optional,
                    "category": "nonblocking",
                    "status": "deferred",
                    "evidence": "Synthetic acceptance criteria already met",
                    "consequence": "Optional readability improvement only",
                },
            )
            record = self.client.dispose(
                GHSA,
                "s",
                {
                    "finding": blocker,
                    "category": "blocking",
                    "status": "investigate",
                    "evidence": "Synthetic demonstrated incorrect behavior",
                    "consequence": "Required synthetic invariant not established",
                },
            )
            new_head = "c" * 40
            inputs.return_value = (new_head, BASE, BASE)
            with mock.patch("subprocess.run", side_effect=self.review_output(new_head)):
                record = self.client.review(
                    GHSA,
                    "s",
                    {
                        "focus": "Synthetic private follow-up",
                        "scope": "follow-up",
                        "prior": [initial["id"]],
                        "verifies": [optional, blocker],
                        "rationale": "Synthetic affected behavior inspected",
                    },
                )
            before = copy.deepcopy(a.metadata(record)["ledger"])
            followup = before["reviews"][-1]
            with self.assertRaisesRegex(a.Error, "current private head"):
                self.client.carry(
                    GHSA,
                    "s",
                    {
                        "receipt": initial["id"],
                        "findings": [optional],
                        "rationale": "Wrong inputs",
                    },
                )
            with self.assertRaises(a.Error):
                self.client.carry(
                    GHSA,
                    "s",
                    {
                        "receipt": followup["id"],
                        "findings": [optional, blocker],
                        "rationale": "Unresolved blocker cannot carry",
                    },
                )
            self.assertEqual(a.metadata(self.client.read(GHSA))["ledger"], before)
            record = self.client.carry(
                GHSA,
                "s",
                {
                    "receipt": followup["id"],
                    "findings": [optional],
                    "rationale": "Synthetic optional disposition remains applicable",
                },
            )
            after = a.metadata(record)["ledger"]
            self.assertEqual(after["reviews"], before["reviews"])
            self.assertEqual(after["findings"], before["findings"])
            self.assertFalse(policy.approved(after, new_head, BASE, confidential=True))
            returning = a.Advisory(api=self.api, directory=self.root / "state")
            self.assertEqual(a.metadata(returning.read(GHSA))["ledger"], after)

    def test_private_review_cannot_carry_a_disposition_written_after_invocation(self):
        self.claimed()
        self.deliverable()
        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(
                self.client, "inputs", return_value=(HEAD, BASE, BASE)
            ) as inputs,
        ):
            with mock.patch(
                "subprocess.run",
                side_effect=self.review_output(
                    findings=[
                        {"title": "Synthetic required correction", "severity": "high"}
                    ]
                ),
            ):
                record = self.client.review(
                    GHSA, "s", {"focus": "Synthetic initial review"}
                )
            initial = a.metadata(record)["ledger"]["reviews"][-1]
            fid = initial["finding_ids"][0]
            self.client.dispose(
                GHSA,
                "s",
                {
                    "finding": fid,
                    "category": "blocking",
                    "status": "investigate",
                    "evidence": "Synthetic required invariant not established",
                    "consequence": "Investigation is still required",
                },
            )
            b_head, c_head = "b1" * 20, "c1" * 20
            inputs.return_value = (b_head, BASE, BASE)
            with mock.patch("subprocess.run", side_effect=self.review_output(b_head)):
                record = self.client.review(
                    GHSA,
                    "s",
                    {
                        "scope": "follow-up",
                        "focus": "Synthetic review at B",
                        "prior": [initial["id"]],
                        "verifies": [fid],
                        "rationale": "Inspect the still unresolved claim",
                    },
                )
            review_b = copy.deepcopy(a.metadata(record)["ledger"]["reviews"][-1])
            inputs.return_value = (c_head, BASE, BASE)
            self.client.dispose(
                GHSA,
                "s",
                {
                    "finding": fid,
                    "category": "blocking",
                    "status": "verified",
                    "evidence": "Synthetic correction implemented and checked only at C",
                    "consequence": "Required invariant restored at C",
                },
            )
            inputs.return_value = (b_head, BASE, BASE)
            before = self.client.read(GHSA)
            with self.assertRaises(a.Error):
                self.client.carry(
                    GHSA,
                    "s",
                    {
                        "receipt": review_b["id"],
                        "findings": [fid],
                        "rationale": "C evidence must not be attributed to the earlier B review",
                    },
                )
            self.assertEqual(self.client.read(GHSA), before)
            ledger = a.metadata(before)["ledger"]
            self.assertEqual(ledger["reviews"][-1], review_b)
            self.assertFalse(policy.approved(ledger, b_head, BASE, confidential=True))
            # A later review can attest the already-written resolution.
            inputs.return_value = (c_head, BASE, BASE)
            with mock.patch("subprocess.run", side_effect=self.review_output(c_head)):
                record = self.client.review(
                    GHSA,
                    "s",
                    {
                        "scope": "follow-up",
                        "focus": "Synthetic verification at C",
                        "prior": [initial["id"], review_b["id"]],
                        "verifies": [fid],
                        "rationale": "Inspect the actual C resolution",
                    },
                )
            review_c = a.metadata(record)["ledger"]["reviews"][-1]
            record = self.client.carry(
                GHSA,
                "s",
                {
                    "receipt": review_c["id"],
                    "findings": [fid],
                    "rationale": "The current reviewer received this exact resolution",
                },
            )
            self.assertTrue(
                policy.approved(
                    a.metadata(record)["ledger"], c_head, BASE, confidential=True
                )
            )

    def test_private_unused_extensions_cannot_fund_another_deliverable(self):
        record = self.claimed()
        record = self.client.authorize(
            GHSA,
            {
                "expected": policy.digest(record),
                "owner": board.OWNER,
                "source": "Synthetic old lifetime allowance",
                "scope": "Synthetic old scope",
                "reconfirm": True,
                "allowances": {"code": 7},
            },
        )
        old_grants = copy.deepcopy(a.metadata(record)["grants"])
        old_auth = copy.deepcopy(a.metadata(record)["ledger"]["authorizations"])
        self.deliverable(record)
        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(self.client, "inputs", return_value=(HEAD, BASE, BASE)),
            mock.patch(
                "subprocess.run", side_effect=self.review_output()
            ) as invocation,
        ):
            previous = None
            for index in range(3):
                request = {
                    "focus": "Synthetic first deliverable",
                    "scope": "initial" if index == 0 else "follow-up",
                }
                if previous:
                    request.update(
                        prior=[previous], rationale="Synthetic bounded follow-up"
                    )
                record = self.client.review(GHSA, "s", request)
                previous = a.metadata(record)["ledger"]["reviews"][-1]["id"]
            with self.assertRaisesRegex(a.Error, "budget exhausted"):
                self.client.review(
                    GHSA,
                    "s",
                    {
                        "scope": "follow-up",
                        "focus": "Old grant is insufficient",
                        "prior": [previous],
                        "rationale": "No current extension",
                    },
                )
            self.assertEqual(invocation.call_count, 3)
            record = self.client.authorize(
                GHSA,
                {
                    "expected": policy.digest(record),
                    "owner": board.OWNER,
                    "source": "Synthetic scoped extension",
                    "scope": "Synthetic first deliverable",
                    "reconfirm": True,
                    "allowances": {"code": 8},
                },
            )
            record = self.client.review(
                GHSA,
                "s",
                {
                    "scope": "follow-up",
                    "focus": "Current scoped fourth review",
                    "prior": [previous],
                    "rationale": "Explicit extension",
                },
            )
            record = self.client.deliverable(
                GHSA,
                {
                    "expected": policy.digest(record),
                    "owner": board.OWNER,
                    "source": "Synthetic second selected outcome",
                    "id": "synthetic-second-deliverable",
                    "outcome": "Another explicitly selected synthetic outcome",
                    "acceptance": "Second synthetic outcome verified",
                },
            )
            previous = None
            for index in range(3):
                request = {
                    "focus": "Synthetic second deliverable",
                    "scope": "initial" if index == 0 else "follow-up",
                }
                if previous:
                    request.update(
                        prior=[previous], rationale="Synthetic bounded follow-up"
                    )
                record = self.client.review(GHSA, "s", request)
                previous = a.metadata(record)["ledger"]["reviews"][-1]["id"]
            with self.assertRaisesRegex(a.Error, "budget exhausted"):
                self.client.review(
                    GHSA,
                    "s",
                    {
                        "scope": "follow-up",
                        "focus": "Earlier scope extension is insufficient",
                        "prior": [previous],
                        "rationale": "No second-scope extension",
                    },
                )
            self.assertEqual(invocation.call_count, 7)
        meta = a.metadata(record)
        self.assertEqual(meta["grants"][: len(old_grants)], old_grants)
        self.assertEqual(meta["ledger"]["authorizations"][: len(old_auth)], old_auth)
        policy.check_ledger(
            meta["ledger"],
            lambda ph, rd, grant, kind, binding=None: self.client.check_auth(
                meta, ph, rd, grant, kind, binding
            ),
        )

    def test_explicit_deliverable_cap_limits_spending_without_changing_legacy_cap(self):
        record = self.claimed()
        record = self.client.authorize(
            GHSA,
            {
                "expected": policy.digest(record),
                "owner": board.OWNER,
                "source": "Synthetic historical stopped allowance",
                "scope": "Synthetic bounded correction",
                "reconfirm": True,
                "allowances": {"code": 0},
            },
        )
        legacy = copy.deepcopy(a.metadata(record)["ledger"]["ceilings"])
        record = self.deliverable(record)
        record = self.client.authorize(
            GHSA,
            {
                "expected": policy.digest(record),
                "owner": board.OWNER,
                "source": "Synthetic one-review allowance for this deliverable",
                "scope": "Synthetic bounded correction",
                "reconfirm": True,
                "allowances": {"code": 1},
            },
        )
        ledger = a.metadata(record)["ledger"]
        self.assertEqual(ledger["ceilings"], legacy)
        self.assertEqual(ledger["deliverable_migration"]["ceilings"], legacy)
        self.assertEqual(
            policy.active_deliverable(ledger)["ceilings"]["code"]["round"], 1
        )
        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(self.client, "inputs", return_value=(HEAD, BASE, BASE)),
            mock.patch(
                "subprocess.run", side_effect=self.review_output()
            ) as invocation,
        ):
            record = self.client.review(
                GHSA, "s", {"focus": "Synthetic bounded review"}
            )
            prior = a.metadata(record)["ledger"]["reviews"][-1]["id"]
            with self.assertRaisesRegex(a.Error, "allowance exhausted"):
                self.client.review(
                    GHSA,
                    "s",
                    {
                        "focus": "Synthetic follow-up",
                        "scope": "follow-up",
                        "prior": [prior],
                        "rationale": "Bounded fix",
                    },
                )
            self.assertEqual(invocation.call_count, 1)
        ledger = a.metadata(record)["ledger"]
        policy.check_ledger(
            ledger,
            lambda ph, rd, grant, kind, binding=None: self.client.check_auth(
                a.metadata(record), ph, rd, grant, kind, binding
            ),
        )

    def test_code_followup_carries_plan_finding_only_with_its_original_context(self):
        self.claimed()
        self.deliverable()
        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(
                self.client, "inputs", return_value=(HEAD, BASE, BASE)
            ) as inputs,
        ):
            with mock.patch(
                "subprocess.run",
                side_effect=self.review_output(
                    findings=[
                        {
                            "title": "Synthetic optional plan suggestion",
                            "severity": "low",
                        }
                    ]
                ),
            ):
                record = self.client.review(
                    GHSA, "s", {"phase": "plan", "focus": "Synthetic design"}
                )
            plan = a.metadata(record)["ledger"]["reviews"][-1]
            fid = plan["finding_ids"][0]
            self.client.dispose(
                GHSA,
                "s",
                {
                    "finding": fid,
                    "category": "nonblocking",
                    "status": "deferred",
                    "evidence": "Synthetic required plan guarantees are met",
                    "consequence": "Optional refinement does not affect correctness",
                },
            )
            with mock.patch("subprocess.run", side_effect=self.review_output()):
                record = self.client.review(
                    GHSA, "s", {"focus": "Synthetic initial implementation"}
                )
            initial = a.metadata(record)["ledger"]["reviews"][-1]
            head = "e" * 40
            inputs.return_value = (head, BASE, BASE)
            request = {
                "scope": "follow-up",
                "focus": "Synthetic focused implementation",
                "verifies": [fid],
                "rationale": "Synthetic plan disposition inspected with implementation",
            }
            with mock.patch(
                "subprocess.run", side_effect=self.review_output(head)
            ) as invocation:
                with self.assertRaises(a.Error):
                    self.client.review(GHSA, "s", {**request, "prior": [plan["id"]]})
                self.assertFalse(invocation.called)
                record = self.client.review(
                    GHSA, "s", {**request, "prior": [initial["id"], plan["id"]]}
                )
            followup = a.metadata(record)["ledger"]["reviews"][-1]
            record = self.client.carry(
                GHSA,
                "s",
                {
                    "receipt": followup["id"],
                    "findings": [fid],
                    "rationale": "Original plan disposition still applies",
                },
            )
            ledger = a.metadata(record)["ledger"]
            self.assertEqual(ledger["reviews"][0], plan)
            self.assertTrue(policy.approved(ledger, head, BASE, confidential=True))

    def test_private_verification_recomputes_imported_continuity_proof(self):
        self.claimed()
        self.deliverable()
        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(
                self.client, "inputs", return_value=(HEAD, BASE, BASE)
            ) as inputs,
            mock.patch("subprocess.run", side_effect=self.review_output()),
        ):
            record = self.client.review(
                GHSA, "s", {"focus": "Synthetic private initial"}
            )
            m = a.metadata(record)
            receipt = m["ledger"]["reviews"][-1]
            current = "d" * 40
            proof = {
                "kind": "license-headers",
                "from_head": HEAD,
                "head": current,
                "base": BASE,
            }
            policy.record_continuity(
                m["ledger"], receipt["id"], current, BASE, proof, confidential=True
            )
            m["checkpoint"] = {
                "head": current,
                "base": BASE,
                "verification": "Synthetic tests passed",
            }
            self.client.change(
                record, m, "synthetic", "Synthetic imported continuity only", trust=True
            )
            inputs.return_value = (current, BASE, BASE)
            with mock.patch.object(
                work_issue,
                "license_continuity",
                return_value={"different": "actual Git proof"},
            ) as comparison:
                with self.assertRaisesRegex(a.Error, "actual Git objects"):
                    self.client.verified(
                        GHSA,
                        "s",
                        {
                            "receipt": receipt["id"],
                            "rationale": "Synthetic integration",
                        },
                    )
                comparison.assert_called_once()
            self.assertNotEqual(
                a.metadata(self.client.read(GHSA))["status"],
                "Fixed, awaiting disclosure",
            )

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
                    "rationale": "Synthetic private continuity detail",
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
            self.assertNotIn("Synthetic private continuity detail", str(args))

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

    def test_pending_fork_does_not_bless_control_edits_or_public_state(self):
        self.approve()
        self.api.fork_ready = False
        with self.assertRaises(a.Error):
            self.client.work(GHSA, "s", self.root / "private")
        original = copy.deepcopy(self.api.records[GHSA])
        m = a.metadata(original)
        m["scope"] = "Unauthorized expansion"
        m["grants"][0]["allowances"] = {"code": 99}
        self.api.records[GHSA]["description"] = a.description(seed()["description"], m)
        self.api.records[GHSA]["private_fork"] = {
            "full_name": "owner/private-fork",
            "private": True,
        }
        with self.assertRaisesRegex(a.Error, "control state changed"):
            self.client.recover()
        self.assertTrue(self.client.pending())
        with self.assertRaises(a.Error):
            self.client.trusted(self.client.read(GHSA))
        self.api.records[GHSA]["description"] = original["description"]
        self.api.records[GHSA]["state"] = "published"
        with self.assertRaisesRegex(a.Error, "control state changed"):
            self.client.recover()
        self.api.records[GHSA]["state"] = "draft"
        self.client.recover()
        self.client.trusted(self.client.read(GHSA))
        self.assertEqual(
            a.metadata(self.client.read(GHSA))["scope"], a.metadata(original)["scope"]
        )

    def test_existing_creation_never_returns_an_unrelated_pending_advisory(self):
        original = self.create()
        other = seed("different-key", "Unrelated synthetic phenomenon")
        other["legacy_ids"] = ["TEST-2"]
        other["reviewed_related"] = [GHSA]
        self.api.lose = True
        with self.assertRaises(a.APIError):
            self.client.create(other)
        with self.assertRaisesRegex(a.Error, "unrelated pending"):
            self.create()
        self.client.recover()
        self.assertEqual(self.create()["ghsa_id"], original["ghsa_id"])
        self.assertEqual(self.client.create(other)["ghsa_id"], OTHER)
        self.assertEqual(sum(c[2] == "POST" for c in self.api.calls), 2)

    def test_matching_pending_create_still_rejects_changed_input(self):
        self.api.lose = True
        with self.assertRaises(a.APIError):
            self.create()
        with self.assertRaisesRegex(a.Error, "changed content"):
            self.client.create({**seed(), "description": "Different content"})
        self.assertTrue(self.client.pending())
        self.create()
        self.assertIsNone(self.client.pending())

    def test_owner_reconciles_active_pending_work_without_losing_history(self):
        pending = self.pending_review()
        known = self.client.read(GHSA)
        old = a.metadata(known)
        changed = a.metadata(known)
        changed["scope"] = "Unexpected scope"
        changed["ledger"]["reviews"] = []
        self.api.records[GHSA]["description"] = a.description(
            seed()["description"], changed
        )
        observed = self.client.read(GHSA)
        decision = {
            "expected": policy.digest(observed),
            "owner": board.OWNER,
            "source": "Explicit current owner recovery instruction",
            "reason": "Restore trusted control history after inspecting observed edit",
            "stopped_attempts": [pending["id"]],
        }
        with self.assertRaises(a.Error):
            self.client.reconcile(GHSA, {**decision, "expected": "stale"})
        with self.assertRaisesRegex(a.Error, "pending invocation"):
            self.client.reconcile(GHSA, {**decision, "stopped_attempts": []})
        restored = self.client.reconcile(GHSA, decision)
        meta = a.metadata(restored)
        self.assertEqual(meta["owner"], old["owner"])
        self.assertEqual(meta["ledger"], old["ledger"])
        self.assertEqual(meta["grants"], old["grants"])
        self.assertEqual(meta["history"][:-1], old["history"])
        self.assertEqual(meta["history"][-1]["note"]["observed_metadata"], changed)
        a.atomic(
            self.client.directory / (pending["id"] + ".json"),
            {
                "codex": {"status": 0},
                "inputs": {"head": HEAD, "base": BASE, "merge_base": BASE},
                "result": {"verdict": "approve", "findings": []},
            },
        )
        recovered = self.client.recover_review(GHSA, "s")
        self.assertEqual(policy.count(a.metadata(recovered)["ledger"], "code"), 1)
        with self.assertRaises(a.Error):
            self.client.recover_review(GHSA, "s")

    def test_reconciliation_never_takes_over_another_clones_active_work(self):
        r = self.claimed()
        other = a.Advisory(api=self.api, directory=self.root / "another-machine")
        for file in (
            self.client.anchor,
            self.client.directory / (GHSA + ".trusted.json"),
        ):
            a.atomic(other.directory / file.name, a.read_file(file))
        with self.assertRaisesRegex(a.Error, "trusted active claim"):
            other.reconcile(
                GHSA,
                {
                    "expected": policy.digest(r),
                    "owner": board.OWNER,
                    "source": "Synthetic decision",
                    "reason": "test",
                    "stopped_attempts": [],
                },
            )

    def test_repeated_independent_finding_retains_tracking_through_history_replay(self):
        for confidential, tracking in (
            (True, board.REPO + "#" + GHSA),
            (False, "#123"),
        ):
            with self.subTest(confidential=confidential):
                fid = "F-123456789abc"
                s = {
                    "findings": {
                        fid: {
                            "id": fid,
                            "sources": [["first", 0]],
                            "history": [],
                            "severity": "low",
                        }
                    }
                }
                disposition = {
                    "category": "independent",
                    "status": "deferred",
                    "tracking": tracking,
                    "evidence": "Synthetic independent claim",
                    "consequence": "No dependency on this change.",
                }
                policy.disposition(
                    s, fid, disposition, HEAD, BASE, confidential=confidential
                )
                r = {
                    "id": "second",
                    "commit": HEAD,
                    "base_sha": BASE,
                    "verifies": [fid],
                }
                policy.register_result(
                    s,
                    r,
                    {
                        "verdict": "needs-attention",
                        "findings": [
                            {
                                "title": fid + " Synthetic repeated claim",
                                "severity": "low",
                            }
                        ],
                    },
                )
                self.assertEqual(
                    s["findings"][fid]["history"][-1]["tracking"], tracking
                )
                self.assertFalse(
                    policy.findings_ready(s, HEAD, BASE, confidential=confidential)
                )
                policy.disposition(
                    s, fid, disposition, HEAD, BASE, confidential=confidential
                )
                returning = json.loads(json.dumps(s))
                self.assertTrue(
                    policy.findings_ready(
                        returning, HEAD, BASE, confidential=confidential
                    )
                )

    def test_released_handoff_restores_the_recorded_private_branch_and_commit(self):
        self.approve()
        first = self.root / "first"
        bare = self.root / "private.git"
        subprocess.run(
            ["git", "init", "-q", "-b", "remediation", str(first)], check=True
        )
        for key, value in (
            ("user.name", "Synthetic"),
            ("user.email", "test@example.invalid"),
        ):
            subprocess.run(["git", "-C", str(first), "config", key, value], check=True)
        (first / "test.txt").write_text("synthetic only\n")
        subprocess.run(["git", "-C", str(first), "add", "test.txt"], check=True)
        subprocess.run(
            ["git", "-C", str(first), "commit", "-qm", "synthetic"], check=True
        )
        head = subprocess.check_output(
            ["git", "-C", str(first), "rev-parse", "HEAD"], text=True
        ).strip()
        subprocess.run(["git", "-C", str(first), "branch", "main"], check=True)
        subprocess.run(
            ["git", "clone", "-q", "--bare", str(first), str(bare)], check=True
        )
        subprocess.run(
            ["git", "-C", str(bare), "symbolic-ref", "HEAD", "refs/heads/main"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(first),
                "remote",
                "add",
                "origin",
                "https://github.com/owner/private-fork.git",
            ],
            check=True,
        )
        original = guard.command
        clones = []

        def command(args, cwd=None):
            if args[0] == "gh":
                return json.dumps({"full_name": "owner/private-fork", "private": True})
            if args[:2] == ["git", "clone"]:
                clones.append(args[-1])
                original(["git", "clone", "--", str(bare), args[-1]])
                return original(
                    [
                        "git",
                        "remote",
                        "set-url",
                        "origin",
                        "https://github.com/owner/private-fork.git",
                    ],
                    args[-1],
                )
            if args == ["git", "fetch", "origin"]:
                return original(
                    ["git", "fetch", str(bare), "+refs/heads/*:refs/remotes/origin/*"],
                    cwd,
                )
            return original(args, cwd)

        with mock.patch.object(guard, "command", side_effect=command):
            self.client.work(GHSA, "s", first)
            with self.assertRaisesRegex(a.Error, "another workspace"):
                self.client.work(GHSA, "s", self.root / "duplicate")
            with self.assertRaisesRegex(a.Error, "associated private workspace"):
                self.client.owned(GHSA, "s")
            old = Path.cwd()
            try:
                os.chdir(first)
                with mock.patch.object(
                    self.client, "inputs", return_value=(head, head, head)
                ):
                    self.client.checkpoint(
                        GHSA,
                        "s",
                        {
                            "completed": "Synthetic code",
                            "verification": "Synthetic test passed",
                            "blockers": "",
                            "next": "Private handoff",
                        },
                    )
                self.client.release(GHSA, "s")
            finally:
                os.chdir(old)
            other = a.Advisory(api=self.api, directory=self.root / "other-state")
            r = other.read(GHSA)
            other.authorize(
                GHSA,
                {
                    "expected": policy.digest(r),
                    "owner": board.OWNER,
                    "source": "Explicit synthetic owner handoff",
                    "scope": "Same correction",
                    "reconfirm": True,
                },
            )
            second = self.root / "second"
            r = other.work(GHSA, "new", second)
            self.assertEqual(
                original(["git", "branch", "--show-current"], second), "remediation"
            )
            self.assertEqual(original(["git", "rev-parse", "HEAD"], second), head)
            self.assertEqual(a.metadata(r)["checkpoint"]["head"], head)
            self.assertEqual(other.work(GHSA, "new", second), r)
            self.assertEqual(len(clones), 1)

    def test_initial_pending_claim_already_binds_workspace(self):
        self.approve()
        self.api.fork_ready = False
        with self.assertRaises(a.Error):
            self.client.work(GHSA, "s", self.root / "first")
        self.api.records[GHSA]["private_fork"] = {
            "full_name": "owner/private-fork",
            "private": True,
        }
        self.client.recover()
        with self.assertRaisesRegex(a.Error, "another workspace"):
            self.client.work(GHSA, "s", self.root / "second")

    def test_released_clone_cannot_erase_successors_completed_or_pending_review(self):
        self.claimed()
        self.client.release(GHSA, "s")
        other = a.Advisory(api=self.api, directory=self.root / "successor")
        record = other.read(GHSA)
        record = other.authorize(
            GHSA,
            {
                "expected": policy.digest(record),
                "owner": board.OWNER,
                "source": "Synthetic released handoff",
                "scope": "Same bounded work",
                "reconfirm": True,
            },
        )
        m = a.metadata(record)
        m["owner"] = {"session": "successor", "clone": other.clone_id()}
        m["workspace"]["prepared_for"] = m["owner"]
        other.change(record, m, "claim", "Synthetic successor claim", trust=True)

        def reviewer(args, **kwargs):
            kwargs["stdout"].write(
                json.dumps(
                    {
                        "codex": {"status": 0},
                        "inputs": {"head": HEAD, "base": BASE, "merge_base": BASE},
                        "result": {"verdict": "approve", "findings": []},
                    }
                )
            )
            return subprocess.CompletedProcess(args, 0)

        marker = {"repository": board.REPO, "ghsa": GHSA, "fork": "owner/private-fork"}
        with (
            mock.patch.object(guard, "verify", return_value=marker),
            mock.patch.object(other, "inputs", return_value=(HEAD, BASE, BASE)),
        ):
            with mock.patch("subprocess.run", side_effect=reviewer):
                other.review(
                    GHSA,
                    "successor",
                    {
                        "phase": "code",
                        "scope": "initial",
                        "focus": "Synthetic successor review",
                    },
                )
            with mock.patch(
                "subprocess.run", side_effect=OSError("synthetic stopped invocation")
            ):
                with self.assertRaises(OSError):
                    other.review(
                        GHSA,
                        "successor",
                        {
                            "phase": "code",
                            "scope": "initial",
                            "focus": "Synthetic pending successor review",
                        },
                    )
        before = other.read(GHSA)
        ledger = a.metadata(before)["ledger"]
        self.assertEqual(policy.count(ledger, "code"), 1)
        self.assertEqual(sum(r["status"] == "pending" for r in ledger["reviews"]), 1)
        with self.assertRaisesRegex(a.Error, "trusted active claim"):
            self.client.reconcile(
                GHSA,
                {
                    "expected": policy.digest(before),
                    "owner": board.OWNER,
                    "source": "Synthetic stale returning decision",
                    "reason": "Must not erase successor",
                    "stopped_attempts": [],
                },
            )
        self.assertEqual(other.read(GHSA), before)
        other.owned(GHSA, "successor", False)
        after = other.recover_review(GHSA, "successor", failed=True)
        self.assertEqual(policy.count(a.metadata(after)["ledger"], "code"), 1)
        self.assertEqual(a.metadata(after)["ledger"]["reviews"][-1]["status"], "failed")

    def test_same_path_successor_must_restore_branch_even_after_failed_retry(self):
        self.approve()
        shared = self.root / "same-path"
        bare = self.root / "remote.git"
        archive = self.root / "first-machine-copy"
        subprocess.run(["git", "init", "-q", "-b", "main", str(shared)], check=True)
        for key, value in (
            ("user.name", "Synthetic"),
            ("user.email", "test@example.invalid"),
        ):
            subprocess.run(["git", "-C", str(shared), "config", key, value], check=True)
        (shared / "test.txt").write_text("base\n")
        subprocess.run(["git", "-C", str(shared), "add", "test.txt"], check=True)
        subprocess.run(["git", "-C", str(shared), "commit", "-qm", "base"], check=True)
        subprocess.run(
            ["git", "-C", str(shared), "switch", "-qc", "remediation"], check=True
        )
        (shared / "test.txt").write_text("synthetic remediation\n")
        subprocess.run(
            ["git", "-C", str(shared), "commit", "-qam", "synthetic correction"],
            check=True,
        )
        head = subprocess.check_output(
            ["git", "-C", str(shared), "rev-parse", "HEAD"], text=True
        ).strip()
        subprocess.run(
            ["git", "clone", "-q", "--bare", str(shared), str(bare)], check=True
        )
        subprocess.run(
            ["git", "-C", str(bare), "symbolic-ref", "HEAD", "refs/heads/main"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(bare), "update-ref", "-d", "refs/heads/remediation"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(shared),
                "remote",
                "add",
                "origin",
                "https://github.com/owner/private-fork.git",
            ],
            check=True,
        )
        original = guard.command
        clones = []

        def command(args, cwd=None):
            if args[0] == "gh":
                return json.dumps({"full_name": "owner/private-fork", "private": True})
            if args[:2] == ["git", "clone"]:
                clones.append(args[-1])
                original(["git", "clone", "--", str(bare), args[-1]])
                return original(
                    [
                        "git",
                        "remote",
                        "set-url",
                        "origin",
                        "https://github.com/owner/private-fork.git",
                    ],
                    args[-1],
                )
            if args == ["git", "fetch", "origin"]:
                return original(
                    ["git", "fetch", str(bare), "+refs/heads/*:refs/remotes/origin/*"],
                    cwd,
                )
            return original(args, cwd)

        with mock.patch.object(guard, "command", side_effect=command):
            self.client.work(GHSA, "s", shared)
            old = Path.cwd()
            try:
                os.chdir(shared)
                with mock.patch.object(
                    self.client, "inputs", return_value=(head, head, head)
                ):
                    self.client.checkpoint(
                        GHSA,
                        "s",
                        {
                            "completed": "Synthetic correction",
                            "verification": "Synthetic tests passed",
                            "blockers": "",
                            "next": "Push and hand off",
                        },
                    )
                self.client.release(GHSA, "s")
            finally:
                os.chdir(old)
            shared.rename(archive)  # Model another machine with the identical pathname.
            successor = a.Advisory(
                api=self.api, directory=self.root / "second-machine-state"
            )
            r = successor.read(GHSA)
            successor.authorize(
                GHSA,
                {
                    "expected": policy.digest(r),
                    "owner": board.OWNER,
                    "source": "Explicit synthetic handoff",
                    "scope": "Same bounded correction",
                    "reconfirm": True,
                },
            )
            for _ in range(2):
                with self.assertRaisesRegex(a.Error, "branch has not reached"):
                    successor.work(GHSA, "next", shared)
                self.assertEqual(
                    original(["git", "branch", "--show-current"], shared), "main"
                )
                self.assertNotEqual(
                    original(["git", "rev-parse", "HEAD"], shared), head
                )
                try:
                    os.chdir(shared)
                    with self.assertRaisesRegex(a.Error, "preparation is incomplete"):
                        successor.owned(GHSA, "next")
                finally:
                    os.chdir(old)
            # Original machine makes its already-recorded commit available privately.
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(bare),
                    "fetch",
                    "-q",
                    str(archive),
                    "remediation:remediation",
                ],
                check=True,
            )
            r = successor.work(GHSA, "next", shared)
            self.assertEqual(
                original(["git", "branch", "--show-current"], shared), "remediation"
            )
            self.assertEqual(original(["git", "rev-parse", "HEAD"], shared), head)
            self.assertEqual(
                a.metadata(r)["workspace"]["prepared_for"], a.metadata(r)["owner"]
            )
            self.assertEqual(successor.work(GHSA, "next", shared), r)
            self.assertEqual(len(clones), 1)


if __name__ == "__main__":
    unittest.main()
