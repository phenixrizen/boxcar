# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
import json
import subprocess
import unittest
from unittest import mock
import board

OPTIONS = [
    {"id": str(i), "name": n}
    for i, n in enumerate(["Backlog", "Ready", "In progress", "In review", "Done"])
]


class FakeGh:
    def __init__(self):
        self.calls = []
        self.denied = False
        self.partial = False

    def __call__(self, args, **kw):
        self.calls.append(args)
        s = " ".join(args)
        if self.partial:
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"data": {}, "errors": [{"message": "denied"}]}), ""
            )
        if "projectV2(number" in s:
            d = {
                "data": {
                    "user": {
                        "projectV2": {
                            "id": "P",
                            "viewerCanUpdate": not self.denied,
                            "field": {"id": "F", "options": OPTIONS},
                        }
                    }
                }
            }
        elif "/issues/" in s:
            d = {"node_id": "I", "state": "open"}
        elif "addProjectV2ItemById" in s:
            d = {"data": {"addProjectV2ItemById": {"item": {"id": "ITEM"}}}}
        else:
            d = {
                "data": {
                    "updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "ITEM"}}
                }
            }
        return subprocess.CompletedProcess(args, 0, json.dumps(d), "")


class Board(unittest.TestCase):
    def test_options_discovered_and_idempotent_add_used(self):
        f = FakeGh()
        self.assertEqual(board.set_status(1, "in PROGRESS", f), "In progress")
        self.assertIn("option=2", f.calls[-1])
        self.assertIn("project=P", f.calls[-1])

    def test_read_only_project_is_refused_before_mutation(self):
        f = FakeGh()
        f.denied = True
        with self.assertRaises(board.BoardError):
            board.set_status(1, "Done", f)
        self.assertEqual(len(f.calls), 1)

    def test_graphql_partial_failure_is_not_success(self):
        f = FakeGh()
        f.partial = True
        with self.assertRaises(board.BoardError):
            board.set_status(1, "Done", f)

    def test_unknown_status_and_unset_board(self):
        with self.assertRaises(board.BoardError):
            board.set_status(1, "invented", FakeGh())
        with mock.patch.object(board, "BOARD", 0), self.assertRaises(board.BoardError):
            board.project(FakeGh())

    def test_done_delegates_to_merge_evidence_and_does_not_blindly_set(self):
        import work_issue

        with mock.patch.object(
            work_issue, "finish", side_effect=work_issue.Error("no merge")
        ):
            with self.assertRaisesRegex(board.BoardError, "no merge"):
                board.move(1, "Done", FakeGh())

    def test_partial_pr_cannot_advance_issue(self):
        import work_issue

        with mock.patch.object(
            work_issue, "pulls", return_value=[{"body": "Part of #1", "state": "open"}]
        ):
            with self.assertRaisesRegex(board.BoardError, "finishing"):
                board.move(1, "In review", FakeGh())
