# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
import contextlib
import io
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


LEGACY_OPTIONS = [
    {"id": "o1", "name": "Backlog"},
    {"id": "o2", "name": "Ready"},
    {"id": "o3", "name": "In progress"},
    {"id": "o4", "name": "In review"},
    {"id": "o5", "name": "Done"},
]


class LegacyGh:
    """Answers gh as GitHub would, and keeps every argv it was given."""

    def __init__(self, fail_on: str | None = None):
        self.calls: list[list[str]] = []
        self.fail_on = fail_on

    def __call__(self, argv, capture_output=True, text=True):
        self.calls.append(argv)
        joined = " ".join(argv)
        if self.fail_on and self.fail_on in joined:
            return subprocess.CompletedProcess(
                argv, 1, "", "HTTP 403: missing scope project"
            )
        if "projectV2(number" in joined:
            out = {
                "data": {
                    "user": {
                        "projectV2": {
                            "id": "P1",
                            "viewerCanUpdate": True,
                            "field": {"id": "F1", "options": LEGACY_OPTIONS},
                        }
                    }
                }
            }
        elif argv[:2] == ["gh", "api"] and argv[2].startswith("repos/"):
            out = {"node_id": "I_138", "state": "open"}
        elif "addProjectV2ItemById" in joined:
            out = {"data": {"addProjectV2ItemById": {"item": {"id": "IT1"}}}}
        else:
            out = {
                "data": {
                    "updateProjectV2ItemFieldValue": {"projectV2Item": {"id": "IT1"}}
                }
            }
        return subprocess.CompletedProcess(argv, 0, json.dumps(out), "")


class LegacyPickOption(unittest.TestCase):
    def test_a_status_whatever_its_case(self):
        self.assertEqual(board.pick_option(LEGACY_OPTIONS, "in PROGRESS")["id"], "o3")

    def test_an_unknown_status_names_the_boards(self):
        with self.assertRaises(board.BoardError) as e:
            board.pick_option(LEGACY_OPTIONS, "Doing")
        self.assertIn("Backlog, Ready, In progress, In review, Done", str(e.exception))


@mock.patch.object(board, "BOARD", 7)
class LegacyMove(unittest.TestCase):
    def test_puts_the_issue_on_the_board_then_sets_its_status(self):
        fake = LegacyGh()
        self.assertEqual(board.set_status(138, "in review", fake), "In review")
        self.assertEqual(fake.calls[1], ["gh", "api", f"repos/{board.REPO}/issues/138"])
        add = " ".join(fake.calls[2])
        self.assertIn("project=P1", add)
        self.assertIn("content=I_138", add)
        last = fake.calls[3]
        for want in ("project=P1", "item=IT1", "field=F1", "option=o4"):
            self.assertIn(want, last)

    def test_the_boards_number_goes_as_an_int(self):
        fake = LegacyGh()
        board.set_status(1, "Done", fake)
        first = fake.calls[0]
        self.assertEqual(first[first.index("number=7") - 1], "-F")

    def test_an_unknown_status_changes_nothing(self):
        fake = LegacyGh()
        with self.assertRaises(board.BoardError):
            board.set_status(138, "Doing", fake)
        self.assertEqual(len(fake.calls), 1)

    def test_a_gh_failure_says_why(self):
        with self.assertRaises(board.BoardError) as e:
            board.set_status(138, "Done", LegacyGh(fail_on="graphql"))
        self.assertIn("missing scope project", str(e.exception))


class LegacyMain(unittest.TestCase):
    def test_usage_without_two_arguments(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(board.main(["138"], LegacyGh()), 2)
        self.assertIn("board.py", err.getvalue())

    @mock.patch.object(board, "BOARD", 7)
    def test_a_hash_before_the_number_is_taken(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(board.main(["#138", "Ready"], LegacyGh()), 0)
        self.assertEqual(out.getvalue().strip(), "#138: Ready")

    def test_an_unset_board_is_refused(self):
        err = io.StringIO()
        with mock.patch.object(board, "BOARD", 0), contextlib.redirect_stderr(err):
            self.assertEqual(board.main(["138", "Done"], LegacyGh()), 1)
        self.assertIn("BOARD is not set", err.getvalue())
