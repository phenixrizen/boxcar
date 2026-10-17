# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Tests for codex_review: python3 -m unittest discover -s scripts -p '*_test.py'"""

import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import codex_review
from codex_review import (
    BaseRepeated,
    BaseUnknown,
    NotInstalled,
    base_of,
    behind,
    install_root,
    main,
    refused_flag,
    registry_path,
    remote_of,
)

HERE = Path("/repo/boxcar")


def same(p: Path) -> Path:
    return p


def entry(path: str, scope: str = "user", project: str | None = None) -> dict:
    e = {"installPath": path, "scope": scope, "version": path.rsplit("/", 1)[-1]}
    if project:
        e["projectPath"] = project
    return e


def registry(*entries: dict) -> dict:
    return {"version": 2, "plugins": {"codex@openai-codex": list(entries)}}


class InstallRoot(unittest.TestCase):
    def test_the_users_installation(self):
        self.assertEqual(
            install_root(registry(entry("/cache/codex/1.0.6")), HERE, same),
            Path("/cache/codex/1.0.6"),
        )

    def test_another_projects_installation_listed_first_is_passed_over(self):
        reg = registry(
            entry("/cache/codex/0.9.0", "project", "/elsewhere"),
            entry("/cache/codex/1.0.6"),
        )
        self.assertEqual(install_root(reg, HERE, same), Path("/cache/codex/1.0.6"))

    def test_this_projects_installation_wins_over_the_users(self):
        reg = registry(
            entry("/cache/codex/1.0.6"), entry("/cache/codex/1.0.7", "local", str(HERE))
        )
        self.assertEqual(install_root(reg, HERE, same), Path("/cache/codex/1.0.7"))

    def test_only_another_projects_installation_is_not_installed(self):
        with self.assertRaises(NotInstalled):
            install_root(
                registry(entry("/cache/codex/1.0.6", "project", "/elsewhere")),
                HERE,
                same,
            )

    def test_two_for_the_same_scope_are_refused(self):
        with self.assertRaises(NotInstalled):
            install_root(
                registry(entry("/cache/codex/1.0.6"), entry("/cache/codex/1.0.7")),
                HERE,
                same,
            )

    def test_nothing_installed(self):
        with self.assertRaises(NotInstalled):
            install_root({"version": 2, "plugins": {}}, HERE, same)

    def test_an_inherited_git_dir_does_not_make_another_project_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            mine, other = Path(tmp, "mine"), Path(tmp, "other")
            for repo in (mine, other):
                repo.mkdir()
                subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            reg = registry(
                entry("/cache/codex/0.9.0", "project", str(other)),
                entry("/cache/codex/1.0.6"),
            )
            with mock.patch.dict(os.environ, {"GIT_DIR": str(other / ".git")}):
                self.assertEqual(install_root(reg, mine), Path("/cache/codex/1.0.6"))

    def test_a_linked_worktree_finds_its_main_checkouts_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            main_checkout, worktree = Path(tmp, "main"), Path(tmp, "wt")
            git = lambda *a: subprocess.run(
                ["git", *a], cwd=main_checkout, check=True, capture_output=True
            )
            main_checkout.mkdir()
            git("init", "-q")
            git(
                "-c",
                "user.name=t",
                "-c",
                "user.email=t@example.com",
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                "x",
            )
            git("worktree", "add", "-q", str(worktree))
            reg = registry(
                entry("/cache/codex/1.0.6"),
                entry("/cache/codex/1.0.7", "project", str(main_checkout)),
            )
            self.assertEqual(install_root(reg, worktree), Path("/cache/codex/1.0.7"))
            self.assertEqual(
                install_root(reg, worktree / "."), Path("/cache/codex/1.0.7")
            )


class Registry(unittest.TestCase):
    def test_under_claude_config_dir_when_set(self):
        self.assertEqual(
            registry_path({"CLAUDE_CONFIG_DIR": "/profiles/work"}),
            Path("/profiles/work/plugins/installed_plugins.json"),
        )

    def test_under_home_otherwise(self):
        self.assertEqual(
            registry_path({}),
            Path(os.path.expanduser("~/.claude/plugins/installed_plugins.json")),
        )


class Flags(unittest.TestCase):
    def test_base_and_scope_pass(self):
        for argv in (
            ["focus"],
            ["--base", "main", "focus"],
            ["--base=main", "--scope", "branch", "focus"],
            ["--scope=auto", "a", "b"],
        ):
            self.assertEqual(refused_flag(argv), "", argv)

    def test_every_other_flag_is_refused_the_directory_options_first(self):
        for argv, bad in (
            (["--cwd", "/other", "focus"], "--cwd"),
            (["--cwd=/other"], "--cwd=/other"),
            (["-C", "../other"], "-C"),
            (["--C", "/other"], "--C"),
            (["--C=/other"], "--C=/other"),
            (["-cwd", "/other"], "-cwd"),
            (["--base", "main", "--background", "focus"], "--background"),
        ):
            self.assertEqual(refused_flag(argv), bad, argv)

    def test_main_refuses_before_reading_anything(self):
        for argv in (
            ["--cwd", "/other", "focus"],
            ["-cwd", "/other", "focus"],
            ["--C=/other", "focus"],
        ):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main(argv), 2, argv)
            self.assertIn("refused", err.getvalue())


class FakeGit:
    """Answers git as a repository would, keeping every argv: remotes, each
    base's full ref, a fetch that works or not, and how far HEAD is behind
    each base."""

    def __init__(
        self,
        behind_by: dict[str, int],
        remotes=("origin",),
        fetch_ok=True,
        full: dict[str, str] | None = None,
    ):
        self.calls: list[list[str]] = []
        self.behind_by, self.remotes, self.fetch_ok = behind_by, remotes, fetch_ok
        self.full = (
            full
            if full is not None
            else {b: f"refs/remotes/{b}" for b in behind_by if "/" in b}
        )

    def __call__(self, argv, capture_output=True, text=True, env=None):
        self.calls.append(argv)
        if argv[:2] == ["git", "remote"]:
            return subprocess.CompletedProcess(
                argv, 0, "\n".join(self.remotes) + "\n", ""
            )
        if argv[:2] == ["git", "fetch"]:
            return subprocess.CompletedProcess(
                argv,
                0 if self.fetch_ok else 1,
                "",
                "" if self.fetch_ok else "network down",
            )
        if argv[:3] == ["git", "rev-parse", "--symbolic-full-name"]:
            full = self.full.get(argv[3], "")
            return subprocess.CompletedProcess(
                argv,
                0 if full else 128,
                full + "\n" if full else "",
                "" if full else "fatal: unknown",
            )
        base = argv[-1].split("..", 1)[1]
        if base not in self.behind_by:
            return subprocess.CompletedProcess(
                argv, 128, "", f"fatal: bad revision '{argv[-1]}'"
            )
        return subprocess.CompletedProcess(argv, 0, f"{self.behind_by[base]}\n", "")

    def fetched(self):
        return [c[3:] for c in self.calls if c[:2] == ["git", "fetch"]]


class Behind(unittest.TestCase):
    def test_the_base_is_base_s_one_value_else_origin_main(self):
        self.assertEqual(base_of(["focus"]), "origin/main")
        self.assertEqual(base_of(["--base", "origin/parent", "focus"]), "origin/parent")
        self.assertEqual(base_of(["--base=origin/parent", "focus"]), "origin/parent")

    def test_a_second_base_is_refused_whatever_its_form(self):
        for argv in (
            ["--base", "HEAD", "--base", "origin/main", "focus"],
            ["--base=HEAD", "--base", "origin/main", "focus"],
        ):
            with self.assertRaises(BaseRepeated):
                base_of(argv)

    def test_an_empty_base_is_refused_whatever_its_form(self):
        for argv in (
            ["--base", "", "focus"],
            ["--base=", "focus"],
            ["--base", " ", "focus"],
            ["focus", "--base"],
        ):
            with self.assertRaises(BaseUnknown):
                base_of(argv)

    def test_the_remote_and_branch_come_from_the_base_s_full_ref(self):
        git = FakeGit(
            {},
            full={
                "origin/main": "refs/remotes/origin/main",
                "refs/remotes/origin/main": "refs/remotes/origin/main",
                "origin/feature/x": "refs/remotes/origin/feature/x",
                "main": "refs/heads/main",
                "parent": "refs/heads/parent",
            },
        )
        self.assertEqual(remote_of("origin/main", git), ("origin", "main"))
        self.assertEqual(remote_of("refs/remotes/origin/main", git), ("origin", "main"))
        self.assertEqual(remote_of("origin/feature/x", git), ("origin", "feature/x"))
        self.assertEqual(remote_of("main", git), ("", ""))
        self.assertEqual(remote_of("parent", git), ("", ""))
        self.assertEqual(remote_of("nope", git), ("", ""))

    def test_a_remote_whose_name_holds_a_slash_is_found(self):
        git = FakeGit(
            {},
            remotes=("origin", "up/stream"),
            full={"up/stream/main": "refs/remotes/up/stream/main"},
        )
        self.assertEqual(remote_of("up/stream/main", git), ("up/stream", "main"))

    def test_the_base_branch_is_fetched_by_its_own_refspec_before_counting_however_the_base_is_spelled(
        self,
    ):
        for base in ("origin/main", "refs/remotes/origin/main"):
            git = FakeGit({base: 3}, full={base: "refs/remotes/origin/main"})
            self.assertEqual(behind(base, git), 3, base)
            fetch = [
                "git",
                "fetch",
                "-q",
                "origin",
                "+refs/heads/main:refs/remotes/origin/main",
            ]
            self.assertIn(fetch, git.calls, base)
            self.assertLess(
                git.calls.index(fetch),
                git.calls.index(["git", "rev-list", "--count", f"HEAD..{base}"]),
            )

    def test_a_local_base_fetches_nothing(self):
        git = FakeGit(
            {"parent-branch": 0}, full={"parent-branch": "refs/heads/parent-branch"}
        )
        self.assertEqual(behind("parent-branch", git), 0)
        self.assertEqual(git.fetched(), [])

    def test_a_failed_fetch_refuses_even_when_the_base_last_fetched_is_caught_up(self):
        with self.assertRaises(BaseUnknown) as e:
            behind("origin/main", FakeGit({"origin/main": 0}, fetch_ok=False))
        self.assertIn("could not fetch origin/main", str(e.exception))

    def test_an_unknown_base_is_refused(self):
        with self.assertRaises(BaseUnknown):
            behind("origin/nope", FakeGit({}, full={}))


class MainChecksTheBase(unittest.TestCase):
    def test_a_branch_behind_its_base_can_reach_the_reviewer(self):
        with (
            mock.patch.object(codex_review, "behind", return_value=2),
            mock.patch.object(
                codex_review, "install_root", side_effect=NotInstalled("not installed")
            ),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(main(["focus"]), 1)
        self.assertIn("not installed", err.getvalue())
        self.assertNotIn("rebase", err.getvalue())

    def test_a_stacked_branch_is_compared_with_the_base_it_names(self):
        seen = []
        with (
            mock.patch.object(
                codex_review,
                "behind",
                side_effect=lambda base, env=None: seen.append(base) or 0,
            ),
            mock.patch.object(
                codex_review, "install_root", side_effect=NotInstalled("not installed")
            ),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(["--base", "origin/parent", "focus"]), 1)
        self.assertEqual(seen, ["origin/parent"])

    def test_a_second_base_is_refused_before_the_plugin_is_looked_for(self):
        with (
            mock.patch.object(
                codex_review, "behind", side_effect=AssertionError("compared")
            ),
            mock.patch.object(
                codex_review,
                "registry_path",
                side_effect=AssertionError("looked for the plugin"),
            ),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(
                main(["--base", "HEAD", "--base", "origin/main", "focus"]), 2
            )
        self.assertIn("more than once", err.getvalue())

    def test_an_empty_base_is_refused_before_the_plugin_is_looked_for(self):
        for argv in (["--base", "", "focus"], ["--base=", "focus"]):
            with (
                mock.patch.object(
                    codex_review, "behind", side_effect=AssertionError("compared")
                ),
                mock.patch.object(
                    codex_review,
                    "registry_path",
                    side_effect=AssertionError("looked for the plugin"),
                ),
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                self.assertEqual(main(argv), 2)
            self.assertIn("no ref", err.getvalue())

    def test_a_branch_on_its_base_goes_on_to_the_review(self):
        with (
            mock.patch.object(codex_review, "behind", return_value=0),
            mock.patch.object(
                codex_review, "install_root", side_effect=NotInstalled("not installed")
            ),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(main(["focus"]), 1)
        self.assertIn("not installed", err.getvalue())

    def test_a_base_that_cannot_be_fetched_or_compared_is_refused(self):
        with (
            mock.patch.object(
                codex_review,
                "behind",
                side_effect=BaseUnknown("could not fetch origin"),
            ),
            mock.patch.object(
                codex_review,
                "registry_path",
                side_effect=AssertionError("looked for the plugin"),
            ),
            contextlib.redirect_stderr(io.StringIO()) as err,
        ):
            self.assertEqual(main(["focus"]), 2)
        self.assertIn("could not fetch", err.getvalue())


class StructuredOutput(unittest.TestCase):
    def test_json_flag_is_allowed_for_workflow_receipts(self):
        self.assertEqual(refused_flag(["--json", "--base=origin/parent", "focus"]), "")

    def test_both_base_forms_resolve_to_the_supplied_immutable_input(self):
        for form in (["--base=origin/parent"], ["--base", "origin/parent"]):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "scripts").mkdir()
                (root / "scripts/codex-companion.mjs").touch()
                seen = []

                def resolve(*args):
                    seen.append(args)
                    return "b" * 40 if "origin/parent^{commit}" in args else "a" * 40

                with (
                    mock.patch.object(codex_review, "behind", return_value=0),
                    mock.patch.object(codex_review, "install_root", return_value=root),
                    mock.patch.object(codex_review, "git_value", side_effect=resolve),
                    mock.patch.object(
                        codex_review,
                        "snapshot",
                        return_value=contextlib.nullcontext(root),
                    ),
                    mock.patch.object(
                        codex_review.subprocess,
                        "run",
                        return_value=subprocess.CompletedProcess([], 0, "{}", ""),
                    ) as call,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(main(["--json", *form, "focus"]), 0)
                argv = call.call_args.args[0]
                self.assertIn(("rev-parse", "--verify", "origin/parent^{commit}"), seen)
                self.assertNotIn("origin/main", argv)
                self.assertEqual(argv[argv.index("--base") + 1], "b" * 40)


if __name__ == "__main__":
    unittest.main()
