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

from codex_review import NotInstalled, install_root, main, refused_flag, registry_path

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
        self.assertEqual(install_root(registry(entry("/cache/codex/1.0.6")), HERE, same), Path("/cache/codex/1.0.6"))

    def test_another_projects_installation_listed_first_is_passed_over(self):
        reg = registry(entry("/cache/codex/0.9.0", "project", "/elsewhere"), entry("/cache/codex/1.0.6"))
        self.assertEqual(install_root(reg, HERE, same), Path("/cache/codex/1.0.6"))

    def test_this_projects_installation_wins_over_the_users(self):
        reg = registry(entry("/cache/codex/1.0.6"), entry("/cache/codex/1.0.7", "local", str(HERE)))
        self.assertEqual(install_root(reg, HERE, same), Path("/cache/codex/1.0.7"))

    def test_only_another_projects_installation_is_not_installed(self):
        with self.assertRaises(NotInstalled):
            install_root(registry(entry("/cache/codex/1.0.6", "project", "/elsewhere")), HERE, same)

    def test_two_for_the_same_scope_are_refused(self):
        with self.assertRaises(NotInstalled):
            install_root(registry(entry("/cache/codex/1.0.6"), entry("/cache/codex/1.0.7")), HERE, same)

    def test_nothing_installed(self):
        with self.assertRaises(NotInstalled):
            install_root({"version": 2, "plugins": {}}, HERE, same)

    def test_an_inherited_git_dir_does_not_make_another_project_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            mine, other = Path(tmp, "mine"), Path(tmp, "other")
            for repo in (mine, other):
                repo.mkdir()
                subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            reg = registry(entry("/cache/codex/0.9.0", "project", str(other)), entry("/cache/codex/1.0.6"))
            with mock.patch.dict(os.environ, {"GIT_DIR": str(other / ".git")}):
                self.assertEqual(install_root(reg, mine), Path("/cache/codex/1.0.6"))

    def test_a_linked_worktree_finds_its_main_checkouts_installation(self):
        with tempfile.TemporaryDirectory() as tmp:
            main_checkout, worktree = Path(tmp, "main"), Path(tmp, "wt")
            git = lambda *a: subprocess.run(["git", *a], cwd=main_checkout, check=True, capture_output=True)
            main_checkout.mkdir()
            git("init", "-q")
            git("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "--allow-empty", "-m", "x")
            git("worktree", "add", "-q", str(worktree))
            reg = registry(entry("/cache/codex/1.0.6"), entry("/cache/codex/1.0.7", "project", str(main_checkout)))
            self.assertEqual(install_root(reg, worktree), Path("/cache/codex/1.0.7"))
            self.assertEqual(install_root(reg, worktree / "."), Path("/cache/codex/1.0.7"))


class Registry(unittest.TestCase):
    def test_under_claude_config_dir_when_set(self):
        self.assertEqual(registry_path({"CLAUDE_CONFIG_DIR": "/profiles/work"}), Path("/profiles/work/plugins/installed_plugins.json"))

    def test_under_home_otherwise(self):
        self.assertEqual(registry_path({}), Path(os.path.expanduser("~/.claude/plugins/installed_plugins.json")))


class Flags(unittest.TestCase):
    def test_base_and_scope_pass(self):
        for argv in (["focus"], ["--base", "main", "focus"], ["--base=main", "--scope", "branch", "focus"], ["--scope=auto", "a", "b"]):
            self.assertEqual(refused_flag(argv), "", argv)

    def test_every_other_flag_is_refused_the_directory_options_first(self):
        for argv, bad in ((["--cwd", "/other", "focus"], "--cwd"), (["--cwd=/other"], "--cwd=/other"), (["-C", "../other"], "-C"),
                          (["--C", "/other"], "--C"), (["--C=/other"], "--C=/other"), (["-cwd", "/other"], "-cwd"),
                          (["--base", "main", "--background", "focus"], "--background")):
            self.assertEqual(refused_flag(argv), bad, argv)

    def test_main_refuses_before_reading_anything(self):
        for argv in (["--cwd", "/other", "focus"], ["-cwd", "/other", "focus"], ["--C=/other", "focus"]):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main(argv), 2, argv)
            self.assertIn("refused", err.getvalue())


if __name__ == "__main__":
    unittest.main()
