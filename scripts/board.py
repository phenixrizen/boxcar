#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The boxcar Authors
"""Moves an issue's or a pull request's card on the project board (AGENTS.md,
Issues and the board). Adapted from Conductor's `scripts/board.py`.

    python3 scripts/board.py <issue or pull request number> <status>

The issue is put on the board when it is not on it yet, then its Status is
set: Backlog, Ready, In progress, In review or Done (case does not matter).
It goes through `gh api graphql`, so it needs a gh token with the `project`
scope (`gh auth refresh -s project`).
"""
import json
import subprocess
import sys

OWNER = "phenixrizen"
REPO = "phenixrizen/boxcar"
BOARD = 2  # https://github.com/users/phenixrizen/projects/2
USAGE = "usage: python3 scripts/board.py <issue or pull request number> <status>"

PROJECT_QUERY = """query($login: String!, $number: Int!) {
  user(login: $login) { projectV2(number: $number) { id
    field(name: "Status") { ... on ProjectV2SingleSelectField { id options { id name } } } } } }"""
ADD_ITEM = """mutation($project: ID!, $content: ID!) {
  addProjectV2ItemById(input: {projectId: $project, contentId: $content}) { item { id } } }"""
SET_STATUS = """mutation($project: ID!, $item: ID!, $field: ID!, $option: String!) {
  updateProjectV2ItemFieldValue(input: {projectId: $project, itemId: $item, fieldId: $field,
    value: {singleSelectOptionId: $option}}) { projectV2Item { id } } }"""


class BoardError(Exception):
    pass


def gh(args: list[str], run=subprocess.run) -> dict:
    """Runs gh with args and answers its JSON output."""
    r = run(["gh", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise BoardError(r.stderr.strip() or f"gh {args[0]} failed")
    return json.loads(r.stdout or "null")


def graphql(query: str, variables: dict, run=subprocess.run) -> dict:
    args = ["api", "graphql", "-f", f"query={query}"]
    for k, v in variables.items():
        args += ["-F" if isinstance(v, int) else "-f", f"{k}={v}"]
    return gh(args, run)


def pick_option(options: list[dict], wanted: str) -> dict:
    """The Status option named wanted, whatever its case."""
    for o in options:
        if o["name"].lower() == wanted.strip().lower():
            return o
    names = ", ".join(o["name"] for o in options)
    raise BoardError(f"no status {wanted!r} on the board; it has: {names}")


def move(issue: int, status: str, run=subprocess.run) -> str:
    """Puts the issue on the board and sets its Status; answers the option's name."""
    if not BOARD:
        raise BoardError("BOARD is not set in scripts/board.py")
    p = graphql(PROJECT_QUERY, {"login": OWNER, "number": BOARD}, run)["data"]["user"]["projectV2"]
    field = p["field"]
    option = pick_option(field["options"], status)
    content = gh(["api", f"repos/{REPO}/issues/{issue}"], run)["node_id"]
    item = graphql(ADD_ITEM, {"project": p["id"], "content": content}, run)["data"]["addProjectV2ItemById"]["item"]["id"]
    graphql(SET_STATUS, {"project": p["id"], "item": item, "field": field["id"], "option": option["id"]}, run)
    return option["name"]


def main(argv: list[str], run=subprocess.run) -> int:
    if len(argv) != 2 or not argv[0].lstrip("#").isdigit():
        print(USAGE, file=sys.stderr)
        return 2
    try:
        name = move(int(argv[0].lstrip("#")), argv[1], run)
    except BoardError as e:
        print(f"board: {e}", file=sys.stderr)
        return 1
    print(f"#{argv[0].lstrip('#')}: {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
