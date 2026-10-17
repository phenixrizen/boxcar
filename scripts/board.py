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
  user(login: $login) { projectV2(number: $number) { id viewerCanUpdate
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
    try:
        value = json.loads(r.stdout or "null")
    except ValueError:
        raise BoardError("GitHub returned invalid JSON") from None
    if isinstance(value, dict) and value.get("errors"):
        raise BoardError("GitHub GraphQL failed; check issue/Project access")
    return value


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


def project(run=subprocess.run):
    if not BOARD:
        raise BoardError("BOARD is not set in scripts/board.py")
    data = graphql(PROJECT_QUERY, {"login": OWNER, "number": BOARD}, run)
    p = (data.get("data", {}).get("user") or {}).get("projectV2")
    if not p or not p.get("viewerCanUpdate"):
        raise BoardError(
            "Project write access required; check repository role and gh project scope"
        )
    if not p.get("field") or not p["field"].get("options"):
        raise BoardError("Project Status single-select field is missing")
    for name in ("Backlog", "Ready", "In progress", "In review", "Done"):
        pick_option(p["field"]["options"], name)
    return p


def set_status(issue: int, status: str, run=subprocess.run) -> str:
    """Low-level idempotent mutation; callers must validate work evidence first."""
    p = project(run)
    field = p["field"]
    option = pick_option(field["options"], status)
    content = gh(["api", f"repos/{REPO}/issues/{issue}"], run)["node_id"]
    item = graphql(ADD_ITEM, {"project": p["id"], "content": content}, run)["data"][
        "addProjectV2ItemById"
    ]["item"]["id"]
    changed = graphql(
        SET_STATUS,
        {
            "project": p["id"],
            "item": item,
            "field": field["id"],
            "option": option["id"],
        },
        run,
    )
    if (
        not changed.get("data", {})
        .get("updateProjectV2ItemFieldValue", {})
        .get("projectV2Item", {})
        .get("id")
    ):
        raise BoardError("Project status update was not acknowledged")
    return option["name"]


def move(issue: int, status: str, run=subprocess.run) -> str:
    """Validate evidence, then move. A requested status is not evidence."""
    import work_issue as w

    wanted = pick_option(project(run)["field"]["options"], status)["name"]
    content = gh(["api", f"repos/{REPO}/issues/{issue}"], run)
    client = w.GitHub()
    try:
        if content.get("pull_request"):
            pr = gh(["api", f"repos/{REPO}/pulls/{issue}"], run)
            if wanted == "Done" and not pr.get("merged_at"):
                raise BoardError("PR card needs an actual merge")
            if wanted == "In review" and pr["state"] != "open":
                raise BoardError("PR is not open")
        elif wanted == "Done":
            w.finish(issue, client)
            return wanted
        elif wanted == "In review":
            if not any(
                w.relation(p.get("body"), issue) == "fixes"
                and (p["state"] == "open" or p.get("merged_at"))
                for p in w.pulls(client)
            ):
                raise BoardError(
                    "In review needs a finishing PR; partial work stays In progress"
                )
        elif wanted == "In progress":
            task = w.Task(issue, client)
            if not task.state or not task.state.get("owner"):
                raise BoardError(
                    "start the issue workflow to establish branch/session ownership"
                )
        elif content.get("state") != "open":
            raise BoardError(
                "closed issue: use explicit duplicate/not-planned handling, not a work status"
            )
        return set_status(issue, wanted, run)
    except w.Error as e:
        raise BoardError(str(e)) from None


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
