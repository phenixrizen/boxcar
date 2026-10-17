# Issue workflow

## Claude entry point

From this repository in Claude:

```text
/memory
/work-issue phenixrizen/boxcar#43
/work-issue phenixrizen/boxcar#43 checkpoint
/work-issue phenixrizen/boxcar#43 review
/work-issue phenixrizen/boxcar#43 submit
/work-issue phenixrizen/boxcar#43 complete
```

The repository skill is distinct from bundled commands. Both repositories use
`CLAUDE.md` with `@AGENTS.md`. Current Claude can load AGENTS.md directly in
some configurations; absence of CLAUDE.md alone does not prove instructions
are missing. In `/memory`, inspect loaded files and confirm this worktree's
CLAUDE.md and imported AGENTS.md; inspect exclusions and Project instructions
if absent. Restart after adding a skill if it does not appear in `/` completion.
See [Claude memory](https://code.claude.com/docs/en/memory) and
[skills](https://code.claude.com/docs/en/skills). Architecture/check catalogs
are links, not imports, so they do not all load at startup.

## Commands and checkpoints

Requirements: Python 3.10+, Git, authenticated `gh` with repository and Project
write access, and the existing Codex plugin installation/login for reviews.
The helper runs on Linux/macOS/WSL (its clone lock uses `flock`). Run native
Windows sessions through WSL. No networking configuration is required.

```bash
python3 scripts/work_issue.py start phenixrizen/boxcar#43 --session my-session
# Follow the printed worktree path. To adopt an existing issue branch:
python3 scripts/work_issue.py start phenixrizen/boxcar#43 --session my-session --here
python3 scripts/work_issue.py checkpoint phenixrizen/boxcar#43 --session my-session --file /tmp/checkpoint.json
python3 scripts/work_issue.py review phenixrizen/boxcar#43 --session my-session --phase code --focus 'risks this change touches'
python3 scripts/work_issue.py submit phenixrizen/boxcar#43 --session my-session --relation fixes --title 'area: outcome' --body-file /tmp/pr.md
python3 scripts/work_issue.py complete phenixrizen/boxcar#43
```

A checkpoint file contains these four strings (actual results, not planned tests).
The complete public checkpoint, including review history and triage, is limited
to 60,000 UTF-8 bytes before anything is saved. Summarize lengthy test output;
do not trim review history to fit. A rejected oversized edit leaves the previous
checkpoint intact, so a shorter correction can be submitted normally.
For submission, record results after the implementation is committed; verification
is bound to that clean commit and base and does not become fresh merely on resume:

```json
{
  "completed": "Implemented the change and its regression tests",
  "verification": "python3 -m unittest discover -s scripts -p '*_test.py': 30 passed",
  "blockers": "None",
  "next": "Commit and run the code review"
}
```

The helper adds issue, branch, current commit, session/clone identifier, review
ledger, and base. It updates one owner-authored comment marked
`work-issue-checkpoint:v1`. It fetches discussion and related PRs at start;
read linked plans and dependency issues explicitly. Owner-authorized selection
and acceptance criteria require judgment; a script cannot infer them from a
Ready card. Search before creating an issue for a direct feature request.
Use `gh issue create --body-file` and the task template. No backlog polling.

## Durability and coordination

Local state is `$(git rev-parse --git-common-dir)/work-issue/`: one JSON file
per issue, a clone ID, an operation lock and local raw review reports. It is
outside commits and shared by linked worktrees. File replacement is atomic
and fsynced. Review attempts have IDs; failed publication never erases them.
A lost response is reconciled against the marked comment or exact PR head and
base before retry. Multiple matches or conflicting versions stop the helper.

A claim belongs to one session and clone, not an issue assignee. The OS lock
serializes helper operations in that clone; the persistent claim prevents a
second session from taking the issue or its branch. Other clones have other
locks. GitHub comment version checks are optimistic conflict detection, NOT
an atomic distributed lock. Do not start simultaneously in separate clones.
Coordinate those sessions with the owner; never silently steal a claim.

Before handoff: checkpoint, commit and push the branch, then:

```bash
python3 scripts/work_issue.py release phenixrizen/boxcar#43 --session my-session
```

Release refuses pending reviews and publishes/verifies all history before
publishing the released claim. The next session uses its own ID with `start`.
Returning to an earlier clone also imports a newer released checkpoint when
that clone has no unpublished metadata. Review history is retained. An active
claim, unpublished local changes, or missing review history remains a conflict.
A fresh clone fetches the branch and recovers the ledger from the issue comment.
Unsaved files and private raw reports do not travel: transfer those privately
if needed. If the former process died with an active claim, confirm it has
stopped, synchronize its local metadata, and explicitly release using its old
session ID in that clone. Loss of that clone while ownership/history is
unpublished requires owner reconciliation; do not delete the comment to reset.
Rebases keep the ledger but make old revision approvals stale. After a stacked
parent merges, rebase onto main, then run
`python3 scripts/work_issue.py base phenixrizen/boxcar#N --session SESSION --base origin/main`
in the task worktree. It preserves counts and invalidates old evidence;
submit retargets the existing PR rather than opening another.

## Review evidence and budgets

The wrapper uses the existing `scripts/codex_review.py`, including its plugin
registry resolution and base-freshness checks. It requests structured output,
keeps the raw report locally and publishes only phase, attempt ID, commit,
base ref/SHA, completed count, outcome and unresolved finding count. Do not
copy raw findings into public checkpoints without checking them for private
content. Review all findings and record their disposition in the PR.

Receipts cover the exact committed revision and exact base, not the mutable
working tree, not future commits. No receipt is committed into its own review
target. The helper refuses dirty review/submit operations. It also fetches the
current base again before submit. A changed head OR base needs fresh evidence.
Plan and code reviews are distinct. The PR evidence records plan receipts too.

Budgets: docs/process one; plan two; code three before a findings-triage
checkpoint, five as the hard stop. At code round three with findings, use
`triage --file` (a text file describing dispositions) before another round.
At the final permitted round fix findings, mark the new revision unreviewed,
and seek the owner's decision. The `--pending` submit option opens a draft
and explicitly fails the contract check; it is never a review pass.

For an extra round, the owner posts this exact line in the issue (replace
PHASE and ROUND with the next phase/round):

```text
work-issue authorize phenixrizen/boxcar#43 PHASE ROUND
```

Then `authorize ... --phase PHASE --round ROUND --comment COMMENT_ID` checks
GitHub author and exact scope and persists it. No generic unlimited waiver.
Interrupted attempts block new reviews: `recover` reads the saved structured
result once; `recover --failed` is only for a confirmed stopped invocation
without a completed result. Failed/unavailable invocations consume no completed
round and approve nothing. Never use recovery to hide a completed review.

## PR contract and private exceptions

Use `--relation part` for `Part of #N`; only `--relation fixes` emits `Fixes #N`
and moves the issue In review. An open finishing PR is not Done. A PR merged
into a parent branch is not Done: its final main PR must repeat `Fixes #N`.
`complete` finds merged finishing PRs and verifies their merge commit is on
main. Board commands independently check review/completion evidence; `Done`
is not an arbitrary assignment. Duplicate and not-planned closures keep the
explicit issue discussion/owner decision and are not implementation completion.

`submit` appends a `work-issue-pr:v1` JSON block with the checkpoint URL,
issue, relation and reviewed revision. The contract check re-fetches the PR,
issue and owner-authored checkpoint, verifies the current head/base, actual
verification text, phase counts and approval. It verifies recorded evidence,
not the quality of tests or the model's conclusions. The authenticated owner's
comment is an attestation boundary, not cryptographic model attestation.
Changing the PR, receipt or base invalidates prior results; rerun when evidence
changes. Only the repository owner is a receipt issuer in this initial version.

Private security work uses `/security-finding` and `/work-security REPOSITORY GHSA-xxxx-yyyy-zzzz` (with this repository's full name), bypassing public issue/checkpoint creation. Read `docs/security-workflow.md` first. Keep its
execution history and reviews in the affected repository's GitHub Draft Security Advisories and local raw
reports; use the existing review helper directly and obey the repository's
security authorization rules. An owner-authorized exception can be attested
on the PR using only this neutral exact line:

```text
work-issue exception HEAD_SHA BASE_SHA
```

CI accepts that exact owner-authored attestation for that revision/base without
publishing the reason or linking a private document. It is also the explicit
mechanism for an owner decision to merge final-round fixes without another
review. Do not publish sensitive descriptions, logs, IDs, or private URLs in
exception metadata. Ordinary agents cannot self-authorize an exception.

## GitHub setup and observed settings (2026-10-17)

Project 2 under phenixrizen was accessible with `viewerCanUpdate: true`.
Its Status options are Backlog, Ready, In progress, In review and Done. IDs
are discovered by field/option name, never copied into task state. Both Projects
have Auto-add sub-issues, Item closed, Pull request linked to issue and Pull
request merged enabled; Auto-close issue and Item added to project are disabled.
The API exposes names/enabled state, not conditions/actions. Those existing
workflows were not changed.

At https://github.com/users/phenixrizen/projects/2/workflows inspect:

1. Keep Auto-close issue disabled (status is never permission to close).
2. Keep Auto-add sub-issues if desired. Item added may set Backlog only.
3. Disable Pull request linked to issue for issue status: it cannot distinguish
   partial/finishing evidence. The submit helper owns In review.
4. Disable Item closed for issue status: it cannot prove implementation reached
   main and also catches duplicate/not-planned closure. Use `complete` for Done.
5. Pull request merged may update PR cards only; disable it if it also completes
   issue cards without checking main. Intermediate PR cards can be Done while
   the issue remains In review. No second board-writing Actions workflow is added.

Both repositories had no rulesets and main protection returned 'Branch not
protected'. The file alone is NOT a required merge check. After merging this
bootstrap, verify that `issue-contract` appears on an actual PR's Checks tab
and that a failed check becomes successful after correcting its evidence and
rerunning that same run. Required-check association has not been validated
live before this bootstrap reaches main. Only after that check, Settings → Rules → Rulesets: create
(or narrowly extend) a branch ruleset targeting `main`; require PRs, require
branches up to date, and require the check `issue-contract` alongside the
existing checks the owner chooses. Protect workflow/helper changes with owner
review. Do not replace unrelated settings or imply these were configured.

The contract workflow uses `pull_request_target` with read-only permissions and
checks out only main; it never executes PR files. The new bootstrap workflow
cannot run from main before this PR merges. Validate these initial PRs with
`python3 scripts/work_issue.py ci --pr PR_43` locally. Separate ordinary PR
CI runs helper tests. Once installed, comment edits alone do not trigger it.
Find the existing run through the PR's Checks tab or `gh pr checks PR_NUMBER
--repo phenixrizen/boxcar --json name,link`. Rerun that run with `gh run rerun
RUN_ID --repo phenixrizen/boxcar --failed`, wait with `gh run watch RUN_ID
--repo phenixrizen/boxcar --exit-status`, then confirm the result on the PR
with `gh pr checks`. A separate manually dispatched run is not a replacement
for the PR's failed check. If no PR-associated check appears, leave this check
out of branch requirements and resolve that association before enabling it.
