# Issue workflow

## Claude entry point

From the selected task worktree in Claude:

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
if absent. Establish the task worktree before implementation; an old detached
checkout or unrelated feature branch can still load obsolete instructions. Do not
reset unrelated work to update its instructions. Re-enter the selected worktree
and inspect its current contract. Restart after adding a skill if it does not appear in `/` completion.
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
to 65,000 UTF-8 bytes before anything is saved. Summarize lengthy test output;
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
Use `gh issue create --body-file` and the task template for owner-selected outcomes
or demonstrated independent actionable defects. Necessary fixes stay in the task;
optional suggestions stay dispositions. Do not create issues for every review claim.
No backlog polling.

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
parent merges, integrate onto main as appropriate, then run
`python3 scripts/work_issue.py base phenixrizen/boxcar#N --session SESSION --base origin/main`
in the task worktree. It preserves receipts/counts and requires current verification and integration;
submit retargets the existing PR rather than opening another.

## Review evidence, dispositions and integration

Read [review-policy.md](review-policy.md) when reviewing. Phase and scope are
separate. Existing checkpoints retain their recorded policy and cumulative history.
Policy/schema 3 is an explicit deliverable migration after the validator rollout
below; `start`, a branch change or a new session never resets spending.
Initial, follow-up and integration scopes use the installed plugin's supported
focus text, not invented plugin arguments. Branch review uses an immutable detached
snapshot and records actual head, comparison base and merge base. Behind-base
review is useful; readiness separately requires current target integration.

```bash
python3 scripts/work_issue.py review phenixrizen/boxcar#43 --session my-session --phase code --scope initial --focus 'requirements and workflow invariants'
python3 scripts/work_issue.py review phenixrizen/boxcar#43 --session my-session --phase code --scope follow-up --prior ATTEMPT_ID --verifies F-0123456789ab --rationale 'Bounded fixes against unchanged target' --focus 'fixes, tests and affected callers'
python3 scripts/work_issue.py review phenixrizen/boxcar#43 --session my-session --phase code --scope integration --prior ATTEMPT_ID --rationale 'Target advanced; inspect changed callers and conflict resolution' --focus 'integration behavior'
# After actual checks, checkpoint their results at the committed revision:
python3 scripts/work_issue.py checkpoint phenixrizen/boxcar#43 --session my-session --file /tmp/checkpoint.json
python3 scripts/work_issue.py integrate phenixrizen/boxcar#43 --session my-session --receipt CURRENT_ATTEMPT_ID --rationale 'Current target incorporated; affected behavior and checks assessed'
```

Use `--material-change` with initial review/integration validation when prior
architectural or trust assumptions changed. `--prior` and `--verifies` repeat.
For plan-only diffs use `--phase plan --comparison COMMIT_BEFORE_PLAN`.
`integrate` validates evidence; it does not merge/rebase or run tests on your behalf.
It fetches the target, checks ancestry, verification and applicable review.
A follow-up can establish readiness for bounded fixes against the unchanged target.
A changed target needs integration or initial review. No patch-equivalence shortcut.

Findings start unclassified and hold readiness. Read the restricted report and
append a sanitized disposition with `dispose --finding F-ID --file FILE`:

```json
{
  "category": "blocking",
  "status": "verified",
  "evidence": "Regression test and affected caller trace verify the corrected invariant",
  "consequence": "The required behavior is satisfied at this head and target"
}
```

Categories/statuses and downgrade restrictions are in review-policy.md.
A demonstrated independent actionable defect adds `tracking: "owner/repo#N"`
after searching for an existing issue. Optional suggestions need no issue and
remain `nonblocking` with a reason; unverified claims remain concerns. Never put private technical
claims in this file: its fields are published. A specific exception uses status
`excepted`, its comment ID, and an owner-authored/latest-edited exact issue line:
`work-issue finding-exception REPO#N F-ID HEAD_SHA BASE_SHA`.
Original reviewer verdicts remain unchanged; optional findings need no new round.

Spending limits and new-deliverable boundaries are defined only in
[review-policy.md](review-policy.md). Existing policy-2 ledgers use cumulative
round grants; preserve those grants during this bootstrap. An actual owner instruction
authorizes the agent, using the authenticated owner's identity, to record its source
and exact grant lines in one comment with `gh issue comment --body-file`, then record
them through `authorize`. Do not request the same approval again or require the
owner to type machine syntax. Other actors cannot self-issue an owner grant:

```text
work-issue authorize REFERENCE PHASE ROUND
```

`authorize REFERENCE --session SESSION --phase PHASE --round ROUND --comment ID`
checks current author/editor and exact scope. A narrower allowance uses
`work-issue ceiling REFERENCE PHASE LAST_ROUND` and the `ceiling` command with the
same arguments. Record every round in one bounded owner instruction upfront when
an extension is authorized. A generic policy cannot expand a narrower allowance.
A triage note, new branch or session does not grant spending.
For schema 3, append the active deliverable's `binding` to both authorization and
ceiling lines. The helper verifies that exact scope; unused older grants cannot
fund another outcome. Legacy lines remain valid only for their historical scope.

After trusted main supports schema 3, prepare a deliverable JSON file containing
`id`, `outcome` and `acceptance`. A direct owner request or approved plan for that
outcome authorizes the default bounded grant. Preview its exact line, record it
with the real source instruction using the authenticated owner's identity and a
body file, then activate using that owner-authored/latest-edited comment:

```bash
python3 scripts/work_issue.py deliverable REFERENCE --session SESSION --file /tmp/deliverable.json --preview
# Record the actual owner instruction and: work-issue deliverable REFERENCE ORDINAL BINDING
python3 scripts/work_issue.py deliverable REFERENCE --session SESSION --file /tmp/deliverable.json --comment COMMENT_ID
```

The binding covers the scope and preceding attempt IDs. It establishes only the
explicit owner-scoped outcome; it cannot silently restart an exhausted deliverable.
Lifetime receipts/counts remain intact. Reusing the same boundary cannot replenish
its allowance. Existing issues can hold successive authorized outcomes without
creating another task just for bookkeeping.

A focused review can reconcile earlier dispositions as a batch. Supply JSON
`{"findings": ["F-ID"], "rationale": "What changed and why this review covers it"}`
to `carry REFERENCE --session SESSION --receipt ID --file FILE`. It verifies the
identified batch against the current reviewed inputs, retaining original events.
The review captures disposition/source digests before invocation. Later resolutions
cannot be attributed to that earlier review. Transferred source reports must match
their receipt's result digest and immutable inputs; unverifiable legacy reports
require reconciliation through a new initial review, not automatic carry-forward.
It cannot carry unresolved findings or fabricate evidence. For strictly allowed
license-header-only changes at an unchanged target, use
`continuity REFERENCE --session SESSION --receipt ID`. This accepts only insertion
of the two fixed header lines in existing regular `.py` files with every other
byte, path and mode unchanged; it refuses encoding cookies/BOMs and docs/instruction
changes. Checkpoint current test results first. Behavior-changing or unexplained
changes need applicable independent review. Both operations preserve prior receipts.

Interrupted attempts block spending. `recover` reads a completed result once;
`recover --failed` is only for a confirmed stopped invocation lacking a result.
Failures approve nothing and consume no completed rounds. After two consecutive
failures, repair the cause and obtain `work-issue retry REFERENCE PHASE ROUND FAILED_ATTEMPT_DIGEST`;
record with `retry` (same arguments as authorize). It covers only failures already
recorded, not unlimited retries. Repeating the same command cannot extend the
grant: new failures require a newly authorized digest. Keep old grant lines for
CI to validate historical invocations.

`start` migrates released/reconciled v1 checkpoints to schema 2, preserving all
attempt IDs, original outcomes, counts and authorizations. It records legacy
receipt digests and unclassified findings, with a local `N.v1-backup.json`.
Pending legacy attempts must recover first; `migrate` can then run explicitly.
Historic policy-1 rounds stay under their original rules. Existing schema-2 tasks
continue under policy 2 until explicitly migrated; schema-3 deliverables use their
recorded boundary. Neither handoff nor rebase resets lifetime counts. Older clients
stop on unsupported schemas instead of replacing remote history.
Restricted raw reports do not travel via public checkpoints; transfer them
privately when focused review needs them, or use an authorized initial review.

`submit --pending` permits an ordinary draft before review/verification completion.
Its contract check fails explicitly. A ready submission requires current checks,
resolved blocking findings, applicable review, and exact integration evidence.

## PR contract and private exceptions

Use `--relation part` for `Part of #N`; only `--relation fixes` emits `Fixes #N`
and moves the issue In review. An open finishing PR is not Done. A PR merged
into a parent branch is not Done: its final main PR must repeat `Fixes #N`.
A final stack PR may repeat `Fixes #N` for each carried issue; relationships
are checked per issue. Partial submissions must contain no closing declarations.
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
publishing the reason or linking a private document. It requires a specific
owner decision; spending exhaustion or a general merge instruction is not such
an exception. Do not publish sensitive descriptions, logs, IDs, or private URLs in
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
the check `issue-contract` alongside the
existing checks the owner chooses. Protect workflow/helper changes with owner
review. Do not replace unrelated settings or imply these were configured.

The contract workflow uses `pull_request_target` with read-only permissions and
checks out only main; it never executes PR files. The initial workflow PR has
merged and installed the schema-2 validator on main. Local validation remains
available through `python3 scripts/work_issue.py ci --pr PR_NUMBER`; it is not
a substitute for the actual PR check. Separate ordinary PR CI runs helper tests.
Comment edits alone do not trigger the trusted-main contract workflow.
Find the existing run through the PR's Checks tab or `gh pr checks PR_NUMBER
--repo phenixrizen/boxcar --json name,link`. Rerun that run with `gh run rerun
RUN_ID --repo phenixrizen/boxcar --failed`, wait with `gh run watch RUN_ID
--repo phenixrizen/boxcar --exit-status`, then confirm the result on the PR
with `gh pr checks`. A separate manually dispatched run is not a replacement
for the PR's failed check. If no PR-associated check appears, leave this check
out of branch requirements and resolve that association before enabling it.

Schema rollout: the installed main validator accepts v1/v2 evidence. This amendment
adds schema-3 support while retaining both. Keep this amendment's live checkpoints
schema 2 and use its recorded bounded cumulative allowance. Merge the compatible
validator first, verify its actual PR check, then explicitly activate schema-3
deliverables and update returning clones. Candidate local validation alone cannot
make schema 3 acceptable to the older trusted-main check. Do not execute PR helpers
in that privileged workflow or erase history to bypass compatibility. Repository-file
workflows do not make a required merge check; branch protections remain an owner
setting. Finish the software deliverable when ready and authorized; remaining
private disclosure/source-retirement decisions stay in their existing records.

### Confidential workspace routing

The advisory helper is implemented separately in `scripts/security_advisory.py`.
Use `/security-finding` and `/work-security` and read `docs/security-workflow.md`.
Issue, Project and PR API helpers refuse confidential clone markers before network
operations. Private independent findings use advisory tracking through a distinct
policy-validator mode; ordinary CI retains issue-only references. No raw review
transcripts belong in public artifacts. The privileged validator continues to load
trusted main only; public CI does not validate confidential-fork remediation.
