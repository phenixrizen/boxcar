# Boxcar repository contract

The design is `docs/specs/2026-09-29-boxcar-design.md`; milestone plans under `docs/plans/` record rulings in section 8. Read `CONTRIBUTING.md` for engineering requirements and checks when those surfaces change.

- Sign off commits (`git commit -s`); subjects are `area: summary`. Preserve the licensing and dependency requirements in `CONTRIBUTING.md`.
- Commands are argv arrays, never shell strings built from user input.
- Every control message and audit record type has a size limit and test.
- Test affected surfaces: Rust changes run the Rust checks; guest/VMM behavior requires the relevant gated KVM suite. An exit-zero KVM skip is not a VM test pass.
- No security fix starts without the owner's go-ahead. Never disclose security findings without explicit owner approval, including issue/PR text, plans or commit messages; use the affected repository's GitHub Draft Security Advisories and neutral regression names.

## Working an issue

GitHub Issues are the backlog; the Project board is a view of them. One
issue, one branch, one pull request, and CI is the only gate.

- Take the issue you were given, or else the top unassigned issue labelled
  `ready`. Assign yourself. Never hold two open issues at once.
- Work on the branch `issue-N`, cut from `main` and linked to the issue
  (`gh issue develop N --name issue-N`), in a worktree of its own. The
  branch on origin is the claim: one that already exists is someone's work,
  so ask before touching it.
- Open a draft PR at the first commit. `Fixes #N` finishes the issue;
  `Part of #N` leaves it open. Say in the PR body which agent or person made
  it, with a session link when there is one.
- Before every push run the checks for each affected surface
  (`CONTRIBUTING.md`). Report a check that did not run as not run, never as
  passed. Mark the PR ready when it is complete and green.
- Answer every review comment: fix it, or reply why not, then resolve the
  thread. The owner merges. Merged is done, and GitHub closes the issue.
- Blocked or handing off: push, leave one PR comment saying what is left,
  and unassign yourself.
- Work the owner asks for directly gets an issue first (search for an
  existing one). A defect found on the way gets its own issue, unless this
  change caused it or cannot ship without the fix.
