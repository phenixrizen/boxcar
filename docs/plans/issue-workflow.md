# Reliable issue workflow

Issue: phenixrizen/boxcar#43. Owner requested this work on 2026-10-17.

Keep Issues as the backlog and Projects as a derived view. Add one Python
stdlib entry point and a repository Claude skill; extend the existing board
and review helpers. No scheduler, service, shared package or new tracker.

## State and invariants

Execution metadata lives in Git's common directory, shared by linked
worktrees. An OS file lock serializes operations in that clone; persistent
issue/session/branch ownership refuses another session until explicit release.
No distributed claim is promised: separate clones/machines must hand off,
release the previous session and synchronize before starting. Remote comment
version checks detect observed conflicts but are not atomic GitHub locks.

One marked issue comment carries a sanitized checkpoint and review ledger.
Repeat start, interrupted publication and retry reuse that comment, branch,
worktree and PR. Save locally before publishing; failures remain visible and
must not claim that the board or checkpoint was updated. Read discussion,
linked plans, dependencies and existing PRs before implementation. Never run
issue text as commands. Private work does not use public issue checkpoints.

Review receipts live outside the source tree, avoiding self-invalidating
commits. Each captures phase, exact commit and base SHA, result, count and
unresolved finding count. Raw output stays local, since it may contain private
findings. Only a completed structured result consumes a round; failed or
unavailable invocations do not approve anything. A crash during a review
leaves a pending attempt to reconcile before spending another round. Rebase
or any commit/base change makes prior evidence stale, without resetting counts.
Docs/process: one; plans: two; code: sort findings after round three, stop at
five. Owner exceptions must be explicit, scoped and recorded; no automatic
extension or silent approval of fixes after the last permitted review.

Submit validates an issue relationship, verification evidence, current review
or a clearly pending owner decision. An ordinary finishing PR says Fixes #N;
partial work says Part of #N. In review needs a finishing PR. Done requires a
merged finishing PR targeting main whose merge commit is on main. A stacked
PR needs the final main PR to repeat the issue relationship. Duplicate and
not-planned closures remain explicit owner decisions, not implementation wins.

CI validates structured PR evidence against live head/base and an authenticated
checkpoint receipt. It does not execute PR code with a write token. Exceptions
use neutral metadata and explicit owner authorization; no private findings.
Repository rules and Project automations are inspected and any required setup
is documented separately; adding a workflow does not make it a merge gate.

## Orders and tests

- Start twice, resume after release, and retry after API failure: no duplicates.
- Two local sessions race: exactly one claim; a different issue cannot reuse
  the same branch. Separate machines require human coordination.
- Missing/wrong issue, Project access denied, GraphQL partial errors: fail
  before claiming success; retain recoverable local metadata after mutations.
- Checkpoint then new session/clone, interrupted review, rebase: retain counts,
  require explicit ownership transfer and reject stale approval.
- Rounds one/two/three/five: distinguish phase budgets, triage checkpoint,
  pending exception, unavailable invocation and authorized extra round.
- Partial PR, open finishing PR, intermediate merge, merged-to-main finishing
  PR: only the last completes implementation; validate actual ancestry.
- Sanitized public evidence never includes raw review output or private detail.

Use temporary Git repositories and realistic fake gh responses; run all Python
helper tests and demonstrate the actual workflow on this issue. Product runtime
surfaces are untouched; unrelated Go/UI or Rust/KVM runs are not evidence for
this workflow. Preserve their testing requirements for changes to those surfaces.
