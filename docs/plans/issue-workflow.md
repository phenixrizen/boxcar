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

## Recovery and evidence protocol (plan review dispositions)

The first plan reviews identified missing protocols, not reasons for another
service. The implementation will enforce these boundaries:

- State writes use a temporary file in the same directory, fsync, atomic
  replacement and directory fsync. Corrupt or conflicting metadata is refused.
  The persisted issue/branch identity and a monotonically changing checkpoint
  revision precede mutations. Before retrying a comment creation, enumerate
  every issue comment and find the single owner-authored marker; before a PR
  creation, enumerate PRs for the exact repository/head/base. Read back writes.
  An ambiguous set of matches blocks rather than choosing or creating another.
- A completed review is saved with its attempt UUID before publication. Retry
  publishes the same attempt, never increments it twice. A pending attempt
  blocks another review. Recover it from its local structured plugin result;
  incomplete results require explicit failure reconciliation, not an assumed
  pass. A release first publishes and verifies all local history and refuses
  pending attempts. Only then does it publish the released ownership state.
  Lost acknowledgements are reconciled by revision and attempt IDs. A fresh
  clone must see the released checkpoint; active ownership is a conflict.
- CI runs the validator from main via a read-only pull_request_target workflow,
  never checks out or imports PR files. PR changes to scripts or workflows are
  tested separately without privileged tokens. Main is the trust root, so
  branch/ruleset protection is an explicit setup requirement (currently absent
  in both repositories). The new workflow cannot validate its own bootstrap
  until merged; run its exact command locally for these initial PRs and report
  that distinction. Owner-authored comments are the attestation boundary, not
  cryptographic proof of a model run. The helper generates receipts from the
  plugin's structured result, and CI verifies author identity plus exact repo,
  issue, phase, head and current base, and count/exception rules. Changed or
  replaced comments are revalidated, never trusted merely by marker. Owner
  exceptions bind the exact revision/base or next phase/round; their public
  text is neutral. Explicit workflow dispatch supports rechecking evidence.
- Tests cover success with a lost comment/PR response, atomic replacement
  failure, review saved but unpublished followed by release, duplicate attempt
  recovery, unauthorized markers/exceptions, mismatched and stale receipts,
  and the workflow's trusted checkout. No handoff can silently drop a round.

## Draft advisory extension requested 2026-10-17

GitHub Draft Repository Security Advisories replace the private document as
source of truth. Add a narrow `security_advisory.py` helper and two skills:
`security-finding` for records, `work-security` for authorized remediation.
This is confidential state on GitHub, never an issue or Project card.

- Read fresh draft/closed records each session, with paginated authenticated
  REST calls. Check repository role and token access. Read access does not
  imply write access. Mutations require explicit repository administration
  and the owner identity in this initial helper; collaborator reads remain
  supported. Credentials are independently authorized, never copied between
  Claude accounts. API errors are redacted to status/permission guidance.
- Create requires real package ecosystem metadata, summary and description;
  unknown versions/name remain null where GitHub permits. Search drafts and
  closed records first. A stable caller operation key and legacy IDs in a
  machine-readable description block provide exact duplicate/retry detection.
  Similarity matches require human comparison. No automatic repeat POST after
  an ambiguous timeout: list/read to reconcile, and require owner resolution
  if visibility cannot prove the outcome. GitHub has no distributed creation
  lock; coordinate simultaneous creation across machines explicitly.
- Update fetches current content and requires its version/digest. Re-read
  before PATCH and read back afterward. Keep native state draft while internal
  status moves New, Investigating, Confirmed, Approved for remediation, Fixing,
  Awaiting verification, Fixed awaiting disclosure, Closed. Closing is an
  explicit operation with a private reason; fixed does not publish. Refuse
  published/native triage records for mutation, state=published payloads,
  CVE requests, arbitrary endpoints and extra fields. Preserve prose and
  original claim/evidence/history, including disproven findings.
- Remediation requires durable owner authorization in the advisory and checks
  the current owner GitHub identity. Reuse or request its temporary private
  security fork; handle asynchronous creation without another POST. Validate
  `private: true` through GitHub and clone into an isolated private workspace,
  with push origin restricted to that fork and a local guard against public
  issue/board/PR entry points. Keep technical patches/tests only in that fork.
  No automatic public PR, publication, CVE request or disclosure operation.
- Review budgets use the same policy functions, with receipts/pending attempts
  stored in the advisory, raw logs restricted locally. Rebase invalidates
  evidence; counts survive machine handoff. The private workflow retrieves
  current metadata before spending, requires review recovery before another
  attempt or handoff, and uses the existing base-fresh review helper.
- Public helpers reject advisory references and confidential-workspace markers;
  raw review logs are never CI artifacts. These guards prevent accidental
  routing, not semantic detection of every sensitive sentence; the skills
  require confidentiality review and explicit owner disclosure before anything
  goes to public Git history. Main-only contract CI accepts only neutral,
  exact-revision owner exceptions and authenticates current comment editors.
- Existing artifacts are not deleted. If securely accessible, inventory,
  deduplicate, preserve original IDs and record the original→GHSA mapping only
  inside advisories, verifying retrieval. Otherwise provide a private import
  procedure; do not reconstruct claims from public references. Credible claims
  without honest package metadata stay in the original secure source (or an
  owner-selected encrypted intake) pending schema completion; this is explicitly
  temporary triage, never a new authoritative local backlog. If no secure source
  is available, stop and report only the access/metadata limitation.

Tests use synthetic advisories only: listing/reading, exact and related matches,
creation with lost acknowledgement, update conflicts and recovery, permissions,
invalid IDs, private-fork checks, owner authorization, closed/published states,
publication/CVE rejection, persisted budgets and public-routing guards. No real
advisories are created as tests. Initial read-only access checks found no drafts;
the prior artifact has no location in the repository instructions and remains
untouched. API reference: GitHub REST repository security advisories, consulted
2026-10-17; draft creation is distinct from private vulnerability reporting.
