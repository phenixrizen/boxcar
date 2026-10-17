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

## Review policy amendment (2026-10-17, policy/schema 2)

This section supersedes the review and planning rules above; the earlier text
records the original design. The advisory helper remains unimplemented and is
outside this amendment. Both PRs remain partial drafts for their existing tasks.

Preserve the atomic publication protocol, trusted checkpoint author/editor,
local ownership lock, explicit released handoff, pending attempt recovery,
exactly-once counting, PR ownership checks and merge-to-main completion proof.
A v1 checkpoint migrates only after ownership/publication reconciliation. Keep
an immutable copy of its review history in a local backup and record the
migration's historical attempt IDs in the checkpoint. Existing receipts retain
all original inputs, outcomes, counts and authorizations. Legacy findings become
explicitly unclassified entries; migration never supplies an approval. Returning
clones accept migrated remote history through the existing released handoff.
Old clients fail closed on schema 2. The envelope marker stays stable so an old
client detects the checkpoint rather than creating a duplicate.

Separate review phase (docs, plan, code) from scope (initial, follow-up,
integration). Initial examines the logical change and important surrounding
invariants. Follow-up examines linked prior findings, fixes, tests and affected
callers, while permitting discovery of serious new defects. Integration examines
target changes, conflicts and shared assumptions. Material architecture,
protocol, trust, ownership or concurrency changes require a renewed initial
review. Scope instructions and prior receipt/finding references go in the
plugin's supported focus text; no invented plugin switches. Restricted local
context includes original reports when available; missing context is explicit.

The wrapper reviews a detached snapshot of the recorded commit with an immutable
comparison base; record the actual head, comparison base and merge base. Fetch
failure is an error, but being behind is not. Working-tree changes cannot inherit
branch approval. Before readiness, fetch the target again, incorporate its changes,
checkpoint actual checks, and record integration evidence for that exact head and
target. Require the target to be an ancestor of the integrated head. Changed
head/base needs a new applicable initial or focused integration receipt linked to
previous evidence; unchanged patch identity alone never establishes continuity.
Receipts remain immutable when retargeting or rebasing. Integration evidence
records affected behavior, why the selected scope suffices, and the applicable
receipt. CI independently compares ancestry and exact live revisions.

Original structured reviewer results stay in restricted reports. Public metadata
contains opaque stable finding IDs, source attempt/index, severity and confidence
separately, and sanitized dispositions with evidence and consequences. Findings
start unclassified, not nonblocking. Categories distinguish blocking defects,
nonblocking improvements, unverified concerns and independent existing defects.
Disposition history distinguishes awaiting investigation, fixed/unverified,
fixed/verified, refuted, nonblocking/deferred and a specific owner exception.
A previously blocking or high-impact concern cannot be downgraded with a label;
resolution needs verification, refuting evidence or an exact owner exception.
Independent defects need separate tracking unless the change depends on them.
Original verdicts are never overwritten. Readiness requires no unresolved
blockers or unclassified/necessary investigations, actual verification and an
applicable independent review; optional findings alone require no extra round.
Follow-up references preserve finding identity instead of dropping old findings.

Policy 2 counts all completed code scopes: three autonomous, rounds four/five
require scoped owner authorization, later rounds another explicit exception.
Docs allow one and plans two without exception; ceilings are not targets.
Historical rounds retain policy 1, including its former fourth/fifth-round rule.
Pending failures approve nothing and consume no completed round. Authorization
is checked before invoking and again in CI; a triage paragraph is not permission.
This amendment's recorded owner allowance is one additional plan review and two
additional code reviews per repository, with the second code review focused if
needed. Persist the allowance ceiling as well as individual round authorizations;
it does not waive findings, permit merging or extend the advisory scope.

Design review is needed for changed behavior/guarantees, not merely a file with a
state machine. A bounded invariant correction can use issue, regression and PR
explanation. Plans describe relevant events, failures, interleavings, invariants,
tests and coverage limits without claiming exhaustive concurrency exploration.
Keep a coherent outcome together; split independently useful/risky/revertible work.
Ordinary pending drafts may be submitted before verification/review completion.

Tests use fake GitHub responses and temporary repositories for migration,
publication recovery, finding persistence and forbidden downgrades, real reviewer
argv/focus routing, behind-base review versus integration readiness, exact revision
continuity, authorization parity and missing-output failure. Preserve all existing
ownership, relationship and completion regressions. Run both Python suites; unit
tests establish mechanics, not model judgment or semantic equivalence. Privileged
CI keeps the trusted-main checkout/import boundary. Candidate schema validation
is only local until the validator reaches main; do not change repository settings.

Private security work will use the same versioned policy but store receipts and
findings privately in draft advisories. It is not implemented by these changes.
Temporary private security forks do not run status checks and do not enforce
branch protection; future validation must run in an authorized private workspace
and retain evidence privately. No publication, CVE request, public fix PR or
migration/retirement of the inaccessible source artifact is authorized here.
