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

Review receipts live outside the source tree. The version-2 amendment below
supersedes the original count-only approval and mandatory-rebase design. Record
immutable inputs, preserve original verdicts, append finding dispositions, and
separate review coverage from current integration. Historical rounds retain the
policy under which they ran; failed or unavailable calls approve nothing.

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
  stored in the advisory, raw logs restricted locally. Rebase requires explicit
  continuity evidence; counts survive machine handoff. The private workflow retrieves
  current metadata before spending, requires review recovery before another
  attempt or handoff. The planned private integration follows policy 2 below:
  immutable review inputs, explicit integration evidence and scoped spending.
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
head/base needs a new applicable receipt linked to previous evidence. A bounded
fix with unchanged target accepts a follow-up receipt covering all intervening
fixes and tests. Target changes need integration scope; material changes need
initial scope. Unchanged patch identity alone never establishes continuity.
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

Plan round 3 disposition: both independent reviewers identified the omitted
follow-up eligibility above. Corrected before implementation without changing
the intended bounded-fix policy. The initial → fix → follow-up readiness test
and the amendment code review verify this correction; no extra plan round.


## Advisory implementation and migration continuation (2026-10-17)

The owner requested completing the remaining advisory implementation and private
migration after the partial workflow PRs merged. This section authorizes that
scope; it supersedes the earlier amendment's exclusion of advisory implementation.
Use the existing task issues and ledgers, continuing from merged main without
resetting attempts, counts, outcomes or scoped authorizations. New review spending
requires the separately recorded bounded allowance. Real vulnerability remediation,
publication, CVE requests and retirement of the original source remain separate
owner decisions. Only synthetic records belong in this public change.

### Record operations and privacy boundary

Add one stdlib `scripts/security_advisory.py` entry point; reuse the existing
`review_policy.py` and `codex_review.py`, without an orchestration service or tracker.
Commands cover access, list/read/search, create/update/close/recover, authorization,
work/checkpoint/release, review/review recovery, disposition and integration.
Every session reads the current advisory. GHSA remains the stable identifier.

Use authenticated `gh api` with argv arrays and structured stdin JSON. Restrict
routes to this repository's advisory collection/items and its private-fork action;
never expose arbitrary mutation routes, publication, CVE requests or collaborator
changes. Creation omits publication fields; only explicit close can set closed.
An unexpected public/native state fails closed. Read-only named access may use an
advisory collaborator; full inventory and mutations conservatively require the
owner's administrator identity. Check roles and endpoint access separately: a
read preflight does not prove write-token capability. Sanitize API errors to
status and permission guidance; never echo response bodies, CLI arguments or
private records in public logs. Suppress GH_DEBUG and shell tracing in children.

Read/search outputs, inputs, retry journals, raw review results and exported
migration mappings use restricted files outside Git working trees (0700 parent,
0600 files). Reject symlink destinations and files inside repositories. Public
helpers reject confidential workspace markers before their GitHub operations;
private clones have a pre-push guard that verifies the destination is their
recorded private fork. Direct wrapper reviews of a confidential clone require
the explicit private invocation path. These are accidental-routing guards, not
semantic detection of every confidential sentence or a sandbox against an
operator intentionally bypassing them.

### Data, retries and ownership

Preserve original technical prose. One `security-finding:v1` JSON section records
schema/revision, creation key, original IDs, discovery metadata, confidence,
internal status, append-only progress/history, authorization, session ownership,
private workspace association and the policy-2 review ledger. Confidence is
separate from severity. New/unverified claims do not automatically become confirmed.
Historical source status remains verbatim during import; migration grants no new
remediation authorization or claim that historical fixes were reverified.
Required package ecosystem/name/ranges are taken from evidence; unknown nullable
fields stay null. Insufficient metadata stays in its existing secure source with
an explicit private migration gap, never an invented package or public issue.

Before creation search all visible records for operation key/original IDs and
related summaries. Exact matches are reused; related matches require inspection.
Persist intent atomically before POST. A lost response is reconciled by the same
key and read-back; if absent/ambiguous, stop instead of repeating POST. Definite
rejection is distinguished from an unknown outcome. Updates require the current
snapshot digest, preserve original identifiers and histories, reread before PATCH,
and verify their operation revision afterward. Recover an applied-but-unacknowledged
update without adding another event. Retain unresolved intents across process
restarts; transfer them privately during a machine handoff. Never silently discard
an unknown creation/fork outcome merely because a later list is empty.

A local advisory-state flock serializes sessions sharing that state directory.
The advisory carries an explicit active session/clone claim; resume reuses resources,
release refuses pending review/publication and verifies the released state. Different
machines must coordinate and hand off: REST has neither an atomic claim nor create
idempotency nor a documented compare-and-swap PATCH. Digest checks detect observed
conflicts; they cannot prevent every simultaneous remote writer. Do not claim a
status read/update is a distributed lock.

### Authorized private remediation and review

An explicit owner-authorized scope is recorded separately from status. Generic
progress updates cannot grant scope, reset the review ledger or rewrite receipts.
Work retrieves and checks current scope/status, reuses an existing private fork,
or journals one fork request before the asynchronous operation. Pending provisioning
is polled by retrieval; never automatically POST another fork request. Verify
private=true, remote identity and isolated clone before edits/push. No public PR
or public branch is created for remediation. Creating drafts for migration does
not authorize starting fixes or creating their private forks.

Private review uses the same versioned budget and disposition functions as ordinary
work: phase versus scope, immutable head/base/merge-base, prior original structured
results, stable finding IDs, required investigation, scoped exceptions and explicit
integration evidence. Store structured original results/receipts privately in the
advisory so another authorized account can recover follow-up context; keep raw model
transcripts local. Publish a pending attempt before spending; recover a structured
result exactly once, and distinguish unavailable calls from completed reviews.
Two failed attempts require a bound retry decision; pending calls prevent another
round or release. Before invoking revalidate scope/ownership and current review
allowances. Fresh checks and integration evidence bind actual revisions. Only the
verified completion command may claim Fixed, awaiting disclosure; it leaves the
native advisory draft. A close needs an explicit owner decision and private reason.
Do not infer authorization from migration, a status label or reviewer confidence.

Temporary private forks do not run normal public CI/status checks or enforce branch
protections; integrations cannot access them. Run appropriate tests and independent
review locally in the private workspace and retain evidence privately. Report those
limits. No real security fix/fork is needed to test this workflow implementation.

### Migration and validation

Read current source bodies and all available comment threads, including resolved
comments. Inventory every original finding privately; preserve original identifiers,
claims, severity/confidence, evidence, remediation history and pending decisions.
Map source blocks to records without inventing a claim. Carry administrative context
as provenance where needed. Check existing advisories first; use deterministic source
operation keys. Only actual owner-authorized findings are imported, never synthetic
API-test records. Retrieve each created/updated draft and compare its original-ID
mapping and content; rerun imports to demonstrate reuse. Keep a restricted mapping
and a complete accounting of any unrepresentable/unretrieved records. Keep the
original documents intact pending verified migration and explicit retirement approval.

Focused tests use fake gh responses and temporary Git repositories: permission/auth
failures and partial read access; pagination; invalid repo/GHSA; draft creation and
forbidden publication/CVE payloads; duplicate/related detection; lost POST/PATCH/fork
responses and recovery; stale updates; closed/published handling; owner scope and
session conflicts; private-fork destinations and guards; private output/error handling;
review recovery/counts/allowances across sessions; stale review and integration evidence;
synthetic migration replay. Keep existing scripts regressions and trusted-main CI
boundary. Tests establish mechanics, not model judgment, universal race exclusion or
an actual KVM run. Run the complete scripts suite in both repositories.

### Design-review resolutions before implementation

Advisory descriptions have no REST equivalent of the issue-comment latest-editor
check. Owner-only helper writes therefore do not authenticate an out-of-band
collaborator edit. Persist an execution trust anchor outside Git containing the
last exact advisory digest acknowledged by this owner's helper. Scope, allowances,
exceptions, ownership and review recovery require that anchor to match a fresh
GitHub read. Helper mutations advance it only after verified read-back. A fresh
machine/session handoff without a trusted anchor, or any out-of-band edit, requires
an explicit current owner reconfirmation through a restricted decision file after
reviewing the current description and ledger. Reconfirmation names the exact
snapshot digest, approved scope and source of the owner's instruction; it does
not discard history or grant unknown future rounds. Merely copying remote
`author=phenixrizen` or a status/authorization field is never provenance. Ordinary
reads and migration do not grant remediation trust. This is an owner attestation
boundary, not cryptographic protection against an operator forging the owner's
instructions. Test out-of-band scope/budget edits and fresh-clone recovery.

Extend the shared disposition/readiness validators with an explicit confidential
tracking mode. Independent findings in that mode require a repository-qualified
GHSA identifier whose private record has been retrieved; public issue numbers are
refused. The ordinary validator retains issue-number-only tracking and rejects
advisory references. Both transition validation and history replay receive the
same mode; test private disposition through handoff and readiness. Preserve all
previous policy-2 receipts and ordinary checkpoint schemas.

Implementation review tightened the planned recovery invariants: fork provisioning
may change only its expected server fields, never bless scope/ledger edits; create
recovery is bound to the requested key and original content; trusted snapshots
permit explicit owner reconciliation of active work without deleting attempts;
generated reopening events retain their independent tracking; and private focus
**and continuity rationale** remain outside process arguments. These corrections
restore the existing privacy/recovery contract and have focused synthetic tests.
