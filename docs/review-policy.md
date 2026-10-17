# Review policy (version 3)

Ready means the acceptance criteria are met, required affected-surface verification
is complete, independent review applies to the revision, and no blocking findings
or important unverified concerns remain. Optional suggestions do not require a new
issue or review. Stop when these criteria are met; submit and merge when already
authorized. A draft PR can precede readiness and must say what remains pending.

This is the canonical review and spending policy. Historical plans and execution
logs preserve technical decisions and evidence, not competing process rules.
Skills and the workflow guides explain how to invoke the helpers.

## Deliverables, planning and spending

A deliverable is one explicitly owner-selected outcome with acceptance criteria.
It can use an existing issue; extending a long-lived issue does not require another
issue merely to establish this boundary. The owner's direct request or approval of
that defined outcome authorizes recording its default bounded grant; do not ask
again for machine syntax or the same approval. With the authenticated owner's
GitHub identity, the agent can transcribe that actual instruction into the required
comment using `--body-file`. Record the boundary, acceptance criteria and source
instruction before spending; another actor cannot self-issue an owner grant. Branches, sessions, PRs, rebases and renaming do not
create a new deliverable or replenish its allowance. Necessary corrections and
regression tests stay within the same deliverable.

For a new policy-3 deliverable the ceilings are:

- Docs/process: one review when required.
- Plan: up to two reviews when required; a clean first review is sufficient.
- Code: one initial review and up to two focused follow-ups. An integration review
  consumes a focused slot. A renewed broad review needs a scoped owner exception.

These are ceilings, not targets. Record an owner's bounded extension upfront,
including phase and scope, rather than repeatedly requesting single-round grants.
An exhausted allowance produces one consolidated decision: findings/evidence,
tested state, and the exact additional review needed. Spending permission never
accepts a defect, approves disclosure, or proves safety. Existing exhausted
allowances are not reset by adopting this policy. Lifetime counts and original
attempts remain immutable; the deliverable records the spending boundary.

Review a design before implementation when behavior or guarantees materially
change: architecture, protocols, trust boundaries, ownership, concurrency or
assumptions underlying earlier approval. Touching a state-machine file alone does
not require a plan. A bounded correction restoring an invariant can use the issue,
regression test and PR explanation. Cover relevant events, failure paths,
interleavings, invariants, tests and coverage limits; do not claim exhaustive
ordering coverage without a method. Resolve material plan blockers before code.

Keep one coherent outcome and its verification together. Split independently useful,
risky or revertible work. Parallel work considers shared contracts and state, not
just file overlap. Test affected surfaces; Python-only workflow changes do not
require unrelated runtime suites.

## Findings and their disposition

A finding is a claim to investigate, not an automatic task. Preserve its original
result, severity and confidence separately. Require evidence and consequences:

- `blocking`: demonstrated incorrect behavior, violated requirement/invariant,
  material security risk, or missing verification of critical behavior.
- `concern`: an unverified claim needing investigation. Credible high-impact
  concerns hold readiness; uncertainty is not permission to dismiss them.
- `nonblocking`: an optional refinement; requirements are met without it.
- `independent`: a demonstrated actionable defect outside this change. Search
  for an existing issue, then create or reuse one; preserve the owner's decision
  on whether/when to do that work. If this change worsens, exposes or depends on
  it, resolve it here. An owner-selected independent follow-up also gets an issue.
- `unclassified`: insufficient detail, including legacy findings; never approval.

Optional suggestions remain dispositions with a reason. Unverified concerns do not
become backlog issues merely because a reviewer mentioned them. Never classify an
unknown as optional to obtain a pass. Undisclosed findings follow the private
advisory workflow instead of public issue creation.

Append dispositions (`investigate`, `fixed-unverified`, `verified`, `refuted`,
`deferred`, `excepted`) with evidence and consequence. Only nonblocking/independent
findings may be deferred. Blockers and concerns need verification, refuting evidence
or a specific owner exception, not relabelling. A repeated claim reopens the finding
and preserves earlier observations and severity escalation.

Original verdicts are immutable. A `needs-attention` review can support readiness
once its findings are resolved or nonblocking; a cosmetic `approve` verdict or zero
findings is not required. Missing review output never approves anything. Keep raw
results restricted and public evidence sanitized: no undisclosed technical claims,
reproduction details, private identifiers or advisory links in public checkpoints.

## Review scope, revisions and continuity

Phase (`docs`, `plan`, `code`) and scope are separate:

- `initial`: the complete logical change, requirements, important invariants and
  relevant surrounding code. Material design changes require renewed broad review.
- `follow-up`: previous findings, bounded fixes, tests, callers and affected behavior.
  It can discover a serious new defect without restarting unrestricted design review.
- `integration`: newer target changes, conflicts or stack retargeting, including
  dependencies, configuration, callers and shared assumptions.

Use `scripts/work_issue.py review` and the existing Codex plugin through
`scripts/codex_review.py`. The wrapper resolves the installed registry entry and
refuses ambiguity. Codex implementation requires a separate reviewer session;
self-review does not count. The plugin starts a separate read-only review thread.
The plugin's supported scope is `branch|working-tree|auto`; the helper passes
`branch`, immutable inputs and workflow scope instructions in focus text. Do not
invent plugin flags. Prior receipts/reports and finding IDs identify what a focused
review verifies. Transfer missing reports privately or obtain an authorized initial
review; never invent their contents.

Branch review uses a detached snapshot of the exact commit. A receipt records head,
comparison base and merge base; it does not cover uncommitted files. Fetch/comparison
failures stop the operation. A behind-base review remains useful but proves no
current integration. Direct wrapper `--head SHA` is consumed by the wrapper. Plan
review may use `--comparison COMMIT_BEFORE_PLAN`.

Preserve receipts and their SHAs. Carry-forward explicitly connects prior resolved
findings to the current revision with evidence about changes and affected behavior.
One focused review can reconcile an identified batch of earlier dispositions; do
not demand individual re-attestation of every historical finding after every commit.
It cannot carry an unresolved blocker, erase a new claim or invent verification.
Behavior-changing revisions need applicable independent review. A checked continuity
record may cover only insertion of the two fixed license-header lines in existing
regular Python files: other bytes, file paths and modes stay unchanged, and encoding
cookies/BOMs are refused. Current tests are still required. Docs/instruction edits
are not eligible. An arbitrary prose claim, unchanged patch, or matching tree alone
is insufficient.
Unexplained revision/base changes fail readiness.

Before readiness fetch and incorporate the current target, run affected checks,
checkpoint actual results and validate integration. Evidence binds the actual
head/target/merge base and applicable implementation review, never a plan receipt.
The target must be an ancestor of the head. Target changes require integration or
renewed initial review; material changes require renewed initial scope. A bounded
fix against an unchanged target can use a focused review linked to the prior one.
No integration evidence is claimed when fetching/comparison fails.

These records check consistency and provenance, not model judgment or semantic
equivalence. Investigate honestly and use the repository validator everywhere;
a temporary finishing script must not add a zero-findings gate or blanket-resolve
findings merely to finish.

## Durable history, authorization and rollout

Only completed structured reviews consume rounds. Failed/unavailable calls approve
nothing. Pending attempts block new spending until recovered exactly once. Two
consecutive failures require repairing the cause and an exact owner retry grant
bound to those failed attempts, not unlimited retries.

Owner authorizations must be scoped, authenticated and latest-editor checked in
both invocation and CI validation. Existing `authorize`, `ceiling`, `retry` and
finding-exception records retain their original meaning. A triage note is not an
authorization. Preserve all attempt IDs, counts, outcomes, grants and unresolved
findings through migration, resume and handoff; never fabricate historical approvals.

Ordinary policy/schema 3 is opt-in after its compatible validator reaches trusted
main. Existing live checkpoints stay schema 2 during bootstrap; legacy policy-2 reviews
use their cumulative grants. Policy 1 retains its original fourth/fifth-round
rules; policy 2 retains docs one, plans two, code three autonomous with explicit
permission for each later round. These historic rules do not change retroactively.
The migration preserves the existing comment envelope and history, records the
explicit owner-scoped deliverable boundary, and uses recoverable publication.
Pending attempts must recover first; an active or unpublished conflicting clone
requires reconciliation. A released returning clone imports the migrated remote
history; an older incompatible helper stops instead of resetting it.

The privileged contract workflow executes trusted-main files only. Candidate local
validation is not an enforced GitHub check. Ship dual-version validation before
publishing schema-3 checkpoints; update returning clones before using them. Do not
change branch protections, waive checks or execute PR-controlled validators to
bypass bootstrap.

## Confidential reviews

Draft Security Advisories are authoritative for undisclosed findings. Search related
drafts, preserve unconfirmed claims and verification, and fail closed on unavailable
access. Remediation needs owner authorization; publication and disclosure need a
separate explicit decision. Patches, tests and reports that reveal a finding stay
private; never upload raw reviews as public CI artifacts. Use the same spending,
findings and continuity rules, with private authorization and evidence. Consult
`docs/security-workflow.md` for its currently supported ledger version and fork limits.
Finishing the workflow software does not require disclosure or retirement of the
source artifact; retain those separate private decisions without extending the
software deliverable indefinitely.
