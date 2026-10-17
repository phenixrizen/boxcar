# Review policy (version 2)

A merge-ready change has no unresolved blocking findings, completed required
verification, and applicable independent review/owner approvals. Optional
suggestions are not a reason to spend another review. Ordinary draft PRs may
open before review or verification; they remain explicitly pending.

Use the existing Codex plugin (`codex@openai-codex`) through
`scripts/work_issue.py review`. It calls `scripts/codex_review.py`, which resolves
the installed registry entry for this repository/user and refuses ambiguity.
A Codex implementation session needs a separate reviewer session: its own
self-review does not count. The plugin starts a separate read-only review thread.
Unavailable services, authentication failures and missing output approve nothing.

## Planning and logical boundaries

Review a design before code when behavior or guarantees materially change:
architecture, protocols, trust boundaries, ownership, concurrency or assumptions
underlying an earlier approval. Merely touching a file with a state machine does
not require a design document. A bounded correction restoring an invariant can
use the issue, regression test and PR explanation. Plans cover relevant events,
failure paths, interleavings, invariants, tests and coverage limits; do not claim
exhaustive ordering coverage without a method establishing it. A clean first
plan review does not require a second. Resolve material plan blockers before code.

Keep changes together when they implement and verify one coherent outcome.
Split independently useful, risky or revertible work. A necessary correction in
another file may belong; unrelated cleanup in the same file usually does not.
Parallel work must account for shared contracts/state, not just file overlap.
Test the affected surfaces as specified in AGENTS.md; Python-only workflow
changes do not require unrelated application runtime suites.

## Phase, scope and inputs

Phase is `docs`, `plan` or `code`. Independently select review scope:

- `initial`: complete logical change, requirements, important invariants and
  relevant surrounding code. Renew this scope after material design changes.
- `follow-up`: previous findings, bounded fixes, tests and affected behavior,
  including surrounding code and callers. It may discover serious new defects;
  it does not restart unrestricted architectural review after each correction.
- `integration`: target changes, conflict resolution or stack retargeting,
  including callers, dependencies, configuration and shared assumptions.

The helper's `--scope` is a workflow option. The installed plugin supports only
`--scope branch|working-tree|auto`; it receives `branch`, an immutable base SHA,
and the selected workflow scope/instructions in its focus text. Prior receipts
and restricted reports are supplied as private context. Focused scopes require
prior completed receipts in the same phase and a continuity rationale. Transfer
missing reports privately or choose initial scope; never invent their contents.
Use `--verifies F-ID` for each prior finding being verified. A reviewer can retain
its stable ID in the finding title; otherwise a new claim receives a new opaque
ID and earlier findings remain in the ledger.

Branch review runs in a detached snapshot of the exact commit. Receipts record
head, comparison base and merge base; uncommitted files are excluded. Remote
bases are fetched; fetch/comparison failures stop the operation. Being behind
is permitted and does not assert current integration. Direct wrapper users can
pin `--head SHA`; this is consumed by the wrapper, not forwarded to the plugin.
Plan-only review can use `--comparison COMMIT_BEFORE_PLAN`.

Before readiness, fetch and incorporate the current target, run affected checks,
checkpoint actual results, and use `integrate` with an applicable receipt.
Integration evidence binds the actual head/target/merge base, rationale and
review receipt. The current target must be an ancestor of that head. A bounded
fix against an unchanged target accepts an exact-head follow-up linked to the
prior review. Target changes need integration or renewed initial scope; material
changes need initial scope. Unchanged patch identity alone is not evidence of
unchanged behavior. A new head/base never silently inherits old approval.
Retargeting/rebasing preserves historical receipts rather than rewriting SHAs.

## Finding dispositions

Keep original structured results in restricted reports. A public checkpoint
contains opaque IDs and sanitized evidence, never undisclosed technical claims
or reproductions. Severity and confidence are separate. Classify with evidence
and consequences, not confidence alone:

- `blocking`: demonstrated incorrect behavior, violated requirement/invariant,
  material security risk, or missing verification of critical behavior.
- `nonblocking`: optional refinement; requirements are met without it.
- `concern`: unverified claim needing investigation. High-impact concerns hold
  readiness until investigated; a high/critical reviewer claim cannot simply
  be labelled nonblocking.
- `independent`: existing defect tracked separately unless this change worsens,
  exposes or depends on it. Requires a separate issue reference; preserve the
  owner's decision on whether/when to pursue unrelated work.
- `unclassified`: missing detail, including legacy findings. Never an approval.

`dispose` appends a history event: `investigate`, `fixed-unverified`, `verified`,
`refuted`, `deferred`, or `excepted`, plus evidence and consequence. Blocking
findings/concerns cannot disappear by reclassification. Resolve them with
verification, refuting evidence or a specific owner exception. Only nonblocking
or independent findings may be deferred. Resolution applies to its recorded
head/base; explicitly reconcile it after further changes. A repeated reviewer
claim reopens investigation. Original verdicts are immutable: a needs-attention
review can support readiness after evidence shows all findings are resolved or
nonblocking. Missing review output can never support readiness.

These are attestations, not proofs of model judgment or semantic equivalence.
The helper cannot decide whether prose establishes a real defect or whether an
unreported architecture change is material. The agent must investigate and
choose scope honestly; CI checks evidence consistency and trusted provenance.

## Spending and migration

Version 2 ceilings: docs/process one when required; plans two; code three
autonomously. Code rounds four and five each require explicit scoped owner
authorization; beyond five requires another explicit exception. Initial,
follow-up and integration code reviews all count. Stop once criteria are met.
Round three is a spending/triage checkpoint; a nonempty triage note is not
permission. Exhaustion is neither proof of safety nor an order to redesign.

The existing `authorize` command validates an owner-authored/latest-edited exact
phase/round comment before invocation and again in CI. `ceiling` records a
narrower task allowance, also checked in both paths. These amendments authorize
one additional plan round and at most two additional code rounds in each
repository, with the second code round focused if needed. They do not waive
blockers, authorize merging/disclosure or reset previous rounds.

Only completed structured invocations consume rounds. Pending attempts block
another invocation until recovered exactly once. Two consecutive failures require
repairing the cause and an exact owner `retry` authorization; that authorization
covers only the failed attempt IDs recorded then, not unlimited retries.

Schema 2 retains the stable `work-issue-checkpoint:v1` envelope marker so old
clients find the existing comment and fail closed on its version. Migration
preserves all attempts/outcomes/counts/authorizations, stores historical receipt
digests and a local v1 backup, and creates unclassified legacy findings. Recover
pending v1 attempts before migration. Historic rounds retain policy 1 (including
its old fourth/fifth-round rules); no retrospective permission is fabricated.
New rounds use policy 2. Migration publishes through the same recoverable atomic
protocol. Released returning clones adopt migrated remote history; active or
unpublished conflicting state still requires explicit reconciliation.

## Confidential reviews

Undisclosed vulnerabilities belong in the affected repository's GitHub Draft
Security Advisories. Search related drafts, preserve unconfirmed claims and
verification, and fail closed on unavailable access. No fix without owner
remediation authorization; no disclosure or publication without explicit owner
approval. Revealing patches/tests and review reports stay private. The advisory
helper remains unimplemented; consult `docs/security-workflow.md` for the limits.
Never upload raw reports as public CI artifacts or paste them into checkpoints.
