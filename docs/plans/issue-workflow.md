# Deliverable workflow amendment

Status: implementation design for the owner's approved instruction simplification.
This replaces the chronological process proposals previously in this file; their
history remains in Git. Current policy belongs in `docs/review-policy.md`, command
and recovery procedures in `docs/issue-workflow.md`, and confidential differences
in `docs/security-workflow.md`. Technical requirements in other plans remain valid;
obsolete process rules do not override this repository contract.

## Outcome and acceptance

Finish coherent changes without repeatedly creating issues or restarting settled
review work. Keep independent review, bounded spending, evidence-backed finding
resolution, private handling, ownership and recoverable publication. Existing task
issues and PRs continue. No scheduler, tracker, general orchestration framework,
protection changes or blanket merge exception.

Acceptance: owner-bound deliverable budgets survive resume/handoff; lifetime review
history remains unchanged; optional suggestions need no issue or repeat review;
applicable resolved findings can carry forward in one reviewed batch; only a
strictly checked nonbehavior delta can reuse a receipt at another head; local and
trusted-main validation agree. Current advisory workspace preparation fix still
receives independent verification. Security discovery, remediation authorization,
publication and source retirement remain separate decisions.

## Explicit deliverable boundary and compatibility

Add opt-in checkpoint schema 3 and policy-3 reviews; continue supporting v1/v2.
An explicit `deliverable` operation previews an owner authorization line bound to
an ID, outcome, acceptance criteria and the complete preceding attempt-ID prefix.
Activation verifies its comment author/latest editor and exact binding. The private
helper uses its existing exact-snapshot owner decision and trusted private grants.
No inferred scope transition on start, branch, rebase, rename or handoff. Repeating
the same activation reuses the same boundary; changing it needs a new owner grant.

A boundary permits docs one, plans up to two, code one initial plus up to two
focused reviews. Lifetime rounds still increase; receipts additionally name the
boundary and within-deliverable count. Failures count zero and approve nothing;
pending attempts recover exactly once, with existing bounded retry rules. A second
initial code review needs material change and explicit scoped owner authorization;
it consumes the same allowance. An extension is a consolidated spending decision,
never permission to ignore blockers. Prior allowances remain attached to the
history they governed; a newly granted scope cannot retroactively authorize rounds.

Migration preserves historical receipt digests, grants, original outcomes and v1
migration evidence. Prior unresolved findings carry into readiness; changing scope
cannot discard them. Old validators fail closed on schema 3. The current amendment
uses v2 receipts and one upfront legacy-compatible allowance while main still has
the v2 validator. Activate schema 3 only after the updated trusted-main validator
is merged. CI never imports or executes candidate code in pull_request_target.

## Findings and continuity

Keep the original claim and severity/confidence. Optional suggestions use existing
nonblocking dispositions without creating issues. Confirmed independent actionable
defects require a separate existing/new issue (private advisories for confidential
findings); unverified or refuted claims do not become automatic backlog entries.

A `carry` operation records one explicit batch for already resolved findings. It
binds each original disposition digest/source count to an exact completed review
which received those findings and prior context. Repeated/new claims, unresolved
blockers, fixed-unverified states and revision-specific owner exceptions cannot be
carried. Carry-forward applies only to the reviewed inputs; changed sources or
later dispositions invalidate it. A needs-attention verdict is not rewritten and
can support readiness once all findings have valid resolutions. No empty-findings
or clean-verdict gate is added outside the repository readiness validator.

A `continuity` operation supports a deliberately narrow exception: insertion of
exact approved Python license header comments after an unchanged shebang (or at
the start), with every other byte and every path/file mode unchanged. No additions,
deletions, renames, symlinks, binary or executable-content changes qualify. Reviewed
head must be an ancestor, target unchanged. Bind the proof to actual Git blobs and
trees, receipt and disposition snapshot. Recompute it locally and through GitHub
Git-object reads in CI; never execute candidate files. There is no general semantic
patch-equivalence claim, chained continuity or prose-only bypass. Unexplained head
or target changes remain unready; behavior changes require independent review.

Integration continues to bind the actual head/current target/merge base and checks.
Record current affected-surface test results. Preserve base-fetch failure handling
and separate review evidence from integration evidence. Temporary private forks
still need private/local verification, not public CI or assumed branch protection.

## Instructions and validation

Keep AGENTS concise; skills route to canonical procedures. Verify the selected
worktree and loaded instructions before implementation without resetting unrelated
branches. Replace obsolete process sections with canonical links, retaining their
technical requirements and historical evidence. Keep appropriate Go/UI, Rust/KVM,
licensing, protocol, path, token, network isolation and confidentiality safeguards.
A fulfilled software deliverable need not wait for future disclosure or retirement;
remaining obligations stay in their existing appropriate records.

Tests use synthetic records, fake GitHub and temporary Git repositories: explicit
owner grant/provenance, retry idempotency, scope-renaming/budget escape rejection,
v1/v2 history and returning-clone preservation, failed/pending reviews, unresolved
claims across boundaries, batch carry validity and reopening, nonblocking readiness,
license insertion proof/rejection (including altered blobs and modes), trusted CI
parity and private ledger integration. Run full scripts suites and existing affected
checks in both repositories; retain ownership/publication/PR/completion regressions.
Model judgment and semantic equivalence are not proven by these mechanical tests.
