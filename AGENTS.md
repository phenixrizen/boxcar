# Boxcar repository contract

The design is `docs/specs/2026-09-29-boxcar-design.md`; milestone plans under `docs/plans/` record rulings in section 8. Read `CONTRIBUTING.md` for engineering requirements and checks when those surfaces change.

- Sign off commits (`git commit -s`); subjects are `area: summary`. Preserve the licensing and dependency requirements in `CONTRIBUTING.md`.
- Commands are argv arrays, never shell strings built from user input.
- Every control message and audit record type has a size limit and test.
- Test affected surfaces: Python workflow changes run the full scripts suite; Rust changes run the Rust checks; guest/VMM behavior requires the relevant gated KVM suite. An exit-zero KVM skip is not a VM test pass.
- No security fix starts without the owner's go-ahead. Never publish security findings before the fix ships, including issue/PR text, plans or commit messages; use the affected repository's GitHub Draft Security Advisories and neutral regression names.

## Task contract

GitHub Issues are the authoritative backlog; the Project is its work view:
Backlog → Ready → In progress → In review → Done.
Use `.claude/skills/work-issue/SKILL.md` for ordinary development (Claude:
`/work-issue phenixrizen/boxcar#N`); other agents use the same Python helper.
A direct request for an issue selects it even when it is not Ready. Otherwise
work only the queue the owner authorized. Capture directly requested new work
as a scoped issue before implementation; do not ask again for selection.

- Every independently deliverable task has an issue. Fix defects introduced
  by the current task on its branch and record them in its PR, without extra
  issues. Independent fixes and follow-ups get separate issues/PRs. Ask the
  owner before doing unrelated work or expanding scope. A pre-existing defect
  required by the task in otherwise untouched code gets its own prerequisite
  PR; merge that first, then rebase, retest and review the dependent change.
- One change per PR. Parallel work touches separate files/areas; overlapping
  changes wait. Stacks name their parent base, then rebase and review on main.
- `Part of #N` is partial work; `Fixes #N` is finishing work. In review needs a
  finishing PR; Done needs that fix on main. An open PR or intermediate merge
  is not Done. Duplicates name their original; not-planned closures record the
  owner's decision and reason. Neither claims a delivered implementation.
- Use the helper's persistent session claim and checkpoint; never silently
  take over active work. Locks coordinate linked worktrees in one clone only.
- Every PR gets an adversarial Codex review. State/protocol/concurrency/security
  changes have a reviewed plan before code. Read `docs/review-policy.md` at
  that point. Docs/process: one round; plan: two; code: sort findings after
  round three, stop at five. Owner exceptions are explicit and durable.
  Failed/unavailable reviews are limitations. Commit/base changes invalidate
  approval without resetting budgets; preserve base freshness checks.
- Security findings stay in the affected repository's GitHub Draft Security Advisories until the owner explicitly authorizes disclosure,
  never public issues, cards or checkpoints. A neutral, owner-authorized
  exception supports issue-free private fixes; see `docs/issue-workflow.md`.

Procedures and handoff: `.claude/skills/work-issue/SKILL.md` and
`docs/issue-workflow.md`. Task requirements stay in the issue and linked plan;
execution metadata stays outside the source tree. Do not auto-import these
references or recreate a todo file.

## Undisclosed security findings

GitHub Draft Repository Security Advisories in this affected repository are
mandatory and authoritative. Use `/security-finding` to search existing drafts
before recording a credible finding, update matches, and preserve claims,
confidence and verification. Adversarial-review findings follow the same path.
Use `/work-security phenixrizen/boxcar GHSA-xxxx-yyyy-zzzz` for owner-authorized
remediation. No security fix starts without the owner's required authorization.

Never put undisclosed details in public issues, cards, branches, commits, PRs,
docs, release notes or accessible logs, even after tests pass. Use a temporary
private security fork for revealing patches. Publication, CVE requests and
moving changes into public history need the owner's explicit disclosure decision.
If advisory access fails, stop that operation and report only the access problem;
never fall back to public metadata. Do not retire an original private artifact
until migration is verified and the owner approves retirement. See
`.claude/skills/security-finding/SKILL.md` and `docs/security-workflow.md` on demand.
