---
name: work-security
description: Resume owner-authorized remediation of a draft GitHub Security Advisory in an isolated temporary private fork, retaining private checkpoints and review budgets.
argument-hint: "[owner/repo] [GHSA-xxxx-yyyy-zzzz]"
---

# Work security

Use the implemented `scripts/security_advisory.py` operations below. This is a
repository skill, not a Claude built-in. Read the guide's exact JSON schemas and
restricted output requirements before invoking it. Never claim an operation
succeeded until its verified read-back completes.

This is separate from `/work-issue`. Read `docs/security-workflow.md` and
`docs/review-policy.md`. Retrieve the advisory using `security_advisory.py read`
and inspect its restricted output file. No public issue, Project card or PR.

- Verify native draft state, internal status, owner authorization and its
  approved scope. No security fix starts without that authorization. If absent
  or changed, ask the owner privately; a new machine or out-of-band advisory edit
  also requires explicit current owner reconfirmation of the exact record and
  ledger via `authorize` for a released handoff. If an active record changes,
  use the documented exact-snapshot owner `reconcile` path; retain pending attempts
  and confirm stopped invocations before recovery. A stored author field is not proof. Never infer permission from discovery,
  a Confirmed status, passing tests or authorization for ordinary development.
- Read the original claim, technical evidence, plan, dependencies, previous
  attempts and decisions. A review claim is not a proven vulnerability.
- Use `security_advisory.py work` to reuse/request a temporary private fork
  and establish a private clone. Verify the GitHub fork is private, the push
  remote names only that fork, and the workspace's confidential marker is set.
  Do not use a public worktree; an unpublished branch pushed to a public repo
  is public. A fork may take minutes to appear: retry retrieval, not creation.
- Establish/resume session ownership in the advisory before edits; do not
  overlap another active session. This is explicit coordination, not an atomic
  distributed lock. A private checkpoint must include branch, implementation
  commit, actual verification, pending decisions and next action. Push only to
  the private fork before handoff; release ownership after verified publication.
- Review a required plan before code. Implement and test only the approved
  scope; use neutral test names, keep sensitive fixtures in the private fork,
  and do not upload transcripts or raw reviews to public Actions artifacts.
- Use the advisory helper's private `review` operation: it invokes the existing
  Codex review helper and records phase/head/base/count/outcome privately.
  Follow `docs/review-policy.md`; the guide identifies the private helper's supported
  ledger version and migration limits. Existing authorization/resume never creates
  a fresh allowance: explicit `deliverable` records an already owner-authorized
  outcome using a trusted private input file. Use `carry` for a reviewed batch of
  resolved findings; exact schemas are in the guide. Phase and scope are separate. Persist
  evidence-backed dispositions and current integration; optional suggestions need
  no extra round. Recover interrupted attempts before spending again. Record the
  owner's bounded allowance upfront; sessions and branches never reset it. Stop at
  readiness or present one consolidated spending decision. Unavailable reviews
  approve nothing.
- Keep related claims, necessary fixes and their tests in the same remediation.
  Search existing drafts before recording a separate credible security finding;
  optional suggestions remain dispositions. Preserve unconfirmed claims and the
  owner's decision on unrelated work; never convert them into public issues.
- When fixed and verified, use `verified` to validate integration evidence and
  set internal status to Fixed, awaiting disclosure;
  leave native state draft. Never open a public PR automatically. The owner
  explicitly decides when and how to disclose and move the patch into public
  history. Publication and CVE requests are deliberately outside these helpers.

End with a private handoff in the advisory. In a public/shared status message,
report only that confidential work needs an owner decision or access correction;
include no identifier, private URL, finding details or review transcript.
