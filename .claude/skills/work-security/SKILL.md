---
name: work-security
description: Resume owner-authorized remediation of a draft GitHub Security Advisory in an isolated temporary private fork, retaining private checkpoints and review budgets.
argument-hint: "[owner/repo] [GHSA-xxxx-yyyy-zzzz]"
---

# Work security

This draft's helper implementation is pending an owner plan-budget decision.
If `scripts/security_advisory.py` is absent, stop and report that limitation;
do not record findings elsewhere or claim these operations ran.


This is separate from `/work-issue`. Read `docs/security-workflow.md` and
`docs/review-policy.md`. Retrieve the advisory using `security_advisory.py read`
and inspect its restricted output file. No public issue, Project card or PR.

- Verify native draft state, internal status, owner authorization and its
  approved scope. No security fix starts without that authorization. If absent
  or changed, ask the owner privately; never infer permission from discovery,
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
  Docs/process one, plans two, code triage after three and stop at five still
  apply. Failed/unavailable reviews are never passes. Recover interrupted
  attempts before another round; a session change does not reset the budget.
- Record findings from that review in the same advisory when related, or search
  and create a separate draft for an independent credible finding. Preserve
  the owner decision for unrelated work. Keep verification and dispositions.
- When fixed and verified, update internal status to Fixed, awaiting disclosure;
  leave native state draft. Never open a public PR automatically. The owner
  explicitly decides when and how to disclose and move the patch into public
  history. Publication and CVE requests are deliberately outside these helpers.

End with a private handoff in the advisory. In a public/shared status message,
report only that confidential work needs an owner decision or access correction;
include no identifier, private URL, finding details or review transcript.
