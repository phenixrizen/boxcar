# Private security advisory workflow

Implementation status in this draft: instructions and API design are prepared;
the advisory helper remains unimplemented under the broader task. The review-policy
amendment does not implement or authorize claiming those operations.
Do not invoke nonexistent helper commands or fall back to public metadata.
The sections below specify intended behavior; the advisory operations and
confidential-workspace guard are not yet implemented in this branch.

GitHub Draft Repository Security Advisories in the affected repository are the
source of truth for undisclosed vulnerabilities. This is distinct from private
vulnerability reporting: administrators can create drafts directly without
turning on submissions from the public. The workflows never publish or request
a CVE. The owner explicitly authorizes remediation and later disclosure.

## Entry points

In a private Claude session with independently authorized GitHub credentials:

```text
/security-finding list
/security-finding search
/security-finding read GHSA-xxxx-yyyy-zzzz
/security-finding create
/security-finding update GHSA-xxxx-yyyy-zzzz
/security-finding close GHSA-xxxx-yyyy-zzzz
/work-security phenixrizen/boxcar GHSA-xxxx-yyyy-zzzz
```

Ordinary work remains `/work-issue phenixrizen/boxcar#N`. Never put a draft advisory
reference or contents into its issue, checkpoint, Project card or PR body.
The ordinary helper rejects advisory references; the planned confidential
workspace guard is not implemented. This is accidental-disclosure protection, not semantic classification of
arbitrary prose. Inspect every public change for confidential details.

## Permissions and account independence

The helper uses authenticated `gh api`, not Claude account memory. Every new
session retrieves current GitHub records. Each account/session must have its
own authorized GitHub login or integration; never copy credentials.

According to [GitHub's repository advisories REST API](https://docs.github.com/en/rest/security-advisories/repository-advisories):

- Unpublished read: repository administrator/security manager, or collaborator
  on the advisory. A fine-grained PAT/App needs Repository security advisories:
  read. Public-code access alone is insufficient; an empty list is not proof
  of permission to see all drafts.
- Create: administrator/security manager, plus Repository security advisories:
  write for a fine-grained PAT/App. Update can also be granted to an advisory
  collaborator. This initial helper conservatively restricts mutations to the
  repository owner authenticated as `phenixrizen` with administration rights;
  other authorized advisory collaborators can read using GitHub's UI/API.
- A classic/OAuth token uses `repo` or the corresponding documented
  `repository_advisories:read` / `repository_advisories:write` scope. Do not
  assume token scope replaces repository role. Fine-grained token capabilities
  are not fully introspectable; the endpoint remains authoritative.
- Temporary private fork creation additionally needs Administration: write
  and Repository security advisories: read for fine-grained tokens. Clone/push
  requires access to the resulting private fork and Contents: write.

Read-only preflight checks roles and draft endpoint access; it cannot prove a
write will succeed without making one. A failed mutation reports only status
and permission guidance, never response bodies. Missing access fails closed.
No fallback to public issues, PRs, logs or an invented package/version.

## Private record schema

The description preserves the original technical prose and contains exactly
one `security-finding:v1` JSON block. Native GitHub state stays `draft` during
remediation; the block's `status` is separate:

New → Investigating → Confirmed → Approved for remediation → Fixing →
Awaiting verification → Fixed, awaiting disclosure → Closed.

Keep GHSA as the stable identifier. Record `legacy_ids`, discovery date/source,
confidence, original claim, components/paths, impact/preconditions, evidence
and verification attempts, root cause and affected commits when known. Keep
remediation scope/authorization, private fork/patch reference, branch/session,
implementation commit, verification results, last reviewed commit, pending
decisions and next action. A review suspicion remains unconfirmed until verified;
a disproven claim retains its original statement and private disposition.

Use the API's required summary, description and vulnerabilities array. Each
vulnerability needs a real package ecosystem; package name and affected/patched
ranges can be null where GitHub permits. Do not guess a version or substitute
`other` merely to pass validation. An unrepresentable claim remains in its
original secure source pending accurate metadata; if none exists, ask the
owner privately to designate encrypted intake. That is a temporary secure
triage path, not a second authoritative backlog. If secure access is absent,
report only the limitation and stop that recording operation.

## Concurrency and retries

Before create, search all visible drafts and closed records for related claims
and original IDs. Use one stable operation key for the finding and retain it
on retry; the helper first reconciles that key with GitHub. Similar summaries
are candidates for inspection, not automatic proof of a duplicate. A lost
create response never causes a blind repeated POST. If no record can be found
and the first request's outcome is uncertain, the owner must reconcile it.
No service-side idempotency key or atomic distributed claim exists here.
Coordinate simultaneous create/edit sessions explicitly.

Updates read fresh state, compare the expected version/digest, preserve the
original prose/history, and verify the returned/read-back version. An unknown
PATCH result is reconciled by its operation/version marker, not blindly
replayed. A conflict stops; do not overwrite another session's review history.
Private checkpoints and review counts live in the advisory and survive Claude
accounts and machines. Raw local reports are execution artifacts, not the
backlog. Copy them only through an authorized private path if needed.

## Remediation and review

Retrieve the advisory, owner authorization and current status before any fix.
The helper reuses the advisory's private fork, or requests one once and waits
for GitHub to provision it. A separate clone uses only that verified private
fork as its push remote; a public worktree is not suitable for a revealing
patch. Keep reproduction fixtures, branch names, test names, review text and
implementation details private. No automatic public PR is created.

The planned private review integration uses policy 2 in docs/review-policy.md:
independent review; phase separate from initial/follow-up/integration scope;
immutable reviewed head/comparison/merge base; explicit current integration
and verification; stable findings and evidence-backed dispositions. Docs one,
plans two, code three autonomous; each later code round requires scoped owner
authorization. Historical attempts keep their policy and counts. Raw reports,
receipts, findings, pending attempts and authorizations must remain private.
This advisory integration has not been implemented or validated.

GitHub temporary private security forks have important limits: integrations
cannot access them, status checks do not run, and branch protections are not
enforced. Run appropriate checks locally in an authorized private workspace,
record actual results privately, and obtain the owner's review/disclosure decision.
Normal public Actions and branch-protection enforcement are not a validation path
for these forks. GitHub also merges their open PRs through the advisory rather
than individually; only one PR may target the fork's default branch at that step.
See [GitHub's private-fork documentation](https://docs.github.com/en/code-security/tutorials/fix-reported-vulnerabilities/collaborate-in-a-fork).
No fork creation, merging or publication is performed by this amendment.

When verification succeeds, record Fixed, awaiting disclosure while leaving
native state draft. Closing an invalid/resolved draft is explicit and retains
its private reason; it is not publication. Published records are read-only to
these helpers. Publication/CVE requests and transferring patches to public
history remain separate, explicit owner decisions through GitHub.

## Migration

No original artifact location is recorded in the repository instructions.
Initial read-only checks on 2026-10-17 found zero drafts in each repository;
no real advisory was created as a test and no original artifact was changed.

When the owner provides authorized access in a private session:

1. Inventory the source privately, including stable old IDs and unresolved
   decisions. Do not copy it into this repository or a public transcript.
2. Retrieve all existing drafts/closed records and inspect related claims.
3. For each real finding, create or update the matching advisory with honest
   package metadata; retain severity, confidence, original claim, evidence,
   remediation history and decisions. Put old IDs in `legacy_ids`.
4. Read each GHSA back and compare those fields. The old-ID→GHSA mapping stays
   in advisory metadata; if exporting a mapping, use an access-restricted file
   outside the checkout and transfer it only privately.
5. Re-run using the same original IDs/operation keys to confirm idempotence.
   Account for every source entry, including disproven and incomplete claims.
6. Ask the owner to approve retirement only after all entries and mapping are
   verified. Keep the original artifact until that explicit approval.

An inaccessible artifact or incomplete public reference is not evidence from
which to reconstruct a vulnerability. Report migration as blocked, not complete.
