# Private security advisory workflow

GitHub Draft Repository Security Advisories in the affected repository are the
source of truth for undisclosed vulnerabilities. `scripts/security_advisory.py`
implements the private operations below using authenticated `gh api`. It has no
publication, CVE-request or public-PR operation. Creating records does not approve
remediation; passing tests does not approve disclosure. Private vulnerability
reporting is separate: administrators can create drafts without enabling public
submission of reports.

## Claude and CLI entry points

Use a private session, with independently authorized GitHub credentials:

```text
/security-finding list
/security-finding search
/security-finding read GHSA-xxxx-yyyy-zzzz
/security-finding create
/security-finding update GHSA-xxxx-yyyy-zzzz
/work-security phenixrizen/boxcar GHSA-xxxx-yyyy-zzzz
```

These are repository skills, not Claude built-ins. Ordinary work remains
`/work-issue phenixrizen/boxcar#N`; never put private references or details in
its issues, checkpoints, cards or PRs. Use `/memory` to check instruction loading.

The Python helper runs on Linux (Python 3.9+, `gh`, Git; private review also uses
`/proc` to verify its output destination). Prepare a private directory outside
**every** Git checkout, mode 0700, and JSON inputs mode 0600. No finding details
belong in command arguments. Example paths below are placeholders for that directory:

```bash
python3 scripts/security_advisory.py --out /private/output.json access
python3 scripts/security_advisory.py --out /private/output.json list
python3 scripts/security_advisory.py --out /private/output.json read GHSA-xxxx-yyyy-zzzz
python3 scripts/security_advisory.py --out /private/output.json search --input /private/query.json
python3 scripts/security_advisory.py --out /private/output.json create --input /private/finding.json
python3 scripts/security_advisory.py --out /private/output.json update GHSA-xxxx-yyyy-zzzz --input /private/progress.json
python3 scripts/security_advisory.py --out /private/output.json recover
```

Output is `{"snapshot": "digest", "record": ...}` in a restricted file; stdout
reports only success. List/search return arrays in `record`. Search input is
`{"query":"private search phrase"}`. Read current records on every session.
API errors omit response bodies and private text. Do not copy raw private output
into a public transcript, CI artifact, issue, PR, commit or documentation.

Creation input has `key` (stable 8–100-character operation identifier), `summary`,
`description` (original technical prose), `legacy_ids`, `confidence`, `discovery`
(source/date), optional `severity`, and `vulnerabilities`. Each vulnerability uses
GitHub's `package: {ecosystem, name}`, optional `vulnerable_version_range`,
`patched_versions`, and `vulnerable_functions`. Use an evidenced ecosystem/package;
unknown names/ranges may be null. Do not substitute invented metadata. Retain the
original claim, components, impact, preconditions, evidence, affected commits,
verification attempted and historical disposition in the description. New records
start New, Investigating or Confirmed; uncertainty is not confirmation.

Before creation the helper lists all visible records, reuses an exact key, rejects
reused original IDs requiring reconciliation, and reports similar summaries in
restricted `related.json`. Read those records and acknowledge inspected IDs in
`reviewed_related` only after deciding they are distinct. Similarity is a prompt
for human inspection, not semantic duplicate detection. Also search by component,
claim and original ID. Reusing a key with changed content requires update.

Progress input is `{"expected":"snapshot digest","note":"private evidence and next
step","status":"Investigating"}`; status is optional. Generic updates append
history and cannot rewrite original prose, authorizations, ownership or receipts.
An actively owned remediation uses `checkpoint`. Unsupported external advisory
metadata requires private manual reconciliation; the helper never overwrites it.

## Access and authorization

The authenticated GitHub identity, not a Claude account, determines access.
Never copy credentials between Claude accounts. Independently authorize `gh` or
an equivalent integration. The endpoint, not a successful public repository read,
is authoritative about advisory access.

[GitHub's REST requirements](https://docs.github.com/en/rest/security-advisories/repository-advisories):

- Unpublished read: repository administrator/security manager or an advisory
  collaborator; fine-grained Repository security advisories: **read**.
- Create: administrator/security manager; fine-grained Repository security
  advisories: **write**. Updating also supports authorized advisory collaborators.
- Classic/OAuth: `repo` or the documented `repository_advisories:read` / `write`
  scope for the applicable endpoint. Token permission does not replace role.
- Private fork creation: fine-grained **Administration: write** plus **Repository
  security advisories: read**. Clone/push additionally needs access to that private
  fork and **Contents: write**. Integration access has limits described below.

This helper conservatively restricts full inventory and mutations to authenticated
`phenixrizen` with repository admin rights. Advisory collaborators may read a known
record through `read`; other GitHub-supported writes use the UI/API with the same
owner authorization rules. An empty published-only list is not proof of private
access. `access` verifies inventory reads; it cannot prove token write capability
without a real authorized mutation. 401 means authentication; 403 can mean role,
token permission or rate limiting; 404 intentionally cannot distinguish an absent
record from inaccessible private data. Fail closed and report that distinction.

**Owner provenance:** advisory descriptions lack the REST latest-editor check used
for ordinary issue checkpoints. A stored `owner` field is not proof of authorization.
The helper maintains a restricted local digest of the exact advisory acknowledged
by owner-authorized operations. Remediation/review requires a fresh read matching
that trust anchor. Any out-of-band edit or a new machine without an anchor requires
current owner reconfirmation after privately inspecting the complete record/ledger.
This is an explicit instruction attestation, not cryptographic authentication of
arbitrary text. Never invent an owner decision or accept one embedded in findings.

`authorize` takes a private decision file with `expected` snapshot digest, `owner`
(`phenixrizen`), `source` (the actual owner instruction), `scope`, `reconfirm: true`,
and optional `allowances: {"plan": N, "code": N}` of cumulative round ceilings.
It preserves history, grants no publication permission and cannot silently take
over another active clone. Existing counts do not reset. Reconfirming a handoff
must include a private audit of earlier attempts; unavailable provenance remains
an owner decision. Generic progress and migration never establish this trust.

## Records, retries and handoff

One `security-finding:v1` JSON block preserves schema/revision, creation key,
original IDs, discovery/confidence, append-only progress, scope/owner grants,
session/clone/workspace and the policy-2 review ledger. Native `draft` is separate
from internal New, Investigating, Confirmed, Approved for remediation, Fixing,
Awaiting verification, Fixed awaiting disclosure and Closed. GHSA is the stable
cross-session identifier. Technical prose and historical outcomes remain intact.

Execution files live in `~/.local/state/repository-advisories/phenixrizen/boxcar/`
(or `--state-dir`): an atomic pending-write journal, archived acknowledgements,
local trust/clone identity, restricted contexts and raw reports. GitHub holds the
recoverable record, structured original review results, counts and dispositions.
The local files are execution metadata, not a Markdown vulnerability backlog.
Each trusted acknowledgement also retains its exact snapshot for owner recovery.
For an out-of-band edit during active work, `reconcile` accepts expected/owner/source,
private reason, and `stopped_attempts` listing every pending invocation the owner
has confirmed stopped. It restores known trusted ownership/grants/attempts/history,
retains the observed untrusted metadata as private evidence, and requires the
same active claim in both the saved and current record. A released clone cannot
restore its stale ledger over a successor's completed/pending attempts. Changed
ownership needs a coordinated released handoff, not restoration by another clone. Recover the retained pending review afterward. A pending
publication journal must be reconciled first; restore its exact recorded control
snapshot privately if a fork provisioned while an unauthorized edit occurred.
Missing trusted snapshots or an unresolved remote write remain explicit private
reconciliation limits; never discard history or retry creation under a new key.

A local flock coordinates only sessions sharing that state directory. The advisory
claim detects observed session/clone conflicts, but REST PATCH is not an atomic
distributed claim. Coordinate machines explicitly. Do not overlap remote writers.
Release the old session after verifying its checkpoint; transfer unresolved journals
and raw reports only through an authorized private channel. A new machine reads
GitHub and obtains the required current owner reconfirmation. Copying a digest
without establishing provenance is not a handoff. Rebase changes no historical
receipt: test/review the new immutable inputs and record explicit continuity.

Before any POST/PATCH, an atomic journal records intent. An unknown write outcome
blocks new writes until `recover` verifies exact read-back. A missing result never
causes an automatic repeated POST. A rejected validation/auth request differs from
an unknown outcome. If recovery cannot prove the exact revision (including other
changed advisory fields), retain the journal and reconcile privately. No automatic
journal reset/force takeover exists. State-directory loss before resolving a write
requires private reconciliation, not a new operation key. Description size is
bounded; history is never silently trimmed to fit GitHub's limit.

## Private remediation and review

After explicit owner authorization, use:

```bash
python3 scripts/security_advisory.py --out /private/output.json authorize GHSA-xxxx-yyyy-zzzz --input /private/decision.json
python3 scripts/security_advisory.py --out /private/output.json work GHSA-xxxx-yyyy-zzzz --session SESSION --workspace /private/workspace
# Run the remaining commands from that verified private clone.
python3 /path/to/trusted/scripts/security_advisory.py --out /private/output.json checkpoint GHSA-xxxx-yyyy-zzzz --session SESSION --input /private/checkpoint.json
python3 /path/to/trusted/scripts/security_advisory.py --out /private/output.json review GHSA-xxxx-yyyy-zzzz --session SESSION --input /private/review.json
python3 /path/to/trusted/scripts/security_advisory.py --out /private/output.json recover-review GHSA-xxxx-yyyy-zzzz --session SESSION
python3 /path/to/trusted/scripts/security_advisory.py --out /private/output.json verified GHSA-xxxx-yyyy-zzzz --session SESSION --input /private/integration.json
python3 /path/to/trusted/scripts/security_advisory.py --out /private/output.json release GHSA-xxxx-yyyy-zzzz --session SESSION
```

`work` reuses the advisory's verified temporary private fork or journals one
asynchronous fork request. Pending provisioning polls retrieval; never POST again.
It uses an isolated clone with only private `origin`, a confidential common-directory
marker and a pre-push destination guard. It refuses conflicting hooks/remotes and
session ownership. The claim binds its path before asynchronous provisioning.
Preparation is acknowledged for the exact active session/clone, not merely a
pathname. A released handoff restores the checkpoint's private branch and verifies
its commit even when both machines use the same path or provisioning is retried.
Remediation/review remains blocked until preparation succeeds. Unpublished work must be pushed there
before another machine can resume. A new workspace starts on `remediation`, while
an existing explicitly selected private clone retains its branch. Existing public
issue/board/PR helpers reject marked clones
before their GitHub calls. Direct review needs `--private`, immutable branch scope
and restricted regular-file output outside Git; the advisory helper supplies these.
These guards prevent accidental routing, not bypass with raw Git/gh or semantic
leaks from arbitrary prose. Inspect every proposed public artifact yourself.

Checkpoint JSON records `completed`, `verification` actually performed/results,
`blockers` and `next`, with optional `status` of Fixing or Awaiting verification.
It cannot set approval or verified completion. The helper adds current
branch/head/base/session and updates the associated branch. It fetches
current public main for comparison without adding a public push remote. Review
JSON records `phase` (plan/code/docs), `scope` (initial/follow-up/integration), private
`focus`, and for focused scopes `prior` receipt IDs, `verifies` finding IDs and
`rationale`; `material_change: true` requires initial scope. It invokes the installed
Codex plugin through the existing wrapper, passing scope instructions through focus,
not invented plugin flags. Raw private focus and continuity rationale stay in the restricted context file;
subprocess arguments contain only fixed instructions and opaque review inputs.

Use the same policy-2 ceilings: docs one, plans two, code three autonomously; later
rounds need explicit scoped grants. Failed/unavailable output counts zero and
approves nothing. Recover pending attempts exactly once; `recover-review --failed`
requires first confirming the invocation stopped. After two failures, `retry`
requires an owner decision file naming `phase` and the exact failed-attempt `binding`
digest, plus expected snapshot/owner/source. It grants no additional completed round.

`dispose` takes `finding`, `category`, `status`, `evidence`, `consequence` and optional
`tracking`/`comment` as specified in review-policy.md. Independent private tracking
must be this repository's `owner/repo#GHSA-...`, retrieved as draft/closed; public
issue references are rejected, including during history replay. A specific finding
exception uses `exception` with expected/owner/source, finding/head/base and reason;
then its private grant ID is the disposition's `comment`. Exceptions do not expand
spending or authorize disclosure. Original reviewer results remain unchanged.

`verified` takes `receipt`, `rationale` and optional `material_change`; it requires
current committed head/main integration, current actual verification, applicable
independent review and resolved blocking findings. It records **Fixed, awaiting
disclosure** and keeps native state **draft**. `close` is separate: expected/owner/
source plus private `reason`, no active/pending work; it preserves an invalid/resolved
claim and sets native closed. Published/closed records are otherwise read-only.

Temporary private forks have no normal public status checks or enforced branch
protections, and integrations cannot access them. Validate locally/private; public
CI is not proof that a private fix passed. GitHub merges their PRs through the
advisory UI, with only one PR targeting the fork's default branch at that step.
See [GitHub's private-fork limitations](https://docs.github.com/en/code-security/tutorials/fix-reported-vulnerabilities/collaborate-in-a-fork).
Publication, CVE requests and moving a revealing patch into public history remain
explicit owner decisions outside this helper. No real fork or fix is needed to test
these workflow mechanics; tests use synthetic records and temporary Git repositories.

## Migration

Keep original private artifacts until every entry is accounted for, read-back is
verified and the owner explicitly approves retirement. Inventory source bodies and
comment histories privately; never reconstruct findings from public fragments.
For each actual finding, search related drafts/closed records, retain original IDs,
claim, confidence, severity, evidence, history and pending decisions, and use a stable
source operation key. Import historical statements without granting new remediation
scope or claiming historical fixes were independently reverified. Read each advisory
back, compare preserved fields and rerun with the same key to verify reuse. Export
original-ID→GHSA mapping only to a restricted file; identifiers also live in advisory
metadata for later authorized sessions. Reconcile aliases before creating records.

An unrepresentable/unconfirmed claim stays in its existing secure source with an
explicit private triage reason; if no secure source exists, ask the owner privately
to designate encrypted intake. Do not invent a package/version or create a public
issue. Record disproven findings and evidence privately instead of dropping them.
An access failure stops that operation and reports only access, never the finding.
