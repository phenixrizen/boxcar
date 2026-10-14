# Working on boxcar

The design is `docs/specs/2026-09-29-boxcar-design.md`; each milestone has a
plan under `docs/plans/` whose section 8 records the rulings made while
executing it; a change to a state machine, a protocol, concurrency or a
security behaviour has a plan of its own there, reviewed before its code
(see Reviews). `CONTRIBUTING.md` has the checks every change passes and the
gated KVM suite (`cargo xtask test-kvm m4`).

## Reviews

Every pull request gets a Codex adversarial review before it is opened: a
second model questioning the design, not only the lines. It comes from the
Codex plugin for Claude Code (`openai/codex-plugin-cc`; `/plugin marketplace
add openai/codex-plugin-cc`, `/plugin install codex@openai-codex`,
`/codex:setup`, a Codex login). A person types
`/codex:adversarial-review --base origin/main <focus>`; an agent cannot
invoke that command and runs the same review through the plugin's script,
which `scripts/codex_review.py` finds (the installation Claude Code's
registry names for this repository, else the user's; never the newest
cached copy, and an ambiguous registry is refused):

```bash
python3 scripts/codex_review.py "<focus: the risks this change touches>"
```

- **The plan is reviewed before the code** when a change touches a state
  machine (a flow in the relay or the gate, the reconciler's spans, a
  device's queues, a session's start and stop), a protocol, concurrency
  or a security behaviour. The change's first commit is
  `docs/plans/<branch>.md`: the events that can interact and every order
  they can come in, the invariants that must hold in all of them (say,
  "the gate relays every byte unchanged, however the flow's ends close"),
  what is out of scope, and the tests that will pin each ordering. Codex
  reviews the plan alone (`codex_review.py --base <the commit before the
  plan> "review this plan: <focus>"`, so the review sees only the plan's
  commits) before any code is written; its findings change the plan, and
  each revision is reviewed again until a review finds nothing that
  blocks. Only then are the tests for the orderings written, from the
  plan, and then the code that passes them. A design that has to change
  once code exists goes back to the plan: the plan is revised and
  reviewed before the code follows it. The pull request's body names the
  plan's last reviewed commit apart from the code's. The plan stays as
  the change's design record, written as the pull request is (neutral for
  a security fix). A milestone's plan says what to build; each of its
  tasks that is such a change still gets a plan of its own, reviewed so
  before the task's code. A small fix (one cause, one place, no new state)
  needs no plan.
- `--base` reviews the commits `origin/main...HEAD`, not the working tree:
  commit everything first. A branch stacked on another unmerged branch is
  reviewed against that branch (`--base origin/<branch>`). The pull
  request's body names the commit reviewed; commits after it (the
  review's own fixes included) get another review before the merge.
- **A checkpoint after five rounds.** When the fifth review of a change
  still finds something, stop and sort its findings before going on. A
  finding in the current stream of work (the change introduces it,
  exposes it, needs it fixed or makes a test fail; see Issues and the
  board) is fixed before the change merges, where One change per pull
  request puts it: on the branch when the change introduces it or it is
  in the change's own code, in a pull request of its own that merges
  first when it is a defect already on `main` in code the change does not
  otherwise touch. One that is independent of the change is split off (an
  issue, or the private document for a security finding, and the owner's
  call), not fixed on the branch. The pull request's body records the
  checkpoint and how each finding was sorted. A change still finding its
  own defects after ten rounds goes back to its plan, or gets one when it
  had none.
- The focus names the risks the change touches: what the guest can reach
  or alter, credentials in records, dumps and logs, the gate relaying
  bytes unchanged, a guest blocking the VMM, ring 1 blocking ring 0,
  races and ownership across the VMM's threads, recovery and cleanup at
  stop.
- Its findings are claims, not facts. Each is reproduced (a test, a
  reconciler scenario, a gated run) or traced in the code before it is
  fixed; one the code refutes is answered with the lines that refute it.
- The pull request's body lists the findings and what became of each. One
  independent of the change becomes an issue (below), never dropped
  silently, and the owner says whether it is fixed now, in a pull request
  of its own, or waits.
- A security finding (a way for the guest or anyone else to gain access,
  read what it should not, alter or escape the audit, or deny service)
  never goes into this repository, a pull request, a commit message or a
  plan until its fix has shipped: it goes to the owner's private
  security-findings document. The fix's pull request describes the
  change, not the attack, and its regression tests have neutral names.
  No security fix starts without the owner's go-ahead.
- When the review cannot run (no login, no network), the pull request says
  so: a limitation, not a pass.

## Issues and the board

The backlog is the repository's GitHub issues, on the `boxcar` project
board (https://github.com/users/phenixrizen/projects/2), kanban style:
Backlog, Ready, In progress, In review, Done. There is no todo file.

- Every bug known and every feature or limitation set aside is an issue,
  labelled `bug` or `enhancement` and with one `area: ...` label (`fs`,
  `vmm`, `net`, `gate`, `sensor`, `reconciler`, `audit`, `cli`, `tests`,
  `docs`; add one when a part of the project has none), on the board in
  Backlog. A milestone plan's tasks become issues once the owner accepts
  the plan.
- An issue says what is wrong or wanted, how to see it, what is expected,
  and the cause as far as it is known. Write each paragraph on one line:
  GitHub shows every newline in an issue body as a break.
- **A bug in the current stream of work is fixed now; any other is the
  owner's call.** A bug is in the current stream of work when the change
  introduces it, exposes it (it was harmless until the change), needs it
  fixed to reach its goal, or makes a test fail; this holds at every round
  of review, whatever file the bug is in and whatever the plan left out of
  scope. Such a bug is fixed in that round, with its tests, where the next
  rule puts it, and gets an issue all the same, In progress, so the board
  shows it until its fix merges. Any other bug, one independent of the
  change (it behaves the same with or without it: a review's finding in
  neighbouring code, a defect seen in passing, a test that flakes on
  `main` as well), is not fixed on the spot: it becomes an issue in
  Backlog, and the owner is asked whether it is fixed now (Ready, its own
  pull request) or waits. An agent that cannot ask reports it to whoever
  leads, who asks. A security finding, the change's or not, follows the
  same ask but goes to the owner's private document instead of an issue,
  and its fix waits for the owner's go-ahead (see Reviews).
- **One change per pull request.** A bug fixed now that lies in code the
  change does not otherwise touch and is already on `main` (one the owner
  said to fix now, or a defect the change exposes or needs fixed there)
  gets its own branch and pull request from `main`, not more commits on
  the change's branch, so each review stays on one thing. When the change
  depends on that fix (it exposes or needs it), that pull request merges
  first, and the change, rebased on it, is tested and reviewed again
  before it merges. A defect the change introduces, wherever it shows, is
  fixed on its branch, as is any in the change's own code.
- An issue's card goes through one order:
  1. In progress while the work is under way, from its branch's start. A
     pull request that does only part of it says `Part of #N` and closes
     nothing.
  2. In review once the pull request that finishes it opens. Its body
     says `Fixes #N`.
  3. Done, and closed, only when the fix reaches `main`. GitHub acts on
     `Fixes #N` only for a merge into `main`: a finishing pull request
     stacked on another branch leaves the issue open and In review, and
     the pull request that carries it into `main` repeats `Fixes #N`.
  An issue is never closed by hand as fixed before its fix is on `main`.
  A duplicate is closed by naming the issue it repeats. An issue is
  closed as not planned only when the owner drops it, its comment saying
  why. A pull request's own card goes In review when it opens and Done
  when it merges.
- The exception is a security finding, as defined under Reviews: it never
  becomes an issue, a card, pull request text or a commit message until
  its fix has shipped. It stays in the owner's private security-findings
  document, which keeps its status.
- An agent that only commits locally reports the issues it would open;
  whoever pushes opens them and moves the cards.

```bash
gh issue create -R phenixrizen/boxcar --title "..." --body-file body.md \
    --label enhancement --label "area: gate"
python3 scripts/board.py <issue or pull request number> <status>
```

`scripts/board.py` puts the issue or pull request on the board when it is
not there yet and sets its Status (Backlog, Ready, In progress, In review
or Done; case does not matter). It needs the `project` scope on the gh
token (`gh auth refresh -h github.com -s project`); issues and labels do
not. The board's ids, should a command need them: project
`PVT_kwHOAJ6Ua84Bm2Lc`, Status field `PVTSSF_lAHOAJ6Ua84Bm2Lczhlde_Q`
(`gh project field-list 2 --owner phenixrizen --format json` lists its
options and their ids).
