# Working on boxcar

The design is `docs/specs/2026-09-29-boxcar-design.md`; each milestone has a
plan under `docs/plans/` whose section 8 records the rulings made while
executing it. `CONTRIBUTING.md` has the checks every change passes and the
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

- `--base` reviews the commits `origin/main...HEAD`, not the working tree:
  commit everything first. A branch stacked on another unmerged branch is
  reviewed against that branch (`--base origin/<branch>`). The pull
  request's body names the commit reviewed; commits after it (the
  review's own fixes included) get another review before the merge.
- The focus names the risks the change touches: what the guest can reach
  or alter, credentials in records, dumps and logs, the gate relaying
  bytes unchanged, a guest blocking the VMM, ring 1 blocking ring 0,
  races and ownership across the VMM's threads, recovery and cleanup at
  stop.
- Its findings are claims, not facts. Each is reproduced (a test, a
  reconciler scenario, a gated run) or traced in the code before it is
  fixed; one the code refutes is answered with the lines that refute it.
- The pull request's body lists the findings and what became of each. One
  outside the change's scope goes to the next milestone's plan, never
  dropped silently.
- A security finding (a way for the guest or anyone else to gain access,
  read what it should not, alter or escape the audit, or deny service)
  never goes into this repository, a pull request, a commit message or a
  plan until its fix has shipped: it goes to the owner's private
  security-findings document. The fix's pull request describes the
  change, not the attack, and its regression tests have neutral names.
  No security fix starts without the owner's go-ahead.
- When the review cannot run (no login, no network), the pull request says
  so: a limitation, not a pass.
