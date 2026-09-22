# Security Audit Harness

An agent harness for white-box security audits, optimized for large codebases.

A single agent session auditing a large repository runs out of context, samples the attack
surface and skips entry points. This harness splits the audit into groups of entry points, runs
each group as an independent headless audit in its own git worktree, and folds the results into
one deduped SARIF log and one report. Findings persist across runs in a committed baseline, so
each new run only surfaces what changed.

## Why this design

[*Can LLMs Really Find IDORs?*](https://inkz.github.io/presentations/2026-bsides-montreal.pdf)
(Vasilii Ermilov, BSides Montréal 2026) found that auditing each batch of endpoints separately
catches 4–6× more real vulnerabilities than one prompt over the whole repo. The `scan` skill
applies that at scale: it inventories every entry point and audits them in small groups.

## What it contains

| Component | Path | Role |
|---|---|---|
| `audit` skill | `.agents/skills/audit/` | Audits one scope: traces input to sink, proves reachability, has a critic subagent rate each candidate, writes a failing test per Critical/High. |
| `scan` skill | `.agents/skills/scan/` | Splits a large scope into groups, runs `audit` per group in parallel worktrees, aggregates. |
| SARIF tool | `.agents/skills/audit/scripts/sarif.mjs` | Validates runs, combines group runs, merges into the baseline. Node 18+, no dependencies. |
| Rule list | `security/audit/rules.json` | Closed list of rule ids with CWE mapping. Seeded from the skill's `assets/rules.json` on the first run; edit it per project. |
| Baseline | `security/audit/baseline.sarif` | Committed SARIF log, deduped on `<ruleId>\|<file>\|<symbol>`. Exploit details (`repro`, `flow`) are stripped from it. |
| Threat model | `THREAT_MODEL.md` | Derived from the code on the first run if absent. Its out-of-scope table is the project's drop list. |

## Requirements

- A coding agent CLI that loads [Agent Skills](https://agentskills.io) (`SKILL.md`): Claude Code,
  Codex, OpenCode, or another. `scan` runs each group headless with it.
- Node 18+
- git

## Install

Install the skills into your coding agent once; nothing is copied into the audited repo up front.

**Claude Code.** In a Claude Code session:

```
/plugin marketplace add trebaud/security-audit-harness
/plugin install security@security-audit-harness
```

The skills load as `/security:audit` and `/security:scan`.

**Codex, OpenCode and other Agent Skills clients.** With the [`skills`](https://skills.sh) CLI:

```sh
npx skills add trebaud/security-audit-harness          # into this repo's agent skill folders
npx skills add trebaud/security-audit-harness -g       # user-level, for every repo
```

Add `-a <agent>` to pick the agent. Or copy `.agents/skills/audit/` and
`.agents/skills/scan/` into the folder your agent reads skills from; keep them side by side.

On its first run in a repo, the audit skill creates `security/audit/`, seeds
`security/audit/rules.json` and appends the scratch paths (`run.sarif`, `reports/`, `scan/`) to
`.gitignore`. It never overwrites an existing `rules.json` or `baseline.sarif`.

## Usage

### Agent support

| Agent | Install | Invoke | `scan` runs each group with |
|---|---|---|---|
| Claude Code | plugin | `/security:audit src` | `claude -p`, tool allowlist |
| Codex | `npx skills add` | `$audit src`, or name the skill | `codex exec --sandbox workspace-write` |
| OpenCode | `npx skills add` | ask for the skill by name | `opencode run`, `OPENCODE_PERMISSION` allowlist |
| Other | `npx skills add`, or copy | ask for the skill by name | its own headless mode |

The skills name no vendor tool. Where they need a subagent, a question to the user or a background
command, they say what to do when the agent has none. Examples below use the short slash syntax
(`/audit`, `/scan`); in Claude Code add the plugin prefix (`/security:audit`),
and in other agents ask for the skill with the same arguments.

### First run

Pick one:

- **Small or medium scope:** `/audit src --sarif`
- **Large scope:** `/scan src --sarif`

Either derives `THREAT_MODEL.md` at the repo root if none exists. Review it with the code owner,
then commit it together with `security/audit/baseline.sarif`.

### `/audit`: one scope

```
/audit <scope> [--sarif [--no-merge]]
```

| Scope | Audits |
|---|---|
| `src/payments` | that directory, recursively |
| `payments` | that module and everything it exports |
| `pr#123` | the PR diff (`gh pr diff 123`) |
| `main...HEAD` | that git diff |
| `@path/to/group.md` | the entry points listed in a manifest (used by `scan`) |
| *(empty)* | `git diff <default-branch>...HEAD` |

Steps: threat model check, source-to-sink trace with reachability proof, pre-filter against the
threat model's out-of-scope table, one harsh-critic subagent per candidate (impact × likelihood),
chain detection, a failing-on-vulnerable test for every Critical and High, and a report in
`security/audit/reports/`.

- `--sarif` writes `security/audit/run.sarif`, validates it, and merges it into the baseline.
  Each baseline result is marked `new`, `unchanged`, `updated` or `absent`.
- `--no-merge` stops after validation and leaves the baseline alone.

Use it on PRs (`/audit pr#123`) to audit only what changed.

### `/scan`: a large codebase

```
/scan [scope] [--by modules|endpoints|custom] [--sarif]
```

| Flag | Default | Effect |
|---|---|---|
| `--by` | asked | `modules`: one group per feature directory. `endpoints`: groups of 25 entry points, or the size you name in the request or when asked. `custom`: groups you describe in plain words. |
| `--sarif` | off | Merge the combined findings into the baseline, once. |

Flags that are not given become questions. There is no helper script: the agent running `/scan`
does each phase itself with git, the shell and `sarif.mjs`.

1. **Preflight.** Checks the environment, derives the threat model once in the main tree if
   needed, warns about uncommitted changes (worktrees are cut from `HEAD`).
2. **Inventory and split.** Lists every entry point (routes, webhooks, queue consumers, workers,
   CLI commands, cron jobs), shows counts per module, and proposes a split. You confirm or edit
   the group table before anything runs.
3. **Worktrees.** One `git worktree` and branch `scan-<run-id>-<gNN>` per group, under
   `../<repo>.scan/<run-id>/` (or with [mori](https://github.com/trebaud/mori) when the repo has a
   `.mori.json`, so its `post_create` setup runs), with the rule list, the threat model and the group manifest copied
   in, and dependencies installed so tests can run. A user-level or plugin install of the skills
   is visible from every worktree; a repo-level one is copied in too.
4. **Run.** The CLI you ran `/scan` from runs the audit skill with `<group> --sarif
   --no-merge` in each worktree, headless, four at a time through `xargs -P 4`. A group
   is `done` only when the agent exits 0 and its `run.sarif` validates. The skill offers to rerun
   failed groups.
5. **Aggregate.** Combines every group's SARIF into `combined.sarif` (two groups hitting the same
   sink become one result), runs a critic pass for chains that cross groups, copies the new tests
   into the main tree without overwriting conflicts, merges into the baseline once with `--sarif`,
   and writes `security/audit/reports/scan-<run-id>.md`.
6. **Cleanup.** Worktrees are kept for review by default; the skill asks before removing them.

Examples:

```
/scan src --by modules --sarif
/scan src --by endpoints --sarif
/scan src --by custom
    > payments and refunds together, all /admin routes on their own, webhooks on their own
```

The group audits get only read, edit, git, `sarif.mjs` and the repo's test command (Codex: its
workspace-write sandbox). Run state lives in `security/audit/scan/<run-id>/` (gitignored): the
group list, manifests, logs, the combined SARIF and the group reports.

### Outputs

| File | Committed | Contents |
|---|---|---|
| `THREAT_MODEL.md` | yes | Assets, entry points, standing threats, controls, out of scope. |
| `security/audit/baseline.sarif` | yes | Every finding across runs, with its baseline state. No exploit details. |
| `security/audit/rules.json` | yes | The project's rule list. |
| `security/audit/run.sarif` | no | The last run's findings, including `repro` and `flow`. |
| `security/audit/reports/*.md` | no | Full write-ups and the cleared-candidates appendix. |
| Test files | yes, after review | One failing-on-vulnerable test per Critical/High, at the repo's usual test path. |

## Development

```sh
node --test tests/*.test.mjs
```

## License

MIT.
