# Security Audit Harness

An agent harness for white-box security audits, built for codebases too large to audit in one
session.

A single agent session auditing a large repository runs out of context, samples the attack
surface and skips entry points. This harness splits the audit into groups of entry points, runs
each group as an independent headless audit in its own git worktree, and folds the results into
one deduped SARIF log and one report. Findings persist across runs in a committed baseline, so
each new run only surfaces what changed.

Inspired by the results presented by Vasilii Ermilov at BSides Montréal 2026
([slides](https://inkz.github.io/presentations/2026-bsides-montreal.pdf)).

## What it contains

| Component | Path | Role |
|---|---|---|
| `security-audit` skill | `.agents/skills/security-audit/` | Audits one scope: traces input to sink, proves reachability, has a critic subagent rate each candidate, writes a failing test per Critical/High. |
| `scan` skill | `.agents/skills/scan/` | Splits a large scope into groups, runs `security-audit` per group in parallel worktrees, aggregates. |
| SARIF tool | `.agents/skills/security-audit/scripts/sarif.mjs` | Validates runs, combines group runs, merges into the baseline. Node 18+, no dependencies. |
| Rule list | `security/audit/rules.json` | Closed list of rule ids with CWE mapping. Edit it per project. |
| Baseline | `security/audit/baseline.sarif` | Committed SARIF log, deduped on `<ruleId>\|<file>\|<symbol>`. Exploit details (`repro`, `flow`) are stripped from it. |
| Threat model | `THREAT_MODEL.md` | Derived from the code on the first run if absent. Its out-of-scope table is the project's drop list. |

## Requirements

- Claude Code (the `scan` skill runs each group with `claude -p`)
- Node 18+
- git
- Optional: [mori](https://github.com/trebaud/mori) as the worktree backend (needs `go`; `scan`
  installs it when missing)

## Install

```sh
./install.sh /path/to/repo [--scope app] [--force]   # default scope: src
```

The installer copies both skills and `rules.json` into the target repo, creates
`security/audit/`, and appends the scratch paths (`run.sarif`, `reports/`, `scan/`) to
`.gitignore`. It never overwrites an existing file without `--force`, and never touches an
existing `baseline.sarif` or `rules.json`.

## Usage

### First run

Pick one:

- **Small or medium scope:** `/security-audit src --sarif`
- **Large scope:** `/scan src --sarif`

Either derives `THREAT_MODEL.md` at the repo root if none exists. Review it with the code owner,
then commit it together with `security/audit/baseline.sarif`.

### `/security-audit`: one scope

```
/security-audit <scope> [--sarif [--no-merge]]
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

Use it on PRs (`/security-audit pr#123`) to audit only what changed.

### `/scan`: a large codebase

```
/scan [scope] [--by modules|endpoints|custom] [--size 25] [--parallel 4]
      [--worktrees git|mori] [--sarif] [--resume <run-id>]
```

| Flag | Default | Effect |
|---|---|---|
| `--by` | asked | `modules`: one group per feature directory. `endpoints`: groups of `--size` entry points. `custom`: groups you describe in plain words. |
| `--size N` | 25 | Entry points per group with `--by endpoints`. |
| `--parallel N` | 4 | Concurrent group audits. Use 2 for a tight rate limit, 8 for a high one. |
| `--worktrees` | asked | `git`: native worktrees under `../<repo>.scan/<run-id>/`. `mori`: worktrees under `~/.mori/worktrees/<repo>/`, runs `.mori.json` `post_create`. |
| `--sarif` | off | Merge the combined findings into the baseline, once. |
| `--resume <run-id>` | | Continue an interrupted scan at its first unfinished phase. |

Flags that are not given become questions. The scan runs in phases:

1. **Preflight.** Checks the environment, derives the threat model once in the main tree if
   needed, warns about uncommitted changes (worktrees are cut from `HEAD`).
2. **Inventory and split.** Lists every entry point (routes, webhooks, queue consumers, workers,
   CLI commands, cron jobs) into `inventory.json`, shows counts per module, and proposes a split.
   You confirm or edit the group table before anything runs.
3. **Worktrees.** One worktree and branch `scan-<run-id>-<gNN>` per group, with the harness, the
   threat model and the group manifest copied in, and dependencies installed so tests can run.
4. **Run.** `claude -p` runs `/security-audit <group> --sarif --no-merge` in each worktree, in
   the background, with a restricted tool allowlist. A group is `done` only when `claude` exits 0
   and its `run.sarif` validates. Failed groups can be retried with `--retry-failed`.
5. **Aggregate.** Combines every group's SARIF into `combined.sarif` (two groups hitting the same
   sink become one result), runs a critic pass for chains that cross groups, copies the new tests
   into the main tree without overwriting conflicts, merges into the baseline once with `--sarif`,
   and writes `security/audit/reports/scan-<run-id>.md`.
6. **Cleanup.** Worktrees are kept for review by default; the skill asks before removing them.

Examples:

```
/scan src --by modules --sarif
/scan src --by endpoints --size 20 --parallel 8 --worktrees git --sarif
/scan src --by custom
    > payments and refunds together, all /admin routes on their own, webhooks on their own
/scan --resume 2026-09-22-1430
```

If the repo runs tests with a command outside the default allowlist (npm, pnpm, yarn, bun, vitest,
jest, mocha, `node --test`, go, pytest, cargo), pass it to the group audits:

```sh
SCAN_EXTRA_TOOLS="Bash(make test:*)"
```

Run state lives in `security/audit/scan/<run-id>/` (gitignored): `inventory.json`, `plan.json`,
group manifests, logs (`logs/<gNN>.log`), per-group SARIF and reports. Every step rereads
`plan.json`, so any interrupted step resumes by rerunning it.

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
node --test tests/
```

## License

MIT.
