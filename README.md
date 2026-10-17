# security-audit-harness

Run [Claude Code](https://github.com/anthropics/claude-code) security audits across a whole codebase
in parallel: one isolated git worktree per attack surface, findings traced from input to sink and
challenged by a critic, Critical and High findings confirmed by a failing test, and every report
merged into one summary.

```
🔐 Security audit  my-app-20261017   ⏳ 18:43   💰 ~$6.31
   claude-opus-5-5 · high effort · 14:20:53
   ━━━━━━━━━━━━━━━━━━────────────  3/5   ✓ 3 done  ● 2 running

   TARGET                STATE      TIME AGENTS     IN    OUT     COST  ACTIVITY
   ─────────────────────────────────────────────────────────────────────────────
 ✓ e1-public-api         done      14:10      6   2.1M    48k    $1.92  🟠 1 High · ⚪ 2 Low
 ✓ e2-authenticated-api  done      16:31      8   2.8M    61k    $2.40  No findings.
 ✓ e3-webhooks           done      12:02      5   1.6M    37k    $1.33  🔴 1 Critical · 🟡 1 Medium
 ● e4-admin-api          running    9:13      3   410k    12k   ~$0.41  Bash › Run the CSV export ownership test
 ● e5-workers            running    6:49      2   260k     8k   ~$0.25  Grep › job.data.userId

   14:02:10  · run my-app-20261017: 5 targets, 3 parallel, repo ~/code/my-app
   14:14:25  ✓ e3-webhooks done, $1.33
   14:16:21  ✓ e1-public-api done, $1.92
   14:18:42  ✓ e2-authenticated-api done, $2.40
```

<sub>The live dashboard, with illustrative numbers.</sub>

## How it works

1. **Threat model.** The audited repo has a `THREAT_MODEL.md` that lists its entry points, sources,
   sinks, controls and what is out of scope. Each entry point (E1, E2, …) becomes a target, unless
   you name the targets yourself.
2. **Isolation.** Each target gets its own [mori](https://github.com/trebaud/mori) worktree,
   `sec-audit-<id>-<target>`, cut from the default branch, so parallel audits never touch each
   other or your checkout.
3. **Audit.** A headless Claude Code session runs the bundled `security-audit` skill in each
   worktree, several at a time. The skill traces every source to a sink with `file:line` at each
   hop, drops anything an attacker can't reach, has a fresh critic subagent try to disprove each
   candidate, and writes a failing test for every Critical and High finding.
4. **Summary.** When every audit has finished, one more session merges the reports: it collapses
   duplicates that share a root cause, looks for chains where one finding enables another, and
   writes a single summary with the run's stats.

## Requirements

- [Claude Code](https://github.com/anthropics/claude-code) (`claude`), signed in
- [mori](https://github.com/trebaud/mori), a git worktree manager
- `git`, `jq`, `uuidgen` (preinstalled on macOS; part of `util-linux` on Linux), bash 3.2+

In the repo you audit:

- a filled-in `THREAT_MODEL.md`, committed on the default branch, since every worktree is cut from
  it. `audit.sh` checks this before it starts.
- optionally, a `.mori.json` that installs dependencies in new worktrees, so the audits can run
  their confirming tests.

## Quick start

```sh
git clone https://github.com/trebaud/security-audit-harness ~/security-audit-harness
cd ~/code/my-app

# 1. Draft a threat model from the code, answer the questions the code can't, then commit it.
claude --plugin-dir ~/security-audit-harness "/security-audit-harness:security-audit threat model only"
git add THREAT_MODEL.md && git commit -m "Add threat model"

# 2. Audit every entry point in the threat model, 4 at a time.
~/security-audit-harness/audit.sh
```

The skill ships in this repo as a Claude Code plugin. `audit.sh` loads it into every session with
`--plugin-dir`, so nothing is installed in the audited repo or in your Claude Code config.

## Usage

```sh
./audit.sh                                  # every threat-model entry point
./audit.sh -t e2,e5 -j 2                    # two entry points, 2 at a time
./audit.sh -t payments,refunds -r ~/code/my-app -m opus -e high
./audit.sh -i 20261017                      # resume a run: skips targets that have a report
```

A target is either a threat-model entry point (`e2` or `e2-<name>`) or a module or path name that
the skill audits recursively.

| Flag | Default | |
|---|---|---|
| `-t, --targets` | each threat-model entry point, e.g. `e2-authenticated-api` | comma-separated target names: lowercase letters, digits, `-` |
| `-f, --targets-file` | | file with one target per line, `#` comments allowed; combines with `-t` |
| `-r, --repo` | repo of the current directory | git repo to audit |
| `-j, --jobs` | `4` | audits in parallel |
| `-i, --id` | today (`YYYYMMDD`) | run id (letters, digits, `. _ -`); reusing an id resumes that run |
| `-m, --model` | Claude Code's default | model for every session: an alias (`opus`, `sonnet`) or a full name |
| `-e, --effort` | Claude Code's default | effort for every session: `low`, `medium`, `high`, `xhigh` or `max` |

`NO_COLOR=1` turns colors off. `REFRESH=<seconds>` sets how often the dashboard redraws.

When a run ends, `audit.sh` prints the path to the summary, a command that retries only the failed
targets, and a command that removes the run's worktrees.

## Output

```
runs/my-app-20261017/
├── summary-2026-10-17.md            # merged findings, chains, and run stats
├── e1-public-api-2026-10-17.md      # one report per target
├── e1-public-api.jsonl              # raw Claude stream of each session
├── e1-public-api.err
└── events.log
```

Reports list findings by severity (🔴 Critical · 🟠 High · 🟡 Medium · ⚪ Low). Each Critical and High
finding has a source → sink trace, a repro, a fix and the path of its confirming test. Candidates
the critic cleared are listed in an appendix.

Each worktree keeps its report in `.security-audit/` and its confirming tests in the tree, ready to
become regression tests.

## Use the skill on its own

The skill also works in a single interactive session, without the harness:

```sh
claude --plugin-dir ~/security-audit-harness "/security-audit-harness:security-audit src/payments"
```

| Scope | Audits |
|---|---|
| path or module | that code, recursively |
| `e2`, `e2-<name>` | threat-model entry point E2, traced into whatever it calls |
| `pr#123` | the diff of PR 123 |
| `main...HEAD` | that git diff |
| *(empty)* | the current branch's diff against the default branch |

The skill only runs when invoked by name; Claude won't start an audit on its own.

## Good to know

- **Cost.** Every target is a full Claude Code session with subagents. The dashboard shows a
  running estimate (`~`) at list price, replaced by the exact cost when a session ends. Try a
  couple of targets with `-t` before auditing everything.
- **Permissions.** Sessions run headless with `--permission-mode auto`: they read the code, write
  tests and run them in their worktree without asking. Only audit code you are willing to run.
- **Findings.** Each one is traced, challenged by a critic and, at Critical or High, confirmed by a
  test, but it is still model output. Review it before acting on it.
