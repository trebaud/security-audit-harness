# security-audit-harness

Runs the `security-audit` Claude Code skill on many targets in parallel, each in its own mori
worktree, then merges every report into one summary. A live dashboard shows state, tokens, cost and
findings per audit.

## Requirements

`claude`, `mori`, `jq`, `git`, `uuidgen`. A `.mori.json` in the repo that installs dependencies
lets the audits run their confirming tests.

The skill ships in this repo as a Claude Code plugin. `audit.sh` loads it into every session with
`--plugin-dir`, so nothing gets installed in the audited repo.

The audited repo needs a filled-in `THREAT_MODEL.md` committed on its default branch: every audit
runs in a worktree cut from it. `audit.sh` checks it before it starts. In the repo, this drafts the
model, then asks what the code can't show:

```sh
claude --plugin-dir ~/Code/security-audit-harness "/security-audit-harness:security-audit threat model only"
```

## Run

```sh
./audit.sh \
  --targets auth,payments \
  --repo ~/code/my-app \
  --jobs 6 \
  --id 20261017 \
  --model opus \
  --effort high
./status.sh [run]   # the dashboard, from another terminal
```

| Flag | Default | |
|---|---|---|
| `-t, --targets` | each threat-model entry point, e.g. `e2-authenticated-api` | comma-separated target names: lowercase letters, digits, `-`; `e2` or `e2-<name>` audits entry point E2 |
| `-f, --targets-file` | | file with one target per line; combines with `-t` |
| `-r, --repo` | repo of the current directory | git repo to audit |
| `-j, --jobs` | 4 | audits in parallel |
| `-i, --id` | today (`YYYYMMDD`) | run id (slug: letters, digits, `. _ -`); reusing an id resumes that run and skips targets that have a report |
| `-m, --model` | claude's default | model for every claude session: an alias (`opus`, `sonnet`) or a full name |
| `-e, --effort` | claude's default | effort for every claude session: `low`, `medium`, `high`, `xhigh` or `max` |

`NO_COLOR=1` turns colors off; `REFRESH=<seconds>` sets the dashboard refresh.

## Output

`runs/<repo>-<id>/` holds one report per target, `summary-<date>.md` (merged findings and run
stats), `events.log`, and the raw Claude stream of each session. In each worktree the skill writes
its report to `.security-audit/` and leaves its confirming tests in the tree. Worktrees are named
`sec-audit-<id>-<target>`; the command to remove them is printed when the run ends.
