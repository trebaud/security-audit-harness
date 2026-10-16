# security-audit-runner

Runs the bundled `security-audit` Claude Code skill on many targets in parallel, each in its own
mori worktree, then merges every report into one summary. A live dashboard shows state, tokens,
cost and findings per audit.

## Requirements

`claude`, `mori`, `jq`, `git`, `uuidgen`. The skill ships in `skills/` and is loaded as a plugin,
so the audited repo needs nothing installed. A `.mori.json` in the repo that installs dependencies
lets the audits run their confirming tests.

The skill works from a `THREAT_MODEL.md`. Commit one first, or every audit drafts its own:

```sh
claude --plugin-dir ~/Code/security-audit-runner   # in the repo, then:
/security-audit-runner:security-audit threat model only
```

## Run

```sh
./run.sh -t carts,refunds,b2b-api                    # audits the repo of the current directory
./run.sh -r ~/code/my-app -t auth,payments -j 6
./run.sh -f ~/audits/targets.txt                     # one target per line, # comments skipped
./status.sh [run]                                    # the dashboard, from another terminal
```

| Flag | Default | |
|---|---|---|
| `-t, --targets` | | comma-separated target names: lowercase letters, digits, `-` |
| `-f, --targets-file` | | file with one target per line; combines with `-t`, at least one target required |
| `-r, --repo` | repo of the current directory | git repo to audit |
| `-j, --jobs` | 4 | audits in parallel |
| `-d, --day` | today | `YYYYMMDD`; an earlier day resumes that run and skips targets that have a report |

`NO_COLOR=1` turns colors off; `REFRESH=<seconds>` sets the dashboard refresh.

## Output

`runs/<repo>-<day>/` holds one report per target, `summary-<date>.md` (merged findings and run
stats), `events.log`, and the raw Claude stream of each session. In each worktree the skill writes
its report to `.security-audit/` and leaves its confirming tests in the tree. Worktrees are named
`sec-audit-<day>-<target>`; the command to remove them is printed when the run ends.
