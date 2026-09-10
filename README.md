# security-audit-harness

An LLM-driven white-box security audit that remembers what it already found.

Three parts, installed into any repository with one command:

1. **An agent skill** (`/security-audit <scope> [--ci] [--sarif]`) that traces user input to
   sinks, proves reachability, has an adversarial critic rate every candidate, and confirms
   Critical/High findings with failing-on-vulnerable tests.
2. **A SARIF baseline** (`.security-audit/baseline.sarif`) keyed by a stable fingerprint
   (`<ruleId>|<file>|<symbol>`), so the same bug found on two different days is one result, not
   two. Reviewer edits (severity, suppressions, notes) survive later runs.
3. **A scheduled GitHub Actions workflow** that runs the skill in CI mode, merges into the baseline
   and opens (or refreshes) a single PR containing only findings that are not already known.

## Install into a repository

```sh
git clone <this repo> ~/Code/security-audit-harness
cd ~/Code/security-audit-harness && bun install    # dev deps only (typescript), optional

bun bin/security-audit.ts init /path/to/your/repo            # audits ./src by default
bun bin/security-audit.ts init /path/to/your/repo --scope app
```

`init` writes into the target repo:

| Path | What |
|---|---|
| `.claude/skills/security-audit/` | the skill: `SKILL.md`, `references/`, `scripts/` (Bun, zero deps) |
| `.security-audit/rules.json` | the closed list of finding classes with CWE mapping (kept if present) |
| `.security-audit/README.md` | how to read and edit the baseline |
| `.github/workflows/security-audit.yml` | the scheduled audit + findings PR |
| `.gitignore` | appends the scratch paths (`run.sarif`, `reports/`) |

It never overwrites an existing `baseline.sarif` or `rules.json`; pass `--force` to refresh the
skill and workflow files after upgrading the harness.

Then:

1. Fill in `.claude/skills/security-audit/references/THREAT_MODEL.md`. It ships as a template with
   the table shapes the skill expects: assets, trust boundaries (`E1…`), standing threats with their
   existing controls (`T1…`), and an out-of-scope list. The controls column is what lets the critic
   kill false positives, so name files and functions where you can.
2. Add `ANTHROPIC_API_KEY` to the repository's Actions secrets.
3. Seed the baseline: run `/security-audit src --sarif` once locally in Claude Code and commit
   `.security-audit/baseline.sarif`. Without a seed, the first CI run opens a PR with every finding.
4. Push. The workflow runs weekly (edit the cron) or on `workflow_dispatch`.

## How a run works

```
skill (blind: never reads the baseline)
  └─ writes .security-audit/run.sarif            this run's findings, full detail
       └─ validate-sarif.ts                      closed rule ids, unique fingerprints, SARIF 2.1.0 shape
            └─ merge-sarif.ts                    fingerprint match against baseline.sarif
                 ├─ baseline.sarif  ← committed   every result ever seen, minus repro/flow
                 └─ run.sarif       ← rewritten   only this run's NEW results, with repro/flow
                      └─ report-sarif.ts          PR body / step summary markdown, or --count
```

Merge rules, in one place (`skills/security-audit/scripts/sarif.ts`):

- **Known result** (same fingerprint): keeps every baseline `properties` key and its
  `suppressions`; refreshes `message`, `locations`, `lastSeen`; state `unchanged`.
- **New result**: added with `firstSeen`/`lastSeen` = today, state `new`, and returned for the PR.
- **Not reported this run**: kept as `absent`. One missing LLM run is not proof the bug is gone.
- `level` is derived from `properties.severity` (Critical/High → error, Medium → warning, Low → note).
- Rule descriptors are rebuilt from the ids in use, tagged `external/cwe/cwe-N` so GitHub code
  scanning and other SARIF consumers understand them.

Reviewer workflow on the findings PR:

- Merge → accepted into the baseline.
- False positive / accepted risk → add `"suppressions": [{ "kind": "external", "justification": "…" }]`
  to the result. The audit may report it again; the merge keeps the suppression and does not count
  it as new.
- Fixed → delete the result. If it comes back, that is a regression and it shows as `new`.
- Disagree with the severity → edit `properties.severity`. Hand edits win over later runs.

## Scripts

Run from the audited repository's root (paths are relative to `.security-audit/`):

```sh
bun .claude/skills/security-audit/scripts/validate-sarif.ts <file>        # "valid" or a list of errors
bun .claude/skills/security-audit/scripts/validate-sarif.ts --rules       # rule table as markdown
bun .claude/skills/security-audit/scripts/merge-sarif.ts   .security-audit/run.sarif
bun .claude/skills/security-audit/scripts/report-sarif.ts  .security-audit/run.sarif [--count]
```

The harness CLI wraps the same scripts: `bun bin/security-audit.ts validate|merge|report|rules`.

## Rules

`rules.json` is a closed list in priority order (first row that fits wins): `idor`,
`broken-access-control`, `auth-bypass`, `csrf`, `ssrf`, `injection`, `race-condition`,
`business-logic`, `webhook-forgery`, `secret-exposure`, `crypto-weakness`, `other`. Each has a
`name`, a `cwe` list and a one-line `covers`. Add rules by PR. Never rename an id: it is the
fingerprint prefix, so a rename turns every known finding under it into a `new` one.

## License

MIT.
