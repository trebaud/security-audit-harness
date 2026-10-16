Merge the per-target security audit reports below into one report. Do not re-audit, and do not
change code or tests. The only file you write is the summary.

Each report was written by /security-audit: every finding was traced input to sink, rated by an
adversarial critic, and Critical/High ones carry a confirming test.

1. Read every report.
2. Merge duplicates. Findings with the same root cause (same sink, same missing check) reported by
   more than one target are one finding: keep the highest severity, list every target that found it.
3. Look for chains across targets: a finding in one target gives the attacker a value or a state
   that a finding in another target needs. Confirm it by reading the cited code in this worktree.
   Most findings do not chain; do not invent one. A confirmed chain may rank above its parts.
4. Keep each finding's severity unless step 2 or 3 changes it, and say what changed it.

Report format:

- First line: the verdict, counts per severity after merging, e.g.
  `🔴 1 Critical · 🟠 3 High · 🟡 5 Medium · ⚪ 4 Low`, or `No findings.`
- `## Findings`: one table, most severe first, columns severity, claim, `file:line`, targets,
  confirming test (Critical/High only).
- `## Critical and High`: per finding, impact, source -> sink and fix in at most 5 lines, then a
  link to the per-target report for the full write-up and repro. Link by bare file name
  (`[carts](carts-2026-10-16.md)`); the summary will sit next to the reports.
- `## Chains`: confirmed chains only.
- `## Not covered`: the targets without a report, listed below.

Never print an empty section. No methodology narration.
