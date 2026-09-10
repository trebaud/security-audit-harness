# Security audit baseline

`baseline.sarif` is written by the scheduled [security-audit workflow](../.github/workflows/security-audit.yml),
which runs the `security-audit` skill over the configured scope; the skill merges its findings into this file with
`.claude/skills/security-audit/scripts/merge-sarif.ts`. It is the memory of the audit: every result the skill ever
reported, minus the exploit details (`repro`, `flow`, which the merge strips because this file is committed and
lives in history), keyed by `partialFingerprints["security-audit/v1"]` (`<ruleId>|<file>|<symbol>`). The closed
`ruleId` list is `rules.json` here and the symbol rules live in the skill, so the same bug yields the same key across
runs. Each rule is mapped to CWE by the merge script as GitHub `external/cwe/cwe-N` tags.

- New findings arrive as a PR on the `security-audit-findings` branch. Merging accepts them into the baseline.
- False positive or accepted risk: add a `suppressions` entry to the result, e.g.
  `"suppressions": [{ "kind": "external", "justification": "…" }]`. The audit itself is blind and may report it again;
  the merge matches it by fingerprint, keeps the suppression and does not count it as new.
- Hand edits to a result's `properties` (severity, fix, notes) win over later runs; only `message`, `locations`
  and `lastSeen` refresh. Delete the result to re-accept the audit's own assessment.
- Fixed: delete the result. If the skill reports it again, that is a regression and it comes back as `new`.
- Validate after hand edits: `bun .claude/skills/security-audit/scripts/validate-sarif.ts .security-audit/baseline.sarif`.
- `rules.json` is the closed list of finding classes, in priority order (first row that fits wins), each with
  `name`, `cwe` and `covers`. Adding a rule is a PR. Never rename an id: it is the fingerprint prefix, so a rename
  turns every known finding under it into a `new` one.
- `baselineState` per result: `new` this run, `unchanged` (seen again), `absent` (not seen this run; kept because the audit is not deterministic).
- `run.sarif` and `reports/` are scratch output and gitignored.
