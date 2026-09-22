# Report format

Write-up rules:

- **Critical and High** — full write-up each: severity (with the critic's impact × likelihood
  reasoning), source->sink flow with file:line, a copy-paste payload (curl or dev-tools probe fn)
  to reproduce, a fix suggestion, and the step-4 test file.
- **Medium and Low** — may carry the full trace and repro.
- Never print an empty severity section, methodology narration ("Nine candidates traced…",
  "Scope: …"), or a passing-check paragraph (auth intact, rate limiters intact, …).
- A finding with no attacker relevance (correctness bug, stale comment, ops blocker) is not a Low.
  One-line note outside the severity sections, or drop it.
- Critic-killed candidates are working notes: drop them silently. **No** "Killed during
  verification", "Checked and cleared", "recorded so the next audit…" or any equivalent section.
  The cleared-candidates appendix (below) is the one exception.
- Severity glyphs: 🔴 Critical · 🟠 High · 🟡 Medium · ⚪ Low.
- If the threat model was derived this run (step 0), say so in one line at the top, with its path.

## File

Write `security/audit/reports/<$1 slugified>-$(date +%Y-%m-%d).md` (the folder is gitignored;
for an `@manifest` scope the slug is the manifest's basename without extension).

## Skeleton

```markdown
🟠 1 High · 🟡 1 Medium · ⚪ 2 Low                  <- verdict line, found severities only

🟠 **High — <claim>** — `file:line`
<full write-up per the rules above>

🟡 **Medium — <claim>** — `file:line`. <impact>. Fix: <fix>.

<details><summary>⚪ 2 low-severity findings</summary>

- **<claim>** — `file:line` — fix: <fix>
</details>

## Cleared candidates

- <candidate> — killed by <file:line> <reason>
```

No findings -> the verdict line reads "No findings.", followed by the appendix.

The `## Cleared candidates` appendix holds one line per critic-killed candidate so the next audit
does not redo the work. It lives only in this file.
