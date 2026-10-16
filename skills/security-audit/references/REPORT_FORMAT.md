# Report format

- **Critical/High**: full write-up — severity with the critic's reasoning, source → sink trace with
  file:line, repro (`curl`, job payload, crafted URL, or `postMessage`
  probe), fix, and the test path (or **unconfirmed by test** and why).
- **Medium/Low**: trace and repro optional.
- No empty sections, methodology narration, or passing-check paragraphs.
- No attacker relevance → not a Low; one-line note or drop.
- Critic-cleared candidates appear only in the appendix.
- Glyphs: 🔴 Critical · 🟠 High · 🟡 Medium · ⚪ Low. Tag the package in a mixed repo.

File: `.security-audit/<scope-slug>-<YYYY-MM-DD>.md` (manifest basename for
`@manifest`, branch name for an empty scope).

```markdown
Threat model derived this run — needs owner review: THREAT_MODEL.md   <- only if unconfirmed by the owner

🟠 1 High · 🟡 1 Medium · ⚪ 2 Low                  <- found severities only, or "No findings."

🟠 **High — <claim>** — `file:line`
<full write-up>

🟡 **Medium — <claim>** — `file:line`. <impact>. Fix: <fix>.

<details><summary>⚪ 2 low-severity findings</summary>

- **<claim>** — `file:line` — fix: <fix>
</details>

## Cleared candidates

- <candidate> — cleared by <file:line> <reason>
```
