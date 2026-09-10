---
name: security-audit
description: White-box security audit of a scope (path, module, or PR diff) for IDOR, CSRF, SSRF, NoSQL/SQL injection, auth bypass, race conditions, business-logic errors and broken access control. Traces user input to sink, proves reachability, has an adversarial critic rate severity, confirms Critical/High with failing-on-vulnerable tests. Use for security reviews, audits, pentests, PR security checks.
argument-hint: <scope: path | module | pr#NUMBER | git-ref> [--ci] [--sarif]
allowed-tools: Read, Grep, Glob, Agent, Bash(gh pr diff:*), Bash(git diff:*), Bash(git log:*), Write(.security-audit/reports/**), Write(.security-audit/run.sarif), Edit(.security-audit/run.sarif), Bash(bun .claude/skills/security-audit/scripts/*)
---

# Security Audit

White-box audit of **$ARGUMENTS** for IDOR, CSRF, SSRF, NoSQL/SQL injection, auth bypass, race
conditions, business-logic errors, broken access control and other OWASP API Security Top 10.

## Arguments

`$1` is the scope. `--ci` (mode) and `--sarif` (extra output) are flags, valid anywhere in
`$ARGUMENTS` — strip them before reading `$1`.

| `$1` | Scope |
|---|---|
| a directory path | that path, recursively |
| a module name | that module and everything it exports |
| `pr#123` | `gh pr diff 123` |
| `main...HEAD` | that git diff |
| *(empty)* | `git diff <default-branch>...HEAD`; if empty, ask — do not audit the whole repo |

## Modes

| Mode | When | Steps | Output |
|---|---|---|---|
| **Audit** (default) | no `--ci` flag | 1–5 | audit report md file |
| **CI** | `--ci` passed | 1–3 and 5, **step 4 excluded** | CI report to caller, no file |

`--sarif` is not a mode: in either mode it **also** merges the findings as SARIF into
`.security-audit/baseline.sarif` (see the SARIF output section).

When the scope is larger than one module, split it by subdirectory (one slice per feature folder,
route group, worker area, …) and run steps 1–2 in one Agent subagent per slice, in parallel;
steps 3 and 5 run once over the merged candidates.

## Workflow

### 1 — Trace input to sink and prove reachability

Enumerate and trace each user-controlled input: request -> sink (database query, outbound HTTP,
filesystem, shell, template, etc.). Use -> arrows, cite file:line.

[references/THREAT_MODEL.md](references/THREAT_MODEL.md) is support, not the trace list: it names
the entry points (E-ids) and standing threats (T-ids) a flow may touch, and the control already
covering them. If the file still holds its template placeholders, derive the same tables from the
code first (routes, middleware, workers, webhooks) and note that in the report.

For each flow, prove reachability: mounted route, auth middleware, validators/schemas, input
sanitization.

Not reachable -> discard.

### 2 — Pre-filter

Drop:

- Unsafe defaults, PII in logs, dependency updates, missing headers, info-only findings.
- Any finding that needs a secret, constant, token, id or uuid, if you cannot say how the attacker
  gets that value. Name the source: the repository, the build output, a network position, or a
  value the attacker can guess.
- Anything in the THREAT_MODEL **Out of scope** table.

### 3 — Assign severity = impact × likelihood

Spawn a harsh-critic subagent per candidate in parallel.
It assumes false positive, re-reads the code, rates impact and likelihood and returns the final severity.

Wait for all the critics to return. Then look for a chain.

A chain is two findings that work together. The first finding gives the attacker a value or a state.
The second finding needs that value or that state. The chain gets a higher severity than each
finding alone. Most findings do not make a chain. Do not invent one.

Send each chain to a new critic. Keep the two findings in the report.

### 4 — Confirm with tests (Audit mode only)

For every Critical and High, write a failing-on-vulnerable test that drives the real entry point
(an HTTP-level request for a route, a job payload for a worker) and **run it**. Use the repo's own
test runner and conventions; if the repo ships a test-authoring skill, use it. Medium and Low need
no test. Name the test file path in the report and leave the file in the tree.

### 5 — Report

One format per mode. Rules shared by both:

- **Critical and High** — full write-up each: severity (with the critic's impact × likelihood
  reasoning), source->sink flow with file:line, a copy-paste payload (curl or dev-tools probe fn)
  to reproduce, and a fix suggestion.
- Never print an empty severity section, methodology narration ("Nine candidates traced…",
  "Scope: …"), or a passing-check paragraph (auth intact, rate limiters intact, …).
- A finding with no attacker relevance (correctness bug, stale comment, ops blocker) is not a Low.
  One-line note outside the severity sections, or drop it.
- Severity glyphs: 🔴 Critical · 🟠 High · 🟡 Medium · ⚪ Low.

#### CI report (`--ci`) — returned to the caller

Fixed skeleton, nothing else:

```markdown
🟡 1 Medium · ⚪ 2 Low                              <- verdict line, found severities only

🟠 **High — <claim>** — `file:line`
<full write-up per the shared rules>

🟡 **Medium — <claim>** — `file:line`. <impact>. Fix: <fix>.   <- max 3 sentences

<details><summary>⚪ 2 low-severity findings</summary>

- **<claim>** — `file:line` — fix: <fix>            <- exactly one line each
</details>
```

- No findings -> return exactly "No findings." and nothing else.
- Post an inline PR comment for every Medium and above; the report entry then shrinks to one line
  ending in "(see inline comment)" — never repeat the detail in both places.
- Critic-killed candidates are working notes: drop them silently. **No** "Killed during
  verification", "Checked and cleared", "recorded so the next audit…" or any equivalent section.
- Budget: the whole report fits in ~15 lines, Critical/High write-ups excluded.

#### Audit report (default) — written to file

Writes `.security-audit/reports/<$1 slugified>-$(date +%Y-%m-%d).md` (the folder is gitignored).
Same skeleton, except Medium and Low may carry the full trace and repro, and Critical/High name
the step-4 test file. End the file with a `## Cleared candidates` appendix — one line each,
`<candidate> — killed by <file:line> <reason>` — so the next local audit does not redo the work.
The appendix lives only in this file; it never goes to a caller or a PR comment.

#### SARIF output (`--sarif`) — merged into `.security-audit/baseline.sarif`

Follow [references/SARIF_OUTPUT.md](references/SARIF_OUTPUT.md): write the fixed shape with the
closed rule ids and `security-audit/v1` fingerprints to `.security-audit/run.sarif`, run
`scripts/validate-sarif.ts` on it until it prints `valid`, then run `scripts/merge-sarif.ts` once.

## Reference

- [Threat model](references/THREAT_MODEL.md) — assets, entry points, standing threats and their
  controls, out-of-scope list (a template until the project fills it in)
- [SARIF output](references/SARIF_OUTPUT.md) — file shape, closed rule ids with CWE mapping,
  fingerprint grammar, merge
