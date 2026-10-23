---
name: security-audit
disable-model-invocation: true
description: White-box security audit of this repo's own code — a path, module, PR, or branch diff — for backends, frontends and full-stack apps (IDOR, access control, auth bypass, CSRF, SSRF, injection, race conditions, business logic, XSS, open redirects, postMessage trust, token and secret exposure). Builds a THREAT_MODEL.md with the user when the repo has none, then traces input to sink, proves reachability, has a critic challenge each candidate, and confirms Critical/High with a failing test. Use for a security review, audit, or vuln hunt of application code, a PR security check, or to create a threat model. Trigger on phrasings like "security audit this repo", "security review this PR", "audit src/payments for vulns", "is this endpoint exploitable", "look for IDOR / XSS / injection here", "threat model this repo". Not for CI workflows, third-party skills or plugins, dependency CVEs, or agent config.
argument-hint: "<scope: path | module | E-id | pr#NUMBER | git-ref | @manifest>"
allowed-tools: Read, Grep, Glob, Agent, Write, Edit, Bash, AskUserQuestion
---

# Security Audit

Report only findings an attacker can reach, each backed by a source → sink trace. Precision beats
coverage: a report full of unreachable "possible" issues trains readers to ignore it.

## Scope

Arguments: `$ARGUMENTS`.

| Scope | Audits |
|---|---|
| path or module | that code, recursively |
| `e2`, `e2-<name>` | threat-model entry point E2: its sources, traced into whatever they call |
| `pr#123` | `gh pr diff 123` |
| `main...HEAD` | that git diff |
| `@path/to/group.md` | only the entry points listed in that manifest (one per line), traced into whatever they call |
| *(empty)* | `git diff <default-branch>...HEAD`; if empty, ask — never audit the whole repo unprompted |

For a diff, the diff picks which flows to audit; trace them through the unchanged code they touch.
Run from the repo root.

## Progress

A harness running this skill sets `$AUDIT_PROGRESS` to a file it watches; check once with
`echo "$AUDIT_PROGRESS"` and skip this section if it prints nothing. Otherwise record each step by
overwriting that file with one Bash call:

```sh
printf '{"phase":"%s","done":%d,"total":%d}\n' critic 2 4 >"$AUDIT_PROGRESS"
```

Phases, in order: `orient` (threat model, sizing the scope), `trace`, `critic`, `test`, `report`.
Write at the start of each phase with done 0 and total its slices, candidates or tests, then again
each time one of them finishes.

## Preflight: threat model

The threat model drives the audit: its entry points and sources say where to start tracing, its
sinks say where to stop, its **Controls** column is what critics use to kill false positives, and
its **Out of scope** table is the drop list. Find `**/THREAT_MODEL.md` (outside `node_modules`). If
it exists and has no template `<…>` placeholders, use it and go to the audit.

Otherwise build one with the user — the code shows what exists, only the owner knows what matters,
what is deployed, and what is handled elsewhere:

1. **Draft from the code.** Follow
   [references/THREAT_MODEL_TEMPLATE.md](references/THREAT_MODEL_TEMPLATE.md). Classify each
   package (backend, frontend, full-stack, library), fill every section with controls named by
   file or function, and keep only the rows that fit. Mark anything inferred rather than seen as
   `(?)`.
2. **Refine with the user.** Show a short summary of the draft, then ask with AskUserQuestion, a
   few questions per round, about what the code can't answer:
   - what the system custodies and the worst outcome
   - who the attackers and consumers are
   - entry points and deployment details the code doesn't show
   - controls that live outside the repo
   - each `(?)` item, and what to put **Out of scope**
   Fold answers in and repeat until the user confirms or has nothing to add. Don't ask what the
   code already answers.
3. **Write** `THREAT_MODEL.md` at the repo root, delete the template note, and tell the user to
   commit it — the next audit and every reviewer reuse it.

If nobody can answer (headless run), write the draft, keep the `(?)` marks, and flag it in the
report as needing owner review.

If the user only asked for a threat model, stop here.

## Audit

### Trace and prove reachability

From every threat-model source in scope, trace to a threat-model sink, citing file:line at each
hop; add any source or sink you discover to the model. Prove the flow is reachable from a live
entry point past every control on the way. Not reachable → discard.

Look for the classes that fit each package's profile — server: IDOR, broken access control, auth
bypass, CSRF, SSRF, injection, race conditions, business logic, webhook forgery, mass assignment,
secret exposure; browser: DOM/stored XSS, open redirect, postMessage trust, token storage, secrets
in the bundle, client-only authorization; plus the threat model's own T-rows and anything else in
the OWASP Top 10 and OWASP API Security Top 10 that fits.

For scopes larger than one module, split by subdirectory or package and trace in parallel
subagents, one per slice, each given the threat-model rows for its slice.

### Pre-filter

Drop anything in the **Out of scope** table, and anything needing a secret, token or id whose
source you can't name.

### Critic

Spawn a fresh harsh-critic subagent per candidate, in parallel — the finder is anchored on the
finding being real. The critic assumes false positive, re-reads the code, checks the threat model's
controls and every layer for the killing control, and returns impact × likelihood severity or
"cleared" with file:line.

Then look for chains where one finding supplies what another needs; don't invent one. Send each chain to a new critic and keep both findings.

### Confirm with tests

For every Critical and High, write a failing-on-vulnerable test that drives the real entry point,
not an inner function that skips its controls, using the repo's runner and conventions, and run
it. Leave it in the tree as the future regression test.

### Report

Follow [references/REPORT_FORMAT.md](references/REPORT_FORMAT.md) and write the report to
`.security-audit/` at the repo root.

Print the verdict line, Critical/High headlines, and the report path in chat.
