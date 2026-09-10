---
name: security-audit
description: White-box security audit of a scope (path, module, or PR diff) for IDOR, CSRF, SSRF, NoSQL/SQL injection, auth bypass, race conditions, business-logic errors and broken access control. Traces user input to sink, proves reachability, has an adversarial critic rate severity, confirms Critical/High with failing-on-vulnerable tests. Use for security reviews, audits, pentests, PR security checks.
argument-hint: <scope: path | module | pr#NUMBER | git-ref | @manifest> [--sarif [--no-merge]]
allowed-tools: Read, Grep, Glob, Agent, Bash(gh pr diff:*), Bash(git diff:*), Bash(git log:*), Write(security/audit/reports/**), Write(THREAT_MODEL.md), Write(security/audit/run.sarif), Edit(security/audit/run.sarif), Bash(node .agents/skills/security-audit/scripts/*)
---

# Security Audit

White-box audit of **$ARGUMENTS** for IDOR, CSRF, SSRF, NoSQL/SQL injection, auth bypass, race
conditions, business-logic errors, broken access control and other OWASP API Security Top 10.

## Arguments

`$1` is the scope. `--sarif` (extra output) and `--no-merge` are flags, valid
anywhere in `$ARGUMENTS` — strip them before reading `$1`.

| `$1` | Scope |
|---|---|
| a directory path | that path, recursively |
| a module name | that module and everything it exports |
| `pr#123` | `gh pr diff 123` |
| `main...HEAD` | that git diff |
| `@path/to/group.md` | the entry points listed in that manifest, one per line as `METHOD /route — handler file:line` (or a worker/job/webhook name); trace each into whatever code it calls, shared code included, but enumerate no other entry point |
| *(empty)* | `git diff <default-branch>...HEAD`; if empty, ask — do not audit the whole repo |

## Output

The audit runs steps 0–5 and writes a report file. `--sarif` **also** merges the findings as SARIF into
`security/audit/baseline.sarif` (see the SARIF output section). With `--no-merge` it writes and
validates `security/audit/run.sarif` and stops there: the caller (the `scan` skill) combines
several runs and merges once.

When the scope is larger than one module, split it by subdirectory (one slice per feature folder,
route group, worker area, …) and run steps 1–2 in one Agent subagent per slice, in parallel;
steps 3 and 5 run once over the merged candidates.

## Workflow

### 0 — Precondition: a threat model exists

Find the project's threat model: a `THREAT_MODEL.md` anywhere in the repo (`Glob **/THREAT_MODEL.md`,
outside `node_modules` and the skill's own `references/`), by default at the project root. If there is
none, or it still holds the template's `<…>` placeholders, create it before anything else: take the shape of
[references/THREAT_MODEL_TEMPLATE.md](references/THREAT_MODEL_TEMPLATE.md), fill every section from
the code (routes and their auth middleware, login flows, webhooks and their signature checks, workers
and queues, config loading, CI), delete the template note, and write it to `THREAT_MODEL.md` at the
project root. Name controls by file or function. Say in the report that the model
was derived this run and needs owner review. Never write to the template itself.

### 1 — Trace input to sink and prove reachability

Enumerate and trace each user-controlled input: request -> sink (database query, outbound HTTP,
filesystem, shell, template, etc.). Use -> arrows, cite file:line.

The threat model is support, not the trace list: it names the entry points (E-ids)
and standing threats (T-ids) a flow may touch, and the control already covering them.

For each flow, prove reachability: mounted route, auth middleware, validators/schemas, input
sanitization.

Not reachable -> discard.

### 2 — Pre-filter

Drop:

- Anything in the threat model's **Out of scope** table. That table is the project's drop list;
  it is edited there, never here.
- Any finding that needs a secret, constant, token, id or uuid, if you cannot say how the attacker
  gets that value. Name the source: the repository, the build output, a network position, or a
  value the attacker can guess.

### 3 — Assign severity = impact × likelihood

Spawn a harsh-critic subagent per candidate in parallel.
It assumes false positive, re-reads the code, rates impact and likelihood and returns the final severity.

Wait for all the critics to return. Then look for a chain.

A chain is two findings that work together. The first finding gives the attacker a value or a state.
The second finding needs that value or that state. The chain gets a higher severity than each
finding alone. Most findings do not make a chain. Do not invent one.

Send each chain to a new critic. Keep the two findings in the report.

### 4 — Confirm with tests

For every Critical and High, write a failing-on-vulnerable test that drives the real entry point
(an HTTP-level request for a route, a job payload for a worker) and **run it**. Use the repo's own
test runner and conventions; if the repo ships a test-authoring skill, use it. Medium and Low need
no test. Name the test file path in the report and leave the file in the tree.

### 5 — Report

Follow [references/REPORT_FORMAT.md](references/REPORT_FORMAT.md) exactly: a fixed skeleton,
with full traces, written to `security/audit/reports/` and ending with a cleared-candidates
appendix. Critic-killed candidates appear nowhere else.

#### SARIF output (`--sarif`) — merged into `security/audit/baseline.sarif`

Follow [references/SARIF_OUTPUT.md](references/SARIF_OUTPUT.md): write the fixed shape with the
closed rule ids and `security-audit/v1` fingerprints to `security/audit/run.sarif`, then

```sh
node .agents/skills/security-audit/scripts/sarif.mjs validate security/audit/run.sarif
node .agents/skills/security-audit/scripts/sarif.mjs merge security/audit/run.sarif
```

Validate until it prints `valid`; run the merge exactly once. With `--no-merge`, stop after
`valid` and leave the baseline alone.

## Reference

- [Threat model template](references/THREAT_MODEL_TEMPLATE.md) — the shape of
  the project's `THREAT_MODEL.md`: assets, entry points, standing threats and their controls,
  out-of-scope list
- [Report format](references/REPORT_FORMAT.md) — write-up rules, skeleton, report file and
  its cleared-candidates appendix
- [SARIF output](references/SARIF_OUTPUT.md) — file shape, closed rule ids with CWE mapping,
  fingerprint grammar, merge
