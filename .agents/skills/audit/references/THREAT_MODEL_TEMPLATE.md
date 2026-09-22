# Threat model — <project name>

> **Template.** The skill copies this shape to `THREAT_MODEL.md` at the project root when the audited
> repo has none, filling every `<…>` and example row from the code, and deletes this note. Keep the
> table shapes and the `E`/`T` id schemes: the skill cites them in findings and critics use the
> **Controls** column to kill false positives. Owners edit the derived file, never this template.

## System shape

<One paragraph: runtime, framework, datastores, queues, deployment (edge/proxy, orchestration),
how one build turns into different roles or services, and who the consumers are (end users,
partners with API keys, staff, machine clients).>

<One sentence on what the system custodies or moves: money, credentials, bearer value, PII,
regulated data. Then the dominant risk classes, e.g. **financial integrity, secret exfiltration,
broken access control, webhook forgery**.>

## Assets

| Tier | Assets |
|---|---|
| **Critical** | <signing and encryption keys held in process · auth credentials: password hashes, MFA secrets, reset/magic-link tokens, sessions · API keys · user PII · regulated data (KYC, health, …) · payment instruments · ledger or balance state · external provider credentials> |
| **High** | <derived identifiers that must not leak · fraud/compliance state · availability of the API and workers> |
| **Medium** | <analytics> |

## Trust boundaries

| id | Entry point | Boundary crossed |
|---|---|---|
| E1 | Unauthenticated public API — <list the public endpoints> | internet → app logic |
| E2 | Authenticated API — session cookie, bearer token or API key | credential → account- or key-scoped operations |
| E3 | Auth — password login, OAuth, magic link, passkey, MFA, password reset | unauth → authenticated session |
| E4 | Provider webhooks and callbacks — <providers> | untrusted callback → business state |
| E5 | Background workers / queue consumers | queue payload → execution |
| E6 | Delegated authorization — OAuth authorize/token exchange, device-code or CLI login | untrusted client → delegated tokens |
| E7 | Admin / internal API — staff session with permissions, or a shared internal token | privileged caller → system management |
| E8 | CI/CD, submodules, lockfile, base image | commit / supply chain → prod runtime |

<Add, remove or renumber rows to match the code. One row per distinct auth mechanism or trust level.>

## Standing threats

`I/L` = impact / likelihood prior. **Controls** already exist — this threat with its control intact
is a false positive.

| id | Threat | Entry | I/L | Controls already in place |
|---|---|---|---|---|
| T1 | Forged provider webhook flips payment, compliance or entitlement state | E4 | crit/likely | <most webhooks verify an HMAC or JWT — check *this* one, and check the comparison is constant-time> |
| T2 | Goods, credit or access granted without real payment or settlement | E2 E4 E5 | crit/likely | <locks held over commit, idempotency keys, settlement checks> |
| T3 | Auth/session forgery or field decryption via hardcoded fallback secrets when an env var is unset | E3 E7 | crit/possible | <startup config validation rejects null and placeholder values> |
| T4 | Account takeover via signature flaws, session fixation, or non-constant-time comparison | E3 E1 | crit/possible | <rate limiting and captcha on auth; constant-time credential comparisons> |
| T5 | Privilege abuse by a phished admin or internal-token holder | E7 | crit/possible | <permission-gated routes, caps on bulk operations, audit log> |
| T6 | IDOR / broken access control across users or tenants | E2 E6 | high/likely | <ownership filters in the query, 404-not-403, per-key scoping> |

<Keep the rows that apply, delete the rest, add project-specific ones. Name the control by file or
function when you can — a critic with a concrete control kills more false positives.>

## Out of scope — drop, no critic

The audit's pre-filter drops anything in this table before a critic sees it. This is the project's
drop list: delete a row to bring that class back into the audit, add a row to exclude one.

| Not a finding here | Why |
|---|---|
| Unsafe defaults that the deployed config overrides | <config is validated at startup; a default that never ships is not reachable> |
| PII or tokens in logs | <covered by the logging-redaction review, not by this audit> |
| Missing security headers (CSP, HSTS, …) | <set at the edge/proxy> |
| Informational or best-practice notes with no attacker path | <not a finding; note in one line or drop> |
| Reflected/stored XSS in rendered UI | <this is a JSON API; the UI is a separate repo> |
| L3/L4 DDoS | <absorbed at the edge> |
| TLS spoofing/downgrade | <TLS terminates at the edge/proxy and the app deliberately trusts it> |
| Local-user / physical attacks on the host | <managed hosting, no untrusted local users> |
| Dependency CVEs | <handled by a dependency-audit process; in scope only where repo code misuses the dependency> |
