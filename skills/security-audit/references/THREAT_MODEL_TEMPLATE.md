# Threat model — <project name>

> **Template.** Fill every `<…>` from the code and the owner's answers, keep the row groups that fit
> each package's profile, renumber, and delete this note. Keep the table shapes and `E`/`T` ids —
> findings cite them and critics use **Controls** to kill false positives.

## System shape

<Profile per package: backend / frontend / full-stack / library. Runtime, framework, datastores,
queues, deployment and edge, how a frontend authenticates to its backend, who the consumers and
attackers are. What the system custodies (money, credentials, bearer value, PII) and the dominant
risk classes.>

## Assets

| Tier | Assets |
|---|---|
| **Critical** | <keys, credentials, sessions/tokens, PII, ledger/balance state, payment and wallet-signing flows> |
| **High** | <identifiers that must not leak, fraud/compliance state, availability, integrity of displayed amounts/addresses> |
| **Medium** | <analytics, feature flags> |

## Trust boundaries

| id | Entry point | Boundary crossed |
|---|---|---|
| | **Backend** | |
| E1 | Public API — <endpoints> | internet → app logic |
| E2 | Authenticated API — <cookie / bearer / API key> | credential → scoped operations |
| E3 | Auth flows — <login, OAuth, magic link, MFA, reset> | unauth → session |
| E4 | Webhooks — <providers> | untrusted callback → business state |
| E5 | Workers / queues | payload → execution |
| E6 | Admin / internal API | privileged caller → system management |
| | **Frontend** | |
| E7 | URL, fragment, deep links — <routes> | crafted link → victim's browser |
| E8 | Other users' content from the API — <fields> | another user's data → victim's DOM |
| E9 | `postMessage`, iframes, OAuth/payment return pages | other origin → app state |
| E10 | Third-party scripts — <vendors> | vendor code → page with session |
| | **Both** | |
| E11 | CI/CD, lockfile, build-time env | supply chain → runtime or bundle |

## Sources and sinks

Where the audit starts and stops tracing. Name each by file or function.

| Entry | Sources (attacker-controlled input) |
|---|---|
| <E-id> | <request params/body/headers, webhook payload, job payload, URL params, postMessage data, stored user content, …> |

| Sink | Where |
|---|---|
| <database queries / raw queries> | <file or module> |
| <outbound HTTP> | <…> |
| <filesystem, shell, templates, deserialization> | <…> |
| <balance, ledger, order-state writes> | <…> |
| <raw-HTML rendering, redirects/navigation, postMessage sends, token storage> | <…> |

## Standing threats

`I/L` = impact / likelihood. A threat with its control intact is a false positive.

| id | Threat | Entry | I/L | Controls in place |
|---|---|---|---|---|
| | **Backend** | | | |
| T1 | Forged webhook flips payment/entitlement state | E4 | crit/likely | <signature check, constant-time> |
| T2 | Goods or credit without real settlement | E2 E4 E5 | crit/likely | <locks, idempotency keys> |
| T3 | Hardcoded fallback secrets when env unset | E3 E6 | crit/possible | <startup config validation> |
| T4 | Account takeover | E1 E3 | crit/possible | <rate limits, constant-time compares> |
| T5 | Admin privilege abuse | E6 | crit/possible | <permission gates, audit log> |
| T6 | IDOR across users/tenants | E2 | high/likely | <ownership filters in queries> |
| | **Frontend** | | | |
| T7 | Session theft via XSS | E7 E8 | crit/possible | <framework escaping, sanitizer, CSP, HttpOnly cookie> |
| T8 | OAuth code / payment return hijack via open redirect | E7 E9 | high/possible | <redirect allowlist> |
| T9 | Forged cross-origin message | E9 | high/possible | <`event.origin` allowlist> |
| T10 | Secret shipped in bundle | E11 | high/possible | <server-only secrets> |
| T11 | Displayed amount/address differs from what is signed | E8 E10 | crit/possible | <server-computed amounts> |

## Out of scope — drop, no critic

The project's drop list. Delete a row to bring a class back.

| Not a finding here | Why |
|---|---|
| Notes with no attacker path | <not a finding> |
| Dependency CVEs | <separate process, unless repo code misuses the dependency> |
| L3/L4 DDoS, TLS downgrade | <handled at the edge> |
| Local/physical attacks | <no victim> |
| Missing security headers | <set at the edge — delete if the app sets them> |
| PII/tokens in logs | <separate review> |
| *Backend:* XSS in rendered UI | <JSON API, UI in another repo> |
| *Frontend:* server-side authz, injection, business rules | <enforced by backend repo <name>> |
| *Frontend:* self-XSS, self-tampering | <no victim> |
