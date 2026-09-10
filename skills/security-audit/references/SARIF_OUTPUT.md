# SARIF output (`--sarif`)

Write this run's findings as SARIF 2.1.0 to `.security-audit/run.sarif`, then merge them into the
committed baseline `.security-audit/baseline.sarif` (see Merge). Do not read the baseline: the audit
is blind, and earlier findings are matched by fingerprint during the merge.

One run, final findings only, `"results": []` when there are none.

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": { "driver": { "name": "security-audit" } },
    "results": [{
      "ruleId": "<ruleId>",
      "message": { "text": "<claim — one sentence>" },
      "locations": [{ "physicalLocation": { "artifactLocation": { "uri": "src/…" }, "region": { "startLine": 1 } } }],
      "partialFingerprints": { "security-audit/v1": "<ruleId>|<uri>|<symbol>" },
      "properties": { "severity": "Critical | High | Medium | Low", "flow": "<source -> sink, file:line>", "impact": "…", "likelihood": "…", "repro": "<payload>", "fix": "…" }
    }]
  }]
}
```

- No `level`: the merge derives it from `properties.severity`.
- `repro` may be empty below High; everything else is required.
- No `rules` array: the merge builds the rule descriptors and their CWE mapping from the `ruleId`s used.

## Rule ids — closed list

Exactly one per finding, first row that fits. Never invent or respell an id. The list lives in
`.security-audit/rules.json`; print it as a table with

```sh
bun .claude/skills/security-audit/scripts/validate-sarif.ts --rules
```

CWE mapping is added by `merge-sarif.ts`, not by you.

## Fingerprint `<ruleId>|<uri>|<symbol>`

The dedupe key, so the same bug must yield the same string across runs. `<uri>` is the sink file
as in `artifactLocation.uri`. `<symbol>` is the stable unit holding the sink, in order of
preference: exported function or method (`OrderController.refund`), route (`POST /orders/:id/refund`),
job or queue name, model name, enclosing top-level declaration. Never a line number, claim text
or hash.

## Validate, then merge

```sh
bun .claude/skills/security-audit/scripts/validate-sarif.ts .security-audit/run.sarif
bun .claude/skills/security-audit/scripts/merge-sarif.ts .security-audit/run.sarif
```

Run the validator. Fix each error in `.security-audit/run.sarif`. Run the validator again until it prints `valid`.
Then run the merge one time. The merge adds the results to `.security-audit/baseline.sarif` with
`baselineState: "new"` and without `repro`/`flow`, prints the new/known counts and rewrites
`.security-audit/run.sarif` to hold only this run's new results in full. The merge stops on an invalid
file and does not change the baseline. Do not run it twice: the second pass finds nothing new.
