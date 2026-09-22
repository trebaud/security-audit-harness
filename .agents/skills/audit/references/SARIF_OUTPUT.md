# SARIF output (`--sarif`)

Write this run's findings as SARIF 2.1.0 to `security/audit/run.sarif`, then merge them into the
committed baseline `security/audit/baseline.sarif` (see Merge). Do not read the baseline: the audit
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

Exactly one per finding, first row that fits. Never invent or respell an id. Read the list from
`security/audit/rules.json`: an object keyed by `ruleId`, in priority order, each row carrying the
`covers` text the id is chosen on.

CWE mapping is added by `sarif.mjs merge`, not by you.

## Fingerprint `<ruleId>|<uri>|<symbol>`

The dedupe key, so the same bug must yield the same string across runs. `<uri>` is the sink file
as in `artifactLocation.uri`. `<symbol>` is the stable unit holding the sink, in order of
preference: exported function or method (`Controller.method`), route (`POST /resource/:id`),
job or queue name, model name, enclosing top-level declaration. Never a line number, claim text
or hash.

Write every path repo-relative (`src/a.ts`), in both the fingerprint and
`artifactLocation.uri`. The tool normalizes paths on the way in — `./src/a.ts`, `src/./a.ts`,
a percent-encoded uri and the runner's absolute checkout path are one file, and
a baseline written with another spelling still matches instead of reporting the bug as new.

`validate` enforces the grammar: three `|` segments, the first equal to the result's `ruleId`, the
second naming the same file as `locations[0]` (compared after normalization), the third a non-empty
`<symbol>` that is not a line number. A fingerprint that parses but names the wrong rule or file
splits one bug into two baseline entries, permanently, which is why it is checked and not trusted.

## Validate, then merge

```sh
node <skill-dir>/scripts/sarif.mjs validate security/audit/run.sarif
node <skill-dir>/scripts/sarif.mjs merge security/audit/run.sarif
```

Run the validator. Fix each error in `security/audit/run.sarif`. Run the validator again until it prints `valid`.
Then run the merge one time. The merge adds the results to `security/audit/baseline.sarif` with
`baselineState: "new"` and without `repro`/`flow`, prints the new/known counts and rewrites
`security/audit/run.sarif` to hold only this run's new results in full — read it back when the caller
wants a write-up of what this run added. The merge stops on an invalid file and does not change the
baseline. Do not run it twice: the second pass finds nothing new.

With `--no-merge`, stop once the validator prints `valid`: do not run the merge. The caller
folds several run files with `sarif.mjs combine <out> <in...>` and merges the result once;
merging each partial run would mark every finding outside its scope `absent`.
