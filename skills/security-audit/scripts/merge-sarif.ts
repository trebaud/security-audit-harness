#!/usr/bin/env bun
// Merges this run's security-audit SARIF (.security-audit/run.sarif) into the
// committed baseline (.security-audit/baseline.sarif). A missing baseline means
// every result is new.
//
//   bun merge-sarif.ts <run>
//
// The baseline is committed, so exploit details (`repro`, `flow`) are stripped
// from it. The run file is rewritten to hold only this run's new results, in
// full, for the PR body and the step summary; it is gitignored. Run the merge
// once per audit: a second pass finds nothing new and empties the run file.
//
// The merge stops on an invalid file and does not change the baseline. Rule
// descriptors get a helpUri pointing at the skill folder when GITHUB_REPOSITORY
// is set (i.e. in CI). See sarif.ts `merge` for the matching rules.
import { existsSync, writeFileSync } from 'node:fs';
import { BASELINE_FILE, assertValid, defaultHelpUri, loadRules, merge, readValidSarif, withoutExploitDetails } from './sarif.ts';

if (import.meta.main) {
    const [file] = process.argv.slice(2);
    if (!file) fail('usage: merge-sarif.ts <run>');

    const rules = attempt(() => loadRules());
    const fresh = attempt(() => readValidSarif(file, rules));
    const baseline = existsSync(BASELINE_FILE) ? attempt(() => readValidSarif(BASELINE_FILE, rules)) : null;

    const { doc, added } = merge(fresh, baseline, rules, { helpUri: defaultHelpUri() });
    attempt(() => assertValid(doc, rules, 'merged output'));

    writeFileSync(file, `${JSON.stringify({ ...doc, runs: [{ ...doc.runs[0], results: added }] }, null, 2)}\n`);
    doc.runs[0].results = doc.runs[0].results.map(withoutExploitDetails);
    writeFileSync(BASELINE_FILE, `${JSON.stringify(doc, null, 2)}\n`);
    console.log(`${BASELINE_FILE}: ${added.length} new, ${doc.runs[0].results.length - added.length} known`);
}

function attempt<T>(fn: () => T): T {
    try {
        return fn();
    } catch (e) {
        return fail((e as Error).message);
    }
}

function fail(message: string): never {
    console.error(`merge-sarif: ${message}`);
    process.exit(1);
}
