#!/usr/bin/env bun
// Prints the findings-PR markdown for a run file that has already been merged
// (so it holds only this run's new results, with `flow` and `repro`).
//
//   bun report-sarif.ts <run>            # markdown to stdout
//   bun report-sarif.ts <run> --count    # number of results only
//
// The workflow uses `--count` to decide whether to open a PR and the markdown
// for the PR body and the step summary. Exploit details live only there; the
// committed baseline omits them.
import { loadRules, readValidSarif, renderReport } from './sarif.ts';

if (import.meta.main) {
    const [file, flag] = process.argv.slice(2);
    if (!file) {
        console.error('usage: report-sarif.ts <run> [--count]');
        process.exit(2);
    }
    try {
        const doc = readValidSarif(file, loadRules());
        const results = doc.runs[0].results;
        if (flag === '--count') console.log(String(results.length));
        else process.stdout.write(renderReport(results));
    } catch (e) {
        console.error(`report-sarif: ${(e as Error).message}`);
        process.exit(1);
    }
}
