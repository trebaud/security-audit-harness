#!/usr/bin/env bun
// Validates a security-audit SARIF file: valid JSON, the SARIF 2.1.0 required
// fields and enums, ruleId in the closed list (.security-audit/rules.json), and
// a unique `security-audit/v1` fingerprint per result.
//
//   bun validate-sarif.ts <file>
//   bun validate-sarif.ts --rules   # prints the closed rule table as markdown
//
// Run from the audited repository's root.
import { loadRules, readValidSarif, rulesTable } from './sarif.ts';

if (import.meta.main) {
    const file = process.argv[2];
    if (!file) {
        console.error('usage: validate-sarif.ts <file> | --rules');
        process.exit(2);
    }
    try {
        const rules = loadRules();
        if (file === '--rules') {
            console.log(rulesTable(rules));
            process.exit(0);
        }
        readValidSarif(file, rules);
    } catch (e) {
        console.error((e as Error).message);
        process.exit(1);
    }
    console.log(`${file}: valid`);
}
