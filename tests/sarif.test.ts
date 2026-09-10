import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import {
    FINGERPRINT_KEY, assertValid, defaultHelpUri, loadRules, merge, parseRules, renderReport, rulesTable, validate,
    withoutExploitDetails, type SarifDoc,
} from '../skills/security-audit/scripts/sarif.ts';

const rules = loadRules('templates/.security-audit/rules.json');
const load = (name: string): SarifDoc => JSON.parse(readFileSync(`tests/fixtures/${name}`, 'utf8'));
const clone = <T>(v: T): T => structuredClone(v);

describe('rules', () => {
    test('template rule list parses and ends with "other"', () => {
        const ids = Object.keys(rules);
        expect(ids[0]).toBe('idor');
        expect(ids.at(-1)).toBe('other');
        expect(rules.injection!.cwe).toContain(943);
    });

    test('rejects bad shapes with the file name in the message', () => {
        expect(() => parseRules('nope', 'x.json')).toThrow('x.json: not valid JSON');
        expect(() => parseRules('{}', 'x.json')).toThrow('non-empty object');
        expect(() => parseRules('{"Bad Id": {"name":"n","cwe":[1],"covers":"c"}}', 'x.json')).toThrow('kebab-case');
        expect(() => parseRules('{"ok": {"name":"n","cwe":[0],"covers":"c"}}', 'x.json')).toThrow('positive integers');
    });

    test('loadRules names a missing file', () => {
        expect(() => loadRules('does/not/exist.json')).toThrow('does not exist');
    });

    test('rulesTable is a markdown table in priority order', () => {
        const lines = rulesTable(rules).split('\n');
        expect(lines[0]).toBe('| `ruleId` | Covers |');
        expect(lines[2]).toStartWith('| `idor` |');
    });
});

describe('validate', () => {
    test('accepts the run fixture', () => {
        expect(validate(load('run.sarif'), rules)).toEqual([]);
    });

    test('accepts the baseline fixture with suppressions and states', () => {
        expect(validate(load('baseline.sarif'), rules)).toEqual([]);
    });

    test('reports every problem with a path', () => {
        const doc = load('run.sarif');
        const r = doc.runs[0].results[0]!;
        r.ruleId = 'made-up';
        r.partialFingerprints[FINGERPRINT_KEY] = ' padded ';
        r.properties.severity = 'Urgent' as never;
        r.locations[0]!.physicalLocation.region = { startLine: 0 };
        const errors = validate(doc, rules);
        expect(errors).toContain('runs[0].results[0].ruleId: "made-up" is not in the closed rule list');
        expect(errors).toContain(`runs[0].results[0].partialFingerprints["${FINGERPRINT_KEY}"]: has leading or trailing whitespace`);
        expect(errors).toContain('runs[0].results[0].properties.severity: must be Critical, High, Medium, Low');
        expect(errors).toContain('runs[0].results[0].locations[0].physicalLocation.region.startLine: must be an integer >= 1');
    });

    test('rejects duplicate fingerprints', () => {
        const doc = load('run.sarif');
        doc.runs[0].results[1]!.partialFingerprints[FINGERPRINT_KEY] = doc.runs[0].results[0]!.partialFingerprints[FINGERPRINT_KEY]!;
        expect(validate(doc, rules)).toEqual([`runs[0].results[1].partialFingerprints["${FINGERPRINT_KEY}"]: duplicate of results[0]`]);
    });

    test('rejects non-SARIF roots early', () => {
        expect(validate(null, rules)).toEqual(['root: not a JSON object']);
        expect(validate({ version: '2.1.0', runs: [] }, rules)).toEqual(['runs: must be an array with exactly one run']);
    });

    test('assertValid lists every error under the label', () => {
        expect(() => assertValid({ version: '1.0' }, rules, 'x')).toThrow(/^x: 2 error\(s\)\n {2}- version/);
    });
});

describe('merge', () => {
    const fresh = load('run.sarif');
    const baseline = load('baseline.sarif');
    const today = '2026-09-10';

    test('with no baseline every result is new and levels follow severity', () => {
        const { doc, added } = merge(clone(fresh), null, rules, { today });
        expect(added).toHaveLength(2);
        expect(doc.runs[0].results.map((r) => [r.level, r.baselineState, r.properties.firstSeen]))
            .toEqual([['error', 'new', today], ['warning', 'new', today]]);
        expect(validate(doc, rules)).toEqual([]);
    });

    test('known results keep baseline properties and suppressions, refresh message/location/lastSeen', () => {
        const { doc, added } = merge(clone(fresh), clone(baseline), rules, { today });
        expect(added.map((r) => r.ruleId)).toEqual(['ssrf']);
        const idor = doc.runs[0].results.find((r) => r.ruleId === 'idor')!;
        expect(idor.baselineState).toBe('unchanged');
        expect(idor.properties.severity).toBe('Critical'); // reviewer edit wins
        expect(idor.properties.impact).toBe('reviewer-adjusted');
        expect(idor.properties.firstSeen).toBe('2026-01-01');
        expect(idor.properties.lastSeen).toBe(today);
        expect(idor.message.text).toStartWith('GET /orders/:id returns');
        expect(idor.locations[0]!.physicalLocation.region!.startLine).toBe(42);
        expect(idor.suppressions).toHaveLength(1);
        expect(idor.level).toBe('error');
        // fresh properties fill only missing keys
        expect(idor.properties.flow).toBeDefined();
    });

    test('baseline results not reported this run stay as absent', () => {
        const { doc } = merge(clone(fresh), clone(baseline), rules, { today });
        const csrf = doc.runs[0].results.find((r) => r.ruleId === 'csrf')!;
        expect(csrf.baselineState).toBe('absent');
        expect(csrf.properties.lastSeen).toBe('2026-01-01');
    });

    test('results are sorted by severity then fingerprint and rules are rebuilt with CWE tags', () => {
        const { doc } = merge(clone(fresh), clone(baseline), rules, { today, helpUri: 'https://example.test/skill' });
        expect(doc.runs[0].results.map((r) => r.properties.severity)).toEqual(['Critical', 'Medium', 'Medium']);
        expect(doc.runs[0].results.map((r) => r.ruleId)).toEqual(['idor', 'csrf', 'ssrf']);
        const ruleDescs = doc.runs[0].tool.driver.rules!;
        expect(ruleDescs.map((r) => r.id)).toEqual(['csrf', 'idor', 'ssrf']);
        expect(ruleDescs[1]!.properties.tags).toEqual(['security', 'external/cwe/cwe-639']);
        expect(ruleDescs[1]!.helpUri).toBe('https://example.test/skill');
    });

    test('omits helpUri when none is given', () => {
        const { doc } = merge(clone(fresh), null, rules, { today });
        expect('helpUri' in doc.runs[0].tool.driver.rules![0]!).toBe(false);
    });

    test('a second merge finds nothing new', () => {
        const first = merge(clone(fresh), clone(baseline), rules, { today });
        const second = merge(clone(fresh), first.doc, rules, { today });
        expect(second.added).toEqual([]);
    });

    test('withoutExploitDetails strips repro and flow only', () => {
        const stripped = withoutExploitDetails(clone(fresh).runs[0].results[0]!);
        expect(stripped.properties).not.toHaveProperty('repro');
        expect(stripped.properties).not.toHaveProperty('flow');
        expect(stripped.properties.fix).toBeDefined();
    });
});

describe('report', () => {
    test('empty run', () => {
        expect(renderReport([])).toBe('No new findings.\n');
    });

    test('one bullet per result with exploit details and a dash for blanks', () => {
        const out = renderReport(load('run.sarif').runs[0].results);
        expect(out).toStartWith('## 2 new security finding(s)\n');
        expect(out).toContain('- **High** — GET /orders/:id returns any order by id without an owner check. — `src/routes/orders.ts:42`');
        expect(out).toContain('  repro: curl -H');
        expect(out).toContain('  repro: —'); // ssrf has an empty repro
        expect(out).toContain('.security-audit/baseline.sarif');
    });
});

describe('defaultHelpUri', () => {
    test('undefined outside CI, skill folder URL inside', () => {
        expect(defaultHelpUri({})).toBeUndefined();
        expect(defaultHelpUri({ GITHUB_REPOSITORY: 'acme/api', GITHUB_REF_NAME: 'main' }))
            .toBe('https://github.com/acme/api/tree/main/.claude/skills/security-audit');
    });
});
