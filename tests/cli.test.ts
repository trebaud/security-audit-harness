// End-to-end: install into a scratch repo, then validate → merge → report with the real scripts.
import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const HARNESS = resolve(import.meta.dir, '..');
const CLI = join(HARNESS, 'bin/security-audit.ts');
const SCRIPTS = '.claude/skills/security-audit/scripts';
let repo: string;

async function sh(cmd: string[], cwd = repo, env: Record<string, string> = {}) {
    const proc = Bun.spawn(cmd, { cwd, stdout: 'pipe', stderr: 'pipe', env: { ...process.env, ...env } });
    const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited]);
    return { stdout, stderr, code };
}

beforeAll(() => {
    repo = mkdtempSync(join(tmpdir(), 'security-audit-harness-'));
    writeFileSync(join(repo, '.gitignore'), 'node_modules/\n');
});
afterAll(() => rmSync(repo, { recursive: true, force: true }));

describe('init', () => {
    test('installs skill, rules, README, workflow and gitignore block', async () => {
        const r = await sh(['bun', CLI, 'init', repo, '--scope', 'app']);
        expect(r.code).toBe(0);
        for (const f of [
            '.claude/skills/security-audit/SKILL.md',
            '.claude/skills/security-audit/references/SARIF_OUTPUT.md',
            '.claude/skills/security-audit/references/THREAT_MODEL.md',
            `${SCRIPTS}/sarif.ts`, `${SCRIPTS}/validate-sarif.ts`, `${SCRIPTS}/merge-sarif.ts`, `${SCRIPTS}/report-sarif.ts`,
            '.security-audit/rules.json', '.security-audit/README.md', '.github/workflows/security-audit.yml',
        ]) expect(existsSync(join(repo, f))).toBe(true);
        expect(readFileSync(join(repo, '.gitignore'), 'utf8')).toContain('.security-audit/run.sarif');
        const wf = readFileSync(join(repo, '.github/workflows/security-audit.yml'), 'utf8');
        expect(wf).toContain("inputs.scope || 'app'");
        expect(wf).toContain('default: app');
    });

    test('second init keeps existing files and does not duplicate the gitignore block', async () => {
        writeFileSync(join(repo, '.security-audit/rules.json'), JSON.stringify({ custom: { name: 'Custom', cwe: [1], covers: 'x' } }));
        const r = await sh(['bun', CLI, 'init', repo, '--force']);
        expect(r.code).toBe(0);
        expect(r.stdout).toContain('= .security-audit/rules.json (kept)');
        expect(JSON.parse(readFileSync(join(repo, '.security-audit/rules.json'), 'utf8'))).toHaveProperty('custom');
        const gi = readFileSync(join(repo, '.gitignore'), 'utf8');
        expect(gi.match(/run\.sarif/g)).toHaveLength(1);
        // restore the template rules for the pipeline tests below
        cpSync(join(HARNESS, 'templates/.security-audit/rules.json'), join(repo, '.security-audit/rules.json'));
    });

    test('rejects a missing directory and unknown flags', async () => {
        expect((await sh(['bun', CLI, 'init', join(repo, 'nope')])).code).toBe(1);
        expect((await sh(['bun', CLI, 'init', repo, '--bogus'])).code).toBe(1);
        expect((await sh(['bun', CLI, 'frobnicate'])).code).toBe(2);
    });
});

describe('validate → merge → report inside the installed repo', () => {
    test('validator prints the rule table from the installed rules.json', async () => {
        const r = await sh(['bun', `${SCRIPTS}/validate-sarif.ts`, '--rules']);
        expect(r.code).toBe(0);
        expect(r.stdout).toContain('| `idor` |');
    });

    test('validator rejects a bad run file and names the error', async () => {
        writeFileSync(join(repo, '.security-audit/run.sarif'), '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"nope"}]}]}');
        const r = await sh(['bun', `${SCRIPTS}/validate-sarif.ts`, '.security-audit/run.sarif']);
        expect(r.code).toBe(1);
        expect(r.stderr).toContain('"nope" is not in the closed rule list');
    });

    test('first merge creates the baseline without exploit details; run file keeps them', async () => {
        cpSync(join(HARNESS, 'tests/fixtures/run.sarif'), join(repo, '.security-audit/run.sarif'));
        const v = await sh(['bun', `${SCRIPTS}/validate-sarif.ts`, '.security-audit/run.sarif']);
        expect(v.stdout.trim()).toBe('.security-audit/run.sarif: valid');

        const m = await sh(['bun', `${SCRIPTS}/merge-sarif.ts`, '.security-audit/run.sarif'], repo, { GITHUB_REPOSITORY: 'acme/api', GITHUB_REF_NAME: 'main' });
        expect(m.code).toBe(0);
        expect(m.stdout.trim()).toBe('.security-audit/baseline.sarif: 2 new, 0 known');

        const baseline = JSON.parse(readFileSync(join(repo, '.security-audit/baseline.sarif'), 'utf8'));
        expect(baseline.runs[0].results).toHaveLength(2);
        expect(baseline.runs[0].results[0].properties).not.toHaveProperty('repro');
        expect(baseline.runs[0].tool.driver.rules[0].helpUri).toBe('https://github.com/acme/api/tree/main/.claude/skills/security-audit');

        const run = JSON.parse(readFileSync(join(repo, '.security-audit/run.sarif'), 'utf8'));
        expect(run.runs[0].results).toHaveLength(2);
        expect(run.runs[0].results[0].properties.repro).toContain('curl');
    });

    test('report prints count and markdown from the merged run file', async () => {
        const c = await sh(['bun', `${SCRIPTS}/report-sarif.ts`, '.security-audit/run.sarif', '--count']);
        expect(c.stdout.trim()).toBe('2');
        const md = await sh(['bun', `${SCRIPTS}/report-sarif.ts`, '.security-audit/run.sarif']);
        expect(md.stdout).toStartWith('## 2 new security finding(s)');
    });

    test('second merge of the same run: 0 new, run file emptied, report says no new findings', async () => {
        cpSync(join(HARNESS, 'tests/fixtures/run.sarif'), join(repo, '.security-audit/run.sarif'));
        const m = await sh(['bun', `${SCRIPTS}/merge-sarif.ts`, '.security-audit/run.sarif']);
        expect(m.stdout.trim()).toBe('.security-audit/baseline.sarif: 0 new, 2 known');
        const c = await sh(['bun', `${SCRIPTS}/report-sarif.ts`, '.security-audit/run.sarif', '--count']);
        expect(c.stdout.trim()).toBe('0');
        const md = await sh(['bun', `${SCRIPTS}/report-sarif.ts`, '.security-audit/run.sarif']);
        expect(md.stdout.trim()).toBe('No new findings.');
    });

    test('merge refuses an invalid run and leaves the baseline untouched', async () => {
        const before = readFileSync(join(repo, '.security-audit/baseline.sarif'), 'utf8');
        writeFileSync(join(repo, '.security-audit/run.sarif'), '{ not json');
        const m = await sh(['bun', `${SCRIPTS}/merge-sarif.ts`, '.security-audit/run.sarif']);
        expect(m.code).toBe(1);
        expect(m.stderr).toContain('merge-sarif: .security-audit/run.sarif: not valid JSON');
        expect(readFileSync(join(repo, '.security-audit/baseline.sarif'), 'utf8')).toBe(before);
    });

    test('wrapper commands work from the repo root', async () => {
        const r = await sh(['bun', CLI, 'rules']);
        expect(r.code).toBe(0);
        expect(r.stdout).toContain('| `other` |');
    });
});
