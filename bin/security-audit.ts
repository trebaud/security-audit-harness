#!/usr/bin/env bun
// security-audit — installs the harness into a repository and wraps its scripts.
//
//   security-audit init <repo-path> [--force] [--scope <path>]
//   security-audit validate <file>
//   security-audit merge <run>
//   security-audit report <run> [--count]
//   security-audit rules
//
// `init` copies the skill, the closed rule list, the baseline README, the
// threat-model template and the GitHub Actions workflow into the target repo
// and appends the scratch paths to its .gitignore. It never overwrites an
// existing file unless --force is passed, and it never touches an existing
// baseline.sarif or rules.json (those are the project's memory).
//
// The other commands run the skill scripts against the current directory, which
// must be the audited repository's root.
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync, appendFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HARNESS_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SKILL_SRC = join(HARNESS_ROOT, 'skills', 'security-audit');
const TEMPLATES = join(HARNESS_ROOT, 'templates');

const GITIGNORE_BLOCK = `
# security-audit scratch output: the audit's SARIF for one run (after the merge it
# holds only that run's new results, with exploit details) and local audit reports
.security-audit/run.sarif
.security-audit/reports/
`;

/** Files that init never replaces, even with --force: they hold the project's decisions. */
const PRESERVED = new Set(['.security-audit/baseline.sarif', '.security-audit/rules.json']);

const USAGE = `usage:
  security-audit init <repo-path> [--force] [--scope <path>]
  security-audit validate <file>
  security-audit merge <run>
  security-audit report <run> [--count]
  security-audit rules`;

if (import.meta.main) {
    const [cmd, ...rest] = process.argv.slice(2);
    switch (cmd) {
        case 'init':
            init(rest);
            break;
        case 'validate':
            await run('validate-sarif.ts', rest);
            break;
        case 'merge':
            await run('merge-sarif.ts', rest);
            break;
        case 'report':
            await run('report-sarif.ts', rest);
            break;
        case 'rules':
            await run('validate-sarif.ts', ['--rules']);
            break;
        case undefined:
        case '-h':
        case '--help':
            console.log(USAGE);
            break;
        default:
            console.error(`unknown command "${cmd}"\n${USAGE}`);
            process.exit(2);
    }
}

async function run(script: string, args: string[]): Promise<void> {
    const proc = Bun.spawn(['bun', join(SKILL_SRC, 'scripts', script), ...args], { stdio: ['inherit', 'inherit', 'inherit'] });
    process.exit(await proc.exited);
}

function init(args: string[]): void {
    const opts = parseInitArgs(args);
    const target = resolve(opts.repo);
    if (!existsSync(target) || !statSync(target).isDirectory()) fail(`${target} is not a directory`);

    const plan: [string, string][] = [
        ...walk(SKILL_SRC).map((f): [string, string] => [f, join('.claude/skills/security-audit', relative(SKILL_SRC, f))]),
        [join(TEMPLATES, '.security-audit/rules.json'), '.security-audit/rules.json'],
        [join(TEMPLATES, '.security-audit/README.md'), '.security-audit/README.md'],
        [join(TEMPLATES, 'security-audit.yml'), '.github/workflows/security-audit.yml'],
    ];

    const written: string[] = [];
    const skipped: string[] = [];
    for (const [src, relDest] of plan) {
        const dest = join(target, relDest);
        if (existsSync(dest) && (PRESERVED.has(relDest) || !opts.force)) {
            skipped.push(relDest);
            continue;
        }
        mkdirSync(dirname(dest), { recursive: true });
        let content = readFileSync(src, 'utf8');
        if (relDest.endsWith('security-audit.yml') && opts.scope !== 'src') content = content.replaceAll("default: src", `default: ${opts.scope}`).replaceAll("inputs.scope || 'src'", `inputs.scope || '${opts.scope}'`);
        writeFileSync(dest, content);
        written.push(relDest);
    }

    const gitignore = join(target, '.gitignore');
    const current = existsSync(gitignore) ? readFileSync(gitignore, 'utf8') : '';
    if (!current.includes('.security-audit/run.sarif')) {
        appendFileSync(gitignore, `${current.endsWith('\n') || current === '' ? '' : '\n'}${GITIGNORE_BLOCK}`);
        written.push('.gitignore (appended)');
    } else {
        skipped.push('.gitignore (already ignores the scratch paths)');
    }

    for (const f of written) console.log(`  + ${f}`);
    for (const f of skipped) console.log(`  = ${f} (kept)`);
    console.log(`
Installed into ${target}. Next:
  1. Fill in .claude/skills/security-audit/references/THREAT_MODEL.md (assets, entry points, controls).
  2. Add ANTHROPIC_API_KEY to the repository's Actions secrets.
  3. Run it locally once: in Claude Code, \`/security-audit ${opts.scope} --sarif\`, then commit .security-audit/baseline.sarif.
  4. Push; the workflow runs on schedule or via workflow_dispatch and opens a PR only for findings not in the baseline.`);
}

function parseInitArgs(args: string[]): { repo: string; force: boolean; scope: string } {
    let repo: string | undefined;
    let force = false;
    let scope = 'src';
    for (let i = 0; i < args.length; i++) {
        const a = args[i]!;
        if (a === '--force') force = true;
        else if (a === '--scope') scope = args[++i] ?? fail('--scope needs a path');
        else if (a.startsWith('-')) fail(`unknown flag ${a}\n${USAGE}`);
        else if (repo) fail(`unexpected argument ${a}\n${USAGE}`);
        else repo = a;
    }
    if (!repo) fail(`init needs a repo path\n${USAGE}`);
    if (!/^[A-Za-z0-9_./-]+$/.test(scope)) fail(`--scope must be a plain relative path, got "${scope}"`);
    return { repo, force, scope };
}

function walk(dir: string): string[] {
    return readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
        const p = join(dir, e.name);
        return e.isDirectory() ? walk(p) : [p];
    });
}

function fail(message: string): never {
    console.error(`security-audit: ${message}`);
    process.exit(1);
}

