// Shared library for the security-audit SARIF scripts: the closed rule list,
// validation, the baseline merge and the new-findings report. Zero
// dependencies beyond Bun/Node built-ins so it runs before any install step.
//
// Every path is relative to the audited repository's root (`.security-audit/`),
// so run the scripts from there.
import { readFileSync } from 'node:fs';

export const DIR = '.security-audit';
export const RULES_FILE = `${DIR}/rules.json`;
export const BASELINE_FILE = `${DIR}/baseline.sarif`;
export const RUN_FILE = `${DIR}/run.sarif`;

// The fingerprint key is namespaced by this harness, not by the audited
// project, so baselines stay comparable across repositories.
export const FINGERPRINT_KEY = 'security-audit/v1';
export const SCHEMA_URL = 'https://json.schemastore.org/sarif-2.1.0.json';
export const TOOL_NAME = 'security-audit';

export const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'] as const;
export type Severity = (typeof SEVERITIES)[number];

const LEVELS = new Set(['error', 'warning', 'note', 'none']);
const BASELINE_STATES = new Set(['new', 'unchanged', 'updated', 'absent']);
const SUPPRESSION_KINDS = new Set(['inSource', 'external']);

/** Exploit details: kept in the run file and the PR body, stripped from the committed baseline. */
export const EXPLOIT_DETAILS = ['repro', 'flow'] as const;

export interface Rule {
    name: string;
    cwe: number[];
    covers: string;
}
export type Rules = Record<string, Rule>;

export interface SarifLocation {
    physicalLocation: {
        artifactLocation: { uri: string };
        region?: { startLine?: number };
    };
}

export interface SarifResult {
    ruleId: string;
    level?: string;
    message: { text: string };
    locations: SarifLocation[];
    partialFingerprints: Record<string, string>;
    properties: Record<string, unknown> & { severity: Severity };
    baselineState?: string;
    suppressions?: { kind: string; justification?: string }[];
}

export interface SarifRuleDescriptor {
    id: string;
    name: string;
    shortDescription: { text: string };
    helpUri?: string;
    properties: { tags: string[] };
}

export interface SarifDoc {
    $schema: string;
    version: '2.1.0';
    runs: [{
        tool: { driver: { name: string; rules?: SarifRuleDescriptor[] } };
        results: SarifResult[];
    }];
}

// ---------------------------------------------------------------------------
// Rules

/**
 * Parses and checks the closed rule list: { "<ruleId>": { name, cwe: [n], covers } }
 * in priority order (first row that fits wins). ruleId doubles as the fingerprint
 * prefix, so ids are never renamed; the CWE list is the cross-tool identifier.
 * Throws with a message that names the file on any problem.
 */
export function parseRules(json: string, file = RULES_FILE): Rules {
    let rules: unknown;
    try {
        rules = JSON.parse(json);
    } catch (e) {
        throw new Error(`${file}: not valid JSON (${(e as Error).message})`);
    }
    if (!isObject(rules) || Object.keys(rules).length === 0) throw new Error(`${file}: must be a non-empty object keyed by ruleId`);
    for (const [id, rule] of Object.entries(rules)) {
        const ok = /^[a-z][a-z0-9-]*$/.test(id) && isObject(rule) && nonEmptyString(rule.name) && nonEmptyString(rule.covers)
            && Array.isArray(rule.cwe) && rule.cwe.every((n) => Number.isInteger(n) && n > 0);
        if (!ok) throw new Error(`${file}: rule "${id}" must be { name, cwe: [positive integers], covers } with a kebab-case id`);
    }
    return rules as Rules;
}

/** Reads the closed rule list from disk; throws when missing or malformed. */
export function loadRules(file = RULES_FILE): Rules {
    let json: string;
    try {
        json = readFileSync(file, 'utf8');
    } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        throw new Error(`${file}: ${code === 'ENOENT' ? 'does not exist (run from the repo root, or run `security-audit init` first)' : (e as Error).message}`);
    }
    return parseRules(json, file);
}

/** The rule list as a markdown table, in priority order. */
export function rulesTable(rules: Rules): string {
    const rows = Object.entries(rules).map(([id, { covers }]) => `| \`${id}\` | ${covers} |`);
    return ['| `ruleId` | Covers |', '|---|---|', ...rows].join('\n');
}

// ---------------------------------------------------------------------------
// Validation

/** Returns a list of error strings; empty means valid. */
export function validate(doc: unknown, rules: Rules): string[] {
    const errors: string[] = [];
    const err = (path: string, msg: string) => errors.push(`${path}: ${msg}`);

    if (!isObject(doc)) return ['root: not a JSON object'];
    if (doc.version !== '2.1.0') err('version', 'must be "2.1.0"');
    if (!Array.isArray(doc.runs) || doc.runs.length !== 1) return [...errors, 'runs: must be an array with exactly one run'];

    const run = doc.runs[0];
    if (!nonEmptyString(run?.tool?.driver?.name)) err('runs[0].tool.driver.name', 'must be a non-empty string');
    for (const [i, rule] of (run?.tool?.driver?.rules ?? []).entries()) {
        if (!(rule?.id in rules)) err(`runs[0].tool.driver.rules[${i}].id`, `"${rule?.id}" is not in the closed rule list`);
    }
    if (!Array.isArray(run?.results)) return [...errors, 'runs[0].results: must be an array'];

    const seen = new Map<string, number>();
    for (const [i, r] of run.results.entries()) {
        const p = `runs[0].results[${i}]`;
        if (!isObject(r)) { err(p, 'not an object'); continue; }
        if (!(r.ruleId in rules)) err(`${p}.ruleId`, `"${r.ruleId}" is not in the closed rule list`);
        if (r.level !== undefined && !LEVELS.has(r.level)) err(`${p}.level`, 'must be error, warning, note or none');
        if (!nonEmptyString(r.message?.text)) err(`${p}.message.text`, 'must be a non-empty string');
        if (!SEVERITIES.includes(r.properties?.severity)) err(`${p}.properties.severity`, `must be ${SEVERITIES.join(', ')}`);

        if (!Array.isArray(r.locations) || r.locations.length === 0) err(`${p}.locations`, 'must have at least one location');
        else {
            const loc = r.locations[0]?.physicalLocation;
            if (!nonEmptyString(loc?.artifactLocation?.uri)) err(`${p}.locations[0].physicalLocation.artifactLocation.uri`, 'missing');
            const line = loc?.region?.startLine;
            if (line !== undefined && (!Number.isInteger(line) || line < 1)) err(`${p}.locations[0].physicalLocation.region.startLine`, 'must be an integer >= 1');
        }

        const fp = r.partialFingerprints?.[FINGERPRINT_KEY];
        const fpPath = `${p}.partialFingerprints["${FINGERPRINT_KEY}"]`;
        if (!nonEmptyString(fp)) err(fpPath, 'missing');
        else if (fp !== fp.trim()) err(fpPath, 'has leading or trailing whitespace');
        else if (seen.has(fp)) err(fpPath, `duplicate of results[${seen.get(fp)}]`);
        else seen.set(fp, i);

        if (r.baselineState !== undefined && !BASELINE_STATES.has(r.baselineState)) err(`${p}.baselineState`, 'must be new, unchanged, updated or absent');
        for (const [j, s] of (r.suppressions ?? []).entries()) {
            if (!SUPPRESSION_KINDS.has(s?.kind)) err(`${p}.suppressions[${j}].kind`, 'must be inSource or external');
        }
    }
    return errors;
}

/** Throws one Error listing every validation error under `label`. */
export function assertValid(doc: unknown, rules: Rules, label: string): asserts doc is SarifDoc {
    const errors = validate(doc, rules);
    if (errors.length) throw new Error(`${label}: ${errors.length} error(s)\n  - ${errors.join('\n  - ')}`);
}

/** Reads, parses and validates a SARIF file; throws on any failure. */
export function readValidSarif(path: string, rules: Rules): SarifDoc {
    let doc: unknown;
    try {
        doc = JSON.parse(readFileSync(path, 'utf8'));
    } catch (e) {
        const code = (e as NodeJS.ErrnoException).code;
        throw new Error(`${path}: ${code === 'ENOENT' ? 'does not exist' : `not valid JSON (${(e as Error).message})`}`);
    }
    assertValid(doc, rules, path);
    return doc;
}

// ---------------------------------------------------------------------------
// Merge

export interface MergeOptions {
    /** ISO date used for firstSeen/lastSeen; defaults to today (UTC). */
    today?: string;
    /** helpUri for every rule descriptor; omitted when undefined. */
    helpUri?: string;
}

/**
 * Merges this run's results into the baseline. Results are keyed by fingerprint.
 * A known result keeps its baseline entry — suppressions and every property
 * already there (severity, fix, reviewer notes) — and refreshes location, message
 * and lastSeen; fresh properties only fill keys the baseline lacks. A baseline
 * result the run did not report stays as `absent`: one missing LLM run is not
 * proof the bug is gone. Returns the merged document and the results that were new.
 */
export function merge(fresh: SarifDoc, baseline: SarifDoc | null, rules: Rules, options: MergeOptions = {}): { doc: SarifDoc; added: SarifResult[] } {
    const today = options.today ?? new Date().toISOString().slice(0, 10);
    const baselineByFp = new Map<string, SarifResult>();
    for (const r of baseline?.runs[0].results ?? []) baselineByFp.set(fingerprint(r), r);

    const seen = new Set<string>();
    const merged: SarifResult[] = [];
    const added: SarifResult[] = [];
    for (const r of fresh.runs[0].results) {
        const fp = fingerprint(r);
        seen.add(fp);
        const prev = baselineByFp.get(fp);
        if (prev) {
            merged.push(withLevel({
                ...prev,
                message: r.message,
                locations: r.locations,
                properties: { firstSeen: today, ...r.properties, ...prev.properties, lastSeen: today },
                baselineState: 'unchanged',
            }));
        } else {
            const result = withLevel({ ...r, properties: { ...r.properties, firstSeen: today, lastSeen: today }, baselineState: 'new' });
            merged.push(result);
            added.push(result);
        }
    }
    for (const [fp, prev] of baselineByFp) {
        if (!seen.has(fp)) merged.push(withLevel({ ...prev, baselineState: 'absent' }));
    }
    merged.sort((a, b) => severityRank(a) - severityRank(b) || fingerprint(a).localeCompare(fingerprint(b)));

    const usedRuleIds = [...new Set(merged.map((r) => r.ruleId))].sort();
    const doc: SarifDoc = {
        $schema: SCHEMA_URL,
        version: '2.1.0',
        runs: [{
            tool: { driver: { ...fresh.runs[0].tool.driver, rules: usedRuleIds.map((id) => ruleDescriptor(id, rules, options.helpUri)) } },
            results: merged,
        }],
    };
    return { doc, added };
}

/** Rules carry their CWE mapping as GitHub `external/cwe/cwe-N` tags. */
export function ruleDescriptor(id: string, rules: Rules, helpUri?: string): SarifRuleDescriptor {
    const rule = rules[id]!;
    return {
        id,
        name: rule.name,
        shortDescription: { text: rule.name },
        ...(helpUri ? { helpUri } : {}),
        properties: { tags: ['security', ...rule.cwe.map((n) => `external/cwe/cwe-${n}`)] },
    };
}

export function fingerprint(result: SarifResult): string {
    return result.partialFingerprints[FINGERPRINT_KEY]!;
}

/** SARIF level follows severity: Critical/High → error, Medium → warning, Low → note. */
export function withLevel(result: SarifResult): SarifResult {
    const level = ({ Critical: 'error', High: 'error', Medium: 'warning', Low: 'note' } as const)[result.properties.severity];
    return { ...result, level };
}

export function withoutExploitDetails(result: SarifResult): SarifResult {
    const properties = { ...result.properties };
    for (const key of EXPLOIT_DETAILS) delete properties[key];
    return { ...result, properties };
}

export function severityRank(result: SarifResult): number {
    return SEVERITIES.indexOf(result.properties.severity);
}

/**
 * Derives the rule helpUri from the CI environment when available: the skill
 * folder in the audited repository. Undefined outside GitHub Actions.
 */
export function defaultHelpUri(env: Record<string, string | undefined> = process.env): string | undefined {
    const repo = env.GITHUB_REPOSITORY;
    if (!repo) return undefined;
    const server = env.GITHUB_SERVER_URL ?? 'https://github.com';
    const ref = env.GITHUB_REF_NAME ?? 'HEAD';
    return `${server}/${repo}/tree/${ref}/.claude/skills/security-audit`;
}

// ---------------------------------------------------------------------------
// Report

/**
 * Markdown for the findings PR body and the step summary: one bullet per result
 * with the exploit details the committed baseline omits. Empty results → "No new findings."
 */
export function renderReport(results: SarifResult[]): string {
    if (results.length === 0) return 'No new findings.\n';
    const lines = [`## ${results.length} new security finding(s)`, ''];
    for (const r of results) {
        const loc = r.locations[0]!.physicalLocation;
        const line = loc.region?.startLine;
        const where = line ? `${loc.artifactLocation.uri}:${line}` : loc.artifactLocation.uri;
        const p = r.properties;
        lines.push(`- **${p.severity}** — ${r.message.text} — \`${where}\``);
        lines.push(`  flow: ${str(p.flow)}`);
        lines.push(`  repro: ${str(p.repro)}`);
        lines.push(`  fix: ${str(p.fix)}`);
    }
    lines.push('');
    lines.push(`Merging accepts these into the committed baseline. Add a \`suppressions\` entry to a result to mark it a false positive; delete it once fixed. Impact and likelihood are in \`${BASELINE_FILE}\`; flow and repro are only in this PR.`);
    return `${lines.join('\n')}\n`;
}

function str(v: unknown): string {
    return typeof v === 'string' && v.trim() ? v : '—';
}

// ---------------------------------------------------------------------------

export function isObject(v: unknown): v is Record<string, any> {
    return v !== null && typeof v === 'object' && !Array.isArray(v);
}

export function nonEmptyString(v: unknown): v is string {
    return typeof v === 'string' && v.trim().length > 0;
}
