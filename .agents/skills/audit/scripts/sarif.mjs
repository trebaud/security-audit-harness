#!/usr/bin/env node
/**
 * The audit skill's SARIF tool: the closed rule list, validation and the
 * baseline merge. Node 18+ standard library only, so it runs before any
 * install step. It renders nothing for humans: the audit itself writes the
 * report.
 *
 *   node sarif.mjs validate <file>    check a file; prints "valid" or the errors
 *   node sarif.mjs merge <run>        merge <run> into the committed baseline
 *   node sarif.mjs combine <out> <in...>  fold several runs into one, for one merge
 *
 * The default paths (`security/audit/…`) are relative to the audited repository's
 * root, so run it from there.
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

export const DIR = "security/audit";
export const RULES_FILE = `${DIR}/rules.json`;
export const BASELINE_FILE = `${DIR}/baseline.sarif`;

// The fingerprint key is namespaced by this harness, not by the audited
// project, so baselines stay comparable across repositories.
export const FINGERPRINT_KEY = "security-audit/v1";
export const SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json";

export const SEVERITIES = ["Critical", "High", "Medium", "Low"];

const LEVELS = new Set(["error", "warning", "note", "none"]);
const BASELINE_STATES = new Set(["new", "unchanged", "updated", "absent"]);
const SUPPRESSION_KINDS = new Set(["inSource", "external"]);

// Exploit details: kept in the run file and the report, stripped from the committed baseline.
const EXPLOIT_DETAILS = ["repro", "flow"];

const RULE_ID_RE = /^[a-z][a-z0-9-]*$/;

// The fingerprint grammar: <ruleId>|<uri>|<symbol>.
const FINGERPRINT_SEGMENTS = 3;
// A <symbol> of digits alone is a line number, which moves on the next reformat.
const LINE_ONLY_RE = /^\d+$/;
// Windows absolute paths reach normalizeUri as C:/repo/src/a.ts.
const DRIVE_RE = /^[A-Za-z]:\//;

/** Anything the scripts should report as a one-line failure and exit on. */
export class SarifError extends Error {
  constructor(message) {
    super(message);
    this.name = "SarifError";
  }
}

// ---------------------------------------------------------------------------
// Rules

/**
 * Parse and check the closed rule list: {"<ruleId>": {name, cwe: [n], covers}}
 * in priority order (first row that fits wins). ruleId doubles as the fingerprint
 * prefix, so ids are never renamed; the CWE list is the cross-tool identifier.
 * Throws SarifError naming the file on any problem.
 */
export function parseRules(text, file = RULES_FILE) {
  let rules;
  try {
    rules = JSON.parse(text);
  } catch (e) {
    throw new SarifError(`${file}: not valid JSON (${e.message})`);
  }
  if (!isObject(rules) || Object.keys(rules).length === 0) {
    throw new SarifError(`${file}: must be a non-empty object keyed by ruleId`);
  }
  for (const [ruleId, rule] of Object.entries(rules)) {
    const ok =
      RULE_ID_RE.test(ruleId) &&
      isObject(rule) &&
      nonEmptyString(rule.name) &&
      nonEmptyString(rule.covers) &&
      Array.isArray(rule.cwe) &&
      rule.cwe.every(isPositiveInt);
    if (!ok) {
      throw new SarifError(
        `${file}: rule "${ruleId}" must be { name, cwe: [positive integers], covers } with a kebab-case id`,
      );
    }
  }
  return rules;
}

/** Read the closed rule list from disk; throws when missing or malformed. */
export function loadRules(file = RULES_FILE) {
  let text;
  try {
    text = fs.readFileSync(file, "utf-8");
  } catch (e) {
    if (e.code === "ENOENT") {
      throw new SarifError(`${file}: does not exist (run from the repo root; the audit skill seeds it on its first run)`);
    }
    throw new SarifError(`${file}: ${errorText(e)}`);
  }
  return parseRules(text, file);
}

// ---------------------------------------------------------------------------
// Paths and fingerprints

/**
 * One spelling for one file: the repo-relative POSIX path a fingerprint is keyed on.
 *
 * The same sink arrives as `src/a.ts`, `./src/a.ts`, `file:///…/src/a%20b.ts` or the
 * runner's absolute checkout path depending on where the audit ran. Every spelling is
 * its own fingerprint, so without this the baseline reports one bug as new every run.
 */
export function normalizeUri(uri, root = null) {
  if (typeof uri !== "string" || !uri.trim()) return "";
  uri = percentDecode(uri.trim()).replace(/\\/g, "/");
  if (uri.startsWith("file://")) uri = uri.slice("file://".length);
  uri = uri.replace(DRIVE_RE, "/");
  if (uri.startsWith("/")) {
    const base = (root === null ? process.cwd() : root).replace(/\\/g, "/").replace(/\/+$/, "");
    uri = base && uri.startsWith(base + "/") ? uri.slice(base.length + 1) : uri.replace(/^\/+/, "");
  }
  uri = normpath(uri);
  return uri === "." || uri === ".." ? "" : uri;
}

/** Percent-decoding that leaves an invalid escape as written, like Python's unquote. */
function percentDecode(value) {
  return value.replace(/(?:%[0-9A-Fa-f]{2})+/g, (match) => {
    try {
      return decodeURIComponent(match);
    } catch {
      return match;
    }
  });
}

/** posixpath.normpath for the relative paths normalizeUri produces. */
function normpath(uri) {
  const parts = [];
  for (const part of uri.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === ".." && parts.length && parts[parts.length - 1] !== "..") parts.pop();
    else parts.push(part);
  }
  return parts.length ? parts.join("/") : ".";
}

/**
 * Check one fingerprint against the result carrying it: `<ruleId>|<uri>|<symbol>`.
 *
 * The fingerprint is the whole dedupe key and nothing downstream re-derives it, so one
 * that parses but names the wrong rule or the wrong file splits a single bug into two
 * baseline entries, silently and for good. `uri` is the result's normalized location,
 * or null when it had none to compare against.
 */
export function fingerprintErrors(fp, ruleId, uri) {
  const parts = fp.split("|");
  if (parts.length !== FINGERPRINT_SEGMENTS) {
    return [`must be <ruleId>|<uri>|<symbol>, got ${parts.length} segment(s)`];
  }
  const [fpRule, fpUri, symbol] = parts;
  const problems = [];
  if (fpRule !== ruleId) {
    problems.push(`starts with "${fpRule}", not the result's ruleId "${ruleId}"`);
  }
  if (uri !== null && uri !== undefined && normalizeUri(fpUri) !== uri) {
    problems.push(`names "${fpUri}", not the result's location "${uri}"`);
  }
  if (!symbol.trim()) {
    problems.push("has an empty <symbol>");
  } else if (LINE_ONLY_RE.test(symbol.trim())) {
    problems.push(`uses the line number "${symbol}" as <symbol>: name the enclosing function, route or declaration`);
  }
  return problems;
}

/**
 * Rewrite artifact uris, and the `<uri>` segment of each fingerprint, to their
 * normalized spelling, in place. This runs on every file read, so a baseline whose
 * paths were written with another spelling heals on its next merge instead of
 * duplicating every result it holds.
 *
 * A fingerprint is rewritten only when its `<uri>` already names the result's own
 * location; one naming a different file is left alone for `validate` to report.
 */
export function normalizeDoc(doc) {
  if (!isObject(doc)) return doc;
  for (const run of doc.runs || []) {
    if (!isObject(run)) continue;
    for (const result of run.results || []) {
      if (isObject(result)) normalizeResult(result);
    }
  }
  return doc;
}

/** Normalize one result's locations, then its fingerprint to match. */
function normalizeResult(result) {
  let uri = null;
  const locations = result.locations || [];
  for (let i = 0; i < locations.length; i++) {
    const artifact = dig(locations[i], "physicalLocation", "artifactLocation");
    if (isObject(artifact) && nonEmptyString(artifact.uri)) {
      artifact.uri = normalizeUri(artifact.uri);
      if (i === 0) uri = artifact.uri;
    }
  }
  const prints = result.partialFingerprints;
  const fp = dig(prints, FINGERPRINT_KEY);
  if (uri === null || !nonEmptyString(fp)) return;
  const parts = fp.split("|");
  if (parts.length === FINGERPRINT_SEGMENTS && normalizeUri(parts[1]) === uri) {
    prints[FINGERPRINT_KEY] = [parts[0], uri, parts[2]].join("|");
  }
}

// ---------------------------------------------------------------------------
// Validation

/** Return a list of error strings; empty means valid. */
export function validate(doc, rules) {
  const errors = [];
  const err = (p, msg) => errors.push(`${p}: ${msg}`);

  if (!isObject(doc)) return ["root: not a JSON object"];
  if (doc.version !== "2.1.0") err("version", 'must be "2.1.0"');
  const runs = doc.runs;
  if (!Array.isArray(runs) || runs.length !== 1) {
    return [...errors, "runs: must be an array with exactly one run"];
  }

  const run = isObject(runs[0]) ? runs[0] : {};
  const driver = dig(run, "tool", "driver");
  if (!nonEmptyString(dig(driver, "name"))) {
    err("runs[0].tool.driver.name", "must be a non-empty string");
  }
  const driverRules = dig(driver, "rules") || [];
  if (Array.isArray(driverRules)) {
    driverRules.forEach((rule, i) => {
      const ruleId = dig(rule, "id");
      if (!hasRule(rules, ruleId)) {
        err(`runs[0].tool.driver.rules[${i}].id`, `"${ruleId}" is not in the closed rule list`);
      }
    });
  }
  const results = run.results;
  if (!Array.isArray(results)) return [...errors, "runs[0].results: must be an array"];

  const seen = new Map();
  results.forEach((r, i) => {
    const p = `runs[0].results[${i}]`;
    if (!isObject(r)) {
      err(p, "not an object");
      return;
    }
    if (!hasRule(rules, r.ruleId)) {
      err(`${p}.ruleId`, `"${r.ruleId}" is not in the closed rule list`);
    }
    if ("level" in r && !LEVELS.has(r.level)) {
      err(`${p}.level`, "must be error, warning, note or none");
    }
    if (!nonEmptyString(dig(r, "message", "text"))) {
      err(`${p}.message.text`, "must be a non-empty string");
    }
    if (!SEVERITIES.includes(dig(r, "properties", "severity"))) {
      err(`${p}.properties.severity`, `must be ${SEVERITIES.join(", ")}`);
    }

    let uri = null;
    const locations = r.locations;
    if (!Array.isArray(locations) || locations.length === 0) {
      err(`${p}.locations`, "must have at least one location");
    } else {
      const loc = dig(locations[0], "physicalLocation");
      const rawUri = dig(loc, "artifactLocation", "uri");
      if (!nonEmptyString(rawUri)) {
        err(`${p}.locations[0].physicalLocation.artifactLocation.uri`, "missing");
      } else {
        uri = normalizeUri(rawUri);
      }
      const region = dig(loc, "region") || {};
      if ("startLine" in region && !isPositiveInt(region.startLine)) {
        err(`${p}.locations[0].physicalLocation.region.startLine`, "must be an integer >= 1");
      }
    }

    const fp = dig(r, "partialFingerprints", FINGERPRINT_KEY);
    const fpPath = `${p}.partialFingerprints["${FINGERPRINT_KEY}"]`;
    if (!nonEmptyString(fp)) {
      err(fpPath, "missing");
    } else if (fp !== fp.trim()) {
      err(fpPath, "has leading or trailing whitespace");
    } else {
      if (seen.has(fp)) err(fpPath, `duplicate of results[${seen.get(fp)}]`);
      else seen.set(fp, i);
      for (const problem of fingerprintErrors(fp, r.ruleId, uri)) err(fpPath, problem);
    }

    if ("baselineState" in r && !BASELINE_STATES.has(r.baselineState)) {
      err(`${p}.baselineState`, "must be new, unchanged, updated or absent");
    }
    (r.suppressions || []).forEach((s, j) => {
      if (!SUPPRESSION_KINDS.has(dig(s, "kind"))) {
        err(`${p}.suppressions[${j}].kind`, "must be inSource or external");
      }
    });
  });
  return errors;
}

/** Throw one SarifError listing every validation error under `label`. */
export function assertValid(doc, rules, label) {
  const errors = validate(doc, rules);
  if (errors.length) {
    throw new SarifError(`${label}: ${errors.length} error(s)\n  - ${errors.join("\n  - ")}`);
  }
}

/** Read, parse and validate a SARIF file; throws on any failure. */
export function readValidSarif(file, rules) {
  let text;
  try {
    text = fs.readFileSync(file, "utf-8");
  } catch (e) {
    if (e.code === "ENOENT") throw new SarifError(`${file}: does not exist`);
    throw new SarifError(`${file}: ${errorText(e)}`);
  }
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new SarifError(`${file}: not valid JSON (${e.message})`);
  }
  normalizeDoc(doc);
  assertValid(doc, rules, file);
  return doc;
}

// ---------------------------------------------------------------------------
// Merge

/**
 * Merge this run's results into the baseline. Results are keyed by fingerprint.
 *
 * A known result keeps its baseline entry — suppressions and every property
 * already there (severity, fix, reviewer notes) — and refreshes location, message
 * and lastSeen; fresh properties only fill keys the baseline lacks. A baseline
 * result the run did not report stays as `absent`: one missing LLM run is not
 * proof the bug is gone. Returns [merged document, results that were new].
 */
export function merge(fresh, baseline, rules, { today = null, helpUri = null } = {}) {
  today = today || new Date().toISOString().slice(0, 10);
  const baselineByFp = new Map();
  if (baseline) {
    for (const r of baseline.runs[0].results) baselineByFp.set(fingerprint(r), r);
  }

  const seen = new Set();
  const merged = [];
  const added = [];
  for (const r of fresh.runs[0].results) {
    const fp = fingerprint(r);
    seen.add(fp);
    const prev = baselineByFp.get(fp);
    if (prev !== undefined) {
      merged.push(
        withLevel({
          ...prev,
          message: r.message,
          locations: r.locations,
          properties: {
            firstSeen: today,
            ...r.properties,
            ...prev.properties,
            lastSeen: today,
          },
          baselineState: "unchanged",
        }),
      );
    } else {
      const result = withLevel({
        ...r,
        properties: { ...r.properties, firstSeen: today, lastSeen: today },
        baselineState: "new",
      });
      merged.push(result);
      added.push(result);
    }
  }
  for (const [fp, prev] of baselineByFp) {
    if (!seen.has(fp)) merged.push(withLevel({ ...prev, baselineState: "absent" }));
  }
  merged.sort((a, b) => severityRank(a) - severityRank(b) || compare(fingerprint(a), fingerprint(b)));

  const usedRuleIds = [...new Set(merged.map((r) => r.ruleId))].sort(compare);
  const doc = {
    $schema: SCHEMA_URL,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            ...fresh.runs[0].tool.driver,
            rules: usedRuleIds.map((ruleId) => ruleDescriptor(ruleId, rules, helpUri)),
          },
        },
        results: merged,
      },
    ],
  };
  return [doc, added];
}

// ---------------------------------------------------------------------------
// Combine

/**
 * Fold the runs of a split audit (one per scan group) into one run, so the
 * baseline is merged once. Merging each group on its own would mark every other
 * group's findings `absent`. Results are keyed by fingerprint: two groups that
 * reach the same sink yield one result, at the higher severity, carrying both
 * flows. Returns [combined document, number of duplicates folded].
 */
export function combine(docs) {
  const byFp = new Map();
  let duplicates = 0;
  for (const doc of docs) {
    for (const r of doc.runs[0].results) {
      const fp = fingerprint(r);
      const prev = byFp.get(fp);
      if (prev === undefined) {
        byFp.set(fp, r);
        continue;
      }
      duplicates++;
      const [keep, other] = severityRank(r) < severityRank(prev) ? [r, prev] : [prev, r];
      const flows = [...new Set([keep.properties.flow, other.properties.flow].filter(nonEmptyString))];
      byFp.set(fp, { ...keep, properties: { ...keep.properties, flow: flows.join("\n") } });
    }
  }
  const results = [...byFp.values()].sort(
    (a, b) => severityRank(a) - severityRank(b) || compare(fingerprint(a), fingerprint(b)),
  );
  const driver = docs.length ? docs[0].runs[0].tool.driver : { name: "security-audit" };
  const doc = {
    $schema: SCHEMA_URL,
    version: "2.1.0",
    runs: [{ tool: { driver: { name: driver.name } }, results }],
  };
  return [doc, duplicates];
}

/** Rules carry their CWE mapping as GitHub `external/cwe/cwe-N` tags. */
export function ruleDescriptor(ruleId, rules, helpUri = null) {
  const rule = rules[ruleId];
  const descriptor = {
    id: ruleId,
    name: rule.name,
    shortDescription: { text: rule.name },
  };
  if (helpUri) descriptor.helpUri = helpUri;
  descriptor.properties = { tags: ["security", ...rule.cwe.map((n) => `external/cwe/cwe-${n}`)] };
  return descriptor;
}

export function fingerprint(result) {
  return result.partialFingerprints[FINGERPRINT_KEY];
}

/** SARIF level follows severity: Critical/High -> error, Medium -> warning, Low -> note. */
function withLevel(result) {
  const level = { Critical: "error", High: "error", Medium: "warning", Low: "note" }[result.properties.severity];
  return { ...result, level };
}

export function withoutExploitDetails(result) {
  const properties = { ...result.properties };
  for (const key of EXPLOIT_DETAILS) delete properties[key];
  return { ...result, properties };
}

function severityRank(result) {
  return SEVERITIES.indexOf(result.properties.severity);
}

function compare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The rule helpUri: the harness repository, where the skill is published. */
export const HELP_URI = "https://github.com/trebaud/security-audit-harness";

// ---------------------------------------------------------------------------

/**
 * Write a SARIF document as pretty JSON with a trailing newline, creating
 * `security/audit/` if the repo does not have it yet.
 */
export function dumpSarif(doc, file) {
  const parent = path.dirname(file);
  if (parent && parent !== ".") fs.mkdirSync(parent, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(doc, null, 2) + "\n", "utf-8");
}

/** Walk nested objects, returning undefined as soon as a level is missing or not an object. */
function dig(value, ...keys) {
  for (const key of keys) {
    if (!isObject(value)) return undefined;
    value = value[key];
  }
  return value;
}

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function nonEmptyString(v) {
  return typeof v === "string" && v.trim() !== "";
}

function isPositiveInt(v) {
  return typeof v === "number" && Number.isInteger(v) && v > 0;
}

function hasRule(rules, ruleId) {
  return typeof ruleId === "string" && Object.prototype.hasOwnProperty.call(rules, ruleId);
}

function errorText(e) {
  return e.message.replace(/^[A-Z]+:\s*/, "").split(",")[0];
}

// ---------------------------------------------------------------------------
// Commands

const USAGE = `usage: sarif.mjs <command>

  sarif.mjs validate <file>    check a file; prints "valid" or the errors
  sarif.mjs merge <run>        merge <run> into ${BASELINE_FILE}
  sarif.mjs combine <out> <in...>
                               fold several runs into <out>, deduped by fingerprint`;

/** Validate one SARIF file against the closed rule list. */
function cmdValidate(argv) {
  if (argv.length !== 1) {
    console.error("usage: sarif.mjs validate <file>");
    return 2;
  }
  readValidSarif(argv[0], loadRules());
  console.log(`${argv[0]}: valid`);
  return 0;
}

/**
 * Merge this run's SARIF into the committed baseline.
 *
 * A missing baseline means every result is new. The baseline is committed, so
 * exploit details (`repro`, `flow`) are stripped from it; the run file is
 * rewritten to hold only this run's new results, in full, for whoever writes
 * them up; it is gitignored. Run the merge once per audit: a second
 * pass finds nothing new and empties the run file.
 *
 * The merge stops on an invalid file and does not change the baseline. Rule
 * descriptors get a helpUri pointing at the harness repository. See `merge`
 * for the matching rules.
 */
function cmdMerge(argv) {
  if (argv.length !== 1) {
    console.error("usage: sarif.mjs merge <run>");
    return 2;
  }
  const file = argv[0];
  const rules = loadRules();
  const fresh = readValidSarif(file, rules);
  const baseline = fs.existsSync(BASELINE_FILE) ? readValidSarif(BASELINE_FILE, rules) : null;

  const [doc, added] = merge(fresh, baseline, rules, { helpUri: HELP_URI });
  assertValid(doc, rules, "merged output");

  const run = doc.runs[0];
  dumpSarif({ ...doc, runs: [{ ...run, results: added }] }, file);
  run.results = run.results.map(withoutExploitDetails);
  dumpSarif(doc, BASELINE_FILE);
  console.log(`${BASELINE_FILE}: ${added.length} new, ${run.results.length - added.length} known`);
  return 0;
}

/**
 * Fold the run files of a split audit into one, ready for a single merge.
 * Every input is validated first; one invalid input stops the command and
 * <out> is not written.
 */
function cmdCombine(argv) {
  if (argv.length < 2) {
    console.error("usage: sarif.mjs combine <out> <in...>");
    return 2;
  }
  const [out, ...inputs] = argv;
  const rules = loadRules();
  const docs = inputs.map((file) => readValidSarif(file, rules));
  const [doc, duplicates] = combine(docs);
  assertValid(doc, rules, "combined output");
  dumpSarif(doc, out);
  console.log(`${out}: ${doc.runs[0].results.length} result(s) from ${inputs.length} run(s), ${duplicates} duplicate(s) folded`);
  return 0;
}

const COMMANDS = { validate: cmdValidate, merge: cmdMerge, combine: cmdCombine };

export function main(argv) {
  if (argv.length === 1 && (argv[0] === "-h" || argv[0] === "--help")) {
    console.log(USAGE);
    return 0;
  }
  if (!argv.length || !Object.prototype.hasOwnProperty.call(COMMANDS, argv[0])) {
    console.error(USAGE);
    return 2;
  }
  try {
    return COMMANDS[argv[0]](argv.slice(1));
  } catch (e) {
    if (e instanceof SarifError) {
      console.error(`sarif ${argv[0]}: ${e.message}`);
      return 1;
    }
    throw e;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}
