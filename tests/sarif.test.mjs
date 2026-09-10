#!/usr/bin/env node
/**
 * Tests for the SARIF tool: path normalization, the fingerprint grammar and the
 * baseline merge. Standard library only, like the script under test.
 *
 *     node --test tests/
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { after, before, beforeEach, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.dirname(HERE);
const SCRIPT = path.join(ROOT, ".agents", "skills", "security-audit", "scripts", "sarif.mjs");
const RULES_SEED = path.join(ROOT, "security", "audit", "rules.json");

const sarif = await import(SCRIPT);

const RULES = sarif.parseRules(fs.readFileSync(RULES_SEED, "utf-8"));

const FP = sarif.FINGERPRINT_KEY;

/** One valid result, so each test states only what it is about. */
function result({
  ruleId = "idor",
  uri = "src/a.ts",
  symbol = "Controller.method",
  severity = "High",
  ...properties
} = {}) {
  return {
    ruleId,
    message: { text: "Unvalidated input reaches the sink." },
    locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 42 } } }],
    partialFingerprints: { [FP]: `${ruleId}|${uri}|${symbol}` },
    properties: {
      severity,
      flow: "input -> sink, src/a.ts:42",
      impact: "The sink runs on attacker input.",
      likelihood: "Any authenticated request.",
      repro: 'POST /a with {"id": 1}',
      fix: "Validate the input at the boundary.",
      ...properties,
    },
  };
}

function document(...results) {
  return {
    $schema: sarif.SCHEMA_URL,
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "security-audit" } }, results }],
  };
}

function resultsOf(doc) {
  return doc.runs[0].results;
}

describe("normalizeUri", () => {
  it("collapses every spelling of one file", () => {
    // Every spelling the audit can emit for one file has to key the same.
    const cwd = process.cwd().replace(/\\/g, "/");
    for (const spelling of [
      "src/a.ts",
      "./src/a.ts",
      "src/./a.ts",
      "src/x/../a.ts",
      "src\\a.ts",
      `${cwd}/src/a.ts`,
      `file://${cwd}/src/a.ts`,
    ]) {
      assert.equal(sarif.normalizeUri(spelling), "src/a.ts", spelling);
    }
  });

  it("percent-decodes", () => {
    assert.equal(sarif.normalizeUri("src/a%20b.ts"), "src/a b.ts");
  });

  it("keeps the shape of an absolute path outside the repo", () => {
    // It cannot be made repo-relative; it loses its leading slash so it at least keys consistently.
    assert.equal(sarif.normalizeUri("/builds/proj/src/a.ts"), "builds/proj/src/a.ts");
  });

  it("handles a windows drive", () => {
    assert.equal(sarif.normalizeUri("C:/builds/proj/src/a.ts"), "builds/proj/src/a.ts");
  });

  it("strips the root argument", () => {
    assert.equal(sarif.normalizeUri("/w/repo/src/a.ts", "/w/repo"), "src/a.ts");
  });

  it("returns empty for empty and non-strings", () => {
    for (const value of ["", "   ", null, undefined, 3, ["src/a.ts"]]) {
      assert.equal(sarif.normalizeUri(value), "");
    }
  });

  it("is idempotent", () => {
    const once = sarif.normalizeUri("./src/a.ts");
    assert.equal(sarif.normalizeUri(once), once);
  });
});

describe("validate", () => {
  const assertValid = (doc) => assert.deepEqual(sarif.validate(doc, RULES), []);
  const assertError = (doc, needle) => {
    const errors = sarif.validate(doc, RULES);
    assert.ok(errors.length, "expected an error");
    assert.ok(
      errors.some((e) => e.includes(needle)),
      `${JSON.stringify(needle)} not in ${JSON.stringify(errors)}`,
    );
  };

  it("accepts a well-formed document", () => {
    assertValid(document(result()));
  });

  it("accepts empty results", () => {
    assertValid(document());
  });

  it("rejects a rule id outside the closed list", () => {
    assertError(document(result({ ruleId: "sql-injection" })), "not in the closed rule list");
  });

  it("requires one of the four severities", () => {
    assertError(document(result({ severity: "Info" })), "properties.severity");
  });

  it("checks the fingerprint segment count", () => {
    const r = result();
    r.partialFingerprints[FP] = "idor|src/a.ts";
    assertError(document(r), "got 2 segment(s)");
  });

  it("requires the fingerprint to start with the result's rule id", () => {
    const r = result();
    r.partialFingerprints[FP] = "csrf|src/a.ts|Controller.method";
    assertError(document(r), 'not the result\'s ruleId "idor"');
  });

  it("requires the fingerprint to name the result's own file", () => {
    const r = result();
    r.partialFingerprints[FP] = "idor|src/other/a.ts|Controller.method";
    assertError(document(r), "not the result's location");
  });

  it("allows the fingerprint uri to be spelled differently", () => {
    // Spelling drift is not an error; only naming another file is.
    const r = result();
    r.partialFingerprints[FP] = "idor|./src/a.ts|Controller.method";
    assertValid(document(r));
  });

  it("rejects a line number as the symbol", () => {
    const r = result();
    r.partialFingerprints[FP] = "idor|src/a.ts|42";
    assertError(document(r), "line number");
  });

  it("rejects an empty symbol", () => {
    const r = result();
    r.partialFingerprints[FP] = "idor|src/a.ts|";
    assertError(document(r), "empty <symbol>");
  });

  it("rejects duplicate fingerprints", () => {
    assertError(document(result(), result()), "duplicate of results[0]");
  });

  it("does not treat findings in sibling files as duplicates", () => {
    // The directory is part of the key: one/a.ts and two/a.ts are two files.
    assertValid(document(result({ uri: "src/one/a.ts" }), result({ uri: "src/two/a.ts" })));
  });
});

describe("normalizeDoc", () => {
  it("heals location and fingerprint", () => {
    const doc = document(result({ uri: "./src/a.ts" }));
    sarif.normalizeDoc(doc);
    const r = resultsOf(doc)[0];
    assert.equal(r.locations[0].physicalLocation.artifactLocation.uri, "src/a.ts");
    assert.equal(r.partialFingerprints[FP], "idor|src/a.ts|Controller.method");
  });

  it("leaves a fingerprint naming another file alone", () => {
    const doc = document(result());
    resultsOf(doc)[0].partialFingerprints[FP] = "idor|src/other/a.ts|Controller.method";
    sarif.normalizeDoc(doc);
    assert.equal(resultsOf(doc)[0].partialFingerprints[FP], "idor|src/other/a.ts|Controller.method");
  });

  it("survives malformed input", () => {
    for (const doc of [null, {}, { runs: null }, { runs: [null] }, { runs: [{ results: [null] }] }]) {
      sarif.normalizeDoc(doc);
    }
  });
});

describe("merge", () => {
  it("makes everything new without a baseline", () => {
    const [doc, added] = sarif.merge(document(result()), null, RULES, { today: "2026-01-01" });
    assert.equal(added.length, 1);
    assert.equal(resultsOf(doc)[0].baselineState, "new");
    assert.equal(resultsOf(doc)[0].properties.firstSeen, "2026-01-01");
  });

  it("leaves a known finding unchanged and adds nothing", () => {
    const [baseline] = sarif.merge(document(result()), null, RULES, { today: "2026-01-01" });
    const [doc, added] = sarif.merge(document(result()), baseline, RULES, { today: "2026-02-02" });
    assert.deepEqual(added, []);
    const r = resultsOf(doc)[0];
    assert.equal(r.baselineState, "unchanged");
    assert.equal(r.properties.firstSeen, "2026-01-01");
    assert.equal(r.properties.lastSeen, "2026-02-02");
  });

  it("does not re-report a known finding after path spelling drift", () => {
    // The regression this normalization exists for: one bug, two spellings, one entry.
    const [baseline] = sarif.merge(document(result({ uri: "src/a.ts" })), null, RULES, { today: "2026-01-01" });
    const fresh = sarif.normalizeDoc(document(result({ uri: `${process.cwd()}/src/a.ts` })));
    const [doc, added] = sarif.merge(fresh, baseline, RULES, { today: "2026-02-02" });
    assert.deepEqual(added, []);
    assert.equal(resultsOf(doc).length, 1);
  });

  it("marks a finding the run missed as absent, not gone", () => {
    const [baseline] = sarif.merge(document(result()), null, RULES, { today: "2026-01-01" });
    const [doc, added] = sarif.merge(document(), baseline, RULES, { today: "2026-02-02" });
    assert.deepEqual(added, []);
    assert.equal(resultsOf(doc)[0].baselineState, "absent");
  });

  it("lets reviewer edits in the baseline win over the fresh run", () => {
    const [baseline] = sarif.merge(document(result({ severity: "High" })), null, RULES, { today: "2026-01-01" });
    resultsOf(baseline)[0].properties.severity = "Low";
    resultsOf(baseline)[0].properties.note = "Covered by a control upstream.";
    const [doc] = sarif.merge(document(result({ severity: "High" })), baseline, RULES, { today: "2026-02-02" });
    const r = resultsOf(doc)[0];
    assert.equal(r.properties.severity, "Low");
    assert.equal(r.properties.note, "Covered by a control upstream.");
    assert.equal(r.level, "note");
  });

  it("keeps suppressions through a later run", () => {
    const [baseline] = sarif.merge(document(result()), null, RULES, { today: "2026-01-01" });
    resultsOf(baseline)[0].suppressions = [{ kind: "external", justification: "accepted" }];
    const [doc] = sarif.merge(document(result()), baseline, RULES, { today: "2026-02-02" });
    assert.equal(resultsOf(doc)[0].suppressions[0].kind, "external");
  });

  it("refreshes message and location", () => {
    const [baseline] = sarif.merge(document(result()), null, RULES, { today: "2026-01-01" });
    const fresh = document(result());
    resultsOf(fresh)[0].message.text = "Rewritten claim.";
    resultsOf(fresh)[0].locations[0].physicalLocation.region.startLine = 99;
    const [doc] = sarif.merge(fresh, baseline, RULES, { today: "2026-02-02" });
    const r = resultsOf(doc)[0];
    assert.equal(r.message.text, "Rewritten claim.");
    assert.equal(r.locations[0].physicalLocation.region.startLine, 99);
  });

  it("derives level from severity", () => {
    for (const [severity, level] of [
      ["Critical", "error"],
      ["High", "error"],
      ["Medium", "warning"],
      ["Low", "note"],
    ]) {
      const [doc] = sarif.merge(document(result({ severity })), null, RULES);
      assert.equal(resultsOf(doc)[0].level, level, severity);
    }
  });

  it("sorts results by severity", () => {
    const fresh = document(
      result({ uri: "src/a.ts", severity: "Low" }),
      result({ uri: "src/b.ts", severity: "Critical" }),
      result({ uri: "src/c.ts", severity: "Medium" }),
    );
    const [doc] = sarif.merge(fresh, null, RULES);
    assert.deepEqual(
      resultsOf(doc).map((r) => r.properties.severity),
      ["Critical", "Medium", "Low"],
    );
  });

  it("gives rule descriptors the CWE mapping of the rules used", () => {
    const [doc] = sarif.merge(document(result({ ruleId: "csrf" })), null, RULES);
    const descriptors = doc.runs[0].tool.driver.rules;
    assert.deepEqual(
      descriptors.map((d) => d.id),
      ["csrf"],
    );
    assert.ok(descriptors[0].properties.tags.includes("external/cwe/cwe-352"));
    assert.ok(!("helpUri" in descriptors[0]));
  });

  it("adds the help uri when given", () => {
    const [doc] = sarif.merge(document(result()), null, RULES, { helpUri: "https://example.test/skill" });
    assert.equal(doc.runs[0].tool.driver.rules[0].helpUri, "https://example.test/skill");
  });

  it("produces output that validates", () => {
    const [doc] = sarif.merge(document(result()), null, RULES);
    assert.deepEqual(sarif.validate(doc, RULES), []);
  });

  it("does not mutate its inputs", () => {
    const fresh = document(result());
    const before = structuredClone(fresh);
    sarif.merge(fresh, null, RULES);
    assert.deepEqual(fresh, before);
  });
});

describe("combine", () => {
  it("concatenates distinct results", () => {
    const [doc, duplicates] = sarif.combine([document(result({ uri: "src/a.ts" })), document(result({ uri: "src/b.ts" }))]);
    assert.equal(resultsOf(doc).length, 2);
    assert.equal(duplicates, 0);
  });

  it("folds one fingerprint reached from two groups", () => {
    const low = result({ severity: "Medium", flow: "GET /a -> sink" });
    const high = result({ severity: "High", flow: "POST /b -> sink" });
    const [doc, duplicates] = sarif.combine([document(low), document(high)]);
    assert.equal(duplicates, 1);
    assert.equal(resultsOf(doc).length, 1);
    assert.equal(resultsOf(doc)[0].properties.severity, "High");
    assert.equal(resultsOf(doc)[0].properties.flow, "POST /b -> sink\nGET /a -> sink");
  });

  it("does not repeat an identical flow", () => {
    const [doc] = sarif.combine([document(result()), document(result())]);
    assert.equal(resultsOf(doc)[0].properties.flow, "input -> sink, src/a.ts:42");
  });

  it("sorts by severity", () => {
    const [doc] = sarif.combine([
      document(result({ uri: "src/a.ts", severity: "Low" })),
      document(result({ uri: "src/b.ts", severity: "Critical" })),
    ]);
    assert.deepEqual(resultsOf(doc).map((r) => r.properties.severity), ["Critical", "Low"]);
  });

  it("accepts runs with no results", () => {
    const [doc] = sarif.combine([document(), document()]);
    assert.deepEqual(resultsOf(doc), []);
    assert.deepEqual(sarif.validate(doc, RULES), []);
  });

  it("produces output that validates", () => {
    const [doc] = sarif.combine([document(result({ uri: "src/a.ts" })), document(result({ uri: "src/b.ts" }), result())]);
    assert.deepEqual(sarif.validate(doc, RULES), []);
  });
});

describe("exploit details", () => {
  it("strips repro and flow", () => {
    const stripped = sarif.withoutExploitDetails(result());
    assert.ok(!("repro" in stripped.properties));
    assert.ok(!("flow" in stripped.properties));
    assert.ok("fix" in stripped.properties);
  });

  it("leaves the original untouched", () => {
    const original = result();
    sarif.withoutExploitDetails(original);
    assert.ok("repro" in original.properties);
  });
});

describe("helpUri from CI", () => {
  it("is null outside github actions", () => {
    assert.equal(sarif.defaultHelpUri({}), null);
  });

  it("is derived from the actions environment", () => {
    const uri = sarif.defaultHelpUri({ GITHUB_REPOSITORY: "acme/app", GITHUB_REF_NAME: "main" });
    assert.equal(uri, "https://github.com/acme/app/tree/main/.agents/skills/security-audit");
  });
});

describe("cli", () => {
  // The commands end to end, in a throwaway repo root.
  const cwd = process.cwd();
  const log = console.log;
  const error = console.error;
  let tmp;

  before(() => {
    console.log = () => {};
    console.error = () => {};
  });

  after(() => {
    console.log = log;
    console.error = error;
    process.chdir(cwd);
  });

  beforeEach((t) => {
    process.chdir(cwd);
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "sarif-"));
    process.chdir(tmp);
    fs.mkdirSync(sarif.DIR, { recursive: true });
    fs.copyFileSync(RULES_SEED, sarif.RULES_FILE);
    t.after(() => {
      process.chdir(cwd);
      fs.rmSync(tmp, { recursive: true, force: true });
    });
  });

  const writeRun = (doc, file = "security/audit/run.sarif") => {
    sarif.dumpSarif(doc, file);
    return file;
  };
  const read = (file) => JSON.parse(fs.readFileSync(file, "utf-8"));

  it("validate accepts a good file", () => {
    assert.equal(sarif.main(["validate", writeRun(document(result()))]), 0);
  });

  it("validate rejects a bad fingerprint", () => {
    const doc = document(result());
    resultsOf(doc)[0].partialFingerprints[FP] = "idor|src/a.ts|42";
    assert.equal(sarif.main(["validate", writeRun(doc)]), 1);
  });

  it("merge writes the baseline without exploit details", () => {
    const run = writeRun(document(result()));
    assert.equal(sarif.main(["merge", run]), 0);
    const baseline = read(sarif.BASELINE_FILE);
    assert.ok(!("repro" in resultsOf(baseline)[0].properties));
    assert.ok("repro" in resultsOf(read(run))[0].properties);
  });

  it("merge rewrites the run file to this run's new results", () => {
    const run = writeRun(document(result({ uri: "src/a.ts" })));
    sarif.main(["merge", run]);
    const run2 = writeRun(document(result({ uri: "src/a.ts" }), result({ uri: "src/b.ts" })));
    sarif.main(["merge", run2]);
    const added = resultsOf(read(run2));
    assert.deepEqual(added.map(sarif.fingerprint), ["idor|src/b.ts|Controller.method"]);
    assert.equal(resultsOf(read(sarif.BASELINE_FILE)).length, 2);
  });

  it("adds nothing on a second merge of the same run", () => {
    const run = writeRun(document(result()));
    sarif.main(["merge", run]);
    sarif.main(["merge", run]);
    assert.deepEqual(resultsOf(read(run)), []);
    assert.equal(resultsOf(read(sarif.BASELINE_FILE)).length, 1);
  });

  it("leaves the baseline untouched on an invalid run", () => {
    sarif.main(["merge", writeRun(document(result({ uri: "src/a.ts" })))]);
    const before = read(sarif.BASELINE_FILE);
    const bad = document(result({ uri: "src/b.ts", severity: "Info" }));
    assert.equal(sarif.main(["merge", writeRun(bad, "security/audit/bad.sarif")]), 1);
    assert.deepEqual(read(sarif.BASELINE_FILE), before);
  });

  it("heals a baseline written with other path spellings", () => {
    // An existing baseline is normalized on read, so it matches instead of doubling.
    const legacy = document(result({ uri: "./src/a.ts" }));
    resultsOf(legacy)[0].level = "error";
    Object.assign(resultsOf(legacy)[0].properties, { firstSeen: "2025-01-01", lastSeen: "2025-01-01" });
    sarif.dumpSarif(legacy, sarif.BASELINE_FILE);
    const run = writeRun(document(result({ uri: "src/a.ts" })));
    assert.equal(sarif.main(["merge", run]), 0);
    const baseline = read(sarif.BASELINE_FILE);
    assert.equal(resultsOf(baseline).length, 1);
    assert.equal(resultsOf(baseline)[0].properties.firstSeen, "2025-01-01");
    assert.deepEqual(resultsOf(read(run)), []);
  });

  it("fails on a one-line error when the rules file is missing", () => {
    const run = writeRun(document(result()));
    fs.rmSync(sarif.RULES_FILE);
    assert.equal(sarif.main(["validate", run]), 1);
  });

  it("combine writes one run from several", () => {
    const a = writeRun(document(result({ uri: "src/a.ts" })), "g1.sarif");
    const b = writeRun(document(result({ uri: "src/a.ts" }), result({ uri: "src/b.ts" })), "g2.sarif");
    assert.equal(sarif.main(["combine", "out.sarif", a, b]), 0);
    assert.equal(resultsOf(read("out.sarif")).length, 2);
  });

  it("combine writes nothing when one input is invalid", () => {
    const a = writeRun(document(result()), "g1.sarif");
    const b = writeRun(document(result({ severity: "Info" })), "g2.sarif");
    assert.equal(sarif.main(["combine", "out.sarif", a, b]), 1);
    assert.ok(!fs.existsSync("out.sarif"));
  });

  it("combine needs an output and at least one input", () => {
    assert.equal(sarif.main(["combine", "out.sarif"]), 2);
  });

  it("rejects an unknown command", () => {
    assert.equal(sarif.main(["frobnicate"]), 2);
  });
});

describe("rules", () => {
  it("parses the shipped rule list", () => {
    assert.ok("idor" in RULES);
  });

  it("gives every rule a kebab-case id, a name and covers", () => {
    for (const [ruleId, rule] of Object.entries(RULES)) {
      assert.match(ruleId, /^[a-z][a-z0-9-]*$/);
      assert.ok(rule.name && rule.covers);
    }
  });

  it("rejects a malformed rule", () => {
    for (const text of [
      "{}",
      "[]",
      "not json",
      '{"IDOR": {"name": "x", "cwe": [1], "covers": "y"}}',
      '{"idor": {"name": "x", "cwe": ["639"], "covers": "y"}}',
      '{"idor": {"name": "x", "covers": "y"}}',
    ]) {
      assert.throws(() => sarif.parseRules(text), sarif.SarifError);
    }
  });
});
