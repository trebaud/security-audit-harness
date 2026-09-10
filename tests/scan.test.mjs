import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const scan = await import(path.join(ROOT, ".agents", "skills", "scan", "scripts", "scan.mjs"));

/** `n` entry points, `perFile` to a handler file, in module `mod`. */
function endpoints(n, { mod = "src/orders", perFile = 1, start = 0 } = {}) {
  return Array.from({ length: n }, (_, i) => ({
    method: "GET",
    route: `/${path.basename(mod)}/${start + i}`,
    handler: `${mod}/h${Math.floor((start + i) / perFile)}.ts:${10 + i}`,
    module: mod,
  }));
}

describe("moduleOf", () => {
  it("takes the first directory under the scope", () => {
    assert.equal(scan.moduleOf("src/orders/api/controller.ts:4", "src"), "src/orders");
  });

  it("falls back to the scope for a handler directly in it", () => {
    assert.equal(scan.moduleOf("src/app.ts:1", "src"), "src");
  });

  it("works with the repo root as scope", () => {
    assert.equal(scan.moduleOf("api/users.ts", "."), "api");
  });
});

describe("split by endpoints", () => {
  it("groups every <size> entry points", () => {
    const groups = scan.split({ scope: "src", endpoints: endpoints(60) }, { by: "endpoints", size: 25 });
    assert.deepEqual(groups.map((g) => g.endpoints.length), [25, 25, 10]);
    assert.deepEqual(groups.map((g) => g.id), ["g01", "g02", "g03"]);
  });

  it("does not cut a handler file across groups", () => {
    // Files of 4: 24 fit in the first group, the next file starts the second.
    const groups = scan.split({ scope: "src", endpoints: endpoints(30, { perFile: 4 }) }, { by: "endpoints", size: 25 });
    assert.deepEqual(groups.map((g) => g.endpoints.length), [24, 6]);
  });

  it("cuts a file that alone exceeds the size", () => {
    const groups = scan.split({ scope: "src", endpoints: endpoints(30, { perFile: 30 }) }, { by: "endpoints", size: 25 });
    assert.deepEqual(groups.map((g) => g.endpoints.length), [25, 5]);
  });

  it("scopes every group to its manifest", () => {
    const [g] = scan.split({ scope: "src", endpoints: endpoints(3) }, { by: "endpoints", size: 25 });
    assert.equal(g.scope, "@security/audit/scan/manifests/g01.md");
    assert.equal(g.manifest, "g01.md");
    assert.equal(g.endpoints[0], "GET /orders/0 — src/orders/h0.ts:10");
  });

  it("derives the module when the inventory omits it", () => {
    const eps = endpoints(2).map(({ module, ...e }) => e);
    const [g] = scan.split({ scope: "src", endpoints: eps }, { by: "endpoints", size: 25 });
    assert.deepEqual(g.modules, ["src/orders"]);
  });
});

describe("split by modules", () => {
  it("gives each module its directory as scope", () => {
    const inv = { scope: "src", endpoints: [...endpoints(10, { mod: "src/a" }), ...endpoints(12, { mod: "src/b" })] };
    const groups = scan.split(inv, { by: "modules", size: 25 });
    assert.deepEqual(groups.map((g) => g.scope), ["src/a", "src/b"]);
    assert.ok(groups.every((g) => g.manifest === null));
  });

  it("folds small modules together behind a manifest", () => {
    const inv = {
      scope: "src",
      endpoints: [...endpoints(2, { mod: "src/a" }), ...endpoints(3, { mod: "src/b" }), ...endpoints(10, { mod: "src/c" })],
    };
    const groups = scan.split(inv, { by: "modules", size: 25 });
    assert.equal(groups.length, 2);
    assert.deepEqual(groups[0].modules, ["src/a", "src/b"]);
    assert.ok(groups[0].scope.startsWith("@"));
    assert.equal(groups[1].scope, "src/c");
  });

  it("folds a trailing small module into the last group", () => {
    const inv = { scope: "src", endpoints: [...endpoints(10, { mod: "src/a" }), ...endpoints(2, { mod: "src/z" })] };
    const groups = scan.split(inv, { by: "modules", size: 25 });
    assert.equal(groups.length, 1);
    assert.deepEqual(groups[0].modules, ["src/a", "src/z"]);
    assert.ok(groups[0].scope.startsWith("@"));
  });

  it("cuts a module over twice the size", () => {
    const inv = { scope: "src", endpoints: endpoints(60, { mod: "src/big" }) };
    const groups = scan.split(inv, { by: "modules", size: 25 });
    assert.deepEqual(groups.map((g) => g.endpoints.length), [25, 25, 10]);
    assert.ok(groups.every((g) => g.scope.startsWith("@")));
  });

  it("keeps a module up to twice the size whole", () => {
    const groups = scan.split({ scope: "src", endpoints: endpoints(40, { mod: "src/m" }) }, { by: "modules", size: 25 });
    assert.equal(groups.length, 1);
    assert.equal(groups[0].scope, "src/m");
  });

  it("rejects an unknown strategy", () => {
    assert.throws(() => scan.split({ endpoints: endpoints(1) }, { by: "files", size: 25 }), scan.ScanError);
  });
});

describe("patternMatcher", () => {
  const e = (method, route, handler) => ({ method, route, handler, module: "m" });

  it("matches method and route", () => {
    const m = scan.patternMatcher("POST /admin/**");
    assert.ok(m(e("POST", "/admin/users/1", "src/x.ts:1")));
    assert.ok(!m(e("GET", "/admin/users/1", "src/x.ts:1")));
    assert.ok(!m(e("POST", "/public", "src/x.ts:1")));
  });

  it("takes * for any method, case-insensitively", () => {
    const m = scan.patternMatcher("* /webhooks/*");
    assert.ok(m(e("webhook", "/webhooks/stripe", "src/x.ts:1")));
    assert.ok(!m(e("POST", "/webhooks/stripe/retry", "src/x.ts:1")));
  });

  it("matches a handler-file glob", () => {
    const m = scan.patternMatcher("src/**/admin*.ts");
    assert.ok(m(e("GET", "/a", "src/users/api/adminController.ts:3")));
    assert.ok(!m(e("GET", "/a", "src/users/api/user.ts:3")));
  });

  it("treats a plain path as a directory prefix", () => {
    const m = scan.patternMatcher("src/pay/");
    assert.ok(m(e("GET", "/a", "src/pay/refund.ts:3")));
    assert.ok(!m(e("GET", "/a", "src/payouts/x.ts:3")));
  });
});

describe("splitCustom", () => {
  const inv = {
    scope: "src",
    endpoints: [
      ...endpoints(3, { mod: "src/pay" }),
      { method: "POST", route: "/admin/ban", handler: "src/users/admin.ts:5", module: "src/users" },
      { method: "GET", route: "/admin/stats", handler: "src/pay/stats.ts:9", module: "src/pay" },
      { method: "GET", route: "/me", handler: "src/users/me.ts:2", module: "src/users" },
    ],
  };

  it("builds dir and match groups, named, in the user's order", () => {
    const { groups } = scan.splitCustom(inv, {
      groups: [
        { name: "admin", match: ["* /admin/**"] },
        { name: "payments", dir: "src/pay" },
      ],
    });
    assert.deepEqual(groups.map((g) => [g.id, g.name, g.endpoints.length]), [["g01", "admin", 2], ["g02", "payments", 3], ["g03", "unassigned", 1]]);
    assert.equal(groups[0].scope, "@security/audit/scan/manifests/g01.md");
    assert.equal(groups[1].scope, "src/pay");
    assert.equal(groups[1].manifest, null);
  });

  it("gives an entry point to the first group and reports the overlap", () => {
    const { groups, overlaps } = scan.splitCustom(inv, {
      groups: [{ name: "admin", match: ["* /admin/**"] }, { name: "payments", dir: "src/pay" }],
    });
    assert.ok(!groups[1].endpoints.some((l) => l.includes("/admin/stats")));
    assert.deepEqual(overlaps, [{ endpoint: "GET /admin/stats — src/pay/stats.ts:9", groups: ["admin", "payments"] }]);
  });

  it("drops unassigned entry points when told, and returns them", () => {
    const { groups, unassigned } = scan.splitCustom(inv, { groups: [{ dir: "src/pay" }], unassigned: "drop" });
    assert.equal(groups.length, 1);
    assert.deepEqual(unassigned.sort(), ["GET /me — src/users/me.ts:2", "POST /admin/ban — src/users/admin.ts:5"]);
  });

  it("rejects a group that matches nothing", () => {
    assert.throws(() => scan.splitCustom(inv, { groups: [{ name: "ghost", match: ["src/nope/**"] }] }), /no entry point matches ghost/);
  });

  it("rejects a group with both or neither of dir and match", () => {
    assert.throws(() => scan.splitCustom(inv, { groups: [{ dir: "src/pay", match: ["x"] }] }), scan.ScanError);
    assert.throws(() => scan.splitCustom(inv, { groups: [{ name: "x" }] }), scan.ScanError);
  });

  it("rejects duplicate names and a bad unassigned policy", () => {
    assert.throws(() => scan.splitCustom(inv, { groups: [{ name: "a", dir: "src/pay" }, { name: "a", match: ["/me"] }] }), /duplicate/);
    assert.throws(() => scan.splitCustom(inv, { groups: [{ dir: "src/pay" }], unassigned: "keep" }), scan.ScanError);
  });
});

describe("hasPlaceholders", () => {
  it("flags the template", () => {
    const template = fs.readFileSync(
      path.join(ROOT, ".agents/skills/security-audit/references/THREAT_MODEL_TEMPLATE.md"),
      "utf-8",
    );
    assert.ok(scan.hasPlaceholders(template));
  });

  it("flags a leftover placeholder", () => {
    assert.ok(scan.hasPlaceholders("# Threat model — <project name>\n"));
  });

  it("passes a filled model with generics in code", () => {
    assert.ok(!scan.hasPlaceholders("# Threat model — shop\n\nReturns `Promise<Order>` from `load()`.\n"));
  });
});

describe("setupCommands", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "scan-setup-"));
  after(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("uses the lockfile", () => {
    fs.writeFileSync(path.join(dir, "package.json"), "{}");
    fs.writeFileSync(path.join(dir, "pnpm-lock.yaml"), "");
    assert.deepEqual(scan.setupCommands(dir, "git"), ["pnpm install --frozen-lockfile"]);
  });

  it("runs .mori.json post_create for the git backend and leaves it to mori otherwise", () => {
    fs.writeFileSync(path.join(dir, ".mori.json"), JSON.stringify({ post_create: [{ name: "x", cmd: "make deps" }] }));
    assert.deepEqual(scan.setupCommands(dir, "git"), ["make deps"]);
    assert.deepEqual(scan.setupCommands(dir, "mori"), []);
  });
});

describe("end to end, git backend", () => {
  // A throwaway repo with the harness installed and a stub `claude` that writes
  // one finding per group into the worktree it runs in.
  const cwd = process.cwd();
  const log = console.log;
  const error = console.error;
  const envPath = process.env.PATH;
  let base;
  let repo;
  const runDir = "security/audit/scan/2026-09-22-1200";

  const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { cwd: repo, encoding: "utf-8", ...opts });

  before(() => {
    console.log = () => {};
    console.error = () => {};
    base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "scan-e2e-")));
    repo = path.join(base, "app");
    fs.mkdirSync(repo);
    run("git", ["init", "-q", "-b", "main"]);
    run("git", ["config", "user.email", "t@example.com"]);
    run("git", ["config", "user.name", "t"]);
    fs.cpSync(path.join(ROOT, ".agents"), path.join(repo, ".agents"), { recursive: true });
    fs.mkdirSync(path.join(repo, "security/audit"), { recursive: true });
    fs.copyFileSync(path.join(ROOT, "security/audit/rules.json"), path.join(repo, "security/audit/rules.json"));
    fs.writeFileSync(path.join(repo, ".gitignore"), "security/audit/scan/\nsecurity/audit/run.sarif\nsecurity/audit/reports/\n");
    for (const m of ["a", "b"]) {
      fs.mkdirSync(path.join(repo, "src", m), { recursive: true });
      fs.writeFileSync(path.join(repo, "src", m, "h.ts"), "export const h = 1;\n");
    }
    run("git", ["add", "-A"]);
    run("git", ["commit", "-q", "-m", "init"]);
    // Derived this run and not committed: must still reach every worktree.
    fs.writeFileSync(path.join(repo, "THREAT_MODEL.md"), "# Threat model — app\n");

    const bin = path.join(base, "bin");
    fs.mkdirSync(bin);
    const stub = `#!/usr/bin/env node
const fs = require("fs");
const prompt = process.argv[process.argv.indexOf("-p") + 1];
const scope = /args: \`(\\S+)/.exec(prompt)[1];
const g = scope.startsWith("@") ? scope.replace(/.*\\/(g\\d+)\\.md$/, "$1") : scope.split("/").pop();
if (!fs.existsSync("THREAT_MODEL.md")) process.exit(4);
const uri = "src/shared.ts";
const r = (sym, sev) => ({ ruleId: "idor", message: { text: "x" },
  locations: [{ physicalLocation: { artifactLocation: { uri }, region: { startLine: 1 } } }],
  partialFingerprints: { "security-audit/v1": "idor|" + uri + "|" + sym },
  properties: { severity: sev, flow: "flow from " + g, impact: "i", likelihood: "l", repro: "", fix: "f" } });
fs.mkdirSync("security/audit/reports", { recursive: true });
fs.writeFileSync("security/audit/run.sarif", JSON.stringify({ version: "2.1.0",
  runs: [{ tool: { driver: { name: "security-audit" } }, results: [r("Shared.load", "Medium"), r("Only." + g, "Low")] }] }));
fs.writeFileSync("security/audit/reports/" + g + "-2026-09-22.md", "# report " + g + "\\n");
fs.mkdirSync("test/security", { recursive: true });
fs.writeFileSync("test/security/" + g + ".test.ts", "// " + g + "\\n");
`;
    fs.writeFileSync(path.join(bin, "claude"), stub, { mode: 0o755 });
    process.env.PATH = `${bin}${path.delimiter}${envPath}`;
    process.chdir(repo);
    fs.mkdirSync(runDir, { recursive: true });
    fs.writeFileSync(
      path.join(runDir, "inventory.json"),
      JSON.stringify({
        scope: "src",
        endpoints: [...endpoints(6, { mod: "src/a" }), ...endpoints(6, { mod: "src/b" })].map((e) => ({
          ...e,
          handler: e.handler.replace(/h\d+\.ts/, "h.ts"),
        })),
      }),
    );
  });

  after(() => {
    console.log = log;
    console.error = error;
    process.env.PATH = envPath;
    process.chdir(cwd);
    fs.rmSync(base, { recursive: true, force: true });
  });

  it("preflight passes and sees the uncommitted threat model", async () => {
    assert.equal(await scan.main(["preflight", "src"]), 0);
  });

  it("init writes one group per module", async () => {
    assert.equal(await scan.main(["init", runDir, "--scope", "src", "--by", "modules"]), 0);
    const plan = scan.readPlan(runDir);
    assert.deepEqual(plan.groups.map((g) => g.scope), ["src/a", "src/b"]);
    assert.equal(plan.threatModel, "THREAT_MODEL.md");
  });

  it("init --by custom reads split.json and replaces the previous groups", async () => {
    fs.writeFileSync(
      path.join(runDir, "split.json"),
      JSON.stringify({ groups: [{ name: "b-first", match: ["src/b/**"] }, { name: "a", dir: "src/a" }] }),
    );
    assert.equal(await scan.main(["init", runDir, "--scope", "src", "--by", "custom"]), 0);
    const plan = scan.readPlan(runDir);
    assert.deepEqual(plan.groups.map((g) => [g.name, g.scope]), [["b-first", "@security/audit/scan/manifests/g01.md"], ["a", "src/a"]]);
    assert.deepEqual(fs.readdirSync(path.join(runDir, "manifests")), ["g01.md"]);
  });

  it("init --by custom rejects a dir that does not exist", async () => {
    fs.writeFileSync(path.join(runDir, "split.json"), JSON.stringify({ groups: [{ dir: "src/nope" }] }));
    assert.equal(await scan.main(["init", runDir, "--scope", "src", "--by", "custom"]), 1);
  });

  it("init back to modules for the rest of the run", async () => {
    assert.equal(await scan.main(["init", runDir, "--scope", "src", "--by", "modules"]), 0);
  });

  it("creates the worktrees outside the repo, with the threat model copied in", async () => {
    assert.equal(await scan.main(["worktrees", runDir, "--backend", "git", "--no-setup"]), 0);
    for (const g of scan.readPlan(runDir).groups) {
      assert.ok(!g.worktree.startsWith(repo + path.sep));
      assert.ok(fs.existsSync(path.join(g.worktree, "THREAT_MODEL.md")));
      assert.ok(fs.existsSync(path.join(g.worktree, ".agents/skills/security-audit/SKILL.md")));
    }
  });

  it("is idempotent on a second worktrees call", async () => {
    const before = scan.readPlan(runDir).groups.map((g) => g.worktree);
    assert.equal(await scan.main(["worktrees", runDir, "--backend", "git", "--no-setup"]), 0);
    assert.deepEqual(scan.readPlan(runDir).groups.map((g) => g.worktree), before);
  });

  it("runs every group", async () => {
    assert.equal(await scan.main(["run", runDir, "--parallel", "2"]), 0);
    assert.ok(scan.readPlan(runDir).groups.every((g) => g.status === "done"));
  });

  it("skips done groups on a second run", async () => {
    const before = scan.readPlan(runDir).groups.map((g) => g.finishedAt);
    assert.equal(await scan.main(["run", runDir]), 0);
    assert.deepEqual(scan.readPlan(runDir).groups.map((g) => g.finishedAt), before);
  });

  it("collects one combined run, deduped across groups", async () => {
    assert.equal(await scan.main(["collect", runDir]), 0);
    const combined = JSON.parse(fs.readFileSync(path.join(runDir, "combined.sarif"), "utf-8"));
    const fps = combined.runs[0].results.map((r) => r.partialFingerprints["security-audit/v1"]);
    assert.deepEqual(fps.sort(), ["idor|src/shared.ts|Only.a", "idor|src/shared.ts|Only.b", "idor|src/shared.ts|Shared.load"]);
    const shared = combined.runs[0].results.find((r) => r.partialFingerprints["security-audit/v1"].endsWith("Shared.load"));
    assert.equal(shared.properties.flow, "flow from a\nflow from b");
    assert.equal(fs.readdirSync(path.join(runDir, "reports")).length, 2);
  });

  it("finds the tests each group wrote and nothing it copied in", () => {
    const plan = scan.readPlan(runDir);
    assert.deepEqual(plan.groups.map((g) => g.tests.added), [["test/security/a.test.ts"], ["test/security/b.test.ts"]]);
  });

  it("copies the tests into the main tree", async () => {
    assert.equal(await scan.main(["copy-tests", runDir]), 0);
    assert.ok(fs.existsSync("test/security/a.test.ts"));
    assert.ok(fs.existsSync("test/security/b.test.ts"));
  });

  it("removes worktrees and branches", async () => {
    const trees = scan.readPlan(runDir).groups.map((g) => g.worktree);
    assert.equal(await scan.main(["cleanup", runDir]), 0);
    for (const t of trees) assert.ok(!fs.existsSync(t));
    assert.equal(run("git", ["branch", "--list", "scan-*"]).trim(), "");
  });
});
