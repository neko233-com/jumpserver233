import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, utimesSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { planRetention, applyRetention, retainQAArtifacts } from "./qa-retention.mjs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";

function fixture(t) {
  const root = mkdtempSync(resolve(tmpdir(), "jms233-retention-test-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  function put(path, value = "synthetic QA artifact") {
    path = resolve(root, path); mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, typeof value === "object" ? JSON.stringify(value) : value);
    return path;
  }
  function browser(index, change = {}) {
    const folder = `.cache/qa-reports/browser-${1792400000000 + index}`;
    put(`${folder}/summary.json`, { status: "passed" });
    put(`${folder}/cleanup.json`, { cleaned: true, temporaryDataRemoved: true, ...change });
    for (const name of ["old.en.png", "new.en.png", "new.zh-CN.png", "extra.png", "trace.zip"]) put(`${folder}/${name}`);
    return resolve(root, folder);
  }
  return { root, put, browser };
}

test("preview is read-only; newest three runs keep compact receipts and a bilingual screenshot pair", t => {
  const { root, browser } = fixture(t), folders = Array.from({ length: 5 }, (_, i) => browser(i));
  const plan = planRetention(root);
  assert.ok(existsSync(resolve(folders[0], "summary.json")));
  assert.equal(plan.directories.length, 2);
  const result = applyRetention(plan);
  assert.equal(result.removedFiles, 23);
  assert.equal(existsSync(folders[0]), false);
  for (const folder of folders.slice(2)) {
    assert.ok(existsSync(resolve(folder, "summary.json")));
    const next = planRetention(root);
    assert.equal(next.selected.length, 0);
  }
  assert.equal(applyRetention(plan).removedFiles, 0);
});

test("live PIDs and incomplete cleanup preserve artifacts", t => {
  const { root, browser, put } = fixture(t);
  const active = browser(0), incomplete = browser(1, { cleaned: false });
  put(`${active}/lifecycle.json`, { pid: 12345, status: "running" });
  const plan = planRetention(root, { isAlive: pid => pid === 12345 });
  assert.equal(plan.selected.length, 0);
  assert.equal(plan.skipped.length, 2);
  assert.ok(existsSync(resolve(incomplete, "trace.zip")));
});

test("terminal current run can be retained while its runner process is still alive", t => {
  const { root, browser, put } = fixture(t), folder = browser(0);
  put(`${folder}/lifecycle.json`, { pid: process.pid, status: "passed" });
  assert.equal(planRetention(root).selected.length, 0);
  assert.ok(planRetention(root, { currentRun: folder }).selected.length > 0);
});

test("Docker retained environments and failed diagnostics survive; successful duplicate receipts are removed", t => {
  const { root, put } = fixture(t);
  for (const [name, success, retained] of [["jms233-debug-a", true, true], ["jms233-debug-b", false, false], ["jms233-debug-c", true, false]]) {
    const folder = `.cache/docker-qa/${name}`;
    put(`${folder}/summary.json`, { project: name, cleaned: true, success, retained });
    put(`${folder}/summary-123.json`, {}); put(`${folder}/verify.log`);
  }
  retainQAArtifacts(root);
  assert.ok(existsSync(resolve(root, ".cache/docker-qa/jms233-debug-a/summary-123.json")));
  assert.ok(existsSync(resolve(root, ".cache/docker-qa/jms233-debug-b/verify.log")));
  assert.equal(existsSync(resolve(root, ".cache/docker-qa/jms233-debug-c/verify.log")), false);
});

test("only explicit legacy cleanup removes old known helpers; source and documentation images survive", t => {
  const { root, put } = fixture(t);
  const old = put(".cache/migration-native.mjs"), fresh = put(".cache/discovery-new.mjs");
  utimesSync(old, new Date(0), new Date(0));
  const config = put(".cache/branding.playwright.config.mjs");
  utimesSync(config, new Date(0), new Date(0));
  const keep = [put(".cache/custom-tool.mjs"), put("docs/images/inventory.en.png"), put("screenshots/user.png"), put("server/data/users.json")];
  assert.equal(planRetention(root).selected.length, 0);
  retainQAArtifacts(root, { legacy: true });
  assert.equal(existsSync(old), false);
  assert.equal(existsSync(config), false);
  assert.ok(existsSync(fresh)); keep.forEach(path => assert.ok(existsSync(path)));
});

test("legacy named reports preserve JSON receipts and only two screenshots", t => {
  const { root, put } = fixture(t), folder = ".cache/qa-reports/backup";
  put(`${folder}/summary.json`, { status: "passed" }); put(`${folder}/backend.json`, { passed: 10 });
  put(`${folder}/run.log`);
  for (const name of ["manual.en.png", "manual.zh.png", "extra.png"]) put(`${folder}/${name}`);
  retainQAArtifacts(root, { legacy: true });
  assert.ok(existsSync(resolve(root, folder, "backend.json")));
  assert.equal(existsSync(resolve(root, folder, "extra.png")), false);
  assert.equal(existsSync(resolve(root, folder, "run.log")), false);
  assert.equal(retainQAArtifacts(root, { legacy: true }).removedFiles, 0);
  assert.equal(JSON.parse(readFileSync(resolve(root, ".cache/qa-reports/retention.json"))).removedFiles, 0);
  put(".cache/qa-reports/older/report.json", { browser: { passed: 10, failed: 0 } });
  put(".cache/qa-reports/older/old.log");
  assert.equal(retainQAArtifacts(root, { legacy: true }).removedFiles, 1);
  put(".cache/qa-reports/failed/report.json", { browser: { passed: 2, failed: 1 } });
  const diagnostic = put(".cache/qa-reports/failed/run.log");
  retainQAArtifacts(root, { legacy: true });
  assert.ok(existsSync(diagnostic));
});

test("changed files, forged source paths and linked artifact ancestors are rejected", t => {
  const { root, browser, put } = fixture(t);
  browser(0);
  const plan = planRetention(root), file = plan.selected[0];
  writeFileSync(file.path, "changed after preview");
  assert.throws(() => applyRetention(plan), e => /changed since preview/.test(e.message) && e.retention.removedFiles === 0 && Boolean(e.retention.error));
  const source = put("server/main.go");
  assert.throws(() => applyRetention({ root, selected: [{ path: source }], directories: [] }), /Unowned/);
  const outside = mkdtempSync(resolve(tmpdir(), "jms233-retention-foreign-"));
  t.after(() => rmSync(outside, { recursive: true, force: true }));
  symlinkSync(outside, resolve(root, ".cache/qa-reports/browser-1792499999999"), "junction");
  assert.ok(existsSync(outside));
  // A linked report is never traversed or selected.
  assert.ok(planRetention(root).selected.every(f => !f.path.includes("1792499999999")));
});

test("linked output receipts cannot overwrite another file", t => {
  const { root, put } = fixture(t), outside = put("important.txt", "keep");
  mkdirSync(resolve(root, ".cache/qa-reports"), { recursive: true });
  try { symlinkSync(outside, resolve(root, ".cache/qa-reports/retention.json"), "file"); }
  catch (e) {
    if (e.code !== "EPERM") throw e;
    // Windows junctions exercise the same output-link guard without symlink privileges.
    symlinkSync(dirname(outside), resolve(root, ".cache/qa-reports/retention.json"), "junction");
  }
  assert.throws(() => retainQAArtifacts(root), /links/);
  assert.equal(readFileSync(outside, "utf8"), "keep");
});

test("Git excludes generated evidence and secrets while keeping product screenshots and source", () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  for (const path of [".cache/qa-reports/new.png", "screenshots/qa.png", "web/test-results/trace.zip", "web/blob-report/report.zip", "server/coverage-unit.out", "server/profile.cpuprofile", "tmp/test.exe", "data/vault.key", "backup.jmsbackup", ".jms233-stage-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/partial", "local/.jms233-releases.json", "local/.jms233-release.json"]) {
    const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", path], { cwd: root });
    assert.equal(result.status, 0, `${path} must be ignored`);
  }
  for (const path of ["docs/images/inventory.en.png", "web/src/main.tsx", "scripts/qa-retention.mjs", "web/.env.example"]) {
    const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", path], { cwd: root });
    assert.equal(result.status, 1, `${path} must remain visible`);
  }
});

test("content checks reject newly orphaned product images and the negative fixture is removed", () => {
  const root = fileURLToPath(new URL("..", import.meta.url));
  const image = resolve(root, "docs/images", `.qa-orphan-${randomUUID()}.png`);
  writeFileSync(image, "synthetic image-reference fixture", { flag: "wx" });
  try {
    const result = spawnSync(process.execPath, [resolve(root, "scripts/check-content.mjs")], { cwd: root, encoding: "utf8" });
    assert.equal(result.status, 1);
    assert.match(JSON.parse(result.stdout).errors.join("\n"), /Unreferenced documentation image:.*\.qa-orphan-/);
  } finally { unlinkSync(image); }
  assert.equal(existsSync(image), false);
});
