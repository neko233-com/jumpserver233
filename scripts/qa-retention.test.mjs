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

test("expired successful runs never evict failed browser or Docker receipts", t => {
  const { root, browser, put } = fixture(t);
  const failedBrowser = browser(0);
  put(`${failedBrowser}/summary.json`, { status: "failed", failures: ["sanitized failure"] });
  for (let i = 1; i <= 5; i++) browser(i);
  const docker = index => `.cache/docker-qa/jms233-qa-00000000-0000-0000-0000-${String(index).padStart(12, "0")}`;
  for (let i = 0; i <= 5; i++) {
    const folder = docker(i);
    const path = put(`${folder}/summary.json`, { project: folder.split("/").at(-1), cleaned: true, success: i !== 0 });
    utimesSync(path, new Date(i * 1000), new Date(i * 1000));
    put(`${folder}/verify.log`, "bounded failure diagnostic");
  }
  retainQAArtifacts(root);
  assert.ok(existsSync(resolve(failedBrowser, "summary.json")));
  assert.ok(existsSync(resolve(root, docker(0), "summary.json")));
  assert.ok(existsSync(resolve(root, docker(0), "verify.log")));
  assert.equal(existsSync(resolve(root, docker(1))), false);
  for (let i = 3; i <= 5; i++) assert.ok(existsSync(resolve(root, docker(i), "summary.json")));
  assert.equal(retainQAArtifacts(root).removedFiles, 0);
});

test("a failed final lifecycle protects an otherwise passing browser summary", t => {
  const { root, browser, put } = fixture(t), folder = browser(0);
  put(`${folder}/lifecycle.json`, { status: "failed", artifactRetentionFailed: true });
  for (let i = 1; i <= 5; i++) browser(i);
  retainQAArtifacts(root);
  assert.ok(existsSync(resolve(folder, "summary.json")));
  assert.equal(JSON.parse(readFileSync(resolve(folder, "lifecycle.json"))).status, "failed");
});

test("legacy Web helpers use a fixed allowlist, age limit and active-run protection", t => {
  const { root, put } = fixture(t);
  const old = put("web/.cache/risk-qa.config.mjs"), fresh = put("web/.cache/ticket-qa.config.mjs");
  const keep = [put("web/.cache/custom-qa.config.mjs"), put("web/src/risk-qa.config.mjs"), put("web/.cache/account-risks-results/risk-result.json")];
  utimesSync(old, new Date(0), new Date(0));
  assert.equal(planRetention(root).selected.length, 0);
  const receipt = put(".cache/qa-reports/current/lifecycle.json", { pid: 12345, status: "running" });
  assert.equal(planRetention(root, { legacy: true, isAlive: pid => pid === 12345 }).selected.length, 0);
  unlinkSync(receipt);
  assert.equal(retainQAArtifacts(root, { legacy: true, isAlive: () => false }).removedFiles, 1);
  assert.ok(existsSync(fresh)); keep.forEach(path => assert.ok(existsSync(path)));
  assert.equal(retainQAArtifacts(root, { legacy: true }).removedFiles, 0);
});

test("a new run after legacy preview protects helpers before any deletion", t => {
  const { root, put } = fixture(t), helper = put("web/.cache/risk-qa.config.mjs");
  utimesSync(helper, new Date(0), new Date(0));
  const plan = planRetention(root, { legacy: true });
  assert.equal(plan.selected.length, 1);
  put(".cache/qa-reports/new-run/lifecycle.json", { pid: process.pid, status: "running" });
  assert.throws(() => applyRetention(plan), /activity changed/);
  assert.ok(existsSync(helper));
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
  const folder = browser(0), trace = resolve(folder, "trace.zip");
  utimesSync(trace, 42, 42);
  const plan = planRetention(root), file = plan.selected.find(file => file.path === trace);
  assert.equal(file.size, Buffer.byteLength("changed after preview"));
  writeFileSync(file.path, "changed after preview");
  // Equal size and an intentionally identical mtime must still detect content changes.
  utimesSync(file.path, 42, 42);
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

test("completed native runners compact their current evidence and preserve other named reports", t => {
  const { root, put } = fixture(t), folder = ".cache/qa-reports/native";
  put(`${folder}/native-packages.json`, { pid: process.pid, status: "passed", cleanup: { removed: true, idempotent: true, temporaryArtifactsRemoved: true } });
  put(`${folder}/linux-race.json`, { status: "passed", cleanup: { removed: true, idempotent: true } });
  for (const name of ["files.en.jpeg", "files.zh.webp", "extra.png", "run.log"]) put(`${folder}/${name}`);
  const other = put(".cache/qa-reports/other/report.json", { status: "passed" });
  const otherImage = put(".cache/qa-reports/other/extra.png");
  const currentRun = resolve(root, folder);
  assert.equal(planRetention(root).selected.length, 0);
  assert.equal(retainQAArtifacts(root, { currentRun }).removedFiles, 2);
  assert.ok(existsSync(resolve(root, folder, "files.en.jpeg")));
  assert.ok(existsSync(resolve(root, folder, "files.zh.webp")));
  assert.ok(existsSync(other)); assert.ok(existsSync(otherImage));
  assert.equal(retainQAArtifacts(root, { currentRun }).removedFiles, 0);
});

test("native child PIDs, failed race checks and incomplete cleanup protect diagnostics", t => {
  const { root, put } = fixture(t), folder = ".cache/qa-reports/native";
  const native = { status: "passed", cleanup: { removed: true, idempotent: true, temporaryArtifactsRemoved: true } };
  const report = put(`${folder}/native-packages.json`, native);
  const log = put(`${folder}/run.log`);
  const currentRun = resolve(root, folder);
  const options = { currentRun, legacy: true, isAlive: pid => pid === 12345 };
  put(`${folder}/linux-race.json`, { status: "running", childPID: 12345 });
  assert.equal(planRetention(root, options).selected.length, 0);
  assert.match(planRetention(root, options).skipped[0].reason, /active process/);
  put(`${folder}/linux-race.json`, { status: "failed", cleanup: { removed: true, idempotent: true } });
  assert.equal(planRetention(root, options).selected.length, 0);
  put(`${folder}/linux-race.json`, { status: "passed", cleanup: { removed: true, idempotent: true } });
  writeFileSync(report, JSON.stringify({ ...native, cleanup: { removed: false } }));
  assert.equal(planRetention(root, options).selected.length, 0);
  assert.ok(existsSync(log));
});

test("named screenshot history is bounded independently of durable reports and empty batches", t => {
  const { root, put } = fixture(t);
  const native = { status: "passed", cleanup: { removed: true, idempotent: true, temporaryArtifactsRemoved: true } };
  const batches = Array.from({ length: 5 }, (_, i) => {
    const folder = `.cache/qa-reports/feature-${i}`;
    const receipt = put(`${folder}/native-packages.json`, native);
    const summary = put(`${folder}/summary.json`, { status: "passed" });
    const images = ["result.en.png", "result.zh-CN.png"].map(name => {
      const path = put(`${folder}/${name}`);
      utimesSync(path, new Date(1000 + i), new Date(1000 + i));
      return path;
    });
    return { receipt, summary, images };
  });
  // Updating a receipt does not make old screenshots current evidence.
  utimesSync(batches[0].summary, new Date(), new Date());
  const empty = put(".cache/qa-reports/newer-without-images/native-packages.json", native);
  const protectedFiles = [empty];
  for (const [name, changed] of [["failed", { status: "failed" }], ["incomplete", { cleanup: {} }], ["active", { pid: 12345 }]]) {
    protectedFiles.push(put(`.cache/qa-reports/${name}/native-packages.json`, { ...native, ...changed }));
    protectedFiles.push(put(`.cache/qa-reports/${name}/diagnostic.png`));
  }
  const options = { isAlive: pid => pid === 12345 };
  const result = retainQAArtifacts(root, options);
  assert.equal(result.removedFiles, 4);
  batches.slice(0, 2).flatMap(b => b.images).forEach(path => assert.equal(existsSync(path), false));
  [...batches.flatMap(b => [b.receipt, b.summary]), ...batches.slice(2).flatMap(b => b.images), ...protectedFiles].forEach(path => assert.ok(existsSync(path)));
  assert.equal(retainQAArtifacts(root, options).removedFiles, 0);
});

test("the current named batch occupies one screenshot slot even with older timestamps", t => {
  const { root, put } = fixture(t);
  const folders = Array.from({ length: 5 }, (_, i) => {
    const folder = `.cache/qa-reports/named-${i}`;
    put(`${folder}/summary.json`, { status: "passed" });
    const image = put(`${folder}/result.en.png`);
    utimesSync(image, new Date(1000 + i), new Date(1000 + i));
    return { folder: resolve(root, folder), image };
  });
  const options = { legacy: true, currentRun: folders[0].folder };
  assert.equal(retainQAArtifacts(root, options).removedFiles, 2);
  for (const i of [0, 3, 4]) assert.ok(existsSync(folders[i].image));
  for (const i of [1, 2]) assert.equal(existsSync(folders[i].image), false);
  assert.equal(retainQAArtifacts(root, options).removedFiles, 0);
});

test("named Docker histories share the three screenshot slots without losing summaries", t => {
  const { root, put } = fixture(t), batches = [];
  for (let i = 0; i < 5; i++) {
    const project = `jms233-review-${i}`, folder = `.cache/docker-qa/${project}`;
    const summary = put(`${folder}/summary.json`, { project, success: true, cleaned: true });
    const images = ["result.en.png", "result.zh.png"].map(name => {
      const image = put(`${folder}/${name}`);
      utimesSync(image, new Date(1000 + i), new Date(1000 + i)); return image;
    });
    batches.push({ summary, images });
  }
  const protectedImages = [];
  for (const [project, change] of [["jms233-failed", { success: false }], ["jms233-retained", { retained: true }]]) {
    const folder = `.cache/docker-qa/${project}`;
    put(`${folder}/summary.json`, { project, success: true, cleaned: true, ...change });
    protectedImages.push(put(`${folder}/diagnostic.png`));
  }
  assert.equal(retainQAArtifacts(root).removedFiles, 4);
  batches.slice(0, 2).flatMap(b => b.images).forEach(path => assert.equal(existsSync(path), false));
  [...batches.map(b => b.summary), ...batches.slice(2).flatMap(b => b.images), ...protectedImages].forEach(path => assert.ok(existsSync(path)));
  assert.equal(retainQAArtifacts(root).removedFiles, 0);
});

test("a failed final lifecycle protects named and Docker diagnostic histories", t => {
  const { root, put } = fixture(t), protectedFiles = [];
  for (const [folder, summary] of [[".cache/qa-reports/feature", { status: "passed" }], [".cache/docker-qa/jms233-review", { project: "jms233-review", success: true, cleaned: true }]]) {
    put(`${folder}/summary.json`, summary);
    put(`${folder}/lifecycle.json`, { status: "failed", artifactRetentionFailed: true });
    protectedFiles.push(put(`${folder}/diagnostic.png`), put(`${folder}/verify.log`));
  }
  const plan = planRetention(root, { legacy: true });
  assert.equal(plan.selected.length, 0);
  assert.equal(plan.skipped.filter(row => row.reason === "incomplete or failed runner result").length, 2);
  applyRetention(plan);
  protectedFiles.forEach(path => assert.ok(existsSync(path)));
});

test("only three completed read-only cleanup snapshots survive; recovery receipts remain", t => {
  const { root, put } = fixture(t);
  const base = { root, applied: false, after: "synthetic disk summary", removed: { containers: 0, volumes: 0, networks: 0, images: 0 } };
  const previews = Array.from({ length: 6 }, (_, i) => {
    const path = put(`.cache/qa-reports/cleanup-${1792400000000 + i}.json`, base);
    utimesSync(path, new Date(1000 + i), new Date(1000 + i)); return path;
  });
  const keep = [
    put(".cache/qa-reports/cleanup-1792400000100.json", { ...base, applied: true, composeEvidence: [{ ownership: "keep for retry" }] }),
    put(".cache/qa-reports/cleanup-1792400000101.json", { ...base, error: "daemon unavailable" }),
    put(".cache/qa-reports/cleanup-1792400000102.json", { ...base, root: resolve(root, "foreign") }),
    put(".cache/qa-reports/cleanup-1792400000103.json", { ...base, after: undefined }),
    put(".cache/qa-reports/cleanup-1792400000104.json", { ...base, removed: { images: 1 } }),
    put(".cache/qa-reports/cleanup-1792400000105.json", { ...base, removed: null }),
  ];
  assert.equal(planRetention(root).selected.length, 3);
  assert.equal(retainQAArtifacts(root).removedFiles, 3);
  previews.slice(0, 3).forEach(path => assert.equal(existsSync(path), false));
  [...previews.slice(3), ...keep].forEach(path => assert.ok(existsSync(path)));
  assert.equal(retainQAArtifacts(root).removedFiles, 0);
});

test("partially written runner receipts preserve their batch until a complete result exists", t => {
  const { root, put } = fixture(t), folder = ".cache/qa-reports/race-only";
  const receipt = put(`${folder}/linux-race.json`, '{"status":');
  const log = put(`${folder}/run.log`), options = { currentRun: resolve(root, folder) };
  let plan = planRetention(root, options);
  assert.equal(plan.selected.length, 0);
  assert.match(plan.skipped[0].reason, /unreadable runner receipt/);
  assert.ok(existsSync(log));
  writeFileSync(receipt, JSON.stringify({ status: "passed", cleanup: { removed: true, idempotent: true } }));
  assert.equal(retainQAArtifacts(root, options).removedFiles, 1);
  assert.equal(retainQAArtifacts(root, options).removedFiles, 0);
});

test("cleaned historical native batches automatically discard raw artifacts but retain compact reports", t => {
  const { root, put } = fixture(t), folder = ".cache/qa-reports/completed-native";
  put(`${folder}/native-packages.json`, { status: "passed", cleanup: { removed: true, idempotent: true, temporaryArtifactsRemoved: true } });
  put(`${folder}/linux-race.json`, { status: "passed", cleanup: { removed: true, idempotent: true } });
  const kept = ["backend.json", "diagnostic.txt", "investigation.md", "approval.en.png", "approval.zh-CN.png"].map(name => put(`${folder}/${name}`));
  const raw = ["extra.png", "trace.zip", "recording.webm", "recording.mp4", "report.html", "network.har", "package.tar.gz", "bundle.tar.zst", "package.tgz", "temporary.exe", "cpu.cpuprofile", "temporary.mjs", "temporary.cjs", "temporary.js", "temporary.ts", "temporary.tsx", "temporary.sh", "temporary.ps1", "temporary.py", "temporary.cmd", "temporary.bat", "jms", "jms-agent-linux-amd64", "jms233-server-darwin-arm64", "error-context.md", ".last-run.json"].map(name => put(`${folder}/${name}`));
  const failed = put(".cache/qa-reports/failed-native/native-packages.json", { status: "failed", cleanup: { removed: true } });
  const failureTrace = put(".cache/qa-reports/failed-native/trace.zip");
  const result = retainQAArtifacts(root);
  assert.equal(result.removedFiles, raw.length);
  raw.forEach(path => assert.equal(existsSync(path), false));
  [...kept, failed, failureTrace].forEach(path => assert.ok(existsSync(path)));
  assert.equal(retainQAArtifacts(root).removedFiles, 0);
});

test("successful batches clean dead PID files while live, malformed and changed PID files protect their batch", t => {
  const { root, put } = fixture(t), folder = ".cache/qa-reports/pid-files";
  put(`${folder}/summary.json`, { status: "passed" });
  const pid = put(`${folder}/runner.pid`, "12345\n"), lock = put(`${folder}/runner.pid.lock`, "12345\n");
  const helper = put(`${folder}/temporary.mjs`);
  const options = { legacy: true, isAlive: () => false };
  let plan = planRetention(root, { ...options, isAlive: n => n === 12345 });
  assert.equal(plan.selected.length, 0); assert.match(plan.skipped[0].reason, /active PID/);
  writeFileSync(pid, "unknown");
  plan = planRetention(root, options);
  assert.equal(plan.selected.length, 0); assert.match(plan.skipped[0].reason, /unreadable PID/);
  writeFileSync(pid, "12345\n");
  plan = planRetention(root, options);
  assert.equal(plan.selected.length, 3);
  assert.throws(() => applyRetention(plan, { isAlive: n => n === 12345 }), /PID file is active/);
  const newer = put(`${folder}/new.pid`, "23456");
  assert.throws(() => applyRetention(plan, options), /PID files changed/);
  [pid, lock, helper, newer].forEach(path => assert.ok(existsSync(path)));
  assert.equal(retainQAArtifacts(root, options).removedFiles, 4);
  assert.equal(retainQAArtifacts(root, options).removedFiles, 0);
});

test("only three successful applied no-op sweeps survive; ownership, mutation and unfamiliar receipts remain", t => {
  const { root, put } = fixture(t);
  const base = { root: root + "/", at: new Date().toISOString(), applied: true, before: "synthetic disk summary", after: "synthetic disk summary", composeEvidence: [], containers: [], volumes: [], networks: [], removed: { containers: 0, volumes: 0, networks: 0, images: 0 }, removedBuildHistory: [], prunedCache: [] };
  const noops = Array.from({ length: 5 }, (_, i) => {
    const path = put(`.cache/qa-reports/cleanup-${1792500000000 + i}.json`, base);
    utimesSync(path, new Date(1000 + i), new Date(1000 + i)); return path;
  });
  const keep = [
    { ...base, composeEvidence: [{ ownership: "needed for retry" }] },
    { ...base, containers: ["remaining container"] },
    { ...base, volumes: ["remaining volume"] },
    { ...base, networks: ["remaining network"] },
    { ...base, removed: { ...base.removed, images: 1 } },
    { ...base, removedBuildHistory: ["actual deletion"] },
    { ...base, prunedCache: ["actual deletion"] },
    { ...base, error: "daemon unavailable" },
    { ...base, retentionError: "cleanup incomplete" },
    { ...base, unknown: [] },
    { ...base, removed: {} },
    { ...base, after: undefined },
    { ...base, containers: undefined },
    { ...base, root: resolve(root, "foreign") },
  ].map((value, i) => put(`.cache/qa-reports/cleanup-${1792500000100 + i}.json`, value));
  const plan = planRetention(root);
  assert.equal(plan.selected.length, 2);
  // A no-op that changes into a recovery receipt after preview must survive.
  writeFileSync(noops[0], JSON.stringify({ ...base, volumes: ["new evidence"] }));
  assert.throws(() => applyRetention(plan), /Artifact changed/);
  noops.forEach(path => assert.ok(existsSync(path)));
  writeFileSync(noops[0], JSON.stringify(base)); utimesSync(noops[0], new Date(1000), new Date(1000));
  assert.equal(retainQAArtifacts(root).removedFiles, 2);
  noops.slice(0, 2).forEach(path => assert.equal(existsSync(path), false));
  [...noops.slice(2), ...keep].forEach(path => assert.ok(existsSync(path)));
  assert.equal(retainQAArtifacts(root).removedFiles, 0);
});

test("failed and incomplete named batches preserve temporary programs and error contexts", t => {
  const { root, put } = fixture(t);
  for (const [name, status] of [["failed", "failed"], ["running", "running"]]) {
    put(`.cache/qa-reports/${name}/summary.json`, { status });
    const files = ["temporary.mjs", "jms", "error-context.md", ".last-run.json"].map(file => put(`.cache/qa-reports/${name}/${file}`));
    assert.equal(retainQAArtifacts(root, { legacy: true }).removedFiles, 0);
    files.forEach(path => assert.ok(existsSync(path)));
  }
});

test("new runner receipts and cleanup changes after preview protect the complete batch", t => {
  for (const [file, value] of [["lifecycle.json", { status: "running", pid: process.pid }], ["cleanup.json", { cleaned: false, temporaryDataRemoved: false }], ["native-packages.json", { status: "running", childPID: process.pid }]]) {
    const { root, browser, put } = fixture(t), folder = browser(0), plan = planRetention(root);
    put(`${folder}/${file}`, value);
    assert.throws(() => applyRetention(plan), e => /Runner receipt changed/.test(e.message) && e.retention.removedFiles === 0);
    plan.selected.forEach(f => assert.ok(existsSync(f.path)));
  }
});

test("unchanged runner PID becoming active after preview also cancels deletion", t => {
  const { root, browser, put } = fixture(t), folder = browser(0);
  put(`${folder}/lifecycle.json`, { status: "passed", pid: 12345 });
  const plan = planRetention(root, { isAlive: () => false });
  assert.ok(plan.selected.length > 0);
  assert.throws(() => applyRetention(plan, { isAlive: pid => pid === 12345 }), e => /became active/.test(e.message) && e.retention.removedFiles === 0);
  plan.selected.forEach(f => assert.ok(existsSync(f.path)));
});

test("a reused receipt PID no longer protects a completed batch; repeated cleanup is empty", t => {
  for (const field of ["pid", "buildPID", "playwrightPID", "childPID"]) {
    const { root, browser, put } = fixture(t), folder = browser(0);
    const receipt = put(`${folder}/lifecycle.json`, { status: "passed", [field]: 12345 });
    utimesSync(receipt, new Date(1000), new Date(1000));
    const options = { isAlive: pid => pid === 12345, processStartedAt: () => 10000 };
    const plan = planRetention(root, options);
    assert.ok(plan.selected.length > 0); assert.equal(plan.skipped.length, 0);
    assert.ok(applyRetention(plan, options).removedFiles > 0);
    assert.ok(existsSync(resolve(folder, "summary.json")));
    assert.equal(retainQAArtifacts(root, options).removedFiles, 0);
  }
});

test("unavailable or original process start times still protect runner receipts", t => {
  const { root, browser, put } = fixture(t), folder = browser(0);
  const receipt = put(`${folder}/lifecycle.json`, { status: "passed", pid: 12345 });
  utimesSync(receipt, new Date(1000), new Date(1000));
  for (const started of [null, undefined, NaN, 500, 1000, 3000]) {
    const plan = planRetention(root, { isAlive: pid => pid === 12345, processStartedAt: () => started });
    assert.equal(plan.selected.length, 0); assert.match(plan.skipped[0].reason, /active process/);
  }
  const options = { isAlive: pid => pid === 12345, processStartedAt: () => 10000 };
  const plan = planRetention(root, options);
  assert.ok(plan.selected.length > 0);
  assert.throws(() => applyRetention(plan, { ...options, processStartedAt: () => null }), /became active/);
  plan.selected.forEach(f => assert.ok(existsSync(f.path)));
});

test("PID reuse does not release PID lock files, failed results or incomplete cleanup", t => {
  const { root, browser, put } = fixture(t), options = { isAlive: pid => pid === 12345, processStartedAt: () => 10000 };
  for (let i = 0; i < 3; i++) {
    const folder = browser(i, i === 2 ? { cleaned: false } : {});
    const receipt = put(`${folder}/lifecycle.json`, { status: i === 1 ? "failed" : "passed", pid: 12345 });
    utimesSync(receipt, new Date(1000), new Date(1000));
    if (i === 0) put(`${folder}/runner.pid`, "12345");
    if (i === 1) put(`${folder}/summary.json`, { status: "failed" });
  }
  const plan = planRetention(root, options);
  // The existing browser policy compacts failures too, without expiring the
  // failed batch's result or its retained screenshot pair.
  assert.ok(plan.selected.every(f => f.path.includes("browser-1792400000001") && !f.path.endsWith("summary.json")));
  assert.equal(plan.directories.length, 0);
  assert.ok(plan.skipped.some(row => /active PID file/.test(row.reason)));
  assert.ok(plan.skipped.some(row => /incomplete cleanup/.test(row.reason)));
  applyRetention(plan, options);
  assert.ok(existsSync(resolve(root, ".cache/qa-reports/browser-1792400000001/summary.json")));
});

test("a later changed artifact is found before any file is removed", t => {
  const { root, browser } = fixture(t);
  browser(0);
  const plan = planRetention(root);
  writeFileSync(plan.selected.at(-1).path, "changed after preview, even if it sorts last");
  assert.throws(() => applyRetention(plan), e => /Artifact changed/.test(e.message) && e.retention.removedFiles === 0);
  plan.selected.forEach(f => assert.ok(existsSync(f.path)));
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
  for (const path of ["local/fixed.jms-secret", ".cache/qa-reports/new.png", "screenshots/qa.png", "web/test-results/trace.zip", "web/blob-report/report.zip", "server/coverage-unit.out", "server/profile.cpuprofile", "tmp/test.exe", "data/vault.key", "backup.jmsbackup", ".jms233-stage-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/partial", "local/.jms233-releases.json", "local/.jms233-release.json"]) {
    const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", path], { cwd: root });
    assert.equal(result.status, 0, `${path} must be ignored`);
  }
  for (const path of ["scripts/node_modules/local/index.js", "web/.vite-temp/config.mjs", "web/.vite/cache.js", ".pnpm-store/package", ".npm/_cacache/index", "server/.gocache/entry", ".gomodcache/cache", "web/.nyc_output/unit.json", "server/coverage/index.html", "web/screenshots/qa.jpeg", "web/artifacts/report.json", "server/test-results/run.json", "pnpm-debug.log.1", "Desktop.ini"]) {
    const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", path], { cwd: root });
    assert.equal(result.status, 0, `${path} must be ignored`);
  }
  for (const path of ["scripts/test-results/run.json", "server/testsupport/playwright-report/index.html", "web/e2e/blob-report/run.zip"]) {
    const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", path], { cwd: root });
    assert.equal(result.status, 0, `${path} must be ignored even from a nested runner`);
  }
  for (const path of ["scripts/screenshots/qa.png", "scripts/artifacts/report.json", "server/testsupport/screenshots/qa.png", "server/testsupport/artifacts/trace.zip", "web/e2e/artifacts/result.json", "web/playwright/screenshots/run.png", "web/e2e/coverage/lcov.info", "scripts/coverage/index.html", "scripts/runner.pid", "server/testsupport/runner.pid.lock", "web/e2e/nested/screenshots/run.png", "server/testsupport/openssh/artifacts/temp.zip", "web/src/App.tsx.swp", "docs/PLAN.md~"]) {
    const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", path], { cwd: root });
    assert.equal(result.status, 0, `${path} must be ignored`);
  }
  for (const path of [".playwright-mcp/page-1.png", "web/.playwright-cli/session.json", "screenshot.png", "Screenshot-login.webp", "web/screenshot-qa.jpeg", "codex-clipboard-123.png", "web/codex-clipboard-123.png", "coverage.out", "coverage.html", "junit.xml", "web/junit-results.xml", "server/junit.xml", "jms", "jms-agent", "jms233-server", "jms-package", "server/jms233-server", "server/jms-package", "web/src/App.tsx.orig", "server/main.go.rej"]) {
    const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", path], { cwd: root });
    assert.equal(result.status, 0, `${path} must be ignored`);
  }
  for (const path of ["scripts/Screenshot-qa.png", "scripts/screenshot-qa.jpg", "server/screenshot-auth.jpeg", "server/Screenshot-check.webp", "web/e2e/screenshot.png", "web/e2e/screenshot.jpg", "web/e2e/screenshot.jpeg", "web/e2e/Screenshot.webp", "scripts/codex-clipboard-123.png", "server/codex-clipboard-123.png", "web/e2e/codex-clipboard-123.png", "web/playwright/.auth/operator.json", "scripts/playwright/.auth/storage.json", "scripts/.pytest_cache/nodeids", ".mypy_cache/cache.json", "scripts/.ruff_cache/cache", "scripts/local.pyo", "scripts/junit-run.xml"]) {
    const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", path], { cwd: root });
    assert.equal(result.status, 0, `${path} must be ignored`);
  }
  for (const path of ["docs/images/inventory.en.png", "docs/images/screenshot-guide.png", "web/src/main.tsx", "scripts/qa-retention.mjs", "web/.env.example", ".env.development.example", "web/src/components/icon.png", "web/src/components/screenshot-icon.png", "server/testsupport/fixture.json", "server/testsupport/junit.xml", "server/testsupport/screenshots-fixture.png", "release-please-config.json", "web/pnpm-lock.yaml", "example.tar.gz"]) {
    const result = spawnSync("git", ["check-ignore", "--quiet", "--no-index", "--", path], { cwd: root });
    assert.equal(result.status, 1, `${path} must remain visible`);
  }
  const tracked = spawnSync("git", ["ls-files", "-ci", "--exclude-standard"], { cwd: root, encoding: "utf8" });
  assert.equal(tracked.status, 0); assert.equal(tracked.stdout.trim(), "", "Ignore rules must not hide tracked source");
  const dockerIgnore = readFileSync(resolve(root, ".dockerignore"), "utf8").split(/\r?\n/);
  for (const rule of ["**/screenshots", "**/.jms233-schedule.json", "**/.jms233-automatic.json", "server/testsupport/**/artifacts", "**/.playwright-mcp", "**/.playwright-cli", "/[Ss]creenshot*.png", "/web/[Ss]creenshot*.webp", "/codex-clipboard-*.png", "/junit*.xml", "/jms233-server", "**/*.orig", "**/*.rej"]) assert.ok(dockerIgnore.includes(rule), `Build context must exclude ${rule}`);
  for (const rule of ["/scripts/[Ss]creenshot*.png", "/server/[Ss]creenshot*.jpeg", "/web/e2e/[Ss]creenshot*.webp", "/scripts/codex-clipboard-*.png", "/server/codex-clipboard-*.png", "/web/e2e/codex-clipboard-*.png", "**/playwright/.auth", "**/.pytest_cache", "**/.mypy_cache", "**/.ruff_cache", "**/*.pyo", "/scripts/junit*.xml"]) assert.ok(dockerIgnore.includes(rule), `Build context must exclude ${rule}`);
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
