import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const workspace = fileURLToPath(new URL("..", import.meta.url));
const browserName = /^browser-\d{13}$/;
const dockerName = /^jms233-[a-z0-9][a-z0-9-]{0,48}$/;
const legacyHelper = /^(?:branding|discovery|migration|monitor-history)(?:-[\w-]+\.mjs|\.playwright\.config\.mjs)$/;
const terminal = new Set(["passed", "failed", "interrupted", "timedout"]);
const identity = s => `${s.dev}:${s.ino}:${s.size}:${s.mtimeMs}`;
const alive = pid => { if (!Number.isSafeInteger(pid) || pid <= 0) return false; try { process.kill(pid, 0); return true; } catch (e) { return e.code !== "ESRCH"; } };

// Validate each ancestor, including junctions. Never follow an artifact link.
function checked(root, path) {
  const rel = relative(root, path);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || resolve(root, rel) !== path) throw new Error("Artifact path outside workspace");
  let current = root;
  for (const component of rel.split(sep)) {
    current = resolve(current, component);
    let info;
    try { info = lstatSync(current); } catch (e) { if (e.code === "ENOENT") continue; throw e; }
    if (info.isSymbolicLink()) throw new Error("Artifact links are never cleaned");
    if (realpathSync(current).toLowerCase() !== current.toLowerCase()) throw new Error("Artifact path changed ownership");
  }
  return path;
}
function json(path) {
  if (!existsSync(path)) return null;
  const info = lstatSync(path);
  if (!info.isFile() || info.isSymbolicLink() || info.size > 2 * 1024 * 1024) return null;
  try { return JSON.parse(readFileSync(path, "utf8")); } catch { return null; }
}
function files(root, folder) {
  checked(root, folder);
  const out = [];
  for (const row of readdirSync(folder, { withFileTypes: true })) {
    const path = checked(root, resolve(folder, row.name)), info = lstatSync(path);
    if (info.isDirectory()) out.push(...files(root, path));
    else if (info.isFile()) out.push({ path, size: info.size, modified: info.mtimeMs, identity: identity(info) });
    else throw new Error("Special artifacts are never cleaned");
  }
  return out;
}
function evidence(rows) {
  const pngs = rows.filter(f => /\.png$/i.test(f.path)).sort((a, b) => b.modified - a.modified || a.path.localeCompare(b.path));
  const kept = new Set();
  for (const locale of [/\.en(?:[.-]|$)/, /\.(?:zh-CN|zh)(?:[.-]|$)/]) {
    const match = pngs.find(f => locale.test(basename(f.path)));
    if (match) kept.add(match.path);
  }
  for (const f of pngs) { if (kept.size === 2) break; kept.add(f.path); }
  return kept;
}

export function planRetention(root = workspace, { legacy = false, currentRun, now = Date.now(), isAlive = alive } = {}) {
  root = realpathSync(root);
  if (currentRun) currentRun = realpathSync(currentRun);
  const reportRoot = resolve(root, ".cache/qa-reports"), dockerRoot = resolve(root, ".cache/docker-qa");
  const plan = { root, selected: [], skipped: [], directories: [] }, seen = new Set();
  const select = f => { if (!seen.has(f.path)) { seen.add(f.path); plan.selected.push(f); } };
  const buckets = [];
  let liveRun = false;
  for (const [parent, type, pattern] of [[reportRoot, "browser", browserName], [dockerRoot, "docker", dockerName]]) {
    if (!existsSync(parent)) continue;
    checked(root, parent);
    for (const row of readdirSync(parent, { withFileTypes: true })) {
      if (!row.isDirectory() || row.isSymbolicLink() || type === "docker" && !pattern.test(row.name)) continue;
      const folder = resolve(parent, row.name);
      try {
        const items = files(root, folder), lifecycle = json(resolve(folder, "lifecycle.json"));
        const current = currentRun && resolve(currentRun) === folder;
        const pids = lifecycle ? [lifecycle.pid, lifecycle.buildPID, lifecycle.playwrightPID] : [];
        if (pids.some(pid => isAlive(pid) && !(current && pid === process.pid && terminal.has(lifecycle.status)))) {
          liveRun = true; plan.skipped.push({ name: row.name, reason: "active process" }); continue;
        }
        const summary = json(resolve(folder, "summary.json")) || json(resolve(folder, "report.json")), cleanup = json(resolve(folder, "cleanup.json"));
        if (type === "browser" && pattern.test(row.name)) {
          if (!cleanup?.cleaned || !cleanup.temporaryDataRemoved || !terminal.has(summary?.status || lifecycle?.status)) {
            plan.skipped.push({ name: row.name, reason: "incomplete cleanup or result" }); continue;
          }
          buckets.push({ folder, items, type, time: Number(row.name.slice(8)), expire: true });
        } else if (type === "docker") {
          if (summary?.project !== row.name || summary.cleaned !== true || summary.retained === true) {
            plan.skipped.push({ name: row.name, reason: "retained environment or incomplete cleanup" }); continue;
          }
          buckets.push({ folder, items, type, success: summary.success, time: lstatSync(resolve(folder, "summary.json")).mtimeMs, expire: /^jms233-qa-[a-f0-9-]{36}$/.test(row.name) });
        } else if (legacy) {
          // Named historical evidence is not a disposable run: keep all JSON receipts.
          if (!summary || summary.status && summary.status !== "passed" || summary.success === false || summary.browser?.failed > 0) continue;
          buckets.push({ folder, items, type: "named", expire: false });
        }
      } catch (e) { plan.skipped.push({ name: row.name, reason: e.message }); }
    }
  }
  for (const type of ["browser", "docker"]) {
    const disposable = buckets.filter(b => b.type === type && b.expire).sort((a, b) => b.time - a.time);
    for (const b of disposable.slice(3)) {
      if (currentRun && resolve(currentRun) === b.folder) continue;
      b.items.forEach(select); plan.directories.push(b.folder); b.expired = true;
    }
  }
  for (const b of buckets.filter(b => !b.expired)) {
    const kept = evidence(b.items);
    for (const f of b.items) {
      const name = basename(f.path);
      if (/\.png$/i.test(name) && !kept.has(f.path) || b.type === "browser" && !["summary.json", "cleanup.json", "lifecycle.json"].includes(name) && !kept.has(f.path) || b.type === "docker" && (/^summary-\d+\.json$/.test(name) || name === "verify.log" && b.success === true) || b.type === "named" && /\.log$/i.test(name)) select(f);
    }
  }
  const cache = resolve(root, ".cache");
  if (legacy && !liveRun && existsSync(cache)) for (const row of readdirSync(checked(root, cache), { withFileTypes: true })) {
    if (!row.isFile() || !legacyHelper.test(row.name)) continue;
    const path = checked(root, resolve(cache, row.name)), info = lstatSync(path);
    if (now - info.mtimeMs >= 60 * 60 * 1000) select({ path, size: info.size, modified: info.mtimeMs, identity: identity(info) });
  }
  return plan;
}

export function applyRetention(plan) {
  const root = realpathSync(plan.root), removed = [];
  const receipt = () => ({ at: new Date().toISOString(), removedFiles: removed.length, removedBytes: removed.reduce((n, f) => n + f.bytes, 0), removed, skipped: plan.skipped });
  try {
    for (const file of plan.selected) {
      const path = checked(root, file.path), rel = relative(root, path).replaceAll("\\", "/");
      if (!rel.startsWith(".cache/qa-reports/") && !rel.startsWith(".cache/docker-qa/") && !(dirname(path) === resolve(root, ".cache") && legacyHelper.test(basename(path)))) throw new Error("Unowned artifact deletion rejected");
      if (!existsSync(path)) continue;
      const info = lstatSync(path);
      if (!info.isFile() || identity(info) !== file.identity) throw new Error("Artifact changed since preview; rerun retention");
      unlinkSync(path); removed.push({ path: rel, bytes: file.size });
    }
    function empty(folder) {
      checked(root, folder);
      if (!existsSync(folder)) return;
      for (const row of readdirSync(folder, { withFileTypes: true })) if (row.isDirectory() && !row.isSymbolicLink()) empty(resolve(folder, row.name));
      if (readdirSync(folder).length === 0) rmdirSync(folder);
    }
    for (const folder of plan.directories) {
      if (dirname(folder) !== resolve(root, ".cache/qa-reports") && dirname(folder) !== resolve(root, ".cache/docker-qa")) throw new Error("Unowned report directory");
      empty(folder);
    }
    return receipt();
  } catch (e) {
    e.retention = { ...receipt(), error: "Artifact retention incomplete; re-preview before retrying" };
    throw e;
  }
}

export function retainQAArtifacts(root = workspace, options = {}) {
  const plan = planRetention(root, options);
  const parent = checked(plan.root, resolve(plan.root, ".cache/qa-reports"));
  mkdirSync(parent, { recursive: true });
  const output = checked(plan.root, resolve(parent, "retention.json"));
  let report;
  try { report = applyRetention(plan); }
  catch (e) { writeFileSync(output, JSON.stringify(e.retention, null, 2) + "\n", { mode: 0o600 }); throw e; }
  writeFileSync(output, JSON.stringify(report, null, 2) + "\n", { mode: 0o600 });
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = new Set(process.argv.slice(2));
  if ([...args].some(a => !["--apply", "--legacy"].includes(a))) throw new Error("Use [--apply] [--legacy]; no arguments previews owned QA artifacts");
  const options = { legacy: args.has("--legacy") };
  if (args.has("--apply")) {
    const result = retainQAArtifacts(workspace, options);
    console.log(JSON.stringify({ ...result, removed: undefined, report: ".cache/qa-reports/retention.json" }));
  } else {
    const plan = planRetention(workspace, options);
    console.log(JSON.stringify({ preview: true, files: plan.selected.length, bytes: plan.selected.reduce((n, f) => n + f.size, 0), skipped: plan.skipped, paths: plan.selected.map(f => relative(plan.root, f.path).replaceAll("\\", "/")) }, null, 2));
  }
}
