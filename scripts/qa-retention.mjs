import { closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, realpathSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { basename, dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const workspace = fileURLToPath(new URL("..", import.meta.url));
const browserName = /^browser-\d{13}$/;
const dockerName = /^jms233-[a-z0-9][a-z0-9-]{0,48}$/;
const legacyHelper = /^(?:branding|discovery|migration|monitor-history)(?:-[\w-]+\.mjs|\.playwright\.config\.mjs)$/;
const legacyWebHelper = /^(?:(?:monitoring-alerts|notifications|platform-login-audit|risk|rotation|security-notifications|security-sharing|ticket)-qa\.config\.mjs|security-(?:preview\.vite|production-full)\.config\.ts|run-security-production-full\.mjs)$/;
const legacyHelperPath = (root, path) => dirname(path) === resolve(root, ".cache") && legacyHelper.test(basename(path)) || dirname(path) === resolve(root, "web/.cache") && legacyWebHelper.test(basename(path));
const terminal = new Set(["passed", "failed", "interrupted", "timedout"]);
const screenshot = /\.(?:png|jpe?g|webp)$/i;
const disposableArtifact = /\.(?:log|pid(?:\.lock)?|zip|tar(?:\.(?:gz|zst))?|tgz|html?|har|webm|mp4|exe|test|prof|cpuprofile|heapprofile|heapsnapshot|dmp|[cm]?js|tsx?|sh|ps1|py|cmd|bat)$/i;
const disposableProgram = /^(?:jms|jms-agent|jms233-server)(?:-(?:linux|darwin|windows)-(?:amd64|arm64))?$/;
const disposableSidecar = new Set(["error-context.md", ".last-run.json"]);
const pidArtifact = /\.pid(?:\.lock)?$/i;
const receiptNames = ["lifecycle.json", "native-packages.json", "linux-race.json", "summary.json", "report.json", "cleanup.json"];
const identity = s => `${s.dev}:${s.ino}:${s.size}:${s.mtimeMs}`;
const hashBuffer = Buffer.allocUnsafe(64 * 1024);
function fingerprint(path, info = lstatSync(path)) {
  if (!info.isFile() || info.isSymbolicLink()) throw new Error("Artifact is not a regular file");
  const before = identity(info), hash = createHash("sha256");
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    if (identity(fstatSync(fd)) !== before) throw new Error("Artifact changed during fingerprint");
    let bytes;
    while ((bytes = readSync(fd, hashBuffer, 0, hashBuffer.length, null)) > 0) hash.update(hashBuffer.subarray(0, bytes));
    if (identity(fstatSync(fd)) !== before || identity(lstatSync(path)) !== before) throw new Error("Artifact changed during fingerprint");
    return `${before}:${hash.digest("hex")}`;
  } finally { closeSync(fd); }
}
const alive = pid => { if (!Number.isSafeInteger(pid) || pid <= 0) return false; try { process.kill(pid, 0); return true; } catch (e) { return e.code !== "ESRCH"; } };

// PID numbers can belong to unrelated processes after a runner exits. Only a
// process created after the receipt was written is demonstrably a replacement.
// Read no command lines or environment; an unavailable start time stays live.
function processStartReader() {
  const known = new Map();
  return pid => {
    if (known.has(pid)) return known.get(pid);
    let value = null;
    if (Number.isSafeInteger(pid) && pid > 0) try {
      const windows = process.platform === "win32";
      const output = execFileSync(windows ? "powershell.exe" : "ps", windows ? ["-NoProfile", "-NonInteractive", "-Command", `$ErrorActionPreference='Stop'; (Get-Process -Id ${pid}).StartTime.ToUniversalTime().ToString('O')`] : ["-p", String(pid), "-o", "lstart="], { encoding: "utf8", windowsHide: true, timeout: 3000, stdio: ["ignore", "pipe", "ignore"], env: { ...process.env, LC_ALL: "C" } }).trim();
      const parsed = Date.parse(output);
      if (Number.isFinite(parsed)) value = parsed;
    } catch { /* Fail closed when the process cannot be inspected. */ }
    known.set(pid, value);
    return value;
  };
}

function activeRunner(state, path, current, isAlive, processStartedAt) {
  const writtenAt = lstatSync(path).mtimeMs;
  return [state.pid, state.buildPID, state.playwrightPID, state.childPID].some(pid => {
    if (!isAlive(pid) || current && pid === process.pid && terminal.has(state.status)) return false;
    const started = processStartedAt(pid);
    // Allow timestamp precision differences between filesystems and Unix ps.
    return !Number.isFinite(started) || started <= writtenAt + 2000;
  });
}

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
function files(root, folder, pidOnly = false) {
  checked(root, folder);
  const out = [];
  for (const row of readdirSync(folder, { withFileTypes: true })) {
    const path = checked(root, resolve(folder, row.name)), info = lstatSync(path);
    if (info.isDirectory()) out.push(...files(root, path, pidOnly));
    else if (info.isFile()) { if (!pidOnly || pidArtifact.test(row.name)) out.push({ path, size: info.size, modified: info.mtimeMs, identity: fingerprint(path, info) }); }
    else throw new Error("Special artifacts are never cleaned");
  }
  return out;
}
function evidence(rows) {
  const pngs = rows.filter(f => screenshot.test(f.path)).sort((a, b) => b.modified - a.modified || a.path.localeCompare(b.path));
  const kept = new Set();
  for (const locale of [/\.en(?:[.-]|$)/, /\.(?:zh-CN|zh)(?:[.-]|$)/]) {
    const match = pngs.find(f => locale.test(basename(f.path)));
    if (match) kept.add(match.path);
  }
  for (const f of pngs) { if (kept.size === 2) break; kept.add(f.path); }
  return kept;
}

// No-op applied sweeps carry no resource ownership or recovery evidence.
// Keep mutating, failed and unfamiliar receipts for explicit review.
function emptyCleanup(report, root) {
  const fields = new Set(["root", "at", "applied", "before", "after", "composeEvidence", "containers", "volumes", "networks", "removed", "removedBuildHistory", "prunedCache"]);
  if (!report || Object.keys(report).some(key => !fields.has(key)) || typeof report.root !== "string" || resolve(report.root) !== root || report.applied !== true || typeof report.after !== "string") return false;
  if (!["composeEvidence", "containers", "volumes", "networks"].every(key => Array.isArray(report[key]) && report[key].length === 0)) return false;
  if (!["removedBuildHistory", "prunedCache"].every(key => report[key] === undefined || Array.isArray(report[key]) && report[key].length === 0)) return false;
  return report.removed && Object.keys(report.removed).sort().join(",") === "containers,images,networks,volumes" && Object.values(report.removed).every(n => n === 0);
}

const disposable = name => disposableArtifact.test(name) || disposableProgram.test(name) || disposableSidecar.has(name);

function filePID(file) {
  if (file.size > 24) return null;
  const value = readFileSync(file.path, "utf8").trim();
  const pid = /^\d+$/.test(value) ? Number(value) : NaN;
  return Number.isSafeInteger(pid) && pid > 0 ? pid : null;
}

function runnerGuard(root, folder, current, items) {
  return { folder, current, pidFiles: items.filter(file => pidArtifact.test(file.path)), receipts: receiptNames.map(name => {
    const path = checked(root, resolve(folder, name));
    return { path, identity: items.find(file => file.path === path)?.identity || null };
  }) };
}

function validateRunner(root, guard, isAlive, processStartedAt, removed = new Set()) {
  checked(root, guard.folder);
  if (!existsSync(guard.folder)) return;
  const pids = files(root, guard.folder, true);
  const expected = (guard.pidFiles || []).filter(file => !removed.has(file.path));
  if (pids.length !== expected.length || pids.some(file => !expected.some(old => old.path === file.path && old.identity === file.identity))) throw new Error("Runner PID files changed since preview; rerun retention");
  for (const file of pids) {
    const pid = filePID(file);
    if (!pid || isAlive(pid)) throw new Error("Runner PID file is active or unreadable; rerun retention");
  }
  for (const file of guard.receipts) {
    const path = checked(root, file.path);
    const actual = existsSync(path) ? fingerprint(path) : null;
    if (actual === null && removed.has(path)) continue;
    if (actual !== file.identity) throw new Error("Runner receipt changed since preview; rerun retention");
  }
  for (const name of receiptNames.slice(0, 3)) {
    const state = json(resolve(guard.folder, name));
    if (state && activeRunner(state, resolve(guard.folder, name), guard.current, isAlive, processStartedAt)) {
      throw new Error("Runner became active since preview; rerun retention");
    }
  }
}

export function planRetention(root = workspace, { legacy = false, currentRun, now = Date.now(), isAlive = alive, processStartedAt = processStartReader() } = {}) {
  root = realpathSync(root);
  if (currentRun) currentRun = realpathSync(currentRun);
  const reportRoot = resolve(root, ".cache/qa-reports"), dockerRoot = resolve(root, ".cache/docker-qa");
  const plan = { root, selected: [], skipped: [], directories: [], guards: [] }, seen = new Set();
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
        const native = json(resolve(folder, "native-packages.json")), race = json(resolve(folder, "linux-race.json"));
        const current = currentRun && resolve(currentRun) === folder;
        if ([["lifecycle.json", lifecycle], ["native-packages.json", native], ["linux-race.json", race]].some(([name, value]) => !value && existsSync(resolve(folder, name)))) {
          liveRun = true; plan.skipped.push({ name: row.name, reason: "unreadable runner receipt" }); continue;
        }
        const pids = items.filter(file => pidArtifact.test(file.path)).map(filePID);
        if (pids.some(pid => !pid)) {
          liveRun = true; plan.skipped.push({ name: row.name, reason: "unreadable PID file" }); continue;
        }
        if (pids.some(pid => isAlive(pid))) {
          liveRun = true; plan.skipped.push({ name: row.name, reason: "active PID file" }); continue;
        }
        if ([["lifecycle.json", lifecycle], ["native-packages.json", native], ["linux-race.json", race]].some(([name, state]) => state && activeRunner(state, resolve(folder, name), current, isAlive, processStartedAt))) {
          liveRun = true; plan.skipped.push({ name: row.name, reason: "active process" }); continue;
        }
        const summary = json(resolve(folder, "summary.json")) || json(resolve(folder, "report.json")) || native || race, cleanup = json(resolve(folder, "cleanup.json"));
        if (type === "browser" && pattern.test(row.name)) {
          if (!cleanup?.cleaned || !cleanup.temporaryDataRemoved || !terminal.has(summary?.status || lifecycle?.status)) {
            plan.skipped.push({ name: row.name, reason: "incomplete cleanup or result" }); continue;
          }
          buckets.push({ folder, items, type, success: (summary?.status || lifecycle?.status) === "passed" && (!lifecycle?.status || lifecycle.status === "passed"), time: Number(row.name.slice(8)), expire: true });
        } else if (type === "docker") {
          if (lifecycle && lifecycle.status !== "passed") {
            plan.skipped.push({ name: row.name, reason: "incomplete or failed runner result" }); continue;
          }
          if (summary?.project !== row.name || summary.cleaned !== true || summary.retained === true) {
            plan.skipped.push({ name: row.name, reason: "retained environment or incomplete cleanup" }); continue;
          }
          buckets.push({ folder, items, type, success: summary.success, time: lstatSync(resolve(folder, "summary.json")).mtimeMs, expire: /^jms233-qa-[a-f0-9-]{36}$/.test(row.name) });
        } else if (legacy || current || native || race) {
          // Named historical evidence is not a disposable run: keep all JSON receipts.
          if (lifecycle && lifecycle.status !== "passed") {
            plan.skipped.push({ name: row.name, reason: "incomplete or failed runner result" }); continue;
          }
          const passed = summary?.status === "passed" || summary?.success === true || summary?.browser?.passed > 0 && summary.browser.failed === 0;
          if (!passed || summary.status && summary.status !== "passed" || summary.success === false || summary.browser?.failed > 0) continue;
          if (native && !(native.status === "passed" && native.cleanup?.removed && native.cleanup?.idempotent && native.cleanup?.temporaryArtifactsRemoved) || race && !(race.status === "passed" && race.cleanup?.removed && race.cleanup?.idempotent)) {
            plan.skipped.push({ name: row.name, reason: "incomplete native result or cleanup" }); continue;
          }
          buckets.push({ folder, items, type: "named", success: true, expire: false });
        }
      } catch (e) { plan.skipped.push({ name: row.name, reason: e.message }); }
    }
  }
  for (const type of ["browser", "docker"]) {
    const disposableRuns = buckets.filter(b => b.type === type && b.expire && b.success === true).sort((a, b) => b.time - a.time);
    for (const b of disposableRuns.slice(3)) {
      if (currentRun && resolve(currentRun) === b.folder) continue;
      b.items.forEach(select); plan.directories.push(b.folder); b.expired = true;
    }
  }
  // Named feature reports remain useful; their historical screenshots do not
  // need an unbounded pair per feature. Image timestamps avoid promoting an
  // old batch merely because someone updates its summary or cleanup receipt.
  const imageExpired = new Set();
  for (const type of ["named", "docker"]) {
    const candidates = buckets.filter(b => !b.expired && b.type === type && b.success === true && b.items.some(f => screenshot.test(f.path)))
      .map(b => ({ ...b, imageTime: b.items.reduce((latest, f) => screenshot.test(f.path) ? Math.max(latest, f.modified) : latest, 0) }))
      .sort((a, b) => b.imageTime - a.imageTime || a.folder.localeCompare(b.folder));
    // The current completed runner may still be assembling its final report.
    // Count it within the limit even if its screenshots have old timestamps.
    const kept = new Set(candidates.filter(b => b.folder === currentRun).map(b => b.folder));
    for (const b of candidates) { if (kept.size >= 3) break; kept.add(b.folder); }
    for (const b of candidates) if (!kept.has(b.folder)) imageExpired.add(b.folder);
  }
  for (const b of buckets.filter(b => !b.expired)) {
    const kept = imageExpired.has(b.folder) ? new Set() : evidence(b.items);
    for (const f of b.items) {
      const name = basename(f.path);
      if (screenshot.test(name) && !kept.has(f.path) || b.type === "browser" && !["summary.json", "cleanup.json", "lifecycle.json"].includes(name) && !kept.has(f.path) || b.type === "docker" && (/^summary-\d+\.json$/.test(name) || disposable(name) && b.success === true) || b.type === "named" && disposable(name)) select(f);
    }
  }
  for (const b of buckets) if (plan.directories.includes(b.folder) || plan.selected.some(f => f.path.startsWith(b.folder + sep))) {
    plan.guards.push(runnerGuard(root, b.folder, currentRun === b.folder, b.items));
  }
  // Bound previews and completed no-op sweeps separately. Applied recovery
  // receipts remain intact when any resource, mutation or error is recorded.
  if (existsSync(reportRoot)) {
    const previews = [], noops = [];
    for (const row of readdirSync(checked(root, reportRoot), { withFileTypes: true })) {
      if (!row.isFile() || !/^cleanup-\d+\.json$/.test(row.name)) continue;
      const path = checked(root, resolve(reportRoot, row.name)), report = json(path);
      if (!report || typeof report.root !== "string" || resolve(report.root) !== root) continue;
      const preview = report.applied === false && !report.error && typeof report.after === "string" && report.removed && Object.values(report.removed).every(n => n === 0);
      if (!preview && !emptyCleanup(report, root)) continue;
      const info = lstatSync(path);
      (preview ? previews : noops).push({ path, size: info.size, modified: info.mtimeMs, identity: fingerprint(path, info) });
    }
    for (const group of [previews, noops]) group.sort((a, b) => b.modified - a.modified || b.path.localeCompare(a.path)).slice(3).forEach(select);
  }
  if (legacy && !liveRun) for (const cache of [resolve(root, ".cache"), resolve(root, "web/.cache")]) {
    if (!existsSync(cache)) continue;
    for (const row of readdirSync(checked(root, cache), { withFileTypes: true })) {
      const path = resolve(cache, row.name);
      if (!row.isFile() || !legacyHelperPath(root, path)) continue;
      checked(root, path);
      const info = lstatSync(path);
      if (now - info.mtimeMs >= 60 * 60 * 1000) select({ path, size: info.size, modified: info.mtimeMs, identity: fingerprint(path, info) });
    }
  }
  return plan;
}

export function applyRetention(plan, { isAlive = alive, processStartedAt = processStartReader() } = {}) {
  const root = realpathSync(plan.root), removed = [], removedPaths = new Set();
  const receipt = () => ({ at: new Date().toISOString(), removedFiles: removed.length, removedBytes: removed.reduce((n, f) => n + f.bytes, 0), removed, skipped: plan.skipped });
  try {
    // Revalidate the entire batch before the first unlink, then recheck its
    // runner immediately before each deletion. A new/restarted run wins.
    const guards = plan.guards || [];
    guards.forEach(guard => validateRunner(root, guard, isAlive, processStartedAt));
    if (plan.selected.some(file => legacyHelperPath(root, file.path)) && planRetention(root, { isAlive, processStartedAt }).skipped.some(row => /^(?:active |unreadable (?:runner receipt|PID file))/.test(row.reason))) {
      throw new Error("QA activity changed since preview; rerun retention before deleting legacy helpers");
    }
    function validateFile(file) {
      const path = checked(root, file.path), rel = relative(root, path).replaceAll("\\", "/");
      if (!rel.startsWith(".cache/qa-reports/") && !rel.startsWith(".cache/docker-qa/") && !legacyHelperPath(root, path)) throw new Error("Unowned artifact deletion rejected");
      if (!existsSync(path)) return null;
      const info = lstatSync(path);
      if (!info.isFile() || fingerprint(path, info) !== file.identity) throw new Error("Artifact changed since preview; rerun retention");
      return { path, rel };
    }
    plan.selected.forEach(validateFile);
    for (const file of plan.selected) {
      const guard = guards.find(g => file.path.startsWith(g.folder + sep));
      if (guard) validateRunner(root, guard, isAlive, processStartedAt, removedPaths);
      const valid = validateFile(file);
      if (!valid) continue;
      const { path, rel } = valid;
      unlinkSync(path); removedPaths.add(path); removed.push({ path: rel, bytes: file.size });
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
  options = { ...options, processStartedAt: options.processStartedAt ?? processStartReader() };
  const plan = planRetention(root, options);
  const parent = checked(plan.root, resolve(plan.root, ".cache/qa-reports"));
  mkdirSync(parent, { recursive: true });
  const output = checked(plan.root, resolve(parent, "retention.json"));
  let report;
  try { report = applyRetention(plan, options); }
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
