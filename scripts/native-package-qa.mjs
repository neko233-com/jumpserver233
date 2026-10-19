// Build every native target, execute the host CLI and a Linux single-port server,
// then remove only this run's temporary artifacts and container. Never publish.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { inspectQAContainers, removeOwnedTree } from "./qa-lifecycle.mjs";
import { fixtureDiagnostic } from "../server/testsupport/ci-health.mjs";

const root = fileURLToPath(new URL("..", import.meta.url)), execute = promisify(execFile);
const cache = resolve(root, ".cache"), output = resolve(cache, "qa-reports/updates");
mkdirSync(output, { recursive: true });
const temporary = mkdtempSync(resolve(cache, "native-package-qa-")), packages = resolve(temporary, "packages");
const owner = "jms233-native-package-" + randomUUID();
const report = { at: new Date().toISOString(), pid: process.pid, owner, temporaryDirectory: temporary, status: "running", packages: [], cleanup: {} };
const save = () => writeFileSync(resolve(output, "native-packages.json"), JSON.stringify(report, null, 2));
const run = (command, args, options = {}) => execute(command, args, { cwd: root, windowsHide: true, maxBuffer: 2 * 1024 * 1024, ...options });
const accept = c => c.Config?.Labels?.["com.jumpserver233.qa.owner"] === owner && c.Config?.Labels?.["com.jumpserver233.qa.workspace"] === root;
async function cleanup() {
  const [container] = await inspectQAContainers(run, [owner]);
  if (container) { if (!accept(container)) throw new Error("Native QA container changed ownership"); await run("docker", ["rm", "--force", "--volumes", container.Id]); }
  removeOwnedTree(temporary, cache, "native-package-qa-");
}
async function port() {
  const socket = createServer();
  return new Promise((done, fail) => { socket.once("error", fail); socket.listen(0, "127.0.0.10", () => { const value = socket.address().port; socket.close(() => done(value)); }); });
}
try {
  report.commit = (await run("git", ["rev-parse", "HEAD"])).stdout.trim();
  report.sourceDirty = Boolean((await run("git", ["status", "--porcelain"])).stdout.trim());
  if (report.sourceDirty) throw new Error("Commit the source batch before native provenance verification");
  report.builtAt = (await run("git", ["show", "-s", "--format=%cI", "HEAD"])).stdout.trim();
  report.testVersion = "v0.0.0"; report.published = false; save();
  await run("go", ["generate", "./internal/agentbundle"], { cwd: resolve(root, "server") });
  const nativeWeb = resolve(temporary, "web");
  await run(process.execPath, [resolve(root, "web/node_modules/vite/bin/vite.js"), "build", "--outDir", nativeWeb], { cwd: resolve(root, "web") });
  report.bundle = JSON.parse((await run(process.execPath, [resolve(root, "scripts/check-web-bundle.mjs"), "--dir", nativeWeb])).stdout);
  const targets = ["linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64", "windows/arm64"];
  let index = 0;
  async function build() {
    while (index < targets.length) {
      const target = targets[index++], started = performance.now();
      await run("go", ["run", "./cmd/jms-package", "--version", report.testVersion, "--commit", report.commit, "--built-at", report.builtAt, "--target", target, "--out", packages,"--web-dir",nativeWeb], { cwd: resolve(root, "server") });
      report.packages.push({ target, verified: true, durationMs: Math.round(performance.now() - started) }); save();
      console.log("Native archive verified: " + target);
    }
  }
  // Bound compiler concurrency and allow all owned children to finish before cleanup.
  const builds = await Promise.allSettled([build(), build()]);
  if (builds.some(v => v.status === "rejected")) throw new Error("Native compilation or archive verification failed");
  const hostOS = process.platform === "win32" ? "windows" : process.platform, hostArch = process.arch === "x64" ? "amd64" : process.arch;
  const hostArchive = resolve(packages, `jumpserver233-${report.testVersion}-${hostOS}-${hostArch}.tar.gz`), extracted = resolve(temporary, "host");
  mkdirSync(extracted); await run("tar", ["-xzf", hostArchive, "-C", extracted]);
  const cli = resolve(extracted, process.platform === "win32" ? "jms.exe" : "jms");
  const info = JSON.parse((await run(cli, ["--version"])).stdout);
  if (info.version !== report.testVersion || info.commit !== report.commit || info.os !== hostOS || info.arch !== hostArch) throw new Error("Native CLI build identity differs");
  report.hostExecution = { os: hostOS, arch: hostArch, version: info.version, commit: info.commit };
  // Bootstrap with a test-only tar tool, then exercise the production confined
  // staging CLI. The candidate never activates itself or opens application data.
  const stageRoot = resolve(temporary, "releases"), hostSHA = createHash("sha256").update(readFileSync(hostArchive)).digest("hex");
  const sentinel = resolve(temporary, "data-sentinel"); writeFileSync(sentinel, "preserve-application-data");
  const stageArgs = ["update", "stage", "--root", stageRoot, "--file", hostArchive, "--sha256", hostSHA];
  const staged = JSON.parse((await run(cli, stageArgs)).stdout);
  const repeated = JSON.parse((await run(cli, stageArgs)).stdout);
  const inspected = JSON.parse((await run(cli, ["update", "stage-status", "--root", stageRoot, "--sha256", hostSHA])).stdout);
  const stageClean = JSON.parse((await run(cli, ["update", "stage-clean", "--root", stageRoot])).stdout);
  if (staged.unchanged || !repeated.unchanged || inspected.manifest.commit !== report.commit || stageClean.cleaned_stages !== 0) throw new Error("Native staging identity or idempotence failed");
  const stagedCLI = resolve(staged.directory, process.platform === "win32" ? "jms.exe" : "jms");
  if (JSON.parse((await run(stagedCLI, ["--version"])).stdout).commit !== report.commit) throw new Error("Staged native CLI identity differs");
  writeFileSync(resolve(staged.directory, "web/index.html"), "tampered-qa-candidate");
  let stageConflict = false;
  try { await run(cli, stageArgs); } catch (e) { stageConflict = String(e.stderr).includes("release staging directory is unmanaged, changed or incompatible"); }
  if (!stageConflict || readFileSync(sentinel, "utf8") !== "preserve-application-data") throw new Error("Native staging replaced changed files or application data");
  report.hostStaging = { verified: true, idempotent: true, changedCandidateRefused: true, candidateCLIExecuted: true, dataSentinelUnchanged: true, noOrphanStages: true };
  const arch = (await run("docker", ["info", "--format", "{{.Architecture}}"])).stdout.trim();
  const linuxArch = arch === "x86_64" ? "amd64" : arch === "aarch64" ? "arm64" : arch;
  if (!["amd64", "arm64"].includes(linuxArch)) throw new Error("Unsupported Docker host architecture");
  const archive = resolve(packages, `jumpserver233-${report.testVersion}-linux-${linuxArch}.tar.gz`), selectedPort = await port();
  const linuxSHA = createHash("sha256").update(readFileSync(archive)).digest("hex");
  const token = randomUUID() + randomUUID();
  await run("docker", ["run", "--detach", "--pull", "missing", "--name", owner,
    "--label", `com.jumpserver233.qa.owner=${owner}`, "--label", `com.jumpserver233.qa.workspace=${root}`,
    "--read-only", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=512m", "--publish", `127.0.0.10:${selectedPort}:8080`,
    "--mount", `type=bind,source=${archive},target=/artifact/package.tar.gz,readonly`,
    "--env", "JMS_ADDR=0.0.0.0:8080", "--env", `JMS_ADMIN_TOKEN=${token}`, "--env", "JMS_DATA_DIR=/tmp/data", "--env", `JMS_QA_PACKAGE_SHA=${linuxSHA}`,
    "golang:1.27-bookworm", "sh", "-ceu", 'mkdir /tmp/native; tar -xzf /artifact/package.tar.gz -C /tmp/native; /tmp/native/jms update stage --root /tmp/releases --file /artifact/package.tar.gz --sha256 "$JMS_QA_PACKAGE_SHA" >/dev/null; /tmp/native/jms update stage --root /tmp/releases --file /artifact/package.tar.gz --sha256 "$JMS_QA_PACKAGE_SHA" >/dev/null; /tmp/native/jms update stage-status --root /tmp/releases --sha256 "$JMS_QA_PACKAGE_SHA" >/dev/null; export JMS_WEB_DIR="/tmp/releases/releases/$JMS_QA_PACKAGE_SHA/web"; exec "/tmp/releases/releases/$JMS_QA_PACKAGE_SHA/jms233-server"']);
  const url = `http://127.0.0.10:${selectedPort}`;
  let healthy = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    try { const response = await fetch(url + "/api/health", { signal: AbortSignal.timeout(1000) }); const data = await response.json(); if (response.ok && data.version === report.testVersion) { healthy = true; break; } } catch { /* bounded readiness */ }
    const [container] = await inspectQAContainers(run, [owner]); if (!container || !accept(container)) throw new Error("Native QA container exited or changed ownership");
    await delay(100);
  }
  if (!healthy) throw new Error("Native single-port server not healthy");
  const html = await (await fetch(url + "/console/settings")).text();
  if (!html.includes("JumpServer233") || (await fetch(url + "/api/v1/assets")).status !== 401) throw new Error("Native web/auth isolation failed");
  report.linuxExecution = { arch: linuxArch, singlePort: true, protectedAPI: true, web: true, readOnlyRoot: true, stagedCandidate: true };
  // Repeating package creation must refuse replacement of an existing archive.
  let conflict = false;
  const repeatedArchive = resolve(packages, `jumpserver233-${report.testVersion}-linux-amd64.tar.gz`);
  const originalDigest = createHash("sha256").update(readFileSync(repeatedArchive)).digest("hex");
  try { await run("go", ["run", "./cmd/jms-package", "--version", report.testVersion, "--commit", report.commit, "--built-at", report.builtAt, "--target", "linux/amd64", "--out", packages,"--web-dir",nativeWeb], { cwd: resolve(root, "server") }); }
  catch (e) { conflict = String(e.stderr).includes("update destination already exists"); }
  if (!conflict) throw new Error("Native package unexpectedly replaced existing bytes");
  if (createHash("sha256").update(readFileSync(repeatedArchive)).digest("hex") !== originalDigest) throw new Error("Repeated package changed existing bytes");
  report.replacementRefused = true; report.status = "passed";
} catch (e) {
  report.status = "failed"; report.error = "Native QA failed; no release or deployment was created"; process.exitCode = 1;
  report.diagnostic = fixtureDiagnostic(String(e.stderr || e.message));
} finally {
  for (let round = 0; round < 2; round++) {
    try { await cleanup(); report.cleanup[round ? "idempotent" : "removed"] = true; }
    catch { report.cleanup.error = "Owned native QA cleanup incomplete"; report.status = "cleanup_failed"; process.exitCode = 1; }
  }
  report.cleanup.temporaryArtifactsRemoved = !existsSync(temporary); save();
  console.log(JSON.stringify(report));
}
