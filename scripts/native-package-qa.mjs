// Build every native target, execute the host CLI and a Linux single-port server,
// then remove only this run's temporary artifacts and container. Never publish.
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { createRequire } from "node:module";
import { setTimeout as delay } from "node:timers/promises";
import { inspectQAContainers, inspectQAImages, inspectQANetworks, removeUnusedQAImages, removeLocalBuildHistory, pruneOwnedQACache, removeOwnedTree } from "./qa-lifecycle.mjs";
import { buildQAImage } from "../server/testsupport/docker-qa.mjs";
import { fixtureDiagnostic } from "../server/testsupport/ci-health.mjs";
import { classifyNativeBrowserLog } from "./native-browser-logs.mjs";
import { retainQAArtifacts } from "./qa-retention.mjs";

const root = fileURLToPath(new URL("..", import.meta.url)), execute = promisify(execFile);
const cache = resolve(root, ".cache"), output = resolve(cache, "qa-reports/confined-sftp");
mkdirSync(output, { recursive: true });
const temporary = mkdtempSync(resolve(cache, "native-package-qa-")), packages = resolve(temporary, "packages");
const owner = "jms233-native-package-" + randomUUID();
const sshImage = owner + "-ssh:qa";
const report = { at: new Date().toISOString(), pid: process.pid, owner, temporaryDirectory: temporary, status: "running", packages: [], cleanup: {} };
const save = () => writeFileSync(resolve(output, "native-packages.json"), JSON.stringify(report, null, 2));
const run = (command, args, options = {}) => execute(command, args, { cwd: root, windowsHide: true, maxBuffer: 2 * 1024 * 1024, ...options });
const runInput = (command, args, input, options = {}) => { const pending = run(command, args, options); pending.child.stdin.on("error", () => {}); pending.child.stdin.end(input); return pending; };
const accept = c => c.Config?.Labels?.["com.jumpserver233.qa.owner"] === owner && c.Config?.Labels?.["com.jumpserver233.qa.workspace"] === root;
async function cleanup() {
  for (const container of await inspectQAContainers(run, [owner, owner + "-ssh"])) { if (!accept(container)) throw new Error("Native QA container changed ownership"); await run("docker", ["rm", "--force", "--volumes", container.Id]); }
  const [network] = await inspectQANetworks(run, [owner]);
  if (network) { if (network.Labels?.["com.jumpserver233.qa.owner"] !== owner || network.Labels?.["com.jumpserver233.qa.workspace"] !== root) throw new Error("Native QA network changed ownership"); await run("docker", ["network", "rm", network.Id]); }
  const [image] = await inspectQAImages(run, [sshImage]);
  if (image) { if (!accept(image) || image.RepoTags?.length !== 1 || image.RepoTags[0] !== sshImage) throw new Error("Native QA image changed ownership"); report.cleanup.removedImages = (report.cleanup.removedImages || 0) + await removeUnusedQAImages(run, [image.Id]); }
  report.cleanup.removedBuildHistory = [...(report.cleanup.removedBuildHistory || []), ...await removeLocalBuildHistory(run, root)];
  report.cleanup.prunedCache = [...(report.cleanup.prunedCache || []), ...await pruneOwnedQACache(run, owner)];
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
  const hostEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.toUpperCase().startsWith("JMS_")));
  const hostData = resolve(temporary, "host-data"), hostInstall = resolve(temporary, "host-install");
  hostEnv.JMS_DATA_DIR = hostData; hostEnv.JMS_WEB_DIR = resolve(extracted, "web");
  await run(resolve(extracted, process.platform === "win32" ? "jms233-server.exe" : "jms233-server"), ["--check-data"], { env: hostEnv });
  await run(cli, ["update", "stage", "--root", hostInstall, "--file", hostArchive, "--sha256", hostSHA], { env: hostEnv });
  const password = "synthetic-native-install-checkpoint";
  const hostInstallArgs = ["update", "install", "--root", hostInstall, "--data-dir", hostData, "--sha256", hostSHA, "--revision", "0", "--request-id", "native-install-host-001", "--passphrase-file", "-"];
  const hostSelected = JSON.parse((await runInput(cli, hostInstallArgs, password, { env: hostEnv })).stdout);
  const hostAgain = JSON.parse((await runInput(cli, hostInstallArgs, password, { env: hostEnv })).stdout);
  if (hostSelected.status !== "selected" || hostSelected.revision !== 1 || !hostAgain.unchanged || hostAgain.transaction_id !== hostSelected.transaction_id) throw new Error("Native host installation/checkpoint replay failed");
  report.hostInstallation = { encryptedCheckpoint: true, actualTargetPreflight: true, selected: true, idempotent: true };
  const arch = (await run("docker", ["info", "--format", "{{.Architecture}}"])).stdout.trim();
  const linuxArch = arch === "x86_64" ? "amd64" : arch === "aarch64" ? "arm64" : arch;
  if (!["amd64", "arm64"].includes(linuxArch)) throw new Error("Unsupported Docker host architecture");
  const archive = resolve(packages, `jumpserver233-${report.testVersion}-linux-${linuxArch}.tar.gz`), selectedPort = await port();
  const linuxSHA = createHash("sha256").update(readFileSync(archive)).digest("hex");
  report.upgradeVersion = "v0.0.1";
  await run("go", ["run", "./cmd/jms-package", "--version", report.upgradeVersion, "--commit", report.commit, "--built-at", report.builtAt, "--target", `linux/${linuxArch}`, "--out", packages, "--web-dir", nativeWeb], { cwd: resolve(root, "server") });
  const upgradeArchive = resolve(packages, `jumpserver233-${report.upgradeVersion}-linux-${linuxArch}.tar.gz`), upgradeSHA = createHash("sha256").update(readFileSync(upgradeArchive)).digest("hex");
  // These failure candidates are local fixtures, never release artifacts.
  const linuxBase = resolve(temporary, "linux-base"); mkdirSync(linuxBase); await run("tar", ["-xzf", archive, "-C", linuxBase]);
  const synthetic = [];
  for (const [mode, version] of [["before", "v0.0.2"], ["after", "v0.0.3"]]) {
    const binary = resolve(temporary, "fixture-" + mode), fixtureArchive = resolve(packages, "fixture-" + mode + ".tar.gz");
    await run("go", ["build", "-trimpath", "-buildvcs=false", "-ldflags", `-s -w -X main.failureMode=${mode} -X main.version=${version}`, "-o", binary, "./testsupport/activationfixture"], { cwd: resolve(root, "server"), env: { ...process.env, GOOS: "linux", GOARCH: linuxArch, CGO_ENABLED: "0" } });
    await run("go", ["run", "./testsupport/releasefixture", "--base-dir", linuxBase, "--server-binary", binary, "--out", fixtureArchive, "--version", version], { cwd: resolve(root, "server") });
    synthetic.push({ mode, version, path: fixtureArchive, sha: createHash("sha256").update(readFileSync(fixtureArchive)).digest("hex") });
  }
  report.recoveryVersion = "v0.0.4";
  await run("go", ["run", "./cmd/jms-package", "--version", report.recoveryVersion, "--commit", report.commit, "--built-at", report.builtAt, "--target", `linux/${linuxArch}`, "--out", packages, "--web-dir", nativeWeb], { cwd: resolve(root, "server") });
  const recoveryArchive = resolve(packages, `jumpserver233-${report.recoveryVersion}-linux-${linuxArch}.tar.gz`), recoverySHA = createHash("sha256").update(readFileSync(recoveryArchive)).digest("hex");
  const labels = ["--label", `com.jumpserver233.qa.owner=${owner}`, "--label", `com.jumpserver233.qa.workspace=${root}`];
  await run("docker", ["network", "create", ...labels, owner]);
  await buildQAImage(run, ["build", "--tag", sshImage, ...labels, resolve(root, "server/testsupport/openssh")]);
  await run("docker", ["run", "--detach", "--name", owner + "-ssh", ...labels, "--network", owner, sshImage]);
  let fingerprint = "";
  for (let attempt = 0; attempt < 100; attempt++) { try { fingerprint = (await run("docker", ["exec", owner + "-ssh", "ssh-keygen", "-l", "-E", "sha256", "-f", "/run/keyhost-ed25519.pub"])).stdout.trim().split(/\s+/)[1]; if (fingerprint?.startsWith("SHA256:")) break; } catch { /* bounded fixture readiness */ } await delay(100); }
  if (!fingerprint?.startsWith("SHA256:")) throw new Error("Native installation OpenSSH fixture unavailable");
  const token = randomUUID() + randomUUID();
  await run("docker", ["run", "--detach", "--pull", "missing", "--name", owner,
    ...labels, "--network", owner,
    "--read-only", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=768m", "--publish", `127.0.0.10:${selectedPort}:8080`,
    "--mount", `type=bind,source=${archive},target=/artifact/package.tar.gz,readonly`,
    "--mount", `type=bind,source=${upgradeArchive},target=/artifact/upgrade.tar.gz,readonly`,
    ...synthetic.flatMap(f => ["--mount", `type=bind,source=${f.path},target=/artifact/${f.mode}.tar.gz,readonly`]),
    "--mount", `type=bind,source=${recoveryArchive},target=/artifact/recovery.tar.gz,readonly`,
    "--env", "JMS_ADDR=0.0.0.0:8080", "--env", `JMS_ADMIN_TOKEN=${token}`, "--env", "JMS_DATA_DIR=/tmp/data", "--env", "JMS_WEB_DIR=/tmp/native/web", "--env", `JMS_PUBLIC_URL=http://127.0.0.10:${selectedPort}`, "--env", `JMS_QA_PACKAGE_SHA=${linuxSHA}`,
    "golang:1.27-bookworm", "sh", "-ceu", 'mkdir /tmp/native; tar -xzf /artifact/package.tar.gz -C /tmp/native; /tmp/native/jms233-server --check-data; /tmp/native/jms update stage --root /tmp/releases --file /artifact/package.tar.gz --sha256 "$JMS_QA_PACKAGE_SHA" >/dev/null; exec sleep infinity']);
  const url = `http://127.0.0.10:${selectedPort}`;
  const inContainer = (args, input) => input === undefined ? run("docker", ["exec", owner, "/tmp/native/jms", ...args]) : runInput("docker", ["exec", "-i", owner, "/tmp/native/jms", ...args], input);
  const installArgs = (sha, revision, id) => ["update", "install", "--root", "/tmp/releases", "--data-dir", "/tmp/data", "--sha256", sha, "--revision", String(revision), "--request-id", id, "--passphrase-file", "-"];
  // The container's bounded bootstrap must finish before invoking its CLI.
  for (let attempt = 0; ; attempt++) { try { await inContainer(["update", "stage-status", "--root", "/tmp/releases", "--sha256", linuxSHA]); break; } catch { if (attempt === 99) throw new Error("Native bootstrap did not complete"); await delay(100); } }
  const initial = JSON.parse((await inContainer(installArgs(linuxSHA, 0, "native-linux-initial"), password)).stdout);
  if (initial.status !== "selected") throw new Error("Native Linux initial selection failed");
  await runInput("docker", ["exec", "-i", owner, "sh", "-ceu", "umask 077; cat > /tmp/checkpoint-passphrase"], password);
  const waitHealthy = async version => { for (let attempt = 0; attempt < 100; attempt++) { try { const response = await fetch(url + "/api/health", { signal: AbortSignal.timeout(1000) }); const health = await response.json(); if (response.ok && health.version === version && response.headers.get("X-JMS-Activation-Phase") !== "trial") return; } catch { /* bounded readiness */ } await delay(100); } throw new Error("Selected native server did not open business traffic"); };
  const launchSelected = async () => run("docker", ["exec", "--detach", owner, "sh", "-ceu", 'echo $$ >/tmp/launcher.pid; exec /tmp/native/jms update run --root /tmp/releases --passphrase-file /tmp/checkpoint-passphrase']);
  const startSelected = async version => { await launchSelected(); await waitHealthy(version); };
  const stopSelected = async () => { await run("docker", ["exec", owner, "sh", "-ceu", 'pid=$(cat /tmp/launcher.pid); case "$pid" in ""|*[!0-9]*) exit 1;; esac; kill -INT "$pid"']); for (let attempt = 0; attempt < 150; attempt++) { try { await run("docker", ["exec", owner, "sh", "-ceu", 'pid=$(cat /tmp/launcher.pid); kill -0 "$pid"']); } catch { return; } await delay(100); } throw new Error("Native launcher did not stop"); };
  await startSelected(report.testVersion);
  const api = async (method, path, body, bearer, status = 200) => { const response = await fetch(url + path, { method, headers: { "Content-Type": "application/json", ...(bearer ? { Authorization: "Bearer " + bearer } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(10000) }); if (response.status !== status) throw new Error("Native installation API status " + response.status + " differs from " + status + " at " + path); return response.json(); };
  const loginBefore = await api("POST", "/api/v1/authentication/auth/", { username: "root", password: "root" });
  const asset = await api("POST", "/api/v1/assets", { name: "Native upgrade SSH", host: owner + "-ssh", port: 22, username: "keyqa", password: "synthetic-keyhost-password-233", host_key_fingerprint: fingerprint }, loginBefore.access_token, 201);
  const operatorPassword = "synthetic-native-operator-password";
  const operator = await api("POST", "/api/v1/users", { username: "native.operator", password: operatorPassword, role: "operator" }, loginBefore.access_token, 201);
  const operatorBefore = await api("POST", "/api/v1/authentication/auth/", { username: operator.username, password: operatorPassword });
  if ((await api("GET", "/api/v1/assets", undefined, operatorBefore.access_token)).length !== 0) throw new Error("Ungranting native operator could view assets");
  await api("POST", "/api/v1/grants", { user_id: operator.id, asset_id: asset.id, account: "keyqa", actions: ["view"] }, loginBefore.access_token, 201);
  const viewOnly = async bearer => { if (!(await api("GET", "/api/v1/assets", undefined, bearer)).some(row => row.id === asset.id)) throw new Error("Native view grant was lost"); await api("POST", "/api/v1/sessions", { asset_id: asset.id, cols: 80, rows: 24 }, bearer, 403); };
  await viewOnly(operatorBefore.access_token);
  const execSSH = async (bearer, text) => { const job = await api("POST", "/api/v1/ops/jobs", { asset_id: asset.id, command: "printf " + text, timeout_seconds: 10, request_id: randomUUID() }, bearer, 201); for (let attempt = 0; attempt < 100; attempt++) { const state = await api("GET", "/api/v1/ops/jobs/" + job.id, undefined, bearer); if (state.state === "succeeded" && state.stdout === text) return job.id; if (["failed", "interrupted", "denied"].includes(state.state)) throw new Error("Native installation real SSH failed"); await delay(100); } throw new Error("Native installation SSH timed out"); };
  const originalJob = await execSSH(loginBefore.access_token, "native-before-upgrade");
  await inContainer(["update", "stage", "--root", "/tmp/releases", "--file", "/artifact/upgrade.tar.gz", "--sha256", upgradeSHA]);
  let busy = false; try { await inContainer(installArgs(upgradeSHA, 1, "native-linux-busy"), password); } catch (e) { busy = String(e.stderr).includes("data directory is in use"); } if (!busy) throw new Error("Running data was not protected from upgrade");
  await stopSelected();
  const users = (await run("docker", ["exec", owner, "cat", "/tmp/data/users.json"])).stdout;
  await runInput("docker", ["exec", "-i", owner, "sh", "-ceu", "cat > /tmp/data/users.json"], "synthetic invalid store");
  let rolledBack = false; try { await inContainer(installArgs(upgradeSHA, 1, "native-linux-failed"), password); } catch (e) { const receipt = JSON.parse(e.stdout); rolledBack = receipt.status === "rolled_back" && receipt.current.version === report.testVersion; }
  if (!rolledBack || (await run("docker", ["exec", owner, "cat", "/tmp/data/users.json"])).stdout !== "synthetic invalid store") throw new Error("Failed native preflight did not preserve its original checkpoint");
  await runInput("docker", ["exec", "-i", owner, "sh", "-ceu", "cat > /tmp/data/users.json"], users);
  const upgraded = JSON.parse((await inContainer(installArgs(upgradeSHA, 1, "native-linux-upgrade"), password)).stdout);
  const replayed = JSON.parse((await inContainer(installArgs(upgradeSHA, 1, "native-linux-upgrade"), password)).stdout);
  if (upgraded.status !== "selected" || upgraded.revision !== 2 || !replayed.unchanged || replayed.transaction_id !== upgraded.transaction_id) throw new Error("Native upgrade selection replay failed");
  await startSelected(report.upgradeVersion);
  const loginAfter = await api("POST", "/api/v1/authentication/auth/", { username: "root", password: "root" });
  if (loginAfter.user.id !== loginBefore.user.id || (await api("GET", "/api/v1/ops/jobs/" + originalJob, undefined, loginAfter.access_token)).state !== "succeeded") throw new Error("Native upgrade lost identity or command audit");
  await execSSH(loginAfter.access_token, "native-after-upgrade");
  const operatorAfter = await api("POST", "/api/v1/authentication/auth/", { username: operator.username, password: operatorPassword });
  if (operatorAfter.user.id !== operatorBefore.user.id) throw new Error("Native operator identity changed");
  await viewOnly(operatorAfter.access_token);
  // Before-commit failure must restore the checkpoint and keep the old service.
  await stopSelected();
  await inContainer(["update", "stage", "--root", "/tmp/releases", "--file", "/artifact/before.tar.gz", "--sha256", synthetic[0].sha]);
  await inContainer(installArgs(synthetic[0].sha, 2, "native-activation-before"), password);
  await launchSelected(); await waitHealthy(report.upgradeVersion);
  let state = JSON.parse((await inContainer(["update", "install-status", "--root", "/tmp/releases"])).stdout);
  if (state.revision !== 4 || state.current.version !== report.upgradeVersion || !state.receipts.some(r => r.request_id === "native-activation-before" && r.failure_code === "activation_failed" && r.status === "rolled_back")) throw new Error("First-start failure did not roll back with a monotonic revision");
  let trialWriteAbsent = false; try { await run("docker", ["exec", owner, "test", "!", "-e", "/tmp/data/trial-target-only"]); trialWriteAbsent = true; } catch { /* fail below */ }
  if (!trialWriteAbsent) throw new Error("Failed trial data remained live");
  const fallbackLogin = await api("POST", "/api/v1/authentication/auth/", { username: "root", password: "root" });
  await execSSH(fallbackLogin.access_token, "native-after-activation-rollback");
  // After the durable active guard, a failed process must never restore old data.
  await stopSelected();
  await inContainer(["update", "stage", "--root", "/tmp/releases", "--file", "/artifact/after.tar.gz", "--sha256", synthetic[1].sha]);
  await inContainer(installArgs(synthetic[1].sha, 4, "native-activation-after"), password);
  await launchSelected();
  for (let attempt = 0; ; attempt++) { try { await run("docker", ["exec", owner, "sh", "-ceu", 'pid=$(cat /tmp/launcher.pid); kill -0 "$pid"']); } catch { break; } if (attempt === 199) throw new Error("Post-commit failure launcher did not terminate"); await delay(100); }
  state = JSON.parse((await inContainer(["update", "install-status", "--root", "/tmp/releases"])).stdout);
  if (state.revision !== 5 || state.current.version !== synthetic[1].version || state.activation_state !== "active" || (await run("docker", ["exec", owner, "cat", "/tmp/data/post-active-data"])).stdout !== "preserve post-activation write") throw new Error("Post-commit failure rolled back new data");
  await inContainer(["update", "install-recover", "--root", "/tmp/releases", "--passphrase-file", "-"], password);
  await inContainer(["update", "stage", "--root", "/tmp/releases", "--file", "/artifact/recovery.tar.gz", "--sha256", recoverySHA]);
  await inContainer(installArgs(recoverySHA, 5, "native-activation-recovery"), password);
  await startSelected(report.recoveryVersion);
  if ((await run("docker", ["exec", owner, "cat", "/tmp/data/post-active-data"])).stdout !== "preserve post-activation write") throw new Error("Forward recovery lost committed data");
  const recoveredLogin = await api("POST", "/api/v1/authentication/auth/", { username: "root", password: "root" });
  if (recoveredLogin.user.id !== loginBefore.user.id || (await api("GET", "/api/v1/ops/jobs/" + originalJob, undefined, recoveredLogin.access_token)).state !== "succeeded") throw new Error("Forward recovery lost identity or audit");
  await execSSH(recoveredLogin.access_token, "native-after-forward-recovery");
  const recoveredOperator = await api("POST", "/api/v1/authentication/auth/", { username: operator.username, password: operatorPassword }); await viewOnly(recoveredOperator.access_token);
	const workspace = "/home/keyqa/workspace";
	await run("docker", ["exec", owner + "-ssh", "sh", "-ceu", "mkdir -p /home/keyqa/workspace /home/keyqa/protected; printf preserve > /home/keyqa/protected/sentinel; chown -R keyqa:keyqa /home/keyqa/workspace /home/keyqa/protected"]);
	await api("PUT", "/api/v1/assets/" + asset.id, { name: asset.name, host: asset.host, port: asset.port, username: asset.username, host_key_fingerprint: fingerprint, ssh_workspace: workspace }, recoveredLogin.access_token);
	const workspaceJob = async (command, success) => {
		const submitted = await api("POST", "/api/v1/ops/jobs", { asset_id: asset.id, command, timeout_seconds: 10, request_id: randomUUID() }, recoveredLogin.access_token, 201);
		for (let attempt = 0; attempt < 150; attempt++) {
			const job = await api("GET", "/api/v1/ops/jobs/" + submitted.id, undefined, recoveredLogin.access_token);
			if (["succeeded", "failed", "interrupted", "denied", "timed_out"].includes(job.state)) {
				if ((job.state === "succeeded") !== success) throw new Error("Workspace job result differs from expected enforcement");
				return job;
			}
			await delay(100);
		}
		throw new Error("Workspace job timed out");
	};
	if ((await workspaceJob("pwd", true)).stdout.trim() !== workspace) throw new Error("Workspace cwd was not fixed");
	if ((await workspaceJob("printf workspace-inside > owned; cat owned", true)).stdout !== "workspace-inside") throw new Error("Workspace write failed");
	await workspaceJob("cat /home/keyqa/protected/sentinel", false);
	await workspaceJob("printf changed > /home/keyqa/protected/sentinel", false);
	await api("GET", "/api/v1/assets/" + asset.id + "/files", undefined, recoveredOperator.access_token, 403);
	const transfer = async (method, name, body, status = 200, overwrite = false) => {
		const response = await fetch(url + `/api/v1/assets/${asset.id}/files/content?` + new URLSearchParams({ path: name, overwrite: String(overwrite) }), { method, headers: { Authorization: "Bearer " + recoveredLogin.access_token }, ...(body===undefined ? {} : {body}), signal: AbortSignal.timeout(15000) });
		if(response.status!==status) throw new Error(`Confined SFTP ${method} status ${response.status} differs from ${status}`);
		return response;
	};
	await transfer("PUT", "sftp-api.txt", "first", 201);
	await transfer("PUT", "sftp-api.txt", "must-not-overwrite", 409);
	if(await (await transfer("GET", "sftp-api.txt")).text()!=="first") throw new Error("SFTP conflict overwrote bytes");
	for(let retry=0;retry<2;retry++) await transfer("PUT", "sftp-api.txt", "replacement", 201, true);
	if(await (await transfer("GET", "sftp-api.txt")).text()!=="replacement") throw new Error("SFTP replacement bytes differ");
	await run("docker",["exec",owner+"-ssh","ln","-s","/home/keyqa/protected","/home/keyqa/workspace/escape"]);
	await transfer("GET", "escape/sentinel", undefined, 400);
	await transfer("GET", "../protected/sentinel", undefined, 400);
	const listing=await api("GET",`/api/v1/assets/${asset.id}/files` ,undefined,recoveredLogin.access_token);
	if(!listing.entries.some(f=>f.name==="sftp-api.txt") || listing.entries.some(f=>f.name===".jumpserver233")) throw new Error("SFTP virtual root differs");
	await api("PUT", "/api/v1/assets/"+asset.id,{name:asset.name,host:asset.host,port:asset.port,username:asset.username,host_key_fingerprint:fingerprint,ssh_workspace:"/home/keyqa"},recoveredLogin.access_token);
	await workspaceJob("printf must-not-run > workspace/overlap-executed",false);
	await run("docker",["exec",owner+"-ssh","test","!","-e","/home/keyqa/workspace/overlap-executed"]);
	await api("PUT", "/api/v1/assets/"+asset.id,{name:asset.name,host:asset.host,port:asset.port,username:asset.username,host_key_fingerprint:fingerprint,ssh_workspace:workspace},recoveredLogin.access_token);
	const nativeExec = JSON.parse((await run("docker", ["exec", owner, "sh", "-ceu", 'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 /tmp/native/jms exec "$1" --json -- pwd', "sh", asset.id])).stdout);
	if (nativeExec.state !== "succeeded" || nativeExec.stdout.trim() !== workspace) throw new Error("Native CLI workspace execution failed");
	if ((await run("docker", ["exec", owner + "-ssh", "cat", "/home/keyqa/protected/sentinel"])).stdout !== "preserve") throw new Error("Workspace modified protected content");
	report.workspace = { directory: workspace, realSSH: true, realCLI: true, trustedCwd: true, insideWrite: true, outsideReadAndWriteRefused: true, confinedSFTP: true, sftpNoOverwriteAndRepeatedReplacement: true, sftpSymlinkAndTraversalRefused: true, helperOverlapRefusedBeforeExecution: true, protectedDataPreserved: true };
  report.activation = { privateReadinessAndHTTPProbe: true, businessGateBeforeCommit: true, preCommitFailureRolledBack: true, oldServiceAutomaticallyResumed: true, failedTrialWriteRemoved: trialWriteAbsent, monotonicRollbackRevision: 4, postCommitFailurePreservedVersionAndData: true, forwardRecoveryVersion: report.recoveryVersion, finalRevision: 6, realSSHAfterRollbackAndForwardRecovery: true };
  report.installation = { initialVersion: report.testVersion, selectedVersion: report.upgradeVersion, revision: upgraded.revision, runningUpgradeRefused: busy, failedPreflightRolledBack: rolledBack, checkpointBytesPreserved: true, idempotent: true, userIDPreserved: true, realSSHBeforeAndAfter: true, commandAuditPreserved: true, operatorViewGrantPreserved: true, operatorConnectDeniedBeforeAndAfter: true };
  const html = await (await fetch(url + "/console/settings")).text();
  if (!html.includes("JumpServer233") || (await fetch(url + "/api/v1/assets")).status !== 401) throw new Error("Native web/auth isolation failed");
  report.linuxExecution = { arch: linuxArch, singlePort: true, protectedAPI: true, web: true, readOnlyRoot: true, stagedCandidate: true };
  const { chromium, expect } = createRequire(new URL("../web/package.json", import.meta.url))("@playwright/test");
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ locale: "en-US", viewport: { width: 1280, height: 900 } });
    const page = await context.newPage(), errors = [], httpFailures = [], diagnostics = { anonymous_session_probe: 0, headless_gpu_readback: 0 };
	page.on("response", response => { if(response.status()>=400) { const path=new URL(response.url()).pathname; if (!(response.status()===401 && path==="/api/v1/authentication/session/" && report.browserLoginStatus!==200)) httpFailures.push({method:response.request().method(),path,status:response.status()}); } });
    page.on("pageerror", e => errors.push(e.message));
    page.on("console", message => {
      if (!["warning", "error"].includes(message.type())) return;
      const category = classifyNativeBrowserLog(message.type(), message.text(), message.location().url, url, report.browserLoginStatus === 200);
      if (category === "unexpected") errors.push(message.text()); else diagnostics[category]++;
    });
    await page.goto(url + "/login");
    await page.getByRole("textbox", { name: "Username", exact: true }).fill("root");
    await page.getByRole("textbox", { name: "Password", exact: true }).fill("root");
    const login = page.waitForResponse(response => response.url().endsWith("/api/v1/authentication/auth/") && response.request().method() === "POST");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    report.browserLoginStatus = (await login).status();
    if (report.browserLoginStatus !== 200) throw new Error("Staged candidate browser login status was " + report.browserLoginStatus);
    await expect(page.getByRole("heading", { name: "Assets", exact: true })).toBeVisible();
	let terminalOutput = "";
	page.on("websocket", socket => socket.on("framereceived", event => { if (Buffer.isBuffer(event.payload)) terminalOutput += event.payload.toString("utf8"); }));
	const row = page.getByRole("row").filter({ hasText: "Native upgrade SSH" });
	await row.getByRole("button", { name: "Connect", exact: true }).click();
	const terminal = page.locator(".ssh-terminal-dialog");
	await expect(terminal.locator(".ssh-terminal-status.connected")).toBeVisible();
	await terminal.locator(".xterm-helper-textarea").pressSequentially("printf '\\167\\157\\162\\153\\163\\160\\141\\143\\145\\055\\160\\164\\171\\055\\157\\153\\012'");
	await page.keyboard.press("Enter");
	await expect.poll(() => terminalOutput).toContain("workspace-pty-ok");
	const deletedSession = page.waitForResponse(response => response.request().method() === "DELETE" && /\/api\/v1\/sessions\/[^/]+$/.test(new URL(response.url()).pathname));
	await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
	if ((await deletedSession).status()!==204) throw new Error("Closing the browser session was not idempotent");
	report.workspace.browserPTY = true;
	await row.getByRole("button", { name: "Edit", exact: true }).click();
	await expect(page.getByRole("textbox", { name: "SSH execution workspace (optional)", exact: true })).toHaveValue(workspace);
	await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
	await row.getByRole("button",{name:"Files",exact:true}).click();
	const manager=page.locator(".sftp-manager");
	await expect(manager.getByRole("button",{name:"sftp-api.txt",exact:true})).toBeVisible();
	await expect(manager.getByText(`Workspace ${workspace} (shown as /)`,{exact:true})).toBeVisible();
	await manager.locator('input[type="file"]').setInputFiles({name:"sftp-browser.txt",mimeType:"text/plain",buffer:Buffer.from("browser-confined-upload")});
	await expect(manager.getByRole("button",{name:"sftp-browser.txt",exact:true})).toBeVisible();
	const browserDownload=page.waitForEvent("download");
	await manager.getByRole("row").filter({hasText:"sftp-browser.txt"}).getByRole("button",{name:"Download",exact:true}).click();
	const downloaded=await browserDownload;
	if(readFileSync(await downloaded.path(),"utf8")!=="browser-confined-upload") throw new Error("Browser SFTP download bytes differ");
	await downloaded.delete();
	await manager.getByRole("textbox",{name:"Folder name",exact:true}).fill("browser-dir");
	await manager.getByRole("button",{name:"New folder",exact:true}).click();
	await expect(manager.getByRole("button",{name:"browser-dir",exact:true})).toBeVisible();
	await manager.screenshot({path:resolve(output,"sftp.en.png")});
	await manager.getByRole("button",{name:"Cancel",exact:true}).last().click();
	await page.getByRole("button", { name: "中文", exact: true }).click();
	await row.getByRole("button", { name: "编辑", exact: true }).click();
	await expect(page.getByRole("textbox", { name: "SSH 执行工作区（可选）", exact: true })).toHaveValue(workspace);
	await page.getByRole("button", { name: "取消", exact: true }).click();
	await row.getByRole("button",{name:"文件",exact:true}).click();
	await expect(manager.getByRole("button",{name:"sftp-browser.txt",exact:true})).toBeVisible();
	await expect(manager.getByText(`工作区 ${workspace}（显示为 /）`,{exact:true})).toBeVisible();
	await manager.screenshot({path:resolve(output,"sftp.zh.png")});
	await manager.getByRole("button",{name:"取消",exact:true}).last().click();
	report.workspace.browserUploadDownloadAndMkdir=true;
	await page.getByRole("button", { name: "EN", exact: true }).click();
    await page.goto(url + "/console/settings");
    await page.getByRole("tab", { name: "Security", exact: true }).click();
    const card = page.locator(".update-settings-card");
    await expect(card.getByRole("heading", { name: "Software updates", exact: true })).toBeVisible();
    await expect(card.getByText(report.recoveryVersion, { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(card.getByRole("heading", { name: "软件更新", exact: true })).toBeVisible();
    if (errors.length || httpFailures.length) {
      report.browserDiagnostics = errors.slice(-10).map(message => fixtureDiagnostic(message));
	  report.browserHTTPFailures = httpFailures.slice(-10);
      throw new Error("Staged candidate browser reported runtime warnings or errors");
    }
    report.browser = { languages: ["en", "zh-CN"], authenticated: true, displayedVersion: report.recoveryVersion, applicationWarningsOrErrors: errors.length, expectedBrowserDiagnostics: diagnostics, fromInstalledCandidate: true };
  } finally { await browser.close(); }
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
  try { retainQAArtifacts(root, { currentRun: output }); }
  catch { report.retentionError = "Artifact retention incomplete; retry node scripts/qa-retention.mjs --apply"; process.exitCode = 1; save(); }
  console.log(JSON.stringify(report));
}
