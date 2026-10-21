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
import { verifyScheduledInstallation } from "./scheduled-install-qa.mjs";
import { verifyAutomaticInstallation } from "./automatic-install-qa.mjs";
import { historicalBaseline, prepareHistoricalPackage, verifyHistoricalManifests } from "./historical-source.mjs";
import { verifySSHPasswordPolicy } from "./ssh-password-policy-qa.mjs";
import { verifyAccountChecks } from "./account-checks-qa.mjs";
import { verifyOperationDirectories, verifyOperationDirectoryBrowser } from "./operation-directories-qa.mjs";
import {verifyInteractiveDirectories} from "./interactive-directories-qa.mjs";
import { verifySSHCertificates, verifySSHCertificateRestart, verifySSHCertificateBrowser } from "./ssh-certificates-qa.mjs";

const root = fileURLToPath(new URL("..", import.meta.url)), execute = promisify(execFile);
const options = process.argv.slice(2), historical = options.includes("--historical");
if (historical) options.splice(options.indexOf("--historical"), 1);
const accountChecksOnly = options.includes("--account-checks-only");
if (accountChecksOnly) options.splice(options.indexOf("--account-checks-only"), 1);
const batch = options.length===0 ? (historical ? "historical-upgrade" : "execution-directories") : options.length===2 && options[0]==="--batch" && /^[a-z][a-z0-9-]{0,63}$/.test(options[1]) ? options[1] : null;
if (!batch) throw new Error("Use [--batch lowercase-name] [--historical]");
const cache = resolve(root, ".cache"), output = resolve(cache, "qa-reports/"+batch);
mkdirSync(output, { recursive: true });
const temporary = mkdtempSync(resolve(cache, "native-package-qa-")), packages = resolve(temporary, "packages");
const owner = "jms233-native-package-" + randomUUID();
const sshImage = owner + "-ssh:qa";
const report = { at: new Date().toISOString(), pid: process.pid, owner, temporaryDirectory: temporary, status: "running", scope: accountChecksOnly ? "mini-account-checks-regression" : "mini-ssh", deferredNativeFeatures: ["external-replay-storage"], packages: [], cleanup: {} };
const save = () => writeFileSync(resolve(output, "native-packages.json"), JSON.stringify(report, null, 2));
const run = (command, args, options = {}) => execute(command, args, { cwd: root, windowsHide: true, maxBuffer: 2 * 1024 * 1024, ...options });
const runInput = (command, args, input, options = {}) => { const pending = run(command, args, options); pending.child.stdin.on("error", () => {}); pending.child.stdin.end(input); return pending; };
const accept = c => c.Config?.Labels?.["com.jumpserver233.qa.owner"] === owner && c.Config?.Labels?.["com.jumpserver233.qa.workspace"] === root;
async function cleanup() {
  for (const container of await inspectQAContainers(run, [owner, owner + "-ssh",owner+"-feed"])) { if (!accept(container)) throw new Error("Native QA container changed ownership"); await run("docker", ["rm", "--force", "--volumes", container.Id]); }
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
  report.sourceDirty = Boolean((await run("git", ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "status", "--porcelain", "--untracked-files=all"])).stdout.trim());
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
  const controllerArchive = resolve(packages, `jumpserver233-${report.testVersion}-linux-${linuxArch}.tar.gz`);
  const old = historical ? await prepareHistoricalPackage({ temporary, architecture: linuxArch, run, phase: value => { report.phase=value; save(); } }) : null;
  const archive = old?.archive || controllerArchive, selectedPort = await port();
  const linuxSHA = createHash("sha256").update(readFileSync(archive)).digest("hex");
  report.upgradeVersion = "v0.0.1";
  await run("go", ["run", "./cmd/jms-package", "--version", report.upgradeVersion, "--commit", report.commit, "--built-at", report.builtAt, "--target", `linux/${linuxArch}`, "--out", packages, "--web-dir", nativeWeb], { cwd: resolve(root, "server") });
  const upgradeArchive = resolve(packages, `jumpserver233-${report.upgradeVersion}-linux-${linuxArch}.tar.gz`), upgradeSHA = createHash("sha256").update(readFileSync(upgradeArchive)).digest("hex");
  if (old) {
    const targetManifest = JSON.parse((await run("tar", ["-xOf", upgradeArchive, "manifest.json"])).stdout);
    report.historical = { ...verifyHistoricalManifests(old.manifest, targetManifest, report.commit), sourceTreeArchiveSHA256: old.sourceSHA256, sourcePackageSHA256: old.archiveSHA256, targetPackageSHA256: upgradeSHA, status: "built" };
    save();
  }
  report.phase = "native_fixtures"; save();
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
  await run("go", ["run", "./cmd/jms-package", "--version", "v0.0.5", "--commit", report.commit, "--built-at", report.builtAt, "--target", `linux/${linuxArch}`, "--out", packages, "--web-dir", nativeWeb], { cwd: resolve(root,"server") });
  const scheduledArchive=resolve(packages,`jumpserver233-v0.0.5-linux-${linuxArch}.tar.gz`), scheduledSHA=createHash("sha256").update(readFileSync(scheduledArchive)).digest("hex");
  const failedScheduledBinary=resolve(temporary,"fixture-scheduled-before"),failedScheduledArchive=resolve(packages,"fixture-scheduled-before.tar.gz");
  await run("go",["build","-trimpath","-buildvcs=false","-ldflags","-s -w -X main.failureMode=before -X main.version=v0.0.6","-o",failedScheduledBinary,"./testsupport/activationfixture"],{cwd:resolve(root,"server"),env:{...process.env,GOOS:"linux",GOARCH:linuxArch,CGO_ENABLED:"0"}});
  await run("go",["run","./testsupport/releasefixture","--base-dir",linuxBase,"--server-binary",failedScheduledBinary,"--out",failedScheduledArchive,"--version","v0.0.6"],{cwd:resolve(root,"server")});
  const failedScheduledSHA=createHash("sha256").update(readFileSync(failedScheduledArchive)).digest("hex");
  await run("go",["run","./cmd/jms-package","--version","v0.0.7","--commit",report.commit,"--built-at",report.builtAt,"--target",`linux/${linuxArch}`,"--out",packages,"--web-dir",nativeWeb],{cwd:resolve(root,"server")});
  const automaticArchive=resolve(packages,`jumpserver233-v0.0.7-linux-${linuxArch}.tar.gz`),feedDirectory=resolve(temporary,"feed"),feedBinary=resolve(temporary,"update-feed"),feedPort=await port();
  await run("go",["run","./testsupport/updatefeedfixture","--generate","--dir",feedDirectory],{cwd:resolve(root,"server")});
  await run("go",["build","-trimpath","-buildvcs=false","-o",feedBinary,"./testsupport/updatefeedfixture"],{cwd:resolve(root,"server"),env:{...process.env,GOOS:"linux",GOARCH:linuxArch,CGO_ENABLED:"0"}});
  const labels = ["--label", `com.jumpserver233.qa.owner=${owner}`, "--label", `com.jumpserver233.qa.workspace=${root}`];
  await run("docker", ["network", "create", ...labels, owner]);
  await run("docker",["run","--detach","--name",owner+"-feed",...labels,"--network",owner,"--read-only","--tmpfs","/tmp:rw,exec,nosuid,size=32m","--publish",`127.0.0.10:${feedPort}:9090`,"--mount",`type=bind,source=${feedBinary},target=/fixture/feed,readonly`,"--mount",`type=bind,source=${feedDirectory},target=/fixture/certs,readonly`,"--mount",`type=bind,source=${automaticArchive},target=/fixture/package.tar.gz,readonly`,"golang:1.27-bookworm","sh","-ceu",'cp /fixture/feed /tmp/feed; chmod 700 /tmp/feed; exec /tmp/feed --dir /fixture/certs --archive /fixture/package.tar.gz --version v0.0.7']);
  const feedIP=(await run("docker",["inspect","--format","{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",owner+"-feed"])).stdout.trim();
  if(!/^\d+\.\d+\.\d+\.\d+$/.test(feedIP)) throw new Error("Isolated feed address unavailable");
  const feedURL=`http://127.0.0.10:${feedPort}`;
  for(let attempt=0;;attempt++){try{if((await fetch(feedURL+"/health",{signal:AbortSignal.timeout(1000)})).ok)break;}catch{}if(attempt===99)throw new Error("Isolated feed not ready");await delay(100);}
  await buildQAImage(run, ["build", "--tag", sshImage, ...labels, resolve(root, "server/testsupport/openssh")]);
  await run("docker", ["run", "--detach", "--name", owner + "-ssh", ...labels, "--network", owner, sshImage]);
  let fingerprint = "";
  for (let attempt = 0; attempt < 100; attempt++) { try { fingerprint = (await run("docker", ["exec", owner + "-ssh", "ssh-keygen", "-l", "-E", "sha256", "-f", "/run/keyhost-ed25519.pub"])).stdout.trim().split(/\s+/)[1]; if (fingerprint?.startsWith("SHA256:")) break; } catch { /* bounded fixture readiness */ } await delay(100); }
  if (!fingerprint?.startsWith("SHA256:")) throw new Error("Native installation OpenSSH fixture unavailable");
  const token = randomUUID() + randomUUID();
  await run("docker", ["run", "--detach", "--pull", "missing", "--name", owner,
    ...labels, "--network", owner,
    "--add-host",`api.github.com:${feedIP}`,"--add-host",`github.com:${feedIP}`,
    "--read-only", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=768m", "--publish", `127.0.0.10:${selectedPort}:8080`,
    "--mount", `type=bind,source=${archive},target=/artifact/package.tar.gz,readonly`,
    "--mount", `type=bind,source=${controllerArchive},target=/artifact/controller.tar.gz,readonly`,
    "--mount", `type=bind,source=${upgradeArchive},target=/artifact/upgrade.tar.gz,readonly`,
    ...synthetic.flatMap(f => ["--mount", `type=bind,source=${f.path},target=/artifact/${f.mode}.tar.gz,readonly`]),
    "--mount", `type=bind,source=${recoveryArchive},target=/artifact/recovery.tar.gz,readonly`,
    "--mount", `type=bind,source=${scheduledArchive},target=/artifact/scheduled.tar.gz,readonly`,
    "--mount", `type=bind,source=${failedScheduledArchive},target=/artifact/scheduled-before.tar.gz,readonly`,
    "--mount",`type=bind,source=${feedDirectory},target=/artifact/feed-certs,readonly`,"--env","SSL_CERT_FILE=/artifact/feed-certs/ca.pem",
    "--env", "JMS_ADDR=0.0.0.0:8080", "--env", `JMS_ADMIN_TOKEN=${token}`, "--env", "JMS_DATA_DIR=/tmp/data", "--env", "JMS_WEB_DIR=/tmp/native/web", "--env", `JMS_PUBLIC_URL=http://127.0.0.10:${selectedPort}`, "--env", `JMS_QA_PACKAGE_SHA=${linuxSHA}`,
    "golang:1.27-bookworm", "sh", "-ceu", 'mkdir /tmp/native /tmp/controller; tar -xzf /artifact/package.tar.gz -C /tmp/native; tar -xzf /artifact/controller.tar.gz -C /tmp/controller jms; /tmp/native/jms233-server --check-data; /tmp/controller/jms update stage --root /tmp/releases --file /artifact/package.tar.gz --sha256 "$JMS_QA_PACKAGE_SHA" >/dev/null; exec sleep infinity']);
  const url = `http://127.0.0.10:${selectedPort}`;
  const inContainer = (args, input) => input === undefined ? run("docker", ["exec", owner, "/tmp/controller/jms", ...args]) : runInput("docker", ["exec", "-i", owner, "/tmp/controller/jms", ...args], input);
  const installArgs = (sha, revision, id) => ["update", "install", "--root", "/tmp/releases", "--data-dir", "/tmp/data", "--sha256", sha, "--revision", String(revision), "--request-id", id, "--passphrase-file", "-"];
  // The container's bounded bootstrap must finish before invoking its CLI.
  for (let attempt = 0; ; attempt++) { try { await inContainer(["update", "stage-status", "--root", "/tmp/releases", "--sha256", linuxSHA]); break; } catch { if (attempt === 99) throw new Error("Native bootstrap did not complete"); await delay(100); } }
  const initial = JSON.parse((await inContainer(installArgs(linuxSHA, 0, "native-linux-initial"), password)).stdout);
  if (initial.status !== "selected") throw new Error("Native Linux initial selection failed");
  await runInput("docker", ["exec", "-i", owner, "sh", "-ceu", "umask 077; cat > /tmp/checkpoint-passphrase"], password);
  const waitHealthy = async version => { for (let attempt = 0; attempt < 300; attempt++) { try { const response = await fetch(url + "/api/health", { signal: AbortSignal.timeout(1000) }); const health = await response.json(); if (response.ok && health.version === version && response.headers.get("X-JMS-Activation-Phase") !== "trial") return; } catch { /* bounded readiness */ } await delay(100); } throw new Error("Selected native server did not open business traffic"); };
  const launchSelected = async () => run("docker", ["exec", "--detach", owner, "sh", "-ceu", 'echo $$ >/tmp/launcher.pid; exec /tmp/controller/jms update run --root /tmp/releases --passphrase-file /tmp/checkpoint-passphrase']);
  const startSelected = async version => { await launchSelected(); await waitHealthy(version); };
  const stopSelected = async () => { await run("docker", ["exec", owner, "sh", "-ceu", 'pid=$(cat /tmp/launcher.pid); case "$pid" in ""|*[!0-9]*) exit 1;; esac; kill -INT "$pid"']); for (let attempt = 0; attempt < 150; attempt++) { try { await run("docker", ["exec", owner, "sh", "-ceu", 'pid=$(cat /tmp/launcher.pid); kill -0 "$pid"']); } catch { return; } await delay(100); } throw new Error("Native launcher did not stop"); };
  await startSelected(report.testVersion);
  report.phase = "native_upgrade"; save();
  if (old && JSON.parse((await run("docker", ["exec", owner, "/tmp/native/jms", "--version"])).stdout).commit !== historicalBaseline) throw new Error("Running baseline artifact identity differs");
  const vaultBefore = (await run("docker", ["exec", owner, "sha256sum", "/tmp/data/vault.key"])).stdout.split(/\s+/)[0];
  const api = async (method, path, body, bearer, status = 200) => { const response = await fetch(url + path, { method, headers: { "Content-Type": "application/json", ...(bearer ? { Authorization: "Bearer " + bearer } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), signal: AbortSignal.timeout(10000) }); if (response.status !== status) { const body=await response.json().catch(()=>({})); const code=typeof body.error_code==="string" && /^[a-z_]{1,80}$/.test(body.error_code) ? body.error_code : "unspecified"; throw new Error("Native installation API status " + response.status + " differs from " + status + " at " + method + " " + path + " (" + code + ")"); } return status === 204 ? null : response.json(); };
  const loginBefore = await api("POST", "/api/v1/authentication/auth/", { username: "root", password: "root" });
  if (accountChecksOnly) {
    report.phase = "account_checks"; save();
    const {chromium, expect} = createRequire(resolve(root,"web/package.json"))("@playwright/test");
    const browser = await chromium.launch({headless:true});
    try {
      const context = await browser.newContext({locale:"en-US",viewport:{width:1280,height:900}}), page = await context.newPage();
      context.setDefaultTimeout(10000);
      page.on("pageerror",e => {report.browserErrors = [...(report.browserErrors || []),fixtureDiagnostic(e.message)].slice(-5)});
      await page.goto(url+"/login");
      await page.getByRole("textbox",{name:"Username",exact:true}).fill("root");
      await page.getByRole("textbox",{name:"Password",exact:true}).fill("root");
      await Promise.all([page.waitForURL(url+"/console"),page.getByRole("button",{name:"Sign in",exact:true}).click()]);
      await page.goto(url+"/console/rotation-plans");
      report.accountChecks = await verifyAccountChecks({page,context,expect,api,admin:loginBefore.access_token,run,runInput,owner,sshHost:owner+"-ssh",fingerprint,output,report});
      if(report.browserErrors?.length) throw Error("Focused account-check browser errors");
    } finally {await browser.close()}
    report.status = "passed";
  } else {
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
  const compatibilityTemplate = await api("POST", "/api/v1/ops/templates", {name: "Upgrade preservation template", command: "pwd -P", timeout_seconds: 10}, loginBefore.access_token, 201);
  const compatibilityPlan = await api("POST", "/api/v1/ops/plans", {name: "Upgrade preservation plan", template_id: compatibilityTemplate.id, asset_ids: [asset.id], kind: "once", run_at: new Date(Date.now() + 86400000).toISOString(), request_id: randomUUID()}, loginBefore.access_token, 201);
  const rotationBefore = (await api("GET", "/api/v1/assets", undefined, loginBefore.access_token)).find(a => a.id === asset.id)?.password_rotation;
  if (!rotationBefore || Date.parse(rotationBefore.next_rotation_at) - Date.parse(rotationBefore.last_rotated_at) !== 7 * 86400000) throw new Error("Baseline seven-day SSH rotation schedule is unavailable");
  await inContainer(["update", "stage", "--root", "/tmp/releases", "--file", "/artifact/upgrade.tar.gz", "--sha256", upgradeSHA]);
  let busy = false; try { await inContainer(installArgs(upgradeSHA, 1, "native-linux-busy"), password); } catch (e) { busy = String(e.stderr).includes("data directory is in use"); } if (!busy) throw new Error("Running data was not protected from upgrade");
  await stopSelected();
  const users = (await run("docker", ["exec", owner, "cat", "/tmp/data/users.json"])).stdout;
  await runInput("docker", ["exec", "-i", owner, "sh", "-ceu", "cat > /tmp/data/users.json"], "synthetic invalid store");
  let rolledBack = false; try { await inContainer(installArgs(upgradeSHA, 1, "native-linux-failed"), password); } catch (e) { const receipt = JSON.parse(e.stdout); rolledBack = receipt.status === "rolled_back" && receipt.current.version === report.testVersion; }
  if (!rolledBack || (await run("docker", ["exec", owner, "cat", "/tmp/data/users.json"])).stdout !== "synthetic invalid store") throw new Error("Failed native preflight did not preserve its original checkpoint");
  await runInput("docker", ["exec", "-i", owner, "sh", "-ceu", "cat > /tmp/data/users.json"], users);
  const legacyOperations = (await run("docker", ["exec", owner, "cat", "/tmp/data/operations.json"])).stdout;
  const unknownOperations = JSON.stringify({...JSON.parse(legacyOperations), version: 999});
  await runInput("docker", ["exec", "-i", owner, "sh", "-ceu", "cat > /tmp/data/operations.json"], unknownOperations);
  let unknownFormatRefused = false;
  try { await inContainer(installArgs(upgradeSHA, 1, "native-future-operations"), password); }
  catch (e) { const receipt = JSON.parse(e.stdout); unknownFormatRefused = receipt.status === "rolled_back" && receipt.current.version === report.testVersion; }
  if (!unknownFormatRefused || (await run("docker", ["exec", owner, "cat", "/tmp/data/operations.json"])).stdout !== unknownOperations) throw Error("Unknown data format was accepted or changed during failed upgrade");
  await runInput("docker", ["exec", "-i", owner, "sh", "-ceu", "cat > /tmp/data/operations.json"], legacyOperations);
  const upgraded = JSON.parse((await inContainer(installArgs(upgradeSHA, 1, "native-linux-upgrade"), password)).stdout);
  const replayed = JSON.parse((await inContainer(installArgs(upgradeSHA, 1, "native-linux-upgrade"), password)).stdout);
  if (upgraded.status !== "selected" || upgraded.revision !== 2 || !replayed.unchanged || replayed.transaction_id !== upgraded.transaction_id) throw new Error("Native upgrade selection replay failed");
  await startSelected(report.upgradeVersion);
  const loginAfter = await api("POST", "/api/v1/authentication/auth/", { username: "root", password: "root" });
  if (loginAfter.user.id !== loginBefore.user.id || (await api("GET", "/api/v1/ops/jobs/" + originalJob, undefined, loginAfter.access_token)).state !== "succeeded") throw new Error("Native upgrade lost identity or command audit");
  await execSSH(loginAfter.access_token, "native-after-upgrade");
  const restoredTemplates = await api("GET", "/api/v1/ops/templates", undefined, loginAfter.access_token);
  const restoredPlan = await api("GET", `/api/v1/ops/plans/${compatibilityPlan.id}`, undefined, loginAfter.access_token);
  if (!restoredTemplates.some(t => t.id === compatibilityTemplate.id && t.command === compatibilityTemplate.command && !t.working_directory) || restoredPlan.template_id !== compatibilityTemplate.id || restoredPlan.command !== compatibilityTemplate.command || restoredPlan.working_directory) throw Error("Upgrade lost or reinterpreted legacy operation snapshots");
  await api("PUT", `/api/v1/ops/plans/${restoredPlan.id}`, {enabled: false, revision: restoredPlan.config_revision}, loginAfter.access_token);
  report.upgradeCompatibility = {officialRelease: false, sourceCommit: old?.manifest.commit || report.commit, targetCommit: report.commit, legacyOperationFormat: JSON.parse(legacyOperations).version, targetOperationFormat: JSON.parse((await run("docker", ["exec", owner, "cat", "/tmp/data/operations.json"])).stdout).version, unknownFutureFormatRefused: unknownFormatRefused, failedPreflightPreservedOriginalBytes: true, legacyTemplateAndPlanPreserved: true, noDirectorySemanticsAdded: true};
  const operatorAfter = await api("POST", "/api/v1/authentication/auth/", { username: operator.username, password: operatorPassword });
  if (operatorAfter.user.id !== operatorBefore.user.id) throw new Error("Native operator identity changed");
  await viewOnly(operatorAfter.access_token);
  const rotationAfter = (await api("GET", "/api/v1/assets", undefined, loginAfter.access_token)).find(a => a.id === asset.id)?.password_rotation;
  if (rotationAfter?.last_rotated_at !== rotationBefore.last_rotated_at || rotationAfter?.next_rotation_at !== rotationBefore.next_rotation_at) throw new Error("Native upgrade reset the SSH rotation schedule");
  if ((await run("docker", ["exec", owner, "sha256sum", "/tmp/data/vault.key"])).stdout.split(/\s+/)[0] !== vaultBefore) throw new Error("Native upgrade replaced the Vault key");
  if (old) {
    const target = JSON.parse((await run("docker", ["exec", owner, `/tmp/releases/releases/${upgradeSHA}/jms`, "--version"])).stdout);
    if (target.commit !== report.commit) throw new Error("Activated target artifact identity differs");
    report.historical = { ...report.historical, status: "passed", baselineCLIIdentity: true, targetCLIIdentity: true, vaultKeyPreserved: true, weeklyRotationSchedulePreserved: true, userAndGrantPreserved: true, realSSHBeforeAndAfter: true, oldExecutionAuditPreserved: true, installReplayUnchanged: true }; save();
  }
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
  let recoveredLogin = await api("POST", "/api/v1/authentication/auth/", { username: "root", password: "root" });
  if (recoveredLogin.user.id !== loginBefore.user.id || (await api("GET", "/api/v1/ops/jobs/" + originalJob, undefined, recoveredLogin.access_token)).state !== "succeeded") throw new Error("Forward recovery lost identity or audit");
  await execSSH(recoveredLogin.access_token, "native-after-forward-recovery");
  let recoveredOperator = await api("POST", "/api/v1/authentication/auth/", { username: operator.username, password: operatorPassword }); await viewOnly(recoveredOperator.access_token);
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
	const nativeExec = JSON.parse((await run("docker", ["exec", owner, "sh", "-ceu", 'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 /tmp/controller/jms exec "$1" --json -- pwd', "sh", asset.id])).stdout);
	if (nativeExec.state !== "succeeded" || nativeExec.stdout.trim() !== workspace) throw new Error("Native CLI workspace execution failed");
	if ((await run("docker", ["exec", owner + "-ssh", "cat", "/home/keyqa/protected/sentinel"])).stdout !== "preserve") throw new Error("Workspace modified protected content");
	report.workspace = { directory: workspace, realSSH: true, realCLI: true, trustedCwd: true, insideWrite: true, outsideReadAndWriteRefused: true, confinedSFTP: true, sftpNoOverwriteAndRepeatedReplacement: true, sftpSymlinkAndTraversalRefused: true, helperOverlapRefusedBeforeExecution: true, protectedDataPreserved: true };
  const approvalPassword = "synthetic-scoped-file-operator-password";
  const approvalUser = await api("POST", "/api/v1/users", { username: "native.file.operator", password: approvalPassword, role: "operator" }, recoveredLogin.access_token, 201);
  await api("POST", "/api/v1/grants", { user_id: approvalUser.id, asset_id: asset.id, account: asset.username, actions: ["view", "connect", "sftp"] }, recoveredLogin.access_token, 201);
  let approvalLogin = await api("POST", "/api/v1/authentication/auth/", { username: approvalUser.username, password: approvalPassword });
  const updateApprovalAsset = async remark => api("PUT", "/api/v1/assets/" + asset.id, { name: asset.name, host: asset.host, port: asset.port, username: asset.username, host_key_fingerprint: fingerprint, ssh_workspace: workspace, login_review_required: true, remark }, recoveredLogin.access_token);
  await updateApprovalAsset("connection-snapshot-1");
  const fileSession = `/api/v1/assets/${asset.id}/files/session`;
  const approve = id => api("POST", `/api/v1/access-reviews/${id}/approve`, undefined, recoveredLogin.access_token, 204);
  const scopedList = async (permit, status = 200) => {
    const response = await fetch(url + `/api/v1/assets/${asset.id}/files`, { headers: { Authorization: "Bearer " + approvalLogin.access_token, "X-JMS-SFTP-Session": permit }, signal: AbortSignal.timeout(15000) });
    if (response.status !== status) throw new Error("Scoped SFTP authorization status differs: " + response.status);
    return response.json();
  };
  const oldReview = await api("POST", fileSession, undefined, approvalLogin.access_token, 202);
  const retriedReview = await api("POST", fileSession, undefined, approvalLogin.access_token, 202);
  if (retriedReview.review_id !== oldReview.review_id) throw new Error("Connection review retry created duplicates");
  await approve(oldReview.review_id);
  await run("docker", ["exec", owner + "-ssh", "sh", "-ceu", "mv /home/keyqa/workspace /home/keyqa/workspace-original; mkdir /home/keyqa/workspace; chown keyqa:keyqa /home/keyqa/workspace"]);
  const replacedReview = await api("POST", fileSession, undefined, approvalLogin.access_token, 202);
  if (replacedReview.review_id === oldReview.review_id) throw new Error("Replacement directory reused approval");
  await approve(replacedReview.review_id);
  const replacedPermit = await api("POST", fileSession, undefined, approvalLogin.access_token, 201);
  await scopedList(replacedPermit.session_token);
  await run("docker", ["exec", owner + "-ssh", "sh", "-ceu", "mv /home/keyqa/workspace /home/keyqa/workspace-replacement; mv /home/keyqa/workspace-original /home/keyqa/workspace"]);
  await scopedList(replacedPermit.session_token, 428);
  await updateApprovalAsset("connection-snapshot-2");
  const currentReview = await api("POST", fileSession, undefined, approvalLogin.access_token, 202);
  await approve(currentReview.review_id);
  const currentPermit = await api("POST", fileSession, undefined, approvalLogin.access_token, 201);
  await scopedList(currentPermit.session_token);
  await updateApprovalAsset("connection-snapshot-3");
  await scopedList(currentPermit.session_token, 428);
  const browserReview = await api("POST", fileSession, undefined, approvalLogin.access_token, 202);
  const sessionRequest = { asset_id: asset.id, cols: 80, rows: 24 };
  const sshReview = await api("POST", "/api/v1/sessions", sessionRequest, approvalLogin.access_token, 202);
  await approve(sshReview.review_id);
  const approvedSSH = await api("POST", "/api/v1/sessions", sessionRequest, approvalLogin.access_token, 201);
  await api("DELETE", "/api/v1/sessions/" + approvedSSH.session_id, undefined, approvalLogin.access_token, 204);
  const sshReplay = await api("POST", "/api/v1/sessions", sessionRequest, approvalLogin.access_token, 202);
  await api("POST", `/api/v1/access-reviews/${sshReplay.review_id}/deny`, undefined, recoveredLogin.access_token, 204);
  const approvedExecInput = { asset_id: asset.id, command: "pwd", timeout_seconds: 10, request_id: randomUUID() };
  const execReview = await api("POST", "/api/v1/ops/jobs", approvedExecInput, approvalLogin.access_token, 202);
  await approve(execReview.review_id);
  const approvedExec = await api("POST", "/api/v1/ops/jobs", approvedExecInput, approvalLogin.access_token, 201);
  const repeatedExec = await api("POST", "/api/v1/ops/jobs", approvedExecInput, approvalLogin.access_token, 201);
  if (repeatedExec.id !== approvedExec.id) throw new Error("Approved exec retry created a second job");
  let approvedExecDone = false;
  for (let attempt = 0; attempt < 100; attempt++) {
    const job = await api("GET", "/api/v1/ops/jobs/" + approvedExec.id, undefined, approvalLogin.access_token);
    if (job.state === "succeeded" && job.stdout.trim() === workspace) { approvedExecDone = true; break; }
    if (["failed", "denied", "interrupted", "timed_out"].includes(job.state)) throw new Error("Approved scoped exec failed");
    await delay(100);
  }
  if (!approvedExecDone) throw new Error("Approved scoped exec timed out");
  report.connectionApproval = { idempotentReview: true, realDirectoryReplacementRefused: true, issuedPermitRejectsReplacedDirectory: true, configurationChangeInvalidatesPermit: true, independentSSHAndSFTPApprovals: true, realApprovedSSH: true, oneTimeSSHApproval: true, approvedExecIsConfinedAndIdempotent: true };

  const deployDirectory = workspace + "/deploy", releaseDirectory = deployDirectory + "/releases/12", siblingDirectory = workspace + "/deploy-other";
  const makeDirectory = async directory => { await run("docker", ["exec", owner + "-ssh", "mkdir", "-p", directory]); await run("docker", ["exec", owner + "-ssh", "chown", "-R", "keyqa:keyqa", directory]); };
  for (const directory of [releaseDirectory, siblingDirectory]) await makeDirectory(directory);
  const ruleInput = (name, pattern, action, mode, directory) => ({ name, asset_id: asset.id, account: asset.username, match: "exact", pattern, action, priority: 100, directory_match: mode, directory_pattern: directory });
  const pwdRuleInput = ruleInput("Verified directory review", "pwd", "review", "exact", deployDirectory);
  let pwdRule = await api("POST", "/api/v1/command-filters", pwdRuleInput, recoveredLogin.access_token, 201);
  for (const input of [
    ruleInput("Exact directory denial", "mkdir rejected-exact", "deny", "exact", deployDirectory),
    ruleInput("Tree directory denial", "mkdir rejected-tree", "deny", "tree", deployDirectory),
    ruleInput("Regex directory denial", "mkdir rejected-regex", "deny", "regex", deployDirectory + "/releases/[0-9]+"),
    ruleInput("Unverified terminal denial", "mkdir terminal-blocked", "deny", "exact", deployDirectory),
  ]) await api("POST", "/api/v1/command-filters", input, recoveredLogin.access_token, 201);
  const directoryInput = (command, directory) => ({ asset_id: asset.id, command, working_directory: directory, timeout_seconds: 10, request_id: randomUUID() });
  const waitDirectoryJob = async (id, expected) => {
    for (let attempt = 0; attempt < 150; attempt++) {
      const job = await api("GET", "/api/v1/ops/jobs/" + id, undefined, recoveredLogin.access_token);
      if (["succeeded", "failed", "denied", "interrupted", "timed_out"].includes(job.state)) {
        if (job.state !== expected) {
          report.executionDirectoryFailure = { expected, actual: job.state, errorCode: job.error_code, exitCode: job.exit_code, requestedDirectory: job.working_directory, executionDirectory: job.execution_directory, stderr: fixtureDiagnostic((job.stderr || "").slice(0, 600)) };
          throw new Error("Controlled directory job did not reach expected state");
        }
        return job;
      }
      await delay(100);
    }
    throw new Error("Controlled directory job timed out");
  };
  for (const [command, directory, expected] of [
    ["mkdir rejected-exact", deployDirectory, "denied"],
    ["mkdir rejected-tree", releaseDirectory, "denied"],
    ["mkdir rejected-regex", releaseDirectory, "denied"],
    ["mkdir rejected-exact", siblingDirectory, "succeeded"],
  ]) {
    const job = await api("POST", "/api/v1/ops/jobs", directoryInput(command, directory), recoveredLogin.access_token, 201);
    await waitDirectoryJob(job.id, expected);
  }
  for (const file of [deployDirectory + "/rejected-exact", releaseDirectory + "/rejected-tree", releaseDirectory + "/rejected-regex"]) await run("docker", ["exec", owner + "-ssh", "test", "!", "-e", file]);
  await run("docker", ["exec", owner + "-ssh", "test", "-d", siblingDirectory + "/rejected-exact"]);
  await api("POST", "/api/v1/ops/jobs", directoryInput("pwd", "/home/keyqa/protected"), recoveredLogin.access_token, 400);
  await api("POST", "/api/v1/ops/jobs", directoryInput("pwd", workspace + "/escape"), recoveredLogin.access_token, 412);

  const directoryUser = await api("POST", "/api/v1/users", { username: "native.directory.operator", password: "synthetic-directory-test-password", role: "operator" }, recoveredLogin.access_token, 201);
  await api("POST", "/api/v1/grants", { user_id: directoryUser.id, asset_id: asset.id, account: asset.username, actions: ["view", "connect"] }, recoveredLogin.access_token, 201);
  const directoryLogin = await api("POST", "/api/v1/authentication/auth/", { username: directoryUser.username, password: "synthetic-directory-test-password" });
  const pendingDirectoryInput = directoryInput("pwd", deployDirectory);
  const initialDirectoryReview = await api("POST", "/api/v1/ops/jobs", pendingDirectoryInput, directoryLogin.access_token, 202);
  const repeatedDirectoryReview = await api("POST", "/api/v1/ops/jobs", pendingDirectoryInput, directoryLogin.access_token, 202);
  if (initialDirectoryReview.review_id !== repeatedDirectoryReview.review_id) throw new Error("Directory login retry created duplicate approval");
  await approve(initialDirectoryReview.review_id);
  await run("docker", ["exec", owner + "-ssh", "mv", deployDirectory, deployDirectory + "-before-login"]); await makeDirectory(deployDirectory);
  const replacedDirectoryReview = await api("POST", "/api/v1/ops/jobs", pendingDirectoryInput, directoryLogin.access_token, 202);
  if (replacedDirectoryReview.review_id === initialDirectoryReview.review_id) throw new Error("Replaced cwd reused login approval");
  const unusedApproval = await api("GET", "/api/v1/access-reviews/" + initialDirectoryReview.review_id, undefined, directoryLogin.access_token);
  if (unusedApproval.state !== "approved") throw new Error("Old directory approval was consumed for replacement");
  await approve(replacedDirectoryReview.review_id);
  const pendingDirectoryJob = await api("POST", "/api/v1/ops/jobs", pendingDirectoryInput, directoryLogin.access_token, 201);
  if (pendingDirectoryJob.state !== "pending_review" || pendingDirectoryJob.execution_directory !== deployDirectory) throw new Error("Directory review lost verified cwd");
  await run("docker", ["exec", owner + "-ssh", "mv", deployDirectory, deployDirectory + "-before-command"]); await makeDirectory(deployDirectory);
  await api("POST", "/api/v1/ops/jobs/" + pendingDirectoryJob.id + "/review", { approve: true }, recoveredLogin.access_token, 428);

  const stalePolicy = await api("POST", "/api/v1/ops/jobs", directoryInput("pwd", deployDirectory), recoveredLogin.access_token, 201);
  await api("DELETE", "/api/v1/command-filters/" + pwdRule.id, undefined, recoveredLogin.access_token, 204);
  pwdRule = await api("POST", "/api/v1/command-filters", pwdRuleInput, recoveredLogin.access_token, 201);
  await api("POST", "/api/v1/ops/jobs/" + stalePolicy.id + "/review", { approve: true }, recoveredLogin.access_token, 403);
  const successfulDirectoryInput = directoryInput("pwd", deployDirectory);
  const approvedDirectoryJob = await api("POST", "/api/v1/ops/jobs", successfulDirectoryInput, recoveredLogin.access_token, 201);
  await api("POST", "/api/v1/ops/jobs/" + approvedDirectoryJob.id + "/review", { approve: true }, recoveredLogin.access_token, 200);
  const directoryResult = await waitDirectoryJob(approvedDirectoryJob.id, "succeeded");
  if (directoryResult.stdout.trim() !== deployDirectory || directoryResult.execution_directory !== deployDirectory) throw new Error("Approved command did not execute in verified cwd");
  await run("docker", ["pause", owner + "-ssh"]);
  try {
    const started = performance.now();
    const duplicate = await api("POST", "/api/v1/ops/jobs", successfulDirectoryInput, recoveredLogin.access_token, 201);
    await api("POST", "/api/v1/ops/jobs", { ...successfulDirectoryInput, working_directory: siblingDirectory }, recoveredLogin.access_token, 409);
    if (duplicate.id !== approvedDirectoryJob.id || performance.now() - started > 2500) throw new Error("Receipt retry attempted a new SSH probe");
  } finally { await run("docker", ["unpause", owner + "-ssh"]); }
  const cwdCLI = JSON.parse((await run("docker", ["exec", owner, "sh", "-ceu", 'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 /tmp/controller/jms exec "$1" --directory "$2" --json -- pwd -P', "sh", asset.id, deployDirectory])).stdout);
  if (cwdCLI.state !== "succeeded" || cwdCLI.stdout.trim() !== deployDirectory) throw new Error("Native CLI did not select actual cwd");
  report.executionDirectories = { exactTreeAndRegex: true, deniedCommandsNeverCreatedFiles: true, pathBoundaryPreserved: true, symlinkAndOutsideRefused: true, loginReviewReplacementCreatesNewApproval: true, loginRetryIdempotent: true, commandReviewReplacementRefused: true, sameNamePolicyReplacementRefused: true, approvedCwdVerified: true, retryWithoutLiveSSH: true, changedDirectoryRetryConflict: true, nativeCLI: true };
  report.phase = "operation_directories"; save();
  await verifyOperationDirectories({api, admin: recoveredLogin.access_token, run, runInput, owner, sshHost: owner + "-ssh", fingerprint, workspace, directory: deployDirectory, sibling: siblingDirectory, primary: asset, report});
  report.phase = "interactive_directories"; save();
  await verifyInteractiveDirectories({api,admin:recoveredLogin.access_token,operator:directoryLogin.access_token,asset,workspace,url,run,sshHost:owner+"-ssh",report});
  const completedDirectoryRun = await api("GET", `/api/v1/ops/runs/${report.operationDirectories.playbookRunID}`, undefined, recoveredLogin.access_token);
  report.phase = "ssh_certificates"; save();
  const certificateFixture=await verifySSHCertificates({api,admin:recoveredLogin.access_token,run,runInput,owner,sshHost:owner+"-ssh",fingerprint,url,report});
  const nativeLabelInput = {name: "Native lifecycle", value: "encrypted-restart", request_id: randomUUID()};
  const nativeLabel = await api("POST", "/api/v1/labels/labels", nativeLabelInput, recoveredLogin.access_token, 201);
  const nativeLabelBindingInput = {label_ids: [nativeLabel.id], revision: 0, request_id: randomUUID()};
  const nativeLabelBinding = await api("PUT", `/api/v1/labels/bindings/asset/${asset.id}`, nativeLabelBindingInput, recoveredLogin.access_token);
  const nativeNotice = await api("POST", "/api/v1/announcements", {title: {en: "Native notice", "zh-CN": "原生公告"}, body: {en: "Encrypted restart metadata", "zh-CN": "加密重启元数据"}, published: true, request_id: randomUUID()}, recoveredLogin.access_token, 201);
  const nativeReading = await api("POST", `/api/v1/announcements/${nativeNotice.id}/read`, {revision: nativeNotice.revision}, recoveredLogin.access_token);
  for (const [file, plain] of [["labels.json", "encrypted-restart"], ["announcements.json", "Encrypted restart metadata"]]) {
    if ((await run("docker", ["exec", owner, "cat", `/tmp/data/${file}`])).stdout.includes(plain)) throw Error("Native metadata persisted in plaintext");
  }
  await stopSelected(); await startSelected(report.recoveryVersion);
  // Standalone login sessions deliberately live only in memory. Reauthenticate
  // after a process restart while separately proving that the old token dies.
  await api("GET", `/api/v1/ops/runs/${completedDirectoryRun.id}`, undefined, recoveredLogin.access_token, 401);
  recoveredLogin = await api("POST", "/api/v1/authentication/auth/", { username: "root", password: "root" });
  recoveredOperator = await api("POST", "/api/v1/authentication/auth/", { username: operator.username, password: operatorPassword });
  approvalLogin = await api("POST", "/api/v1/authentication/auth/", { username: approvalUser.username, password: approvalPassword });
  const restartedDirectoryRun = await api("GET", `/api/v1/ops/runs/${completedDirectoryRun.id}`, undefined, recoveredLogin.access_token);
  if (restartedDirectoryRun.state !== "succeeded" || restartedDirectoryRun.working_directory !== deployDirectory || JSON.stringify(restartedDirectoryRun.items.map(i => i.steps.map(s => s.job_id))) !== JSON.stringify(completedDirectoryRun.items.map(i => i.steps.map(s => s.job_id)))) throw Error("Restart lost directory snapshots or replayed completed steps");
  report.operationDirectories.restartPreservesSnapshotsWithoutReplay = true;
  await verifySSHCertificateRestart({api,admin:recoveredLogin.access_token,fixture:certificateFixture,report});
  report.phase = "maintenance_and_updates"; save();
  const nativeLabelAfter = await api("POST", "/api/v1/labels/labels", nativeLabelInput, recoveredLogin.access_token, 201);
  const nativeBindingAfter = await api("PUT", `/api/v1/labels/bindings/asset/${asset.id}`, nativeLabelBindingInput, recoveredLogin.access_token);
  const nativeReadingAfter = await api("POST", `/api/v1/announcements/${nativeNotice.id}/read`, {revision: nativeNotice.revision}, recoveredLogin.access_token);
  if (JSON.stringify(nativeLabelAfter) !== JSON.stringify(nativeLabel) || JSON.stringify(nativeBindingAfter) !== JSON.stringify(nativeLabelBinding) || JSON.stringify(nativeReadingAfter) !== JSON.stringify(nativeReading)) throw Error("Native metadata restart lost immutable receipts");
  const nativeLabelCLI = JSON.parse((await run("docker", ["exec", owner, "sh", "-ceu", 'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 /tmp/controller/jms labels binding asset "$1"', "sh", asset.id])).stdout);
  if (!nativeLabelCLI.effective.some(l => l.id === nativeLabel.id)) throw Error("Native label CLI lost effective binding");
  report.platformMetadata = {encryptedAtRest: true, labelCatalogAndBindingPreserved: true, announcementReadingPreserved: true, unchangedRetryAfterRestart: true, nativeLabelCLI: true};
  report.activation = { privateReadinessAndHTTPProbe: true, businessGateBeforeCommit: true, preCommitFailureRolledBack: true, oldServiceAutomaticallyResumed: true, failedTrialWriteRemoved: trialWriteAbsent, monotonicRollbackRevision: 4, postCommitFailurePreservedVersionAndData: true, forwardRecoveryVersion: report.recoveryVersion, finalRevision: 6, realSSHAfterRollbackAndForwardRecovery: true };
  report.installation = { initialVersion: report.testVersion, selectedVersion: report.upgradeVersion, revision: upgraded.revision, runningUpgradeRefused: busy, failedPreflightRolledBack: rolledBack, checkpointBytesPreserved: true, idempotent: true, userIDPreserved: true, realSSHBeforeAndAfter: true, commandAuditPreserved: true, operatorViewGrantPreserved: true, operatorConnectDeniedBeforeAndAfter: true };
  const html = await (await fetch(url + "/console/settings")).text();
  if (!html.includes("JumpServer233") || (await fetch(url + "/api/v1/assets")).status !== 401) throw new Error("Native web/auth isolation failed");
  report.linuxExecution = { arch: linuxArch, singlePort: true, protectedAPI: true, web: true, readOnlyRoot: true, stagedCandidate: true };
  const { chromium, expect } = createRequire(new URL("../web/package.json", import.meta.url))("@playwright/test");
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ locale: "en-US", viewport: { width: 1280, height: 900 } });
    context.setDefaultTimeout(10000);
    context.setDefaultNavigationTimeout(15000);
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
    const [login] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith("/api/v1/authentication/auth/") && response.request().method() === "POST"),
      page.getByRole("button", { name: "Sign in", exact: true }).click(),
    ]);
    report.browserLoginStatus = login.status();
    if (report.browserLoginStatus !== 200) throw new Error("Staged candidate browser login status was " + report.browserLoginStatus);
    await expect(page.getByRole("heading", { name: "Assets", exact: true })).toBeVisible();
	let terminalOutput = ""; const terminalNotices = [];
	page.on("websocket", socket => socket.on("framereceived", event => { if (Buffer.isBuffer(event.payload)) terminalOutput += event.payload.toString("utf8"); else { try { terminalNotices.push(JSON.parse(event.payload)); } catch { /* Text notices only. */ } } }));
	const row = page.getByRole("row").filter({ hasText: "Native upgrade SSH" });
	await row.getByRole("button", { name: "Connect", exact: true }).click();
	const terminal = page.locator(".ssh-terminal-dialog");
	await expect(terminal.locator(".ssh-terminal-status.connected")).toBeVisible();
	await terminal.locator(".xterm-helper-textarea").pressSequentially("printf '\\167\\157\\162\\153\\163\\160\\141\\143\\145\\055\\160\\164\\171\\055\\157\\153\\012'");
	await page.keyboard.press("Enter");
	await expect.poll(() => terminalOutput).toContain("workspace-pty-ok");
	const beforeDirectoryChange = terminalOutput.length;
	await terminal.locator(".xterm-helper-textarea").pressSequentially("cd "+deployDirectory);
	await page.keyboard.press("Enter");
	await expect.poll(()=>terminalOutput.slice(beforeDirectoryChange)).toMatch(/\n[^\r\n]*[$#] $/);
	await terminal.locator(".xterm-helper-textarea").pressSequentially("mkdir terminal-blocked");
	await page.keyboard.press("Enter");
	await expect.poll(() => terminalNotices.some(notice => notice.type === "command_blocked" && notice.directory_required !== true)).toBe(true);
	await run("docker", ["exec", owner + "-ssh", "test", "!", "-e", workspace + "/terminal-blocked"]);
	await run("docker", ["exec", owner + "-ssh", "test", "!", "-e", deployDirectory + "/terminal-blocked"]);
	report.executionDirectories.browserVerifiedPTYDirectoryDenied = true;
	const [deletedSession] = await Promise.all([
      page.waitForResponse(response => response.request().method() === "DELETE" && /\/api\/v1\/sessions\/[^/]+$/.test(new URL(response.url()).pathname)),
      terminal.getByRole("button", { name: "Close terminal", exact: true }).click(),
    ]);
	if (deletedSession.status()!==204) throw new Error("Closing the browser session was not idempotent");
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
	const [downloaded] = await Promise.all([
      page.waitForEvent("download"),
      manager.getByRole("row").filter({hasText:"sftp-browser.txt"}).getByRole("button",{name:"Download",exact:true}).click(),
    ]);
	if(readFileSync(await downloaded.path(),"utf8")!=="browser-confined-upload") throw new Error("Browser SFTP download bytes differ");
	await downloaded.delete();
	await manager.getByRole("textbox",{name:"Folder name",exact:true}).fill("browser-dir");
	await manager.getByRole("button",{name:"New folder",exact:true}).click();
	await expect(manager.getByRole("button",{name:"browser-dir",exact:true})).toBeVisible();
	await manager.getByRole("button",{name:"Cancel",exact:true}).last().click();
	await page.getByRole("button", { name: "中文", exact: true }).click();
	await row.getByRole("button", { name: "编辑", exact: true }).click();
	await expect(page.getByRole("textbox", { name: "SSH 执行工作区（可选）", exact: true })).toHaveValue(workspace);
	await page.getByRole("button", { name: "取消", exact: true }).click();
	await row.getByRole("button",{name:"文件",exact:true}).click();
	await expect(manager.getByRole("button",{name:"sftp-browser.txt",exact:true})).toBeVisible();
	await expect(manager.getByText(`工作区 ${workspace}（显示为 /）`,{exact:true})).toBeVisible();
	await manager.getByRole("button",{name:"取消",exact:true}).last().click();
	report.workspace.browserUploadDownloadAndMkdir=true;
	await page.getByRole("button", { name: "EN", exact: true }).click();
    await page.goto(url + "/console/settings");
    await page.getByRole("tab", { name: /^Login review\s*\d+$/ }).click();
    const approvalCard = page.locator("article.settings-card").filter({ hasText: approvalUser.username });
    await expect(approvalCard.locator("code")).toHaveText(workspace);
    await approvalCard.screenshot({ path: resolve(output, "execution.en.png") });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(approvalCard.locator("code")).toHaveText(workspace);
    await approvalCard.screenshot({ path: resolve(output, "execution.zh.png") });
    page.once("dialog", dialog => dialog.accept());
    const [approvedResponse] = await Promise.all([
      page.waitForResponse(response => response.url().endsWith(`/access-reviews/${browserReview.review_id}/approve`) && response.request().method() === "POST"),
      approvalCard.getByRole("button", { name: "批准并提交", exact: true }).click(),
    ]);
    if (approvedResponse.status() !== 204) throw new Error("Browser workspace approval failed");
    await expect(approvalCard).toHaveCount(0);
    const browserPermit = await api("POST", fileSession, undefined, approvalLogin.access_token, 201);
    const approvedFiles = await scopedList(browserPermit.session_token);
    if (!approvedFiles.entries.some(file => file.name === "sftp-browser.txt")) throw new Error("Browser approval did not authorize confined file access");
    report.connectionApproval.browserBilingualDirectoryAndApproval = true;
    await page.getByRole("button", { name: "EN", exact: true }).click();
    await page.getByRole("tab", { name: "Command filters", exact: true }).click();
    const directoryForm = page.locator("form").filter({ has: page.getByRole("heading", { name: "Add command filter", exact: true }) });
    await directoryForm.getByRole("textbox", { name: "Rule name", exact: true }).fill("Browser verified directory");
    await directoryForm.getByRole("combobox", { name: "Asset scope", exact: true }).selectOption("asset");
    await directoryForm.getByRole("combobox", { name: "SSH asset and account", exact: true }).selectOption(asset.id);
    await directoryForm.getByRole("combobox", { name: "Match type", exact: true }).selectOption("exact");
    await directoryForm.getByRole("textbox", { name: "Command or pattern", exact: true }).fill("printf browser-directory");
    await directoryForm.getByRole("combobox", { name: "Execution directory scope", exact: true }).selectOption("exact");
    await directoryForm.getByRole("textbox", { name: "Directory path or pattern", exact: true }).fill(deployDirectory);
    await directoryForm.getByRole("combobox", { name: "When matched", exact: true }).selectOption("review");
    const [createdFilter] = await Promise.all([
      page.waitForResponse(response => response.request().method() === "POST" && new URL(response.url()).pathname === "/api/v1/command-filters"),
      directoryForm.locator('button[type="submit"]').click(),
    ]);
    if (createdFilter.status() !== 201) throw new Error("Browser directory rule creation failed");
    await expect(page.getByRole("row").filter({ hasText: "Browser verified directory" })).toContainText(deployDirectory);
    await page.goto(url + "/workbench");
    await expect(page.getByRole("heading", { name: "SSH jobs", exact: true })).toBeVisible();
    await page.getByRole("combobox", { name: "Asset", exact: true }).selectOption(asset.id);
    await page.getByRole("textbox", { name: "Command", exact: true }).fill("printf browser-directory");
    await page.getByRole("textbox", { name: "Execution directory (optional)", exact: true }).fill(deployDirectory);
    await page.getByRole("button", { name: "Run command", exact: true }).click();
    const directoryResultPanel = page.getByRole("region", { name: "Execution result", exact: true });
    await expect(directoryResultPanel).toContainText("Awaiting command review");
    await expect(directoryResultPanel).toContainText(deployDirectory);
    await directoryResultPanel.getByRole("button", { name: "Approve command", exact: true }).click();
    await expect(directoryResultPanel).toContainText("Succeeded", { timeout: 20000 });
    await expect(directoryResultPanel.locator("pre").first()).toHaveText("browser-directory");
    await directoryResultPanel.screenshot({ path: resolve(output, "execution.en.png") });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("textbox", { name: "执行目录（可选）", exact: true })).toHaveValue(deployDirectory);
    const chineseDirectoryResult = page.getByRole("region", { name: "执行结果", exact: true });
    await expect(chineseDirectoryResult).toContainText("已验证的执行目录");
    await page.setViewportSize({ width: 390, height: 844 });
    await chineseDirectoryResult.screenshot({ path: resolve(output, "execution.zh.png") });
    const bounds = await chineseDirectoryResult.boundingBox();
    if (!bounds || bounds.x < 0 || bounds.x + bounds.width > 392) throw new Error("Mobile directory result overflows viewport");
    const closeBounds = await chineseDirectoryResult.getByRole("button", { name: "关闭结果", exact: true }).boundingBox();
    if (!closeBounds || closeBounds.width < 60 || closeBounds.height > 52) throw new Error("Mobile result close button is not readable on one line");
    report.executionDirectories.browserRuleCreationAndRealReviewedCommand = true;
    report.executionDirectories.browserBilingualDesktopAndMobile = true;
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.getByRole("button", { name: "EN", exact: true }).click();
    await verifyOperationDirectoryBrowser({page, expect, url, api, admin: recoveredLogin.access_token, directory: deployDirectory, output, report});
    await verifySSHCertificateBrowser({page,expect,url,api,admin:recoveredLogin.access_token,report});
    // External replay-storage cases remain in replay-storage-qa.mjs. The mini
    // gate validates local recordings, encrypted backups and native updates.
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
  await inContainer(["update","stage","--root","/tmp/releases","--file","/artifact/scheduled.tar.gz","--sha256",scheduledSHA]);
  await inContainer(["update","stage","--root","/tmp/releases","--file","/artifact/scheduled-before.tar.gz","--sha256",failedScheduledSHA]);
  await verifyScheduledInstallation({run,owner,url,root,output,api,admin:recoveredLogin.access_token,operator:recoveredOperator.access_token,refreshOperator:async ()=>(await api("POST","/api/v1/authentication/auth/",{username:operator.username,password:operatorPassword})).access_token,sshHost:owner+"-ssh",fingerprint,candidate:{version:"v0.0.5",sha:scheduledSHA},failedCandidate:{version:"v0.0.6",sha:failedScheduledSHA},stopSelected,waitHealthy,chromium,expect,report});
  await verifyAutomaticInstallation({run,owner,url,output,api,admin:token,operator:async ()=>(await api("POST","/api/v1/authentication/auth/",{username:operator.username,password:operatorPassword})).access_token,sshHost:owner+"-ssh",fingerprint,feedURL,waitHealthy,chromium,expect,report});
  // Repeating package creation must refuse replacement of an existing archive.
  await verifySSHPasswordPolicy({run,runInput,owner,url,output,api,operator:async ()=>(await api("POST","/api/v1/authentication/auth/",{username:operator.username,password:operatorPassword})).access_token,sshHost:owner+"-ssh",fingerprint,chromium,expect,report,stopSelected,startSelected,inContainer});
  let conflict = false;
  const repeatedArchive = resolve(packages, `jumpserver233-${report.testVersion}-linux-amd64.tar.gz`);
  const originalDigest = createHash("sha256").update(readFileSync(repeatedArchive)).digest("hex");
  try { await run("go", ["run", "./cmd/jms-package", "--version", report.testVersion, "--commit", report.commit, "--built-at", report.builtAt, "--target", "linux/amd64", "--out", packages,"--web-dir",nativeWeb], { cwd: resolve(root, "server") }); }
  catch (e) { conflict = String(e.stderr).includes("update destination already exists"); }
  if (!conflict) throw new Error("Native package unexpectedly replaced existing bytes");
  if (createHash("sha256").update(readFileSync(repeatedArchive)).digest("hex") !== originalDigest) throw new Error("Repeated package changed existing bytes");
  if ((await run("git", ["rev-parse", "HEAD"])).stdout.trim() !== report.commit ||
      (await run("git", ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "status", "--porcelain", "--untracked-files=all"])).stdout.trim()) {
    throw new Error("Source changed during native provenance verification");
  }
  report.sourceUnchanged = true;
  report.replacementRefused = true; report.status = "passed";
  }
} catch (e) {
  report.status = "failed"; report.error = "Native QA failed; no release or deployment was created"; process.exitCode = 1;
  report.diagnostic = fixtureDiagnostic(String(e.stderr || e.message));
  report.diagnosticFrames = String(e.stack || "").split("\n").slice(1).filter(line => /scripts[\\/][\w-]+\.mjs:\d+:\d+/.test(line)).map(line => line.match(/scripts[\\/]([\w-]+\.mjs:\d+:\d+)/)?.[1]).filter(Boolean).slice(0, 6);
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
