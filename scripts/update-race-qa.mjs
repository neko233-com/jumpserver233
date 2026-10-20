// Real PostgreSQL takeover and Linux race checks for update delivery paths.
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { mkdirSync, writeFileSync } from "node:fs";
import { setTimeout as delay } from "node:timers/promises";
import { inspectQAContainers, inspectQANetworks } from "./qa-lifecycle.mjs";
import { retainQAArtifacts } from "./qa-retention.mjs";

const execute = promisify(execFile), root = fileURLToPath(new URL("..", import.meta.url));
const id = randomUUID(), owner = `jms233-updates-race-${id}`, db = `${owner}-db`, runner = `${owner}-go`, password = randomUUID();
const labels = ["--label", `com.jumpserver233.qa.owner=${owner}`, "--label", `com.jumpserver233.qa.workspace=${root}`];
const options = process.argv.slice(2), focusIndex = options.indexOf("--rotation-plans-only"), rotationPlansOnly = focusIndex >= 0;
if (rotationPlansOnly) options.splice(focusIndex, 1);
const batch = options.length===0 ? "execution-directories" : options.length===2 && options[0]==="--batch" && /^[a-z][a-z0-9-]{0,63}$/.test(options[1]) ? options[1] : null;
if (!batch) throw new Error("Use [--batch lowercase-name] [--rotation-plans-only]");
const output = resolve(root, `.cache/qa-reports/${batch}/linux-race.json`); mkdirSync(resolve(output, ".."), { recursive: true });
const report = { at: new Date().toISOString(), pid: process.pid, owner, network: owner, database: db, runner, status: "preparing", tests: [], packages: [], cleanup: {} };
const save = () => writeFileSync(output, JSON.stringify(report, null, 2));
const run = (command, args) => execute(command, args, { cwd: root, windowsHide: true, maxBuffer: 2 * 1024 * 1024 });
const owned = labels => labels?.["com.jumpserver233.qa.owner"] === owner && labels?.["com.jumpserver233.qa.workspace"] === root;
async function cleanup() {
  for (const name of [runner, db]) { const [current] = await inspectQAContainers(run, [name]); if (current) { if (!owned(current.Config?.Labels)) throw new Error("QA ownership changed"); await run("docker", ["rm", "--force", "--volumes", current.Id]); } }
  const [network] = await inspectQANetworks(run, [owner]); if (network) { if (!owned(network.Labels)) throw new Error("QA network ownership changed"); await run("docker", ["network", "rm", network.Id]); }
}
save();
try {
  report.commit = (await run("git", ["rev-parse", "HEAD"])).stdout.trim();
  report.sourceDirty = Boolean((await run("git", ["status", "--porcelain"])).stdout.trim());
  report.scope = rotationPlansOnly ? "rotation-plans" : "update-and-ssh";
  save();
  await run("docker", ["network", "create", ...labels, owner]);
  await run("docker", ["run", "--detach", "--name", db, ...labels, "--network", owner, "--tmpfs", "/var/lib/postgresql:rw,nosuid,size=256m", "--env", "POSTGRES_USER=jumpserver", "--env", `POSTGRES_PASSWORD=${password}`, "--env", "POSTGRES_DB=jumpserver_test", "postgres:17"]);
  let ready = false;
  for (let attempt = 0; attempt < 100; attempt++) { try { await run("docker", ["exec", db, "pg_isready", "-U", "jumpserver", "-d", "jumpserver_test"]); ready = true; break; } catch { await delay(100); } }
  if (!ready) throw new Error("QA database not ready");
  const modules = (await execute("go", ["env", "GOMODCACHE"], { cwd: resolve(root, "server") })).stdout.trim();
  const args = ["run", "--rm", "--name", runner, ...labels, "--network", owner,
    "--mount", `type=bind,source=${root},target=/work,readonly`, "--mount", `type=bind,source=${modules},target=/gomod,readonly`,
    "--workdir", "/work/server", "--env", "GOMODCACHE=/gomod", "--env", "GOFLAGS=-buildvcs=false", "--env", "JMS_REQUIRE_WORKSPACE=1", "--env", `JMS_TEST_DATABASE_URL=postgres://jumpserver:${password}@${db}:5432/jumpserver_test?sslmode=disable`,
    "golang:1.27-bookworm", "go", "test", "-race", "-json", "-timeout", "10m", "-run", "NativeNotification|EnterpriseOAuth|EnterpriseLogin|DirectorySync|DirectoryScan|DirectorySnapshot|MissingDirectoryUsers|SourceRegistry|SourcePaths|NamedLDAPSource|NamedSourceHTTP|NamedSources|DirectoryBulk|IdentitySourceCLI|SAMLSource|ReplayArchive|ReplayStorage|SSHCertificate|Label|Announcement|Operation|Playbook|NativeStepMetadata|AccountCheck|Generation|PolicyValidation|EncryptedPolicy|ConcurrentPolicy|FixedPassword|SaveReceipts|PlanPasswordPolicy|RotationPlan|ConfiguredPasswordPolicy|SharedPasswordPolicy|IncompatibleShared|SSHPasswordPolicy|Automatic|NativeSchedule|ScheduledInstallation|DirectoryLock|Supervisor|Drain|Admission|Maintenance|ExecutionDirectory|CommandDirectory|ExecGuard|ConnectionScope|ConnectionBinding|AccessSession|AssetLoginReview|SFTP|CloseSessionIdempotent|Workspace|Update|StableVersions|ReleaseMetadata|VerifiedDownload|DefaultTransport|FailedChecks|AutomaticChecking|NativeArchive|NativeStage|NativeInstall|Activation|GatedStartup|OfflinePreflight|UpgradeGuard|UpgradeLocked|PortableRelease|Packager|StandaloneBackup",
    "./internal/core/replayarchive", "./internal/core/notifications", "./internal/connector/cloudnotify", "./internal/core/enterpriselogin", "./internal/connector/enterpriseoauth", "./internal/core/directorysync", "./internal/core/identitysources", "./internal/core/identityscope", "./internal/core/auth", "./internal/connector/ldapclient", "./internal/connector/samlclient", "./internal/connector/replaystore", "./internal/storage", "./internal/core/credentialpolicy", "./internal/core/operations", "./internal/core/announcements", "./internal/core/labels", "./internal/core/sshcertificates", "./internal/core/rotationplans", "./internal/workgate", "./internal/core/servicemaintenance", "./internal/core/updates", "./internal/releasebundle", "./internal/maintenance", "./internal/api", "./internal/sessionclient", "./internal/hostagent", "./internal/core/hostplugins", "./internal/core/assets", "./internal/core/files", "./internal/core/accessreviews", "./internal/core/jobs", "./internal/core/commandfilters", "./internal/connector/sshclient", "./internal/desktop", "./internal/gateway", "./cmd/jms", "./cmd/jms-package", "./cmd/server"];
  if (rotationPlansOnly) {
    args[args.indexOf("-run") + 1] = ".";
    args.splice(args.indexOf("./internal/core/replayarchive"), args.length, "./internal/core/rotationplans");
  }
  const started = performance.now();
  report.code = await new Promise((done, reject) => {
    const child = spawn("docker", args, { cwd: root, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    report.childPID = child.pid; report.status = "running"; save(); let pending = "";
    child.stdout.on("data", chunk => {
      pending += chunk;
      let index;
      while ((index = pending.indexOf("\n")) >= 0) {
        const line = pending.slice(0, index); pending = pending.slice(index + 1);
        try { const event = JSON.parse(line); if (["pass", "fail", "skip"].includes(event.Action)) { (event.Test ? report.tests : report.packages).push({ package: event.Package, test: event.Test, status: event.Action, seconds: event.Elapsed }); save(); } } catch { /* Compiler output is never persisted. */ }
      }
    });
    // Database URLs and subprocess arguments are excluded from reports.
    child.stderr.on("data", () => {}); child.once("error", reject); child.once("exit", code => done(code ?? 1));
  });
  report.durationMs = Math.round(performance.now() - started); report.status = report.code === 0 ? "passed" : "failed";
  if (report.code !== 0) process.exitCode = 1;
} catch { report.status = "failed"; report.error = "Isolated update race verification failed"; process.exitCode = 1; }
finally {
  report.testStatus = report.status;
  for (let round = 0; round < 2; round++) { try { await cleanup(); report.cleanup[round ? "idempotent" : "removed"] = true; } catch { report.cleanup.error = "Owned QA cleanup incomplete"; report.status = "cleanup_failed"; process.exitCode = 1; } }
  save();
  try { retainQAArtifacts(root, { currentRun: resolve(output, "..") }); }
  catch { report.retentionError = "Artifact retention incomplete; retry node scripts/qa-retention.mjs --apply"; process.exitCode = 1; save(); }
  console.log(JSON.stringify({ status: report.status, code: report.code, passed: report.tests.filter(t => t.status === "pass").length, failed: report.tests.filter(t => t.status === "fail").length, skipped: report.tests.filter(t => t.status === "skip").length, durationMs: report.durationMs, cleanup: report.cleanup, retentionError: report.retentionError }));
}
