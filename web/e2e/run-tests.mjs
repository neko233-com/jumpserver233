import { execFileSync, spawn } from "node:child_process";
import {
  existsSync,
  readFileSync,
  mkdtempSync,
  rmSync,
  mkdirSync,
  readdirSync,
  copyFileSync,
  writeFileSync,
} from "node:fs";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isMissingDockerResource } from "../../server/testsupport/docker-qa.mjs";
import { stagePluginArtifacts } from "./plugin-artifact-cache.mjs";
import { retainQAArtifacts } from "../../scripts/qa-retention.mjs";
import {
  removeOwnedTree,
  removeUnusedQAImages,
  pruneOwnedQACache,
  qaFixtureImage,
  removeLocalBuildHistory,
  inspectQAContainers,
} from "../../scripts/qa-lifecycle.mjs";

const webDir = fileURLToPath(new URL("..", import.meta.url));
const temporaryRoot = resolve(tmpdir());
const cleanupOnly = process.argv[2] === "--cleanup";
const production = process.argv.length === 3 && process.argv[2] === "--production";
if (process.argv.length > 2 && !production && (!cleanupOnly || process.argv.length !== 4))
  throw new Error("Use --production, or --cleanup with one owned E2E directory");
const dataDir = cleanupOnly
  ? resolve(process.argv[3])
  : mkdtempSync(resolve(temporaryRoot, "jumpserver233-e2e-"));
const absoluteDataDir = resolve(dataDir);
const goTemporaryDir = resolve(absoluteDataDir, "go-tmp");
const productionWebDir = resolve(absoluteDataDir, "web-dist");
const artifactCache = resolve(webDir, "node_modules/.cache/jumpserver233-plugin-artifacts");
const reportDir = resolve(webDir, "../.cache/qa-reports", `browser-${Date.now()}`);
const fixtureImages = new Set();
let exitCode = 1;
const lifecycle = { startedAt: new Date().toISOString(), pid: process.pid, dataDirectory: absoluteDataDir, production };
let lifecycleWriteFailed = false;
function recordLifecycle(status, extra = {}) {
  if (cleanupOnly) return;
  Object.assign(lifecycle, { status, at: new Date().toISOString() }, extra);
  try {
    mkdirSync(reportDir, { recursive: true });
    writeFileSync(resolve(reportDir, "lifecycle.json"), JSON.stringify(lifecycle, null, 2));
  } catch {
    lifecycleWriteFailed = true;
  }
}

try {
  if (!cleanupOnly) {
    recordLifecycle("preparing");
    mkdirSync(goTemporaryDir, { recursive: true });
    execFileSync("go", ["generate", "./internal/agentbundle"], {
      cwd: resolve(webDir, "../server"),
      env: { ...process.env, GOTMPDIR: goTemporaryDir },
      stdio: "inherit",
    });
  }
  if (production) {
    await new Promise((done, reject) => {
      const build = spawn("pnpm build", { cwd: webDir, env: { ...process.env, JMS_E2E_WEB_DIR: productionWebDir }, shell: true, stdio: "inherit" });
      recordLifecycle("building", { buildPID: build.pid });
      build.once("error", reject);
      build.once("exit", (code) =>
        code === 0 ? done() : reject(new Error("Production frontend build failed")),
      );
    });
  }
  if (!cleanupOnly)
    stagePluginArtifacts(
      process.env.JMS_E2E_PLUGIN_CACHE_DIR || artifactCache,
      resolve(dataDir, "plugin-artifacts"),
    );
  exitCode = cleanupOnly
    ? 0
    : await new Promise((resolveExit) => {
        const playwright = spawn("pnpm exec playwright test", {
          cwd: webDir,
          env: {
            ...process.env,
            GOTMPDIR: goTemporaryDir,
            JMS_E2E_DATA_DIR: dataDir,
            JMS_E2E_REPORT_DIR: reportDir,
            JMS_E2E_PRODUCTION: production ? "true" : "false",
            JMS_E2E_WEB_DIR: production ? productionWebDir : "",
          },
          shell: true,
          stdio: "inherit",
        });
        recordLifecycle("running", { playwrightPID: playwright.pid });
        playwright.once("error", (error) => {
          process.stderr.write(`Could not start Playwright: ${error.message}\n`);
          resolveExit(1);
        });
        playwright.once("exit", (code) => resolveExit(code ?? 1));
      });
} finally {
  let cleaned = false;
  try {
    if (
      dirname(absoluteDataDir).toLowerCase() !== temporaryRoot.toLowerCase() ||
      !basename(absoluteDataDir).startsWith("jumpserver233-e2e-")
    ) {
      throw new Error(
        "Refusing to remove a path outside the Playwright-owned temporary data directory",
      );
    }
    cleaned = true;
    for (const [filename, prefix] of [
      ["openssh-container.json", "jms233-keyhost-"],
      ["discovery-container.json", "jms233-keyhost-"],
      ["systemdvm-container.json", "jms233-systemdvm-"],
      ["postgres-container.json", "jms233-postgres-"],
      ["mysql-container.json", "jms233-mysql-"],
      ["mariadb-container.json", "jms233-mariadb-"],
      ["sqlserver-container.json", "jms233-sqlserver-"],
      ["clickhouse-container.json", "jms233-clickhouse-"],
      ["redis-container.json", "jms233-redis-"],
      ["mongodb-container.json", "jms233-mongodb-"],
      ["kubernetes-container.json", "jms233-kubernetes-"],
      ["telnet-container.json", "jms233-telnet-"],
      ["rdp-container.json", "jms233-rdp-"],
      ["radius-container.json", "jms233-radius-"],
    ]) {
      const resourcePath = resolve(absoluteDataDir, filename);
      if (!existsSync(resourcePath)) continue;
      const resource = JSON.parse(readFileSync(resourcePath, "utf8"));
      if (
        !resource.name.startsWith(prefix) ||
        !new RegExp(`^${prefix}[a-f0-9-]{36}$`).test(resource.name) ||
        resource.owner !== basename(absoluteDataDir)
      )
        throw new Error("Refusing unowned fixture cleanup");
      const image = qaFixtureImage(filename);
      if (image) fixtureImages.add(image);
      try {
        const [container] = await inspectQAContainers(promisify(execFile), [resource.name]);
        if (!container) continue;
        if (container.Config.Labels["com.jumpserver233.qa.owner"] !== resource.owner)
          throw new Error("Fixture owner mismatch");
        fixtureImages.add(container.Image);
        execFileSync("docker", ["rm", "--force", "--volumes", resource.name], {
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (error) {
        if (!isMissingDockerResource(error)) {
          cleaned = false;
          process.stderr.write("Fixture cleanup failed; preserving owned resource record.\n");
          exitCode = 1;
        }
      }
    }
    if (cleaned) {
      for (const engine of [
        "mysql",
        "mariadb",
        "sqlserver",
        "clickhouse",
        "redis",
        "mongodb",
        "kubernetes",
        "telnet",
        "rdp",
      ]) {
        const record = resolve(absoluteDataDir, `${engine}-container.json`);
        if (!existsSync(record)) continue;
        const resource = JSON.parse(readFileSync(record, "utf8"));
        if (!resource.cert_directory) continue;
        const cert = resolve(resource.cert_directory);
        if (
          dirname(cert).toLowerCase() !== temporaryRoot.toLowerCase() ||
          !basename(cert).startsWith(`jms233-${engine}-cert-`)
        )
          throw new Error("Invalid SQL certificate cleanup path");
        rmSync(cert, { recursive: true, force: true });
      }
    }
    if (cleaned) {
      await removeUnusedQAImages(promisify(execFile), [...fixtureImages]);
      await removeLocalBuildHistory(promisify(execFile), resolve(webDir, ".."));
      await pruneOwnedQACache(promisify(execFile));
      removeOwnedTree(absoluteDataDir, temporaryRoot, "jumpserver233-e2e-");
      if (existsSync(artifactCache))
        removeOwnedTree(artifactCache, dirname(artifactCache), "jumpserver233-plugin-artifacts");
    }
  } catch (error) {
    cleaned = false;
    exitCode = 1;
    throw error;
  } finally {
    if (!cleanupOnly) {
      mkdirSync(reportDir, { recursive: true });
      const results = resolve(webDir, "test-results");
      // Only visual evidence is copied; traces and runtime data may hold secrets.
      function preservePNGs(folder, prefix = "") {
        for (const entry of readdirSync(folder, { withFileTypes: true })) {
          if (entry.isSymbolicLink()) continue;
          const path = resolve(folder, entry.name),
            name = prefix + entry.name;
          if (entry.isDirectory()) preservePNGs(path, name + "-");
          else if (entry.isFile() && entry.name.endsWith(".png"))
            copyFileSync(path, resolve(reportDir, name));
        }
      }
      if (existsSync(results)) {
        preservePNGs(results);
        removeOwnedTree(results, webDir, "test-results");
      }
      writeFileSync(
        resolve(reportDir, "cleanup.json"),
        JSON.stringify(
          {
            at: new Date().toISOString(),
            exitCode,
            cleaned,
            temporaryDataRemoved: !existsSync(absoluteDataDir),
            remainingDataDirectory: existsSync(absoluteDataDir) ? absoluteDataDir : undefined,
            lifecycleRecorded: !lifecycleWriteFailed,
          },
          null,
          2,
        ),
      );
      recordLifecycle(exitCode === 0 && cleaned ? "passed" : "failed", { exitCode, cleaned, temporaryDataRemoved: !existsSync(absoluteDataDir) });
      try { retainQAArtifacts(resolve(webDir, ".."), { currentRun: reportDir }); }
      catch {
        process.stderr.write("QA artifact retention incomplete; retry node scripts/qa-retention.mjs --apply.\n");
        exitCode = 1;
        recordLifecycle("failed", { exitCode, artifactRetentionFailed: true });
      }
      console.log(`QA report: ${reportDir}`);
    }
  }
}

process.exitCode = exitCode;
