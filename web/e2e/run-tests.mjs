import { execFileSync, spawn } from "node:child_process";
import { existsSync, readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isMissingDockerResource } from "../../server/testsupport/docker-qa.mjs";
import { stagePluginArtifacts } from "./plugin-artifact-cache.mjs";

const webDir = fileURLToPath(new URL("..", import.meta.url));
const temporaryRoot = resolve(tmpdir());
const cleanupOnly = process.argv[2] === "--cleanup";
if (process.argv.length > 2 && (!cleanupOnly || process.argv.length !== 4))
  throw new Error("Use --cleanup with one owned E2E directory");
const dataDir = cleanupOnly
  ? resolve(process.argv[3])
  : mkdtempSync(resolve(temporaryRoot, "jumpserver233-e2e-"));
const absoluteDataDir = resolve(dataDir);
const artifactCache = resolve(webDir, "node_modules/.cache/jumpserver233-plugin-artifacts");
let exitCode = 1;

try {
  if (!cleanupOnly) execFileSync("go", ["generate", "./internal/agentbundle"], { cwd: resolve(webDir, "../server"), stdio: "inherit" });
  if (!cleanupOnly) stagePluginArtifacts(process.env.JMS_E2E_PLUGIN_CACHE_DIR || artifactCache, resolve(dataDir, "plugin-artifacts"));
  exitCode = cleanupOnly
    ? 0
    : await new Promise((resolveExit) => {
        const playwright = spawn("pnpm exec playwright test", {
          cwd: webDir,
          env: { ...process.env, JMS_E2E_DATA_DIR: dataDir },
          shell: true,
          stdio: "inherit",
        });
        playwright.once("error", (error) => {
          process.stderr.write(`Could not start Playwright: ${error.message}\n`);
          resolveExit(1);
        });
        playwright.once("exit", (code) => resolveExit(code ?? 1));
      });
} finally {
  if (
    dirname(absoluteDataDir).toLowerCase() !== temporaryRoot.toLowerCase() ||
    !basename(absoluteDataDir).startsWith("jumpserver233-e2e-")
  ) {
    throw new Error(
      "Refusing to remove a path outside the Playwright-owned temporary data directory",
    );
  }
  if (!cleanupOnly) {
    try { stagePluginArtifacts(resolve(dataDir, "plugin-artifacts"), artifactCache); }
    catch { process.stderr.write("Public artifact cache could not be retained; owned fixture cleanup continues.\n"); }
  }
  let cleaned = true;
  for (const [filename, prefix] of [
    ["openssh-container.json", "jms233-keyhost-"],
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
    try {
      const labels = JSON.parse(
        execFileSync("docker", ["inspect", "--format", "{{json .Config.Labels}}", resource.name], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "pipe"],
        }),
      );
      if (labels["com.jumpserver233.qa.owner"] !== resource.owner)
        throw new Error("Fixture owner mismatch");
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
  if (cleaned) rmSync(absoluteDataDir, { recursive: true, force: true });
}

process.exitCode = exitCode;
