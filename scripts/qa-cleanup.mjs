import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdirSync, writeFileSync, readdirSync, readFileSync, existsSync, lstatSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { ownedCompose, historicalQAResource, ownedImage, removeOwnedContainer, pruneOwnedQACache, removeLocalBuildHistory, inspectQAContainers, inspectQAImages, inspectQAVolumes, inspectQANetworks } from "./qa-lifecycle.mjs";
import { retainQAArtifacts } from "./qa-retention.mjs";

const execute = promisify(execFile), root = fileURLToPath(new URL("..", import.meta.url));
const args = new Set(process.argv.slice(2));
if ([...args].some(a => !["--apply", "--include-legacy-fixtures", "--test-caches"].includes(a))) throw new Error("Use --apply, --include-legacy-fixtures and/or --test-caches");
const legacy = args.has("--include-legacy-fixtures"), apply = args.has("--apply");
const run = async command => { try { return (await execute("docker", command, { maxBuffer: 16 * 1024 * 1024 })).stdout.trim(); } catch { throw new Error(`Docker ${command[0]} ${command[1] || ""} failed`); } };
const ids = (await run(["ps", "--all", "--quiet"])).split(/\s+/).filter(Boolean);
const containers = await inspectQAContainers(execute, ids);
// Active E2E runs own their own records and cleanup. A historical sweep must
// never consume another concurrently running suite's temporary namespace.
const accept = c => historicalQAResource(c, root, legacy);
const selected = containers.filter(accept), projects = new Set(selected.filter(c => ownedCompose(c, root)).map(c => c.Config.Labels["com.docker.compose.project"]));
const historicalLogs = resolve(root, ".cache/docker-qa");
if (legacy && existsSync(historicalLogs) && !lstatSync(historicalLogs).isSymbolicLink()) {
  for (const entry of readdirSync(historicalLogs, { withFileTypes: true })) {
    if (!entry.isDirectory() || entry.isSymbolicLink() || !/^jms233-[a-z0-9][a-z0-9-]{0,48}$/.test(entry.name)) continue;
    const log = resolve(historicalLogs, entry.name, "verify.log");
    if (existsSync(log) && !lstatSync(log).isSymbolicLink() && lstatSync(log).size < 8 * 1024 * 1024 && readFileSync(log, "utf8").includes(entry.name)) projects.add(entry.name);
  }
}
const out = resolve(root, ".cache/qa-reports");
// Retain ownership evidence when a partial cleanup removed containers before
// a daemon failure. A later invocation can still clean their orphaned volumes.
for (const name of (existsSync(out) ? readdirSync(out) : []).filter(n => /^cleanup-\d+\.json$/.test(n))) {
  const old = JSON.parse(readFileSync(resolve(out, name), "utf8"));
  if (old.root !== root || !old.applied) continue;
  for (const c of old.composeEvidence || []) if (ownedCompose(c, root)) projects.add(c.Config.Labels["com.docker.compose.project"]);
}
const volumes = await inspectQAVolumes(execute, (await run(["volume", "ls", "--quiet"])).split(/\s+/).filter(Boolean));
const namedCaches = new Set(args.has("--test-caches") ? ["jms233-go-race-cache", "jms233-module-cache"] : []);
const ownedVolume = v => projects.has(v.Labels?.["com.docker.compose.project"]) && v.Labels?.["com.docker.compose.volume"] === "data" || namedCaches.has(v.Name);
const selectedVolumes = volumes.filter(ownedVolume);
const networks = await inspectQANetworks(execute, (await run(["network", "ls", "--quiet"])).split(/\s+/).filter(Boolean));
const selectedNetworks = networks.filter(n => projects.has(n.Labels?.["com.docker.compose.project"]));
const imageIDs = [...new Set((await run(["image", "ls", "--all", "--quiet", "--no-trunc"])).split(/\s+/).filter(Boolean))];
const images = await inspectQAImages(execute, imageIDs);
const acceptImage = image => { const p = image.Config?.Labels?.["com.docker.compose.project"]; return ownedImage(image, projects.has(p) ? p : ""); };
const candidateImages = new Set(selected.map(c => c.Image));
for (const image of images) if (projects.has(image.Config?.Labels?.["com.docker.compose.project"]) || image.RepoTags?.some(tag => [...projects].some(p => tag.startsWith(p + "-api:") || tag.startsWith(p + "-web:")))) candidateImages.add(image.Id);
const report = { root, at: new Date().toISOString(), applied: apply, before: await run(["system", "df"]), composeEvidence: selected.filter(c => ownedCompose(c, root)).map(c => ({ Config: { Labels: c.Config.Labels } })), containers: selected.map(c => ({ id: c.Id, name: c.Name, image: c.Image })), volumes: selectedVolumes.map(v => v.Name), networks: selectedNetworks.map(n => n.Name), removed: { containers: 0, volumes: 0, networks: 0, images: 0 } };
const reportPath = resolve(out, `cleanup-${Date.now()}.json`);
try {
  if (apply) {
    // Every mutation rechecks ownership; missing resources are already clean.
    for (const c of selected) if (await removeOwnedContainer(execute, c.Id, accept)) report.removed.containers++;
    for (const v of selectedVolumes) {
      const [current] = await inspectQAVolumes(execute, [v.Name]);
      if (!current) continue;
      if (!ownedVolume(current)) throw new Error("Volume ownership changed");
      await run(["volume", "rm", v.Name]); report.removed.volumes++;
    }
    for (const n of selectedNetworks) { const [current] = await inspectQANetworks(execute, [n.Id]); if (!current) continue; if (!projects.has(current.Labels?.["com.docker.compose.project"])) throw new Error("Network ownership changed"); await run(["network", "rm", n.Id]); report.removed.networks++; }
    const liveIds = (await run(["ps", "--all", "--quiet"])).split(/\s+/).filter(Boolean);
    const live = await inspectQAContainers(execute, liveIds);
    for (const image of images.filter(i => candidateImages.has(i.Id) && acceptImage(i))) {
      if (live.some(c => c.Image === image.Id)) continue;
      const [current] = await inspectQAImages(execute, [image.Id]);
      if (!current) continue;
      if (!acceptImage(current)) throw new Error("Image ownership changed");
      // Remove only verified QA tags; never force removal of shared images.
      await run(["image", "rm", ...(current.RepoTags?.length ? current.RepoTags : [current.Id])]); report.removed.images++;
    }
    if (args.has("--test-caches")) { report.removedBuildHistory = await removeLocalBuildHistory(execute, root); report.prunedCache = await pruneOwnedQACache(execute); }
  }
} catch (error) { report.error = error.message; process.exitCode = 1; }
finally {
  report.after = await run(["system", "df"]);
  if (apply) {
    mkdirSync(out, { recursive: true }); writeFileSync(reportPath, JSON.stringify(report, null, 2));
    try { retainQAArtifacts(root); }
    catch { report.retentionError = "Artifact retention incomplete; retry node scripts/qa-retention.mjs --apply"; process.exitCode = 1; writeFileSync(reportPath, JSON.stringify(report, null, 2)); }
  }
}
console.log(JSON.stringify({ applied: apply, selected: { containers: selected.length, volumes: selectedVolumes.length, networks: selectedNetworks.length }, removed: report.removed, report: apply ? reportPath : undefined, error: report.error, retentionError: report.retentionError }));
