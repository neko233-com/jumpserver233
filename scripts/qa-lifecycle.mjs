import { lstatSync, realpathSync, rmSync } from "node:fs";
import { basename, dirname, resolve, win32 } from "node:path";
import { isMissingDockerResource } from "../server/testsupport/docker-qa.mjs";

const fixtureName = /^jms233-(?:keyhost|systemdvm|postgres|sharing-postgres|mysql|mariadb|sqlserver|clickhouse|redis|mongodb|kubernetes|telnet|rdp|radius)-[a-f0-9-]{36}$/;
const normalPath = value => /^[A-Za-z]:[\\/]/.test(value || "") ? win32.resolve(value).replaceAll("\\", "/").toLowerCase() : resolve(value || ".");
const configLabels = '{{json (index .Config "Labels")}}', rootLabels = '{{json (index . "Labels")}}';
const containerFormat = '{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"Config":{"Image":{{json .Config.Image}},"Labels":' + configLabels + '}}';
const imageFormat = '{"Id":{{json .Id}},"RepoTags":{{json .RepoTags}},"Config":{"Labels":' + configLabels + '}}';
const ownershipLabels = new Set(["com.docker.compose.project", "com.docker.compose.project.working_dir", "com.docker.compose.project.config_files", "com.docker.compose.volume", "com.jumpserver233.qa.owner", "com.jumpserver233.qa.workspace"]);
async function inspectMetadata(execute, args) {
  let output;
  try { output = (await execute("docker", args, { maxBuffer: 16 * 1024 * 1024 })).stdout; }
  catch (error) {
    // A container may exit between ps and inspect. Docker returns metadata for
    // remaining objects with a nonzero exit. Never print raw inspect output.
    if (isMissingDockerResource(error) || /no such image/i.test(String(error.stderr))) output = error.stdout || "";
    else throw new Error("Docker ownership metadata unavailable");
  }
  let records;
  try { records = output.trim().split(/\r?\n/).filter(Boolean).flatMap(line => JSON.parse(line)); }
  catch { throw new Error("Docker ownership metadata malformed"); }
  for (const record of records) for (const holder of [record, record.Config]) if (holder && "Labels" in holder) holder.Labels = Object.fromEntries(Object.entries(holder.Labels || {}).filter(([key]) => ownershipLabels.has(key)));
  return records;
}
export async function inspectQAContainers(execute, ids) { return ids.length ? inspectMetadata(execute, ["inspect", "--format", containerFormat, ...ids]) : []; }
export async function inspectQAImages(execute, ids) { return ids.length ? inspectMetadata(execute, ["image", "inspect", "--format", imageFormat, ...ids]) : []; }
export async function inspectQAVolumes(execute, ids) { return ids.length ? inspectMetadata(execute, ["volume", "inspect", "--format", '{"Name":{{json .Name}},"Labels":' + rootLabels + '}', ...ids]) : []; }
export async function inspectQANetworks(execute, ids) { return ids.length ? inspectMetadata(execute, ["network", "inspect", "--format", '{"Id":{{json .Id}},"Name":{{json .Name}},"Labels":' + rootLabels + '}', ...ids]) : []; }
export function ownedCompose(container, root) {
  const labels = container.Config?.Labels || {};
  return /^jms233-[a-z0-9][a-z0-9-]{0,48}$/.test(labels["com.docker.compose.project"] || "") &&
    normalPath(labels["com.docker.compose.project.working_dir"]) === normalPath(root) &&
    normalPath(labels["com.docker.compose.project.config_files"]) === normalPath(resolve(root, "compose.qa.yml"));
}
export function ownedFixture(container, root, legacy = false) {
  const name = container.Name?.replace(/^\//, ""), labels = container.Config?.Labels || {};
  if (!fixtureName.test(name || "") || ![name, ...[labels["com.jumpserver233.qa.owner"]].filter(v => /^jumpserver233-e2e-[\w-]+$/.test(v || ""))].includes(labels["com.jumpserver233.qa.owner"])) return false;
  const workspace = labels["com.jumpserver233.qa.workspace"];
  if (workspace) return normalPath(workspace) === normalPath(root);
  return legacy && (/^jms233-[\w-]+(?::|$)/.test(container.Config?.Image || "") || [
    [/^jms233-(?:sharing-)?postgres-/, /^postgres:/], [/^jms233-kubernetes-/, /^rancher\/k3s:/],
    [/^jms233-mysql-/, /^mysql:/], [/^jms233-mariadb-/, /^mariadb:/],
    [/^jms233-sqlserver-/, /^mcr\.microsoft\.com\/mssql\/server:/],
    [/^jms233-clickhouse-/, /^clickhouse\/clickhouse-server:/], [/^jms233-redis-/, /^redis:/], [/^jms233-mongodb-/, /^mongo:/],
  ].some(([names, images]) => names.test(name) && images.test(container.Config?.Image || "")));
}
export function historicalQAResource(container, root, legacy = false) {
  return ownedCompose(container, root) || ownedFixture(container, root, legacy) && !/^jumpserver233-e2e-/.test(container.Config?.Labels?.["com.jumpserver233.qa.owner"] || "");
}
export function qaFixtureImage(record) {
  return ({ "openssh-container.json": "jms233-openssh-qa:local", "systemdvm-container.json": "jms233-systemdvm-qa:local", "postgres-container.json": "jms233-postgres-qa:local", "rdp-container.json": "jms233-rdp-qa:local", "radius-container.json": "jms233-radius-qa:local", "telnet-container.json": "jms233-telnet-qa:local" })[record];
}
export function ownedImage(image, expectedProject = "") {
  const tags = image.RepoTags || [];
  return (tags.length > 0 || /^jms233-[a-z0-9][a-z0-9-]{0,48}$/.test(expectedProject) && image.Config?.Labels?.["com.docker.compose.project"] === expectedProject) && tags.every(tag => /^jms233-[a-z0-9][\w.-]*(?::|\/)/.test(tag));
}
// Check both the lexical path and every existing ancestor. A junction must not
// turn a workspace cleanup into deletion of another directory.
export function removeOwnedTree(path, parent, prefix = "") {
  const target = resolve(path), boundary = resolve(parent);
  if (dirname(target).toLowerCase() !== boundary.toLowerCase() || !basename(target).startsWith(prefix) || target === boundary) throw new Error("Refusing unowned cleanup path");
  const expected = resolve(realpathSync(boundary), basename(target));
  try { if (lstatSync(target).isSymbolicLink() || realpathSync(target).toLowerCase() !== expected.toLowerCase()) throw new Error("Cleanup target must not contain links"); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  rmSync(target, { recursive: true, force: true });
}
export async function removeOwnedContainer(execute, id, accept) {
  const [current] = await inspectQAContainers(execute, [id]);
  if (!current) return false;
  if (!accept(current)) throw new Error("Container ownership changed; cleanup rejected");
  await execute("docker", ["rm", "--force", "--volumes", current.Id]);
  return true;
}
export async function removeUnusedQAImages(execute, imageIDs) {
  let removed = 0;
  const ids = (await execute("docker", ["ps", "--all", "--quiet"])).stdout.trim().split(/\s+/).filter(Boolean);
  const live = await inspectQAContainers(execute, ids);
  for (const id of new Set(imageIDs)) {
    if (live.some(c => c.Image === id)) continue;
    const [current] = await inspectQAImages(execute, [id]);
    if (!current) continue;
    if (!ownedImage(current)) continue;
    if (live.some(c => c.Image === current.Id)) continue;
    await execute("docker", ["image", "rm", ...current.RepoTags]); removed++;
  }
  return removed;
}
export function ownedCache(record) {
  return record.Reclaimable === true && /^[a-z0-9]+$/.test(record.ID || "") && /(?:\bjms233(?:-|\b)|go generate \.\/internal\/agentbundle)/.test(record.Description || "");
}
export async function removeLocalBuildHistory(execute, root) {
  const removed = [], seen = new Set();
  for (let attempt = 0; attempt < 100; attempt++) {
    let output;
    try { output = await execute("docker", ["buildx", "history", "ls", "--local", "--format", "json"], { cwd: root, maxBuffer: 8 * 1024 * 1024 }); }
    catch (error) { if (/unknown (?:command|flag)/i.test(String(error.stderr || error.message))) return removed; throw error; }
    const records = output.stdout.trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)).filter(r => ["Completed", "Error", "Canceled"].includes(r.status) && /^[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+$/.test(r.ref || ""));
    if (!records.length) return removed;
    if (records.some(r => seen.has(r.ref))) throw new Error("Build history cleanup did not progress");
    const builders = Map.groupBy(records, r => r.ref.split("/")[0]);
    for (const [builder, builds] of builders) await execute("docker", ["buildx", "history", "rm", "--builder", builder, ...builds.map(r => r.ref.split("/").at(-1))], { cwd: root });
    for (const r of records) { seen.add(r.ref); removed.push({ ref: r.ref, name: r.name, status: r.status }); }
  }
  throw new Error("Build history cleanup capacity exceeded");
}
export async function pruneOwnedQACache(execute) {
  const { stdout } = await execute("docker", ["buildx", "du", "--format", "json"], { maxBuffer: 16 * 1024 * 1024 });
  const records = stdout.trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line)).filter(ownedCache);
  if (!records.length) return [];
  await execute("docker", ["buildx", "prune", "--force", "--filter", `id~=^(${records.map(r => r.ID).join("|")})$`], { maxBuffer: 16 * 1024 * 1024 });
  const after = await execute("docker", ["buildx", "du", "--format", "json"], { maxBuffer: 16 * 1024 * 1024 });
  const remaining = new Set(after.stdout.trim().split(/\r?\n/).filter(Boolean).map(line => JSON.parse(line).ID));
  // BuildKit may retain shared/dependent records despite a successful command.
  // Count disappearance, never treat a selected record as reclaimed bytes.
  return records.filter(r => !remaining.has(r.ID)).map(r => ({ id: r.ID, size: r.Size }));
}
