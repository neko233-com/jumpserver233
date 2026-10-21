import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, existsSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { ownedCompose, ownedFixture, historicalQAResource, ownedImage, removeOwnedTree, removeOwnedContainer, removeUnusedQAImages, ownedCache, pruneOwnedQACache, qaFixtureImage, removeLocalBuildHistory, inspectQAContainers, inspectQAImages, inspectQAVolumes, inspectQANetworks } from "./qa-lifecycle.mjs";
const root = resolve("workspace");
const compose = () => ({ Id: "immutable-id", Config: { Labels: { "com.docker.compose.project": "jms233-test", "com.docker.compose.project.working_dir": root, "com.docker.compose.project.config_files": resolve(root, "compose.qa.yml") } } });
test("QA cleanup rejects foreign workspaces and normal deployments", () => {
  assert.equal(ownedCompose(compose(), root), true);
  for (const [key, value] of [["com.docker.compose.project.working_dir", resolve("elsewhere")], ["com.docker.compose.project.config_files", resolve(root, "compose.yml")], ["com.docker.compose.project", "production"]]) { const c = compose(); c.Config.Labels[key] = value; assert.equal(ownedCompose(c, root), false); }
  assert.equal(ownedImage({ RepoTags: ["jms233-test-api:latest"] }), true);
  assert.equal(ownedImage({ RepoTags: ["jms233-test-api:latest", "production:latest"] }), false);
  assert.equal(ownedImage({ RepoTags: [] }), false);
  const dangling = { RepoTags: [], Config: { Labels: { "com.docker.compose.project": "jms233-test" } } };
  assert.equal(ownedImage(dangling, "jms233-test"), true); assert.equal(ownedImage(dangling, "jms233-foreign"), false);
});
test("fixture ownership requires workspace and immutable resource record", () => {
  const name = "jms233-keyhost-00000000-0000-0000-0000-000000000000";
  const c = { Name: "/" + name, Config: { Image: "jms233-openssh-qa:local", Labels: { "com.jumpserver233.qa.owner": name, "com.jumpserver233.qa.workspace": root } } };
  assert.equal(ownedFixture(c, root), true); assert.equal(ownedFixture(c, resolve("foreign")), false);
  c.Config.Labels["com.jumpserver233.qa.owner"] = "jumpserver233-e2e-active-run";
  assert.equal(historicalQAResource(c, root, true), false);
  c.Config.Labels["com.jumpserver233.qa.owner"] = name;
  delete c.Config.Labels["com.jumpserver233.qa.workspace"];
  assert.equal(ownedFixture(c, root), false); assert.equal(ownedFixture(c, root, true), true);
  c.Config.Labels["com.jumpserver233.qa.owner"] = "foreign"; assert.equal(ownedFixture(c, root, true), false);
});
test("container cleanup is idempotent and distinguishes missing from failed Docker", async () => {
  let exists = true, removals = 0;
  const execute = async (_, args) => { if (args[0] === "inspect") { if (!exists) throw Object.assign(Error("missing"), { stderr: "No such object" }); return { stdout: JSON.stringify([compose()]) }; } assert.deepEqual(args, ["rm", "--force", "--volumes", "immutable-id"]); removals++; exists = false; return { stdout: "" }; };
  assert.equal(await removeOwnedContainer(execute, "immutable-id", c => ownedCompose(c, root)), true);
  assert.equal(await removeOwnedContainer(execute, "immutable-id", c => ownedCompose(c, root)), false); assert.equal(removals, 1);
  await assert.rejects(removeOwnedContainer(async () => { throw Error("daemon offline"); }, "id", () => true), /metadata unavailable/);
  await assert.rejects(removeOwnedContainer(async () => ({ stdout: JSON.stringify([compose()]) }), "id", () => false), /ownership/);
});
test("temporary cleanup repeats safely and rejects traversal and links", () => {
  const parent = resolve(tmpdir()), folder = mkdtempSync(resolve(parent, "jms-cleanup-test-"));
  try { mkdirSync(resolve(folder, "data")); removeOwnedTree(resolve(folder, "data"), folder, "data"); removeOwnedTree(resolve(folder, "data"), folder, "data"); assert.equal(existsSync(resolve(folder, "data")), false); assert.throws(() => removeOwnedTree(parent, folder), /unowned/); const link = resolve(folder, "link"); try { symlinkSync(parent, link, "junction"); } catch (e) { if (e.code !== "EPERM") throw e; return; } assert.throws(() => removeOwnedTree(link, folder), /links/); }
  finally { removeOwnedTree(folder, parent, "jms-cleanup-test-"); }
});
test("image cleanup preserves shared tags and images used by another container", async () => {
  let removed = 0;
  const execute = async (_, args) => {
    if (args[0] === "ps") return { stdout: "other" };
    if (args[0] === "inspect") return { stdout: JSON.stringify([{ Image: "in-use" }]) };
    if (args[0] === "image" && args[1] === "inspect") return { stdout: JSON.stringify([{ Id: args.at(-1), RepoTags: args.at(-1) === "shared" ? ["jms233-test:local", "other:latest"] : ["jms233-test:local"] }]) };
    removed++; return { stdout: "" };
  };
  assert.equal(await removeUnusedQAImages(execute, ["in-use", "shared", "unused", "unused"]), 1); assert.equal(removed, 1);
});
test("cache cleanup selects only reclaimable project records and is idempotent", async () => {
  const own = { ID: "project123", Reclaimable: true, Description: 'cached mount id "/jms233-go-build"' };
  assert.equal(ownedCache(own), true); assert.equal(ownedCache({ ...own, Reclaimable: false }), false); assert.equal(ownedCache({ ...own, Description: "another repository" }), false);
  let present = true, pruned = 0;
  const execute = async (_, args) => { if (args[1] === "du") return { stdout: present ? JSON.stringify(own) + "\n" + JSON.stringify({ ...own, ID: "foreign", Description: "other" }) : "" }; assert.deepEqual(args.slice(0, 4), ["buildx", "prune", "--force", "--filter"]); assert.equal(args[4], "id~=^(project123)$"); present = false; pruned++; return { stdout: "" }; };
  assert.equal((await pruneOwnedQACache(execute)).length, 1); assert.equal((await pruneOwnedQACache(execute)).length, 0); assert.equal(pruned, 1);
});
test("fixture records identify only fixed QA images after controllers already stopped", () => {
  assert.equal(qaFixtureImage("discovery-container.json"), "jms233-openssh-qa:local"); assert.equal(qaFixtureImage("openssh-container.json"), "jms233-openssh-qa:local"); assert.equal(qaFixtureImage("radius-container.json"), "jms233-radius-qa:local");
  assert.equal(qaFixtureImage("mysql-container.json"), undefined); assert.equal(qaFixtureImage("foreign-container.json"), undefined);
});

test("native cache cleanup is limited to its unique owner", async () => {
  const owner = "jms233-native-package-00000000-0000-0000-0000-000000000000";
  const own = { ID: "native123", Reclaimable: true, Description: "LABEL com.jumpserver233.qa.owner=" + owner };
  let present = true;
  const execute = async (_, args) => { if (args[1] === "du") return { stdout: [present ? own : null, { ID: "other123", Reclaimable: true, Description: 'cached mount id "/jms233-go-build"' }].filter(Boolean).map(r => JSON.stringify(r)).join("\n") }; assert.equal(args[4], "id~=^(native123)$"); present = false; return { stdout: "" }; };
  assert.equal((await pruneOwnedQACache(execute, owner)).length, 1);
  assert.equal((await pruneOwnedQACache(execute, owner)).length, 0);
  await assert.rejects(pruneOwnedQACache(execute, "other project"), /Invalid QA cache owner/);
});
test("build history cleanup is repository scoped, excludes active builds and repeats safely", async () => {
  let removed = false;
  const execute = async (_, args, options) => { assert.equal(options.cwd, root); if (args[2] === "ls") { assert.ok(args.includes("--local")); return { stdout: (removed ? [] : [{ ref: "builder/node/completed", name: "server", status: "Completed" }, { ref: "builder/node/active", status: "Running" }]).map(r => JSON.stringify(r)).join("\n") }; } assert.deepEqual(args, ["buildx", "history", "rm", "--builder", "builder", "completed"]); removed = true; return { stdout: "" }; };
  assert.equal((await removeLocalBuildHistory(execute, root)).length, 1); assert.equal((await removeLocalBuildHistory(execute, root)).length, 0);
  await assert.rejects(removeLocalBuildHistory(async () => { throw Error("daemon offline"); }, root), /unavailable/);
});

test("build history retries only transient metadata reads and sanitizes exhausted failures", async () => {
  let calls = 0;
  const transient = () => Object.assign(Error("private command body"), { stderr: "ERROR: rpc error: code = Unavailable desc = error reading from server: EOF" });
  assert.deepEqual(await removeLocalBuildHistory(async (_, args) => { assert.equal(args[2], "ls"); if (++calls < 3) throw transient(); return { stdout: "" }; }, root), []);
  assert.equal(calls, 3);
  calls = 0;
  await assert.rejects(removeLocalBuildHistory(async () => { calls++; throw transient(); }, root), error => error.message === "Buildx metadata unavailable; cleanup remains incomplete");
  assert.equal(calls, 3);
  calls = 0;
  await assert.rejects(removeLocalBuildHistory(async () => { calls++; throw Object.assign(Error("private"), { stderr: "permission denied" }); }, root), /unavailable/);
  assert.equal(calls, 1);
  assert.deepEqual(await removeLocalBuildHistory(async () => { throw Object.assign(Error("private"), { stderr: 'unknown command: history' }); }, root), []);
});
test("inspect tolerates concurrent fixture exits and never requests environment or command bodies", async () => {
  const execute = async (_, args) => { const format = args[args.indexOf("--format") + 1]; assert.ok(!format.includes(".Env")); assert.ok(!format.includes(".Cmd")); throw Object.assign(Error("partial"), { stderr: "No such object: exited", stdout: JSON.stringify(compose()) + "\n" }); };
  assert.deepEqual(await inspectQAContainers(execute, ["alive", "exited"]), [compose()]);
});
test("every Docker metadata template produces complete JSON without credential fields", async () => {
  for (const inspect of [inspectQAContainers, inspectQAImages, inspectQAVolumes, inspectQANetworks]) {
    const execute = async (_, args) => { const format = args[args.indexOf("--format") + 1]; assert.ok(!format.includes(".Env")); assert.ok(!format.includes(".Cmd")); assert.doesNotThrow(() => JSON.parse(format.replace(/\{\{.*?\}\}/g, '""'))); return { stdout: "[]" }; };
    assert.deepEqual(await inspect(execute, ["owned-id"]), []);
  }
});
test("ownership metadata accepts missing labels and strips unrelated private labels", async () => {
  const output = [{ Config: {} }, { Config: { Labels: null } }, { Config: { Labels: { "com.jumpserver233.qa.owner": "owned", "private-label": "must-not-leave-parser" } } }];
  const records = await inspectQAContainers(async () => ({ stdout: JSON.stringify(output) }), ["a", "b", "c"]);
  assert.deepEqual(records, [{ Config: {} }, { Config: { Labels: {} } }, { Config: { Labels: { "com.jumpserver233.qa.owner": "owned" } } }]);
  await assert.rejects(inspectQAContainers(async () => ({ stdout: "sensitive malformed data" }), ["a"]), error => error.message === "Docker ownership metadata malformed");
});

test("Windows Buildx local Git failure uses the equivalent exact repository filter", async () => {
  const calls = []; let deleted = false;
  const execute = async (command, args) => {
    calls.push([command, args]);
    if (command === "git") return { stdout: "https://github.com/neko233-com/jumpserver233.git\n" };
    if (args.includes("--local")) throw Object.assign(new Error("local Git"), { stderr: "could not get remote URL for local filter: no remote URL found for either origin or upstream" });
    if (args[2] === "rm") { deleted = true; return {stdout:""}; }
    assert(args.includes("repository=https://github.com/neko233-com/jumpserver233.git"));
    return {stdout:deleted ? "" : JSON.stringify({ref:"desktop/node/owned-ref", status:"Completed", name:"owned"})};
  };
  const removed = await removeLocalBuildHistory(execute, process.cwd());
  assert.equal(removed.length, 1);
  assert(calls.filter(([c,a])=>c==="docker"&&a[2]==="ls").every(([,a])=>a.includes("--local")||a.includes("--filter")));
});

test("Buildx fallback rejects a credential-bearing remote before any removal", async () => {
  const execute = async (command, args) => {
    if (command === "git") return {stdout:"https://user:secret@example.test/repo.git"};
    assert.notEqual(args[2], "rm");
    throw Object.assign(new Error("local Git"), {stderr:"could not get remote URL for local filter"});
  };
  await assert.rejects(removeLocalBuildHistory(execute, process.cwd()), /Cannot identify owned/);
});
