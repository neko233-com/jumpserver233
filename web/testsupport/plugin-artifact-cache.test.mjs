import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, openSync, ftruncateSync, closeSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname, basename } from "node:path";
import { stagePluginArtifacts } from "../e2e/plugin-artifact-cache.mjs";
function temporaryFixture(t) {
  const root = mkdtempSync(join(tmpdir(), "jms233-artifact-cache-test-"));
  t.after(() => {
    const absolute = resolve(root);
    if (dirname(absolute).toLowerCase() !== resolve(tmpdir()).toLowerCase() || !basename(absolute).startsWith("jms233-artifact-cache-test-")) throw new Error("Unowned test directory");
    rmSync(absolute, { recursive: true, force: true });
  });
  return root;
}
test("artifact staging copies bounded public artifacts and excludes credentials and partial downloads", (t) => {
  const root = temporaryFixture(t);
  const source = join(root, "source"), target = join(root, "target"), hash = "a".repeat(64);
  mkdirSync(join(source, hash), { recursive: true });
  writeFileSync(join(source, "vault.key"), "must not copy");
  writeFileSync(join(source, hash, "artifact"), "public artifact");
  writeFileSync(join(source, hash, "executable"), "verified binary");
  writeFileSync(join(source, hash, "download-partial.tmp"), "partial");
  assert.equal(stagePluginArtifacts(source, target), 2);
  assert.equal(readFileSync(join(target, hash, "artifact"), "utf8"), "public artifact");
  assert.equal(existsSync(join(target, "vault.key")), false);
  assert.equal(existsSync(join(target, hash, "download-partial.tmp")), false);
  assert.equal(stagePluginArtifacts(join(root, "missing"), target), 0);
});
test("artifact staging rejects an invalid root and oversized files", (t) => {
  const root = temporaryFixture(t);
  const source = join(root, "source"), target = join(root, "target");
  writeFileSync(source, "invalid root");
  assert.throws(() => stagePluginArtifacts(source, target));
  const dir = join(root, "large", "b".repeat(64)); mkdirSync(dir, { recursive: true });
  const fd = openSync(join(dir, "artifact"), "w"); ftruncateSync(fd, 64 * 1024 * 1024 + 1); closeSync(fd);
  assert.throws(() => stagePluginArtifacts(join(root, "large"), target), /size exceeded/);
});
