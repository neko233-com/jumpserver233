import test from "node:test";
import assert from "node:assert/strict";
import { releaseFiles, uploadPlan } from "./publish-release.mjs";

const tag = "v1.2.3", file = { name: "native.tar.gz", bytes: 100, sha256: "a".repeat(64) };
const release = () => ({ tag_name: tag, draft: false, prerelease: false, published_at: "2026-10-19T00:00:00Z", html_url: `https://github.com/neko233-com/jumpserver233/releases/tag/${tag}`, assets: [] });
test("stable publication requires all six platform pairs and sidecars", () => {
  assert.equal(releaseFiles(tag).length, 12);
  for (const value of ["v1.2.3-rc.1", "1.2.3", "v01.2.3", "../v1.2.3"]) assert.throws(() => releaseFiles(value));
});
test("release upload retries are idempotent and never overwrite conflicting artifacts", () => {
  const value = release();
  assert.equal(uploadPlan(value, tag, [file])[0].action, "upload");
  value.assets = [{ name: file.name, size: file.bytes, digest: `sha256:${file.sha256}`, state: "uploaded" }];
  assert.equal(uploadPlan(value, tag, [file])[0].action, "unchanged");
  value.assets[0].digest = "sha256:" + "b".repeat(64);
  assert.throws(() => uploadPlan(value, tag, [file]), /overwrite refused/);
  for (const key of ["draft", "prerelease"]) { const r = release(); r[key] = true; assert.throws(() => uploadPlan(r, tag, [file])); }
});
