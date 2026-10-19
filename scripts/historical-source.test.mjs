import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { historicalBaseline, verifyHistoricalManifests } from "./historical-source.mjs";
const head = "a".repeat(40);
function fixtures() {
  const manifest = (commit, version, digest) => ({ schema: 1, commit, version, platform: "linux", architecture: "amd64", preflight_protocol: 1, activation_protocol: 1, files: Object.fromEntries(["jms", "jms233-server", "web/index.html"].map(n => [n, { sha256: digest.repeat(64) }])) });
  return [manifest(historicalBaseline, "v0.0.0", "1"), manifest(head, "v0.0.1", "2")];
}
test("historical evidence pins distinct sources and server bytes without claiming a release", () => {
  const evidence = verifyHistoricalManifests(...fixtures(), head);
  assert.equal(evidence.sourceCommit, historicalBaseline);
  assert.equal(evidence.targetCommit, head);
  assert.equal(evidence.differentServerBytes, true);
  assert.equal(evidence.officialRelease, false);
});
test("source identity, compatibility, files and server byte mismatches refuse historical evidence", () => {
  for (const change of [
    (a, b) => { a.commit = head; },
    (a, b) => { b.commit = historicalBaseline; },
    (a, b) => { b.files["jms233-server"].sha256 = a.files["jms233-server"].sha256; },
    a => { a.activation_protocol = 0; },
    a => { a.preflight_protocol = 0; },
    a => { a.architecture = "arm64"; },
    a => { a.platform = "windows"; },
    a => { delete a.files.jms; },
    a => { a.version = "dev"; },
    (a, b) => { b.version = "v0.0.0"; },
  ]) {
    const pair = fixtures(); change(...pair);
    assert.throws(() => verifyHistoricalManifests(...pair, head));
  }
  assert.throws(() => verifyHistoricalManifests(...fixtures(), historicalBaseline));
});
test("post-upgrade scheduled and automatic checks use the independent current controller", () => {
  for (const name of ["scheduled-install-qa.mjs", "automatic-install-qa.mjs"]) {
    const code = readFileSync(new URL(name, import.meta.url), "utf8");
    assert.ok(code.includes("/tmp/controller/jms"), name);
    assert.ok(!code.includes("/tmp/native/jms"), `${name} must not invoke the old baseline CLI`);
  }
});
