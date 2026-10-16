import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const script = fileURLToPath(new URL("./docker-qa.mjs", import.meta.url));
for (const [name, args, message] of [
  ["unknown command", ["purge"], /Use up, verify or down/],
  ["foreign namespace", ["down", "--project", "unrelated"], /jms233- prefix/],
  ["external exposure", ["up", "--host", "0.0.0.0"], /dedicated loopback host/],
  ["external browser peer", ["up", "--peer-url", "https://example.com"], /different local loopback host/],
  ["existing debug namespace cannot become disposable", ["verify", "--project", "jms233-debug"], /fresh disposable project/],
  ["conflicting exposed ports", ["up", "--web-port", "18080", "--api-port", "18080"], /distinct ports/],
]) test(name, () => {
  const result = spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, message);
});
