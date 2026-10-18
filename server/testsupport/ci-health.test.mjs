import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { waitCIHealth, fixtureDiagnostic } from "./ci-health.mjs";
import { removeOwnedTree } from "../../scripts/qa-lifecycle.mjs";

test("CI readiness retries observations without restarting a live fixture", async () => { let requests = 0, waits = 0; await waitCIHealth({ engine: "test", url: "http://127.0.0.1:1/health", attempts: 3, request: async () => { if (++requests === 1) throw Error("timeout"); return { ok: requests === 3 }; }, pause: async () => { waits++; } }); assert.equal(requests, 3); assert.equal(waits, 2); });
test("CI readiness fails early for an exited owned PID and redacts logs", async () => { const root = mkdtempSync(resolve(tmpdir(), "jms-ci-health-")); try { const pidPath = resolve(root, "fixture.pid"), logPath = resolve(root, "fixture.log"); writeFileSync(pidPath, "12345"); writeFileSync(logPath, "Image preparation: unexpected EOF\npassword=must-not-print\nBearer hidden\n"); await assert.rejects(waitCIHealth({ engine: "kubernetes", pidPath, logPath, alive: () => false, request: async () => { throw Error("must not request"); } }), e => e.message.includes("exited") && e.message.includes("EOF") && !e.message.includes("must-not-print") && !e.message.includes("Bearer hidden")); } finally { removeOwnedTree(root, tmpdir(), "jms-ci-health-"); } });
test("CI readiness deadlines are bounded and PID records are validated", async () => { let n = 0; await assert.rejects(waitCIHealth({ engine: "test", attempts: 2, request: async () => { n++; return { ok: false }; }, pause: async () => {} }), /deadline/); assert.equal(n, 2); const root = mkdtempSync(resolve(tmpdir(), "jms-ci-health-")); try { const pidPath = resolve(root, "fixture.pid"); writeFileSync(pidPath, "0"); await assert.rejects(waitCIHealth({ engine: "test", pidPath }), /Invalid/); } finally { removeOwnedTree(root, tmpdir(), "jms-ci-health-"); } });
test("fixture diagnostics remain bounded and redact credential lines", () => { const out = fixtureDiagnostic("x".repeat(4000) + "\nsecret=hidden\nnode failed"); assert.ok(out.length <= 2400); assert.ok(!out.includes("hidden")); assert.match(out, /node failed/); });
