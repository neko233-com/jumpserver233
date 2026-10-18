import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fixtureDiagnostic } from "../../server/testsupport/ci-health.mjs";

// Keep a compact result, not request/response bodies or authentication traces.
export default class QAReporter {
  tests = [];
  onTestEnd(test, result) {
    this.tests.push({ title: test.titlePath().join(" > "), status: result.status, expected: test.expectedStatus, retry: result.retry, durationMs: result.duration, errors: result.errors.map(e => fixtureDiagnostic(e.message || "Test failed")) });
  }
  onEnd(result) {
    const output = process.env.JMS_E2E_REPORT_DIR;
    if (!output) return;
    mkdirSync(output, { recursive: true });
    writeFileSync(resolve(output, "summary.json"), JSON.stringify({ at: new Date().toISOString(), status: result.status, durationMs: result.duration, tests: this.tests }, null, 2));
  }
}
