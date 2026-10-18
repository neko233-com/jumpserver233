import { existsSync, readFileSync } from "node:fs";

export function fixtureDiagnostic(text) {
  return String(text).replace(/\x1b\[[0-9;]*m/g, "").split(/\r?\n/).slice(-20)
    .map(line => /password|secret|token|authorization|bearer\s|credential/i.test(line) ? "[sensitive startup diagnostic omitted]" : line)
    .join("\n").slice(-2400);
}

export async function waitCIHealth({ engine, url, pidPath, logPath, attempts = 300, request = fetch, pause = ms => new Promise(r => setTimeout(r, ms)), alive = pid => { try { process.kill(pid, 0); return true; } catch (e) { if (e.code === "ESRCH") return false; throw e; } } }) {
  const diagnostic = () => logPath && existsSync(logPath) ? fixtureDiagnostic(readFileSync(logPath, "utf8")) : "No startup log available";
  for (let i = 0; i < attempts; i++) {
    if (pidPath && existsSync(pidPath)) {
      const pid = Number(readFileSync(pidPath, "utf8").trim());
      if (!Number.isSafeInteger(pid) || pid <= 1) throw new Error(`Invalid ${engine} fixture PID`);
      if (!alive(pid)) throw new Error(`${engine} fixture process exited before readiness\n${diagnostic()}`);
    }
    try { const response = await request(url, { signal: AbortSignal.timeout(1500) }); await response.body?.cancel(); if (response.ok) return; } catch { /* Retry observation while the owned process remains live. */ }
    if (i + 1 < attempts) await pause(1000);
  }
  throw new Error(`${engine} fixture readiness deadline\n${diagnostic()}`);
}
