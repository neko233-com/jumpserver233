// Called by the owned native package runner. No deployment or Release is made.
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { randomUUID } from "node:crypto";
import { classifyNativeBrowserLog } from "./native-browser-logs.mjs";

export async function verifyScheduledInstallation({ run, owner, url, root, output, api, admin, operator, refreshOperator, sshHost, fingerprint, candidate, failedCandidate, stopSelected, waitHealthy, chromium, expect, report }) {
  const endpoint = "/api/v1/settings/security/updates/installation", maintenance = "/api/v1/settings/security/maintenance";
  report.scheduledInstallationStep = "startup";
  const local = args => run("docker", ["exec", owner, "/tmp/controller/jms", ...args]);
  const supervise = () => run("docker", ["exec", "--detach", owner, "sh", "-ceu", 'echo $$ >/tmp/launcher.pid; JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 exec /tmp/controller/jms update supervise --root /tmp/releases --passphrase-file /tmp/checkpoint-passphrase']);
  const status = async () => {
    try { return await api("GET", endpoint, undefined, admin); }
    catch (e) {
      if (!String(e.message).includes("API status 401")) throw e;
      // Standalone browser sessions are process-local. Reauthenticate the same
      // platform user after restart; never weaken server session semantics.
      admin = (await api("POST", "/api/v1/authentication/auth/", { username: "root", password: "root" })).access_token;
      return api("GET", endpoint, undefined, admin);
    }
  };
  const waitPlan = async phase => { for (let n = 0; n < 600; n++) { try { const value = await status(); if (value.plan?.phase === phase) return value; if (value.plan?.phase === "failed" && phase !== "failed") throw new Error("Scheduled installation failed: " + value.plan.error); } catch (e) { if (String(e.message).startsWith("Scheduled installation failed")) throw e; } await delay(100); } throw new Error("Scheduled installation phase timed out: " + phase); };
  const queue = async (target, seconds = 30) => { const s = await status(); const input = { revision: s.revision, installation_revision: s.installation_revision, archive_sha256: target.sha, request_id: randomUUID(), not_before: new Date(Date.now() + 750).toISOString(), drain_timeout_seconds: seconds }; return api("POST", endpoint, input, admin); };
  const waitOpen = async () => { for (let n = 0; n < 80; n++) { if (!(await api("GET", maintenance, undefined, admin)).draining) return; await delay(100); } throw new Error("Admission did not reopen after cancellation"); };
  const command = async text => api("POST", "/api/v1/ops/jobs", { asset_id: asset.id, command: text, timeout_seconds: 30, request_id: randomUUID() }, admin, 201);
  const waitJob = async (id, text) => { for (let n = 0; n < 200; n++) { try { const v = await api("GET", "/api/v1/ops/jobs/" + id, undefined, admin); if (v.state === "succeeded" && v.stdout === text) return; if (["failed", "interrupted", "timed_out"].includes(v.state)) throw new Error("Scheduled SSH job was interrupted"); } catch (e) { if (String(e.message).includes("SSH job was interrupted")) throw e; } await delay(100); } throw new Error("Scheduled SSH result missing"); };
  const asset = await api("POST", "/api/v1/assets", { name: "Scheduled upgrade SSH", host: sshHost, port: 22, username: "keyqa", password: "synthetic-keyhost-password-233", host_key_fingerprint: fingerprint }, admin, 201);
  await api("GET", endpoint, undefined, operator, 403);
  await stopSelected(); await supervise(); await waitHealthy(report.recoveryVersion);
  await status(); operator = await refreshOperator();
  await Promise.all(Array.from({length:8},()=>status()));
  let duplicate = false;
  try { await run("docker", ["exec", owner, "sh", "-ceu", 'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 exec /tmp/controller/jms update supervise --root /tmp/releases --passphrase-file /tmp/checkpoint-passphrase']); } catch (e) { duplicate = String(e.stderr).includes("data directory is in use"); }
  if (!duplicate) throw new Error("Competing update supervisor was admitted");
  const browser = await chromium.launch({ headless: true });
  const errors = [], diagnostics = { anonymous_session_probe: 0, headless_gpu_readback: 0 };
  try {
    const context = await browser.newContext({ locale: "en-US", viewport: { width: 1280, height: 900 } });
    const page = await context.newPage(); let authenticated = false;
    page.on("pageerror", e => errors.push(e.message));
    page.on("console", m => { if (m.type() !== "error" && m.type() !== "warning") return; const kind = classifyNativeBrowserLog(m.type(), m.text(), m.location().url, url, authenticated); if (kind === "unexpected") errors.push(m.text()); else diagnostics[kind]++; });
    await page.goto(url + "/login"); await page.getByRole("textbox", { name: "Username", exact: true }).fill("root"); await page.getByRole("textbox", { name: "Password", exact: true }).fill("root");
    await Promise.all([page.waitForURL(url + "/console"), page.getByRole("button", { name: "Sign in", exact: true }).click()]); authenticated = true;
    await page.goto(url + "/console/settings"); await page.getByRole("tab", { name: "Security", exact: true }).click();
    await expect(page).toHaveTitle(/jumpserver233/i); await expect(page).toHaveURL(url + "/console/settings"); await expect(page.locator("vite-error-overlay")).toHaveCount(0);
    const panel = page.locator(".installation-schedule");
    await panel.locator("summary").filter({ hasText: "Schedule a staged version" }).click();
    await panel.getByRole("button", { name: "Refresh verified candidates", exact: true }).click();
    await panel.getByRole("combobox", { name: "Target version and digest", exact: true }).selectOption(candidate.sha);
    const at = new Date(Date.now() + 600_000); const localAt = new Date(at.getTime() - at.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
    await panel.getByLabel("Install after (local time)", { exact: true }).fill(localAt);
    const [created] = await Promise.all([page.waitForResponse(r => r.request().method() === "POST" && new URL(r.url()).pathname === endpoint), panel.getByRole("button", { name: "Schedule installation", exact: true }).click()]);
    if (created.status() !== 200) throw new Error("Browser could not schedule verified package");
    const original = created.request().postDataJSON();
    report.scheduledInstallationStep = "browser_schedule_replay";
    const first = await status(); await expect(panel.getByRole("status")).toContainText("Scheduled"); await expect(panel.getByRole("status")).toContainText(candidate.version);
    const repeated = await api("POST", endpoint, original, admin); if (repeated.plan.id !== first.plan.id || repeated.revision !== first.revision) throw new Error("Schedule replay mutated state");
    await api("POST", endpoint, { ...original, request_id: randomUUID() }, admin, 409);
    await api("POST", endpoint, original, operator, 403);
    await panel.screenshot({ path: resolve(output, "installation.en.png") });
    await panel.getByRole("button", { name: "Cancel installation", exact: true }).click(); await expect(panel.getByRole("status")).toContainText("Installation cancelled");
    report.scheduledInstallationStep = "browser_cancel_replay";
    const replayAfterCancel = await api("POST", endpoint, original, admin); if (replayAfterCancel.plan.phase !== "cancelled") throw new Error("Replayed schedule restarted cancelled plan");
    if (errors.length) throw new Error("Scheduled installation browser diagnostics before restart");
  } finally { await browser.close(); }
  // A real admitted SSH operation outlives the drain timeout; no kill/restart.
  report.scheduledInstallationStep = "timeout";
  const timeoutJob = await command("sleep 8; printf scheduled_timeout_continued"); await queue(candidate, 5); await waitPlan("draining");
  await api("POST", "/api/v1/sessions", { asset_id: asset.id, cols: 80, rows: 24 }, admin, 503);
  const timed = await waitPlan("failed"); if (timed.plan.error !== "drain_timeout") throw new Error("Drain wait did not time out safely"); await waitOpen(); await waitJob(timeoutJob.id, "scheduled_timeout_continued");
  const ticket = await api("POST", "/api/v1/sessions", { asset_id: asset.id, cols: 80, rows: 24 }, admin, 201);
  report.scheduledInstallationStep = "cancel_drain";
  await queue(candidate); const draining = await waitPlan("draining"); await api("POST", endpoint + "/cancel", { revision: draining.revision, request_id: randomUUID(), plan_id: draining.plan.id }, admin); await waitOpen(); await api("DELETE", "/api/v1/sessions/" + ticket.session_id, undefined, admin, 204);
  const persistedJob = await command("sleep 4; printf scheduled_upgrade_continued");
  report.scheduledInstallationStep = "cli_install";
  const before = await status(), installationBefore = JSON.parse((await local(["update", "install-status", "--root", "/tmp/releases"])).stdout);
  const cli = ["update", "schedule", "--root", "/tmp/releases", "--sha256", candidate.sha, "--revision", String(before.revision), "--installation-revision", String(before.installation_revision), "--request-id", "native-scheduled-install", "--at", new Date(Date.now() + 750).toISOString(), "--drain-timeout", "30s"];
  await local(cli); await waitHealthy(candidate.version); const accepted = await waitPlan("succeeded"); await waitJob(persistedJob.id, "scheduled_upgrade_continued");
  report.scheduledInstallationStep = "accepted";
  const installationAfter = JSON.parse((await local(["update", "install-status", "--root", "/tmp/releases"])).stdout);
  if (installationAfter.revision !== installationBefore.revision + 1 || installationAfter.current.archive_sha256 !== candidate.sha || installationAfter.pending_upgrade) throw new Error("Scheduled candidate activation not committed once");
  await local(cli); if ((await status()).plan.id !== accepted.plan.id) throw new Error("CLI replay repeated completed install");
  await stopSelected(); await supervise(); await waitHealthy(candidate.version); if ((await status()).plan.phase !== "succeeded") throw new Error("Supervisor restart replayed completed plan");
  report.scheduledInstallationStep = "startup_rollback";
  // Candidate trial failure must restore the old service and its current data.
  await queue(failedCandidate); const failed = await waitPlan("failed"); if (failed.plan.error !== "activation_rolled_back") throw new Error("Scheduled first-start failure did not report rollback"); await waitHealthy(candidate.version); await waitJob(persistedJob.id, "scheduled_upgrade_continued");
  const endBrowser = await chromium.launch({ headless: true });
  try {
    const context = await endBrowser.newContext({ locale: "zh-CN", viewport: { width: 390, height: 844 } }); const page = await context.newPage();
    page.on("pageerror", e => errors.push(e.message)); let authenticated = false;
    page.on("console", m => { if (m.type() !== "error" && m.type() !== "warning") return; const kind = classifyNativeBrowserLog(m.type(), m.text(), m.location().url, url, authenticated); if (kind === "unexpected") errors.push(m.text()); else diagnostics[kind]++; });
    await page.goto(url + "/login"); await page.getByRole("textbox", { name: "用户名", exact: true }).fill("root"); await page.getByRole("textbox", { name: "密码", exact: true }).fill("root"); await Promise.all([page.waitForURL(url + "/console"), page.getByRole("button", { name: "登录", exact: true }).click()]); authenticated = true;
    await page.goto(url + "/console/settings"); await page.getByRole("tab", { name: "安全策略", exact: true }).click();
    const panel = page.locator(".installation-schedule"); await expect(panel.getByRole("status")).toContainText("候选在放行前启动失败");
    if (!await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)) throw new Error("Installation card overflows 390px"); await panel.screenshot({ path: resolve(output, "installation.zh.png") });
  } finally { await endBrowser.close(); }
  if (errors.length) throw new Error("Scheduled installation page errors");
  report.scheduledInstallation = { loopback: true, authorizedWebSchedule: true, nonAdminDenied: true, digestAndRevisionBinding: true, idempotentReplayAfterCancellationAndSuccess: true, duplicateSupervisorRefused: true, timeoutRetainsRealSSH: true, pendingSessionCancellation: true, actualStopAndRestart: true, encryptedCheckpoint: true, trialGatingAndAcceptance: true, persistedRealSSHResult: true, restartDoesNotReinstall: true, startupFailureRestoresService: true, languages: ["en", "zh-CN"], mobileWidth: 390, pageErrors: errors.length, expectedBrowserDiagnostics: diagnostics };
}
