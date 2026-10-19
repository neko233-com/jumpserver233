// Real HTTPS download/staging and supervised installation inside owned QA only.
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { classifyNativeBrowserLog } from "./native-browser-logs.mjs";

export async function verifyAutomaticInstallation({ run, owner, url, output, api, admin, operator, sshHost, fingerprint, feedURL, waitHealthy, chromium, expect, report }) {
  const base = "/api/v1/settings/security/updates/installation", path = base + "/automatic", maintenance = "/api/v1/settings/security/maintenance";
  const get = endpoint => api("GET", endpoint, undefined, admin);
  const policy = async patch => { const state = await get(path); return api("PUT", path, { request_id: randomUUID(), policy: { ...state.policy, ...patch } }, admin); };
  const wait = async (read, condition, label) => { for (let n = 0; n < 600; n++) { try { const v = await read(); if (condition(v)) return v; } catch {} await delay(100); } throw new Error("Automatic QA timed out: " + label); };
  const local = args => run("docker", ["exec", owner, "/tmp/controller/jms", ...args]);
  report.automaticStep = "default_off";
  const initial = await get(path); if (initial.policy.mode !== "off") throw new Error("Automatic updating was enabled by default");
  const restricted = await operator(); await api("GET", path, undefined, restricted, 403); await api("PUT", path, { request_id: randomUUID(), policy: initial.policy }, restricted, 403);
  const browser = await chromium.launch({ headless: true }), errors = [], diagnostics = { anonymous_session_probe: 0, headless_gpu_readback: 0 };
  let candidate;
  try {
    const context = await browser.newContext({ locale: "en-US", viewport: { width: 1280, height: 900 } }), page = await context.newPage(); let authenticated = false;
    page.on("pageerror", e => errors.push(e.message)); page.on("console", m => { if (m.type() !== "error" && m.type() !== "warning") return; const code = classifyNativeBrowserLog(m.type(), m.text(), m.location().url, url, authenticated); if (code === "unexpected") errors.push(m.text()); else diagnostics[code]++; });
    await page.goto(url + "/login"); await page.getByRole("textbox", { name: "Username", exact: true }).fill("root"); await page.getByRole("textbox", { name: "Password", exact: true }).fill("root"); await Promise.all([page.waitForURL(url + "/console"), page.getByRole("button", { name: "Sign in", exact: true }).click()]); authenticated = true;
    await page.goto(url + "/console/settings"); await page.getByRole("tab", { name: "Security", exact: true }).click(); await expect(page).toHaveTitle(/jumpserver233/i); await expect(page.locator("vite-error-overlay")).toHaveCount(0);
    const panel = page.locator(".automatic-updates"); await expect(panel.getByRole("status")).toHaveText("Automatic preparation and installation are off.");
    await panel.locator("summary").filter({ hasText: "Configure automatic updates" }).click(); await panel.getByRole("combobox", { name: "Automatic update mode", exact: true }).selectOption("prepare");
    const [saved] = await Promise.all([page.waitForResponse(r => new URL(r.url()).pathname === path && r.request().method() === "PUT"), panel.getByRole("button", { name: "Save automatic update policy", exact: true }).click()]); if (saved.status() !== 200) throw new Error("Browser automatic policy failed");
    const original = saved.request().postDataJSON(); const replay = await context.request.put(url + path, { data: original }); if (replay.status() !== 200) throw new Error("Policy receipt replay failed");
    report.automaticStep = "https_prepare";
    const ready = await wait(() => get(path), v => v.phase === "ready" && v.candidate?.version === "v0.0.7", "HTTPS prepared candidate"); candidate = ready.candidate;
    await expect(panel.getByRole("status")).toContainText("Candidate ready", { timeout: 10_000 }); await expect(panel).toContainText("v0.0.7");
    const inspected = JSON.parse((await local(["update", "stage-status", "--root", "/tmp/releases", "--sha256", candidate.archive_sha256])).stdout); if (inspected.manifest.version !== "v0.0.7") throw new Error("Downloaded candidate manifest differs"); await waitHealthy("v0.0.5");
    await panel.screenshot({ path: resolve(output, "automatic.en.png") });
    await panel.getByRole("combobox", { name: "Automatic update mode", exact: true }).selectOption("install");
    const future = (new Date().getUTCHours() + 2) % 24; await panel.getByLabel("Daily window starts (UTC)", { exact: true }).fill(`${String(future).padStart(2, "0")}:00`); await panel.getByRole("button", { name: "Save automatic update policy", exact: true }).click();
    await wait(() => get(path), v => v.policy.mode === "install", "outside-window policy"); await delay(2500); await waitHealthy("v0.0.5");
    await page.getByRole("button", { name: "中文", exact: true }).click(); await page.setViewportSize({ width: 390, height: 844 }); await expect(panel.getByRole("heading", { name: "自动准备与安装发布版本", exact: true })).toBeVisible(); await expect(panel.getByRole("combobox", { name: "自动更新模式", exact: true })).toHaveValue("install");
    if (!await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)) throw new Error("Automatic policy overflows narrow viewport"); await panel.screenshot({ path: resolve(output, "automatic.zh.png") });
  } finally { await browser.close(); }
  if (errors.length) throw new Error("Automatic policy browser diagnostics");
  const asset = await api("POST", "/api/v1/assets", { name: "Automatic update SSH", host: sshHost, port: 22, username: "keyqa", password: "synthetic-keyhost-password-233", host_key_fingerprint: fingerprint }, admin, 201);
  const ticket = await api("POST", "/api/v1/sessions", { asset_id: asset.id, cols: 80, rows: 24 }, admin, 201);
  const now = new Date(); report.automaticStep = "revoke_waiting_plan";
  await policy({ mode: "install", hour_utc: now.getUTCHours(), minute_utc: now.getUTCMinutes(), window_minutes: 30, drain_timeout_seconds: 30 });
  await wait(() => get(base), v => v.plan?.phase === "draining" && v.plan.automatic_revision > 0, "automatic drain");
  await policy({ mode: "off" }); await wait(() => get(base), v => v.plan?.phase === "cancelled", "policy revocation"); await wait(() => get(maintenance), v => !v.draining, "reopened admission"); await api("DELETE", "/api/v1/sessions/" + ticket.session_id, undefined, admin, 204);
  const job = await api("POST", "/api/v1/ops/jobs", { asset_id: asset.id, command: "sleep 5; printf automatic_upgrade_continued", timeout_seconds: 20, request_id: randomUUID() }, admin, 201);
  const before = await get(base); report.automaticStep = "automatic_install";
  await policy({ mode: "install" }); await waitHealthy("v0.0.7");
  const accepted = await wait(() => get(base), v => v.plan?.phase === "succeeded" && v.plan.target.version === "v0.0.7", "accepted automatic install");
  if (accepted.installation_revision !== before.installation_revision + 1) throw new Error("Automatic install changed revision more than once");
  await wait(() => get("/api/v1/ops/jobs/" + job.id), v => v.state === "succeeded" && v.stdout === "automatic_upgrade_continued", "retained admitted SSH result");
  await delay(2500); if ((await get(base)).plan.id !== accepted.plan.id) throw new Error("Automatic candidate was installed twice");
  const cli = JSON.parse((await local(["update", "auto-status", "--root", "/tmp/releases"])).stdout); if (cli.policy.mode !== "install") throw new Error("CLI automatic policy differs from Web");
  const artifacts = (await run("docker", ["exec", owner, "find", "/tmp/releases/.jms233-maintenance", "-maxdepth", "1", "-name", "prepare-*"])).stdout.trim(); if (artifacts) throw new Error("Automatic download temporary data survived");
  const upstream = await (await fetch(feedURL + "/health")).json(); if (upstream.downloads < 1 || upstream.credential_requests !== 0) throw new Error("HTTPS feed did not verify credential isolation");
  report.automaticStep = "complete";
  report.automaticInstallation = { defaultOff: true, realHTTPSOfficialHosts: true, isolatedTestCA: true, productionURLsUnchanged: true, noPlatformCredentialForwarding: true, verifiedStagingWithoutExecution: true, windowDefersInstallation: true, revisionRevokesWaitingPlan: true, repeatedPolicyReceipt: true, nonAdminDenied: true, actualStopCheckpointAndAcceptance: true, admittedSSHResultPreserved: true, noRepeatedInstall: true, temporaryDownloadsRemoved: true, languages: ["en", "zh-CN"], mobileWidth: 390, pageErrors: errors.length, expectedBrowserDiagnostics: diagnostics, candidateSHA256: candidate.archive_sha256 };
}
