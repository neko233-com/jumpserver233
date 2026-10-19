import { test, expect, request, type Page } from "@playwright/test";
import { mkdir, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

test.use({ locale: "en-US" });
type Status = { instance: string; revision: number; draining: boolean; ready: boolean; activity: Record<string, number> };
const endpoint = "/api/v1/settings/security/maintenance";

test("standalone drain preserves real OpenSSH, blocks new work and supports bilingual cancellation", async ({ page }, info) => {
  test.setTimeout(120_000);
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  const errors: string[] = [];
  const consoleMessages: { level: string; code: string; source: string }[] = [];
  const watchConsole = (target: Page) => target.on("console", message => {
    if (message.type() !== "error" && message.type() !== "warning") return;
    let source = ""; try { source = new URL(message.location().url).pathname; } catch {}
    const text = message.text();
    const expectedLocale = /503 \(Service Unavailable\)/.test(text) && /^\/api\/v1\/(?:platform-)?notifications\/locale$/.test(source);
    const expectedGL = /^\[\.WebGL-/.test(text) && /GPU stall due to ReadPixels/.test(text);
    consoleMessages.push({ level: message.type(), code: expectedLocale ? "drain_blocks_locale_write" : expectedGL ? "headless_readback" : "unexpected", source });
  });
  watchConsole(page);
  page.on("pageerror", e => errors.push(e.message));
  let asset = "";
  // The additional page keeps the live terminal attached while settings change.
  const control = await page.context().newPage();
  watchConsole(control);
  control.on("pageerror", e => errors.push(e.message));
  try {
    const admin = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
    let login = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!login.ok()) { await api.post("/api/v1/authentication/bootstrap", { data: admin }); login = await api.post("/api/v1/authentication/auth/", { data: admin }); }
    expect(login.ok()).toBe(true); const token = ((await login.json()) as { access_token: string }).access_token;
    await page.context().addCookies((await api.storageState()).cookies);
    const host = await (await api.get("http://127.0.0.1:12242/health")).json() as { fingerprint: string };
    const name = `Drain SSH ${Date.now()}`;
    const created = await api.post("/api/v1/assets", { data: { name, host: "127.0.0.1", port: 12241, username: "pluginqa", password: "synthetic-keyhost-password-233", host_key_fingerprint: host.fingerprint } });
    expect(created.status()).toBe(201); asset = ((await created.json()) as { id: string }).id;
    await page.goto("/console");
    await Promise.all([
      page.waitForResponse(r => r.url().endsWith("/api/v1/sessions") && r.request().method() === "POST"),
      page.getByRole("row").filter({ hasText: name }).getByRole("button", { name: "Connect", exact: true }).click(),
    ]);
    const terminal = page.getByRole("dialog");
    await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
    const original = await (await api.get(endpoint)).json() as Status;
    const input = { instance: original.instance, revision: original.revision, request_id: crypto.randomUUID(), draining: true };
    expect((await api.put(endpoint, { data: input })).ok()).toBe(true);
    const active = await (await api.get(endpoint)).json() as Status;
    expect(active.draining).toBe(true); expect(active.ready).toBe(false); expect(active.activity.terminal_sessions).toBeGreaterThan(0);
    expect(((await (await api.put(endpoint, { data: input })).json()) as { replayed: boolean }).replayed).toBe(true);
    expect((await api.put(endpoint, { data: { ...input, request_id: crypto.randomUUID() } })).status()).toBe(409);
    expect((await api.post("/api/v1/sessions", { data: { asset_id: asset, cols: 80, rows: 24 } })).status()).toBe(503);
    expect((await api.post("/api/v1/ops/jobs", { data: { asset_id: asset, command: "false" } })).status()).toBe(503);
    await terminal.getByRole("textbox", { name: "Terminal input", exact: true }).pressSequentially("printf 'drain_%s\\n' 'continued'");
    await terminal.getByRole("textbox", { name: "Terminal input", exact: true }).press("Enter");
    await expect(terminal.locator(".xterm-rows")).toContainText("drain_continued");
    await control.goto("/console/settings");
    await expect(control).toHaveURL(/\/console\/settings$/);
    await expect(control).toHaveTitle(/jumpserver233/i);
    await expect(control.locator("vite-error-overlay")).toHaveCount(0);
    await control.getByRole("tab", { name: "Security", exact: true }).click();
    const panel = control.locator(".service-maintenance");
    await expect(panel.getByRole("button", { name: "Cancel draining", exact: true })).toBeVisible();
    await panel.screenshot({ path: info.outputPath("maintenance.en.png") });
    const cli = await promisify(execFile)("go", ["run", "./cmd/jms", "update", "drain-status"], { cwd: resolve(fileURLToPath(new URL(".", import.meta.url)), "../../server"), env: { ...process.env, JMS_SERVER_URL: "http://127.0.0.1:8083", JMS_TOKEN: token }, timeout: 60_000 });
    expect((JSON.parse(cli.stdout) as Status).instance).toBe(active.instance);
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    await expect.poll(async () => ((await (await api.get(endpoint)).json()) as Status).ready, { timeout: 30_000 }).toBe(true);
    await control.getByRole("button", { name: "中文", exact: true }).click();
    await expect(panel.getByRole("status")).toContainText("已跟踪的活动工作已排空");
    await control.setViewportSize({ width: 390, height: 844 });
    expect(await control.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
    await panel.screenshot({ path: info.outputPath("maintenance.zh-CN.png") });
    await panel.getByRole("button", { name: "取消排空", exact: true }).click();
    await expect(panel.getByRole("status")).toHaveText("正在接受新操作。");
    expect(errors).toEqual([]);
    expect(consoleMessages.filter(message => message.code === "unexpected")).toEqual([]);
  } finally {
    const consoleFile = info.outputPath("maintenance-console.json");
    await mkdir(dirname(consoleFile), { recursive: true });
    await writeFile(consoleFile, JSON.stringify({ messages: consoleMessages, pageErrors: errors.length }, null, 2), { mode: 0o600 });
    const value = await (await api.get(endpoint)).json() as Status;
    if (value.draining) expect((await api.put(endpoint, { data: { instance: value.instance, revision: value.revision, request_id: crypto.randomUUID(), draining: false } })).ok()).toBe(true);
    if (asset) expect((await api.delete(`/api/v1/assets/${asset}`)).ok()).toBe(true);
    await control.close(); await api.dispose();
  }
});
