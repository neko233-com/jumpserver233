import { test, expect, request } from "@playwright/test";

// Optional overrides let the same flow run against the dedicated Docker QA
// namespace without starting unrelated protocol fixtures.
const base = process.env.JMS_LIVE_QA_BASE_URL || "http://127.0.0.1:8083";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base)) throw new Error("Live QA requires a loopback test instance");
const admin = {
  username: process.env.JMS_LIVE_QA_USERNAME || "e2e.admin",
  password: process.env.JMS_LIVE_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
};

test.use({ locale: "en-US" });
test("read-only live monitor preserves primary SSH, bilingual UI and mobile view", async ({ page }, info) => {
  test.setTimeout(60_000);
  const api = await request.newContext({ baseURL: base });
  const errors: string[] = [];
  page.on("pageerror", e => errors.push(e.message));
  try {
    let login = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: admin });
      login = await api.post("/api/v1/authentication/auth/", { data: admin });
    }
    expect(login.ok()).toBe(true);
    const cookies = (await api.storageState()).cookies;
    await page.context().addCookies(cookies);
    const fixture = await (await api.get(process.env.JMS_LIVE_QA_FIXTURE_URL || "http://127.0.0.1:12223/health")).json();
    const name = `Live monitor QA ${Date.now()}`;
    const created = await api.post("/api/v1/assets", { data: {
      name, host: process.env.JMS_LIVE_QA_SSH_HOST || "127.0.0.1", port: Number(fixture.address.split(":").at(-1)),
      username: fixture.username, password: "synthetic-qa-only-password", host_key_fingerprint: fixture.fingerprint,
    } });
    expect(created.status()).toBe(201);
    await page.goto("/console");
    const row = page.getByRole("row").filter({ hasText: name });
    await row.getByRole("button", { name: "Connect", exact: true }).click();
    const primary = page.getByRole("dialog");
    await expect(primary.locator(".ssh-terminal-status")).toHaveText("Connected");
    const observer = await page.context().newPage();
    observer.on("pageerror", e => errors.push(e.message));
    let received = "";
    const sent: string[] = [];
    observer.on("websocket", socket => {
      if (!socket.url().includes("/monitor")) return;
      socket.on("framereceived", frame => { received += Buffer.isBuffer(frame.payload) ? frame.payload.toString("utf8") : frame.payload; });
      socket.on("framesent", frame => sent.push(String(frame.payload)));
    });
    await observer.goto("/audit");
    const live = observer.getByRole("row").filter({ hasText: name });
    await live.getByRole("button", { name: "Monitor live", exact: true }).click();
    const monitor = observer.getByRole("dialog");
    await expect(monitor.getByRole("status")).toHaveText("Connected");
    await expect(monitor).toContainText("Read only.");
    await primary.locator(".xterm-helper-textarea").pressSequentially("monitor-visible-proof");
    await expect.poll(() => received).toContain("monitor-visible-proof");
    await monitor.locator(".xterm-helper-textarea").pressSequentially("must-not-send");
    expect(sent).toEqual([]);
    await observer.screenshot({ path: info.outputPath("live-monitor.en.png") });
    await monitor.getByRole("button", { name: "Close terminal", exact: true }).click();
    await expect(primary.locator(".ssh-terminal-status")).toHaveText("Connected");
    await primary.locator(".xterm-helper-textarea").pressSequentially("primary-still-connected");
    await observer.getByRole("button", { name: "中文", exact: true }).click();
    await live.getByRole("button", { name: "实时监看", exact: true }).click();
    await expect(monitor.getByRole("status")).toHaveText("已连接");
    await expect(monitor).toContainText("只读显示连接后的新增输出");
    await primary.locator(".xterm-helper-textarea").pressSequentially("中文监看输出");
    await expect.poll(() => received).toContain("中文监看输出");
    await observer.screenshot({ path: info.outputPath("live-monitor.zh-CN.png") });
    await observer.setViewportSize({ width: 390, height: 844 });
    await expect(monitor.getByRole("button", { name: "关闭终端", exact: true })).toBeVisible();
    await observer.screenshot({ path: info.outputPath("live-monitor.mobile.png") });
    await monitor.getByRole("button", { name: "关闭终端", exact: true }).click();
    await observer.close();
    await primary.getByRole("button", { name: /^(Close terminal|关闭终端)$/ }).click();
    expect(errors).toEqual([]);
  } finally { await api.dispose(); }
});
