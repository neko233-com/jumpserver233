import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const base = process.env.JMS_DESKTOP_QA_BASE_URL || "http://127.0.0.1:8083";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Desktop QA requires loopback isolation");
test.use({ locale: "en-US" });
test("RDP live monitoring has independent authority, no input or clipboard, CLI capture and durable bilingual activity", async ({
  page,
  browser,
}, info) => {
  test.setTimeout(150000);
  const api = await request.newContext({ baseURL: base });
  const reviewerContext = await browser.newContext({ locale: "en-US" });
  const reviewer = await reviewerContext.newPage();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  reviewer.on("pageerror", (e) => errors.push(e.message));
  let sessionID = "";
  const stamp = Date.now(),
    name = `Live desktop ${stamp}`;
  const account = { username: `desktop.viewer.${stamp}`, password: "synthetic-desktop-viewer-233" };
  try {
    const admin = {
      username: process.env.JMS_DESKTOP_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_DESKTOP_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let auth = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!auth.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: admin });
      auth = await api.post("/api/v1/authentication/auth/", { data: admin });
    }
    expect(auth.ok()).toBe(true);
    await page.context().addCookies((await api.storageState()).cookies);
    const fixture = (await (
      await api.get(process.env.JMS_DESKTOP_QA_FIXTURE_URL || "http://127.0.0.1:19392/health")
    ).json()) as { address: string; server_name: string; root_ca_pem: string };
    const createdAsset = await api.post("/api/v1/assets", {
      data: {
        name,
        protocol: "rdp",
        host: process.env.JMS_DESKTOP_QA_RDP_HOST || "127.0.0.1",
        port: Number(fixture.address.split(":").at(-1)),
        username: "rdpqa",
        password: "synthetic-rdp-password-233",
        rdp: {
          security: "tls",
          server_name: fixture.server_name,
          root_ca_pem: fixture.root_ca_pem,
          clipboard: true,
        },
      },
    });
    expect(createdAsset.status()).toBe(201);
    const asset = await createdAsset.json();
    await page.goto("/console");
    const opening = page.waitForResponse(
      (r) =>
        r.url().includes(`/assets/${asset.id}/rdp/sessions`) && r.request().method() === "POST",
    );
    await page
      .getByRole("row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    sessionID = (await (await opening).json()).session_id;
    const primary = page.getByRole("dialog"),
      ownerScreen = primary.getByLabel("Remote RDP desktop", { exact: true });
    await expect(primary.getByRole("status")).toHaveText("Connected");
    const userResponse = await api.post("/api/v1/users", {
      data: { ...account, role: "operator" },
    });
    expect(userResponse.status()).toBe(201);
    const user = await userResponse.json();
    const login = await reviewer.request.post(base + "/api/v1/authentication/auth/", {
      data: account,
    });
    expect(login.ok()).toBe(true);
    const viewerToken = (await login.json()).access_token;
    const headers = { Authorization: `Bearer ${viewerToken}` };
    const monitorPath = `/api/v1/desktop-sessions/${sessionID}/monitor`;
    expect((await api.post(monitorPath, { headers })).status()).toBe(404);
    const roleA = await api.post("/api/v1/system/rbac/roles", {
      data: {
        name: `history reviewer ${stamp}`,
        permissions: [
          "audit.sessions.view_all",
          "audit.replays.view_all",
          "audit.sessions.monitor_all",
        ],
      },
    });
    expect(roleA.status()).toBe(201);
    const historyRole = await roleA.json();
    let binding = await (
      await api.put("/api/v1/system/rbac/bindings", {
        data: { subject_type: "user", subject_id: user.id, role_ids: [historyRole.id] },
      })
    ).json();
    expect((await api.post(monitorPath, { headers })).status()).toBe(404);
    expect(
      (await api.get(`/api/v1/desktop-sessions/${sessionID}/frames/0`, { headers })).status(),
    ).toBe(404);
    const roleB = await api.post("/api/v1/system/rbac/roles", {
      data: { name: `desktop reviewer ${stamp}`, permissions: ["audit.desktops.monitor_all"] },
    });
    expect(roleB.status()).toBe(201);
    const desktopRole = await roleB.json();
    const bound = await api.put("/api/v1/system/rbac/bindings", {
      data: {
        subject_type: "user",
        subject_id: user.id,
        role_ids: [historyRole.id, desktopRole.id],
        revision: binding.revision,
      },
    });
    expect(bound.ok()).toBe(true);
    binding = await bound.json();
    expect((await api.post(`/api/v1/assets/${asset.id}/rdp/sessions`, { headers })).status()).toBe(
      403,
    );
    const stateURL = (
      process.env.JMS_DESKTOP_QA_FIXTURE_URL || "http://127.0.0.1:19392/health"
    ).replace(/\/health$/, "/state");
    const before = await (await api.get(stateURL)).json();
    const raw = await api.post(monitorPath, { headers });
    expect(raw.status()).toBe(201);
    const ticket = await raw.json();
    expect(ticket.websocket_url).not.toContain(ticket.ticket);
    await new Promise<void>((resolve, reject) => {
      let opened = false;
      const ws = new WebSocket(base.replace("http:", "ws:") + ticket.websocket_url, [
        "jms233-desktop-monitor-v1",
        `jms233-desktop-monitor-ticket.${ticket.ticket}`,
      ]);
      const timer = setTimeout(() => {
        ws.close();
        reject(Error("Readonly injection did not disconnect"));
      }, 10000);
      ws.onopen = () => {
        opened = true;
        ws.send(
          JSON.stringify({
            type: "pointer",
            action: "button",
            button: "left",
            down: true,
            x: 100,
            y: 175,
          }),
        );
        ws.send(
          JSON.stringify({
            type: "pointer",
            action: "button",
            button: "left",
            down: false,
            x: 100,
            y: 175,
          }),
        );
      };
      ws.onclose = () => {
        clearTimeout(timer);
        if (opened) resolve();
        else reject(Error("Monitor handshake failed"));
      };
      ws.onerror = () => {
        if (opened) return;
        clearTimeout(timer);
        reject(Error("Monitor attachment failed"));
      };
    });
    expect((await (await api.get(stateURL)).json()).clicks).toBe(before.clicks);
    await reviewer.goto("/audit");
    await reviewer.getByText("RDP desktop audit", { exact: true }).first().click();
    const row = reviewer.getByRole("row").filter({ hasText: name });
    await expect(row.getByRole("button", { name: "Replay", exact: true })).toHaveCount(0);
    await row.getByRole("button", { name: "Monitor live", exact: true }).click();
    const view = reviewer.getByRole("dialog");
    await expect(view.getByRole("status")).toHaveText("Connected");
    await expect(view.getByLabel("Session clipboard text", { exact: true })).toHaveCount(0);
    await expect(view.getByLabel("Text to type remotely", { exact: true })).toHaveCount(0);
    const screen = view.getByRole("img", { name: "Live RDP monitor image", exact: true });
    const initial = await screen.evaluate((c) => (c as HTMLCanvasElement).toDataURL());
    const rect = await ownerScreen.boundingBox();
    expect(rect).not.toBeNull();
    await ownerScreen.click({
      position: { x: (100 * rect!.width) / 1280, y: (175 * rect!.height) / 720 },
    });
    await expect
      .poll(async () => (await (await api.get(stateURL)).json()).clicks)
      .toBeGreaterThan(before.clicks);
    await expect
      .poll(async () => screen.evaluate((c) => (c as HTMLCanvasElement).toDataURL()))
      .not.toBe(initial);
    const current = await (await api.get(stateURL)).json();
    await screen.click();
    await expect
      .poll(async () => (await (await api.get(stateURL)).json()).clicks)
      .toBe(current.clicks);
    await reviewer.screenshot({ path: info.outputPath("desktop-monitor.en.png") });
    const starts = async () =>
      (
        (await (await api.get(`/api/v1/desktop-sessions/${sessionID}/monitor-events`)).json())
          .results as { event: string }[]
      ).filter((e) => e.event === "monitor_started").length;
    const started = await starts();
    await view.getByRole("button", { name: "中文", exact: true }).click();
    await expect(view.getByRole("status")).toHaveText("已连接");
    expect(await starts()).toBe(started);
    await reviewer.setViewportSize({ width: 390, height: 844 });
    expect(
      await reviewer.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1),
    ).toBe(true);
    await reviewer.screenshot({ path: info.outputPath("desktop-monitor.mobile.zh-CN.png") });
    const capture = info.outputPath("desktop-monitor-cli.png");
    const cli = await execute(
      "go",
      ["run", "./cmd/jms", "rdp", "monitor", sessionID, "--capture", capture, "--wait", "1"],
      {
        cwd: fileURLToPath(new URL("../../server", import.meta.url)),
        timeout: 45000,
        env: {
          ...process.env,
          JMS_SERVER_URL: base,
          JMS_TOKEN: viewerToken,
          JMS_ORG_ID: "",
          JMS_ACCESS_KEY_ID: "",
          JMS_ACCESS_KEY_SECRET: "",
        },
      },
    );
    expect(JSON.parse(cli.stdout).monitor).toBe(true);
    expect((await readFile(capture)).subarray(0, 8)).toEqual(
      Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    );
    expect(cli.stdout + cli.stderr).not.toContain("synthetic-rdp-password-233");
    expect((await (await api.get(`/api/v1/desktop-sessions/${sessionID}`)).json()).status).toBe(
      "active",
    );
    const revoked = await api.put("/api/v1/system/rbac/bindings", {
      data: {
        subject_type: "user",
        subject_id: user.id,
        role_ids: [historyRole.id],
        revision: binding.revision,
      },
    });
    expect(revoked.ok()).toBe(true);
    await expect(view.getByRole("status")).toHaveText("会话已结束");
    expect((await api.post(monitorPath, { headers })).status()).toBe(404);
    await expect(primary.getByRole("status")).toHaveText("Connected");
    await view.getByRole("button", { name: "关闭监看", exact: true }).click();
    await primary.getByRole("button", { name: "Close terminal", exact: true }).click();
    await page.goto("/audit");
    await page.getByText("RDP desktop audit", { exact: true }).first().click();
    await page
      .getByRole("row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Desktop viewing activity", exact: true })
      .click();
    await expect(page.getByRole("dialog")).toContainText(account.username);
    await expect(page.getByRole("dialog")).toContainText("Viewing ended");
    expect(errors).toEqual([]);
  } finally {
    await reviewerContext.close().catch(() => {});
    if (sessionID) await api.delete(`/api/v1/desktop-sessions/${sessionID}`);
    await api.dispose();
  }
});
