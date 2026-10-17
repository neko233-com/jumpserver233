import { test, expect, request } from "@playwright/test";

const base = process.env.JMS_LIVE_QA_BASE_URL || "http://127.0.0.1:8083";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw new Error("Session QA requires a loopback test instance");
const admin = {
  username: process.env.JMS_LIVE_QA_USERNAME || "e2e.admin",
  password: process.env.JMS_LIVE_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
};
const policyPath = "/api/v1/settings/security/sessions";
type Settings = { idle_minutes: number; max_hours: number; watermark: boolean; revision: number };
test.use({ locale: "en-US" });

test("session security saves audited settings and watermarks terminal replay and native RDP", async ({
  page,
}, info) => {
  test.setTimeout(90_000);
  const api = await request.newContext({ baseURL: base });
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  let original: Settings | null = null;
  try {
    let auth = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!auth.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: admin });
      auth = await api.post("/api/v1/authentication/auth/", { data: admin });
    }
    expect(auth.ok()).toBe(true);
    await page.context().addCookies((await api.storageState()).cookies);
    original = (await (await api.get(policyPath)).json()) as Settings;
    await page.goto("/console/settings");
    await page.getByRole("tab", { name: "Security", exact: true }).click();
    const card = page.locator("section.settings-card").filter({
      has: page.getByRole("heading", { name: "Resource session security", exact: true }),
    });
    await card.getByLabel("Maximum idle time (minutes)", { exact: true }).fill("15");
    await card.getByLabel("Maximum connection duration (hours)", { exact: true }).fill("4");
    await card.getByLabel("Session watermark", { exact: true }).check();
    await card.getByRole("button", { name: "Save session security", exact: true }).click();
    await expect(card.getByRole("status")).toHaveText("Session security saved.");
    const saved = (await (await api.get(policyPath)).json()) as Settings;
    expect(saved).toMatchObject({ idle_minutes: 15, max_hours: 4, watermark: true });
    expect(saved.revision).toBeGreaterThan(original.revision);
    await page.screenshot({ path: info.outputPath("session-security.en.png") });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "资源会话安全", exact: true })).toBeVisible();
    await page.screenshot({ path: info.outputPath("session-security.zh-CN.png") });
    await page.setViewportSize({ width: 390, height: 844 });
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
    ).toBe(true);
    await page.screenshot({ path: info.outputPath("session-security.mobile.png") });
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.getByRole("button", { name: "EN", exact: true }).click();

    const fixture = await (
      await api.get(process.env.JMS_LIVE_QA_FIXTURE_URL || "http://127.0.0.1:12223/health")
    ).json();
    const name = `Watermarked SSH ${Date.now()}`;
    const asset = await api.post("/api/v1/assets", {
      data: {
        name,
        host: process.env.JMS_LIVE_QA_SSH_HOST || "127.0.0.1",
        port: Number(fixture.address.split(":").at(-1)),
        username: fixture.username,
        password: "synthetic-qa-only-password",
        host_key_fingerprint: fixture.fingerprint,
      },
    });
    expect(asset.status()).toBe(201);
    await page.goto("/console");
    const connected = page.waitForResponse(
      (r) => r.url().includes("/api/v1/sessions") && r.request().method() === "POST",
    );
    await page
      .getByRole("row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    const session = await (await connected).json();
    const terminal = page.getByRole("dialog");
    await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
    await expect(terminal.getByLabel("Session watermark", { exact: true })).toContainText(
      session.session_id,
    );
    await terminal
      .getByRole("textbox", { name: "Terminal input", exact: true })
      .pressSequentially("watermarked replay proof");
    await expect(terminal.locator(".xterm-rows")).toContainText("watermarked replay proof");
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    const now = (await (await api.get(policyPath)).json()) as Settings;
    expect((await api.put(policyPath, { data: { ...now, watermark: false } })).ok()).toBe(true);
    await page.goto("/audit");
    await page
      .getByRole("row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Replay", exact: true })
      .click();
    await expect(
      page.getByRole("dialog").getByLabel("Session watermark", { exact: true }),
    ).toContainText(session.session_id);
    await page.getByRole("dialog").getByRole("button", { name: "Play", exact: true }).click();
    await expect(page.getByRole("dialog").locator(".xterm-rows")).toContainText(
      "watermarked replay proof",
    );
    await page.screenshot({ path: info.outputPath("terminal-replay-watermark.en.png") });
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Close replay", exact: true })
      .click();
    const disabled = (await (await api.get(policyPath)).json()) as Settings;
    expect((await api.put(policyPath, { data: { ...disabled, watermark: true } })).ok()).toBe(true);

    const rdp = await (
      await api.get(process.env.JMS_SESSION_QA_RDP_URL || "http://127.0.0.1:19392/health")
    ).json();
    const rdpName = `Watermarked RDP ${Date.now()}`;
    const desktop = await api.post("/api/v1/assets", {
      data: {
        name: rdpName,
        protocol: "rdp",
        host: process.env.JMS_SESSION_QA_RDP_HOST || "127.0.0.1",
        port: Number(rdp.address.split(":").at(-1)),
        username: "rdpqa",
        password: "synthetic-rdp-password-233",
        rdp: {
          security: "tls",
          server_name: rdp.server_name,
          root_ca_pem: rdp.root_ca_pem,
          width: 1280,
          height: 720,
          clipboard: false,
        },
      },
    });
    expect(desktop.status()).toBe(201);
    await page.goto("/console");
    const desktopCreated = page.waitForResponse(
      (r) => r.url().includes("/rdp/sessions") && r.request().method() === "POST",
    );
    await page
      .getByRole("row")
      .filter({ hasText: rdpName })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    const rdpSession = await (await desktopCreated).json();
    await expect(page.getByRole("dialog").getByRole("status")).toHaveText("Connected");
    const canvas = page.getByLabel("Remote RDP desktop", { exact: true });
    await expect
      .poll(() =>
        canvas.evaluate((element: HTMLCanvasElement) => {
          const pixels = element.getContext("2d")?.getImageData(0, 704, 1280, 16).data;
          if (!pixels) return 0;
          let count = 0;
          for (let i = 0; i < pixels.length; i += 4)
            if (pixels[i] > 120 && pixels[i + 1] > 120 && pixels[i + 2] > 120) count++;
          return count;
        }),
      )
      .toBeGreaterThan(100);
    await page.screenshot({ path: info.outputPath("rdp-burned-watermark.en.png") });
    await page
      .getByRole("dialog")
      .getByRole("button", { name: "Close terminal", exact: true })
      .click();
    await expect
      .poll(
        async () =>
          (await (await api.get(`/api/v1/desktop-sessions/${rdpSession.session_id}`)).json())
            .status,
      )
      .toBe("ended");
    const recorded = await (
      await api.get(`/api/v1/desktop-sessions/${rdpSession.session_id}`)
    ).json();
    expect(recorded.watermark).toContain(rdpSession.session_id);
    expect((await api.get(`/api/v1/desktop-sessions/${rdpSession.session_id}/frames/0`)).ok()).toBe(
      true,
    );
    expect(errors).toEqual([]);
  } finally {
    if (original) {
      const current = (await (await api.get(policyPath)).json()) as Settings;
      expect(
        (await api.put(policyPath, { data: { ...original, revision: current.revision } })).ok(),
      ).toBe(true);
    }
    await api.dispose();
  }
});
