import { test, expect, request, type Page } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const admin = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
const password = "synthetic-rdp-password-233";
let token = "";
let cookies: Parameters<import("@playwright/test").BrowserContext["addCookies"]>[0] = [];
test.describe.configure({ mode: "serial" });
test.use({ locale: "en-US" });
test.beforeAll(async () => {
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  try {
    let r = await api.post("/api/v1/authentication/bootstrap", { data: admin });
    if (r.status() !== 201) r = await api.post("/api/v1/authentication/auth/", { data: admin });
    expect(r.ok()).toBe(true);
    token = (await r.json()).access_token;
    cookies = (await api.storageState()).cookies;
  } finally {
    await api.dispose();
  }
});
async function signIn(page: Page) {
  await page.context().addCookies(cookies);
  await page.goto("/console");
  await expect(page).toHaveURL(/\/console$/);
}
async function state(api: import("@playwright/test").APIRequestContext) {
  const r = await api.get("http://127.0.0.1:19392/state");
  return r.ok() ? await r.json() : null;
}

test("RDP cold desktop, native mouse/text, encrypted replay and Chinese UI", async ({
  page,
  request: api,
}) => {
  test.setTimeout(60_000);
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const fixture = await (await api.get("http://127.0.0.1:19392/health")).json();
  await signIn(page);
  await page.getByRole("button", { name: "Add asset", exact: false }).first().click();
  const form = page.getByRole("dialog");
  await form.getByLabel("Asset protocol", { exact: true }).selectOption("rdp");
  await expect(form.getByLabel("RDP port", { exact: true })).toHaveValue("3389");
  await expect(form.getByLabel("Security mode", { exact: false })).toHaveValue("nla");
  await form.getByLabel("Security mode", { exact: false }).selectOption("tls");
  await form.getByLabel("Name", { exact: true }).fill("Browser Native RDP");
  await form.getByLabel("Host address", { exact: true }).fill("127.0.0.1");
  await form.getByLabel("RDP port", { exact: true }).fill("19391");
  await form.getByLabel("RDP account", { exact: true }).fill("rdpqa");
  await form.getByLabel("RDP password", { exact: true }).fill(password);
  await form.getByLabel("TLS server name", { exact: true }).fill(fixture.server_name);
  await form
    .getByLabel("Trusted CA certificate (PEM, optional)", { exact: true })
    .fill(fixture.root_ca_pem);
  await form.getByLabel("Text clipboard", { exact: true }).check();
  await form.getByRole("button", { name: "Save", exact: true }).click();
  await expect(form).not.toBeVisible();
  const row = page.getByRole("row").filter({ hasText: "Browser Native RDP" });
  await expect(row.getByRole("button", { name: "Files", exact: true })).toHaveCount(0);
  const created = page.waitForResponse(
    (r) => r.url().includes("/rdp/sessions") && r.request().method() === "POST",
  );
  await row.getByRole("button", { name: "Connect", exact: true }).click();
  const session = await (await created).json();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("status")).toHaveText("Connected");
  const canvas = dialog.getByLabel("Remote RDP desktop", { exact: true });
  await expect
    .poll(
      () =>
        canvas.evaluate((host: HTMLCanvasElement) => {
          const v = host.getContext("2d")?.getImageData(60, 430, 1, 1).data;
          return !!v && v[0] > 180 && v[1] < 130 && v[2] < 130;
        }),
      { timeout: 25000 },
    )
    .toBe(true);
  const before = await state(api);
  const clickAt = async (x: number, y: number) => {
    const rect = await canvas.boundingBox();
    expect(rect).toBeTruthy();
    await canvas.click({ position: { x: (x * rect!.width) / 1280, y: (y * rect!.height) / 720 } });
  };
  await clickAt(100, 175);
  await expect.poll(async () => (await state(api))?.clicks).toBeGreaterThan(before.clicks);
  await clickAt(100, 260);
  await expect.poll(async () => (await state(api))?.focus).toBe(true);
  await canvas.press("a");
  await expect.poll(async () => (await state(api))?.text).toBe("a");
  await canvas.press("Backspace");
  await expect.poll(async () => (await state(api))?.text).toBe("");
  await dialog.getByLabel("Text to type remotely", { exact: true }).fill("Browser RDP 233");
  await dialog.getByRole("button", { name: "Send text", exact: true }).click();
  await expect.poll(async () => (await state(api))?.text).toContain("Browser RDP 233");
  await clickAt(800, 175);
  await dialog.getByText("Text clipboard", { exact: true }).click();
  await dialog.getByRole("button", { name: "Read remote text", exact: true }).click();
  const clipboard = dialog.getByLabel("Session clipboard text", { exact: true });
  await expect(clipboard).toHaveValue("Browser RDP 233");
  await clipboard.fill("Unsent local edit");
  await dialog.getByRole("button", { name: "Read remote text", exact: true }).click();
  await expect(clipboard).toHaveValue("Browser RDP 233");
  await clipboard.fill("Browser clipboard 233 中文");
  await dialog.getByRole("button", { name: "Offer text to remote clipboard", exact: true }).click();
  await dialog.getByText("Text clipboard", { exact: true }).click();
  await clickAt(800, 260);
  await expect.poll(async () => (await state(api))?.text).toBe("Browser clipboard 233 中文");
  await dialog.getByRole("button", { name: "Close terminal", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  const headers = { Authorization: `Bearer ${token}` };
  let recording: { frames: { index: number }[]; status: string };
  await expect
    .poll(async () => {
      recording = await (
        await api.get(`/api/v1/desktop-sessions/${session.session_id}`, { headers })
      ).json();
      return recording.status;
    })
    .toBe("ended");
  expect(recording!.frames.length).toBeGreaterThan(0);
  const image = await api.get(`/api/v1/desktop-sessions/${session.session_id}/frames/0`, {
    headers,
  });
  expect(image.status()).toBe(200);
  expect((await image.body()).subarray(0, 8)).toEqual(
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  );
  await page.getByRole("link", { name: "Audit", exact: true }).click();
  await page.getByText("RDP desktop audit", { exact: true }).first().click();
  const auditRow = page.getByRole("row").filter({ hasText: "Browser Native RDP" });
  await auditRow.getByRole("button", { name: "Replay", exact: true }).click();
  await expect(
    page.getByRole("dialog").getByAltText("Recorded remote desktop frame"),
  ).toBeVisible();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Close terminal", exact: true })
    .click();
  await page.getByRole("link", { name: "Assets", exact: true }).click();
  await page.locator(".lang-switch").click();
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
  await page
    .getByRole("row")
    .filter({ hasText: "Browser Native RDP" })
    .getByRole("button", { name: "连接", exact: true })
    .click();
  await expect(page.getByRole("dialog").getByRole("status")).toHaveText("已连接");
  await expect(page.getByLabel("RDP 远程桌面画面", { exact: true })).toBeVisible();
  await page.getByRole("dialog").getByRole("button", { name: "关闭终端", exact: true }).click();
  expect(errors).toEqual([]);
  expect(await (await api.get("/api/v1/assets", { headers })).text()).not.toContain(password);
});

test("RDP Agent CLI capture through a pinned SSH gateway", async ({ request: api }) => {
  test.setTimeout(60_000);
  const headers = { Authorization: `Bearer ${token}` };
  const fixture = await (await api.get("http://127.0.0.1:19392/health")).json();
  const gateway = await (await api.get("http://127.0.0.1:12238/health")).json();
  const g = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "RDP gateway",
      host: "127.0.0.1",
      port: 12237,
      username: gateway.username,
      password: "synthetic-gateway-password",
      host_key_fingerprint: gateway.fingerprint,
    },
  });
  expect(g.status()).toBe(201);
  const gatewayID = (await g.json()).id;
  const response = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "RDP CLI routed",
      protocol: "rdp",
      host: "rdp.synthetic.invalid",
      port: 3389,
      username: "rdpqa",
      password,
      gateway_id: gatewayID,
      rdp: { security: "tls", server_name: fixture.server_name, root_ca_pem: fixture.root_ca_pem },
    },
  });
  expect(response.status()).toBe(201);
  const asset = await response.json();
  const root = process.env.JMS_E2E_DATA_DIR!;
  const capture = resolve(root, "rdp-cli.png"),
    input = resolve(root, "rdp-events.json");
  writeFileSync(
    input,
    JSON.stringify([
      { type: "pointer", action: "button", button: "left", down: true, x: 100, y: 175 },
      { type: "pointer", action: "button", button: "left", down: false, x: 100, y: 175 },
    ]),
  );
  const before = await state(api);
  const result = await execute(
    "go",
    ["run", "./cmd/jms", "rdp", asset.id, "--capture", capture, "--input", input, "--wait", "2"],
    {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      env: {
        ...process.env,
        JMS_SERVER_URL: "http://127.0.0.1:8083",
        JMS_TOKEN: token,
        JMS_ORG_ID: "",
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
      },
      timeout: 45000,
    },
  );
  const output = JSON.parse(result.stdout);
  expect(output.bytes).toBeGreaterThan(1000);
  expect(readFileSync(capture).subarray(0, 8)).toEqual(
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
  );
  await expect.poll(async () => (await state(api))?.clicks).toBeGreaterThan(before.clicks);
  expect(result.stdout + result.stderr).not.toContain(password);
  const record = await (
    await api.get(`/api/v1/desktop-sessions/${output.session_id}`, { headers })
  ).json();
  expect(record.gateway_ids).toEqual([gatewayID]);
  expect(record.status).toBe("ended");
});

test("RDP view-only denial, independent review and live grant revocation", async ({
  page,
  request: api,
}) => {
  test.setTimeout(60_000);
  const headers = { Authorization: `Bearer ${token}` };
  const fixture = await (await api.get("http://127.0.0.1:19392/health")).json();
  const identity = { username: "e2e.rdp.operator", password: "synthetic-rdp-operator-pass-233" };
  const u = await api.post("/api/v1/users", { headers, data: { ...identity, role: "operator" } });
  expect(u.status()).toBe(201);
  const user = await u.json();
  const r = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "RDP reviewed operator",
      protocol: "rdp",
      host: "127.0.0.1",
      port: 19391,
      username: "rdpqa",
      password,
      login_review_required: true,
      rdp: { security: "tls", server_name: fixture.server_name, root_ca_pem: fixture.root_ca_pem },
    },
  });
  expect(r.status()).toBe(201);
  const asset = await r.json();
  let g = await api.post("/api/v1/grants", {
    headers,
    data: { user_id: user.id, asset_id: asset.id, account: "rdpqa", actions: ["view"] },
  });
  expect(g.status()).toBe(201);
  const view = await g.json();
  await page.goto("/login");
  await page.getByLabel("Username", { exact: true }).fill(identity.username);
  await page.getByLabel("Password", { exact: true }).fill(identity.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/console$/);
  const row = page.getByRole("row").filter({ hasText: asset.name });
  await expect(row.getByRole("button", { name: "Connect", exact: true })).toBeDisabled();
  expect((await page.request.post(`/api/v1/assets/${asset.id}/rdp/sessions`)).status()).toBe(403);
  expect((await api.delete(`/api/v1/grants/${view.id}`, { headers })).status()).toBe(204);
  g = await api.post("/api/v1/grants", {
    headers,
    data: { user_id: user.id, asset_id: asset.id, account: "rdpqa", actions: ["connect"] },
  });
  const grant = await g.json();
  await page.getByRole("button", { name: "Refresh status", exact: true }).click();
  await row.getByRole("button", { name: "Connect", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("status")).toHaveText("Desktop login awaiting review");
  const reviews = await (await api.get("/api/v1/access-reviews", { headers })).json();
  const review = reviews.results.find((v: { asset_id: string }) => v.asset_id === asset.id);
  expect(review.action).toBe("rdp");
  expect(
    (await api.post(`/api/v1/access-reviews/${review.id}/approve`, { headers })).status(),
  ).toBe(204);
  await expect(dialog.getByRole("status")).toHaveText("Connected");
  expect((await api.delete(`/api/v1/grants/${grant.id}`, { headers })).status()).toBe(204);
  await expect(dialog.getByRole("status")).toHaveText("Session ended");
  await expect(dialog.getByRole("button", { name: "Send text", exact: true })).toBeDisabled();
  expect((await page.request.post(`/api/v1/assets/${asset.id}/rdp/sessions`)).status()).toBe(403);
  await dialog.getByRole("button", { name: "Close terminal", exact: true }).click();
  expect((await page.request.get("/api/v1/desktop-sessions")).ok()).toBe(true);
});
