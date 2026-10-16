import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const admin = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
const password = "synthetic-telnet-password-233";
let token = "";
let cookies: Parameters<import("@playwright/test").BrowserContext["addCookies"]>[0] = [];
test.describe.configure({ mode: "serial" });
test.use({ locale: "en-US" });
test.beforeAll(async () => {
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  try {
    let response = await api.post("/api/v1/authentication/bootstrap", { data: admin });
    if (response.status() !== 201)
      response = await api.post("/api/v1/authentication/auth/", { data: admin });
    expect(response.ok()).toBe(true);
    token = (await response.json()).access_token;
    cookies = (await api.storageState()).cookies;
  } finally {
    await api.dispose();
  }
});
async function signIn(page: import("@playwright/test").Page) {
  await page.context().addCookies(cookies);
  await page.goto("/console");
  await expect(page).toHaveURL(/\/console$/);
}
function observeTerminal(page: import("@playwright/test").Page) {
  let output = "";
  page.on("websocket", (socket) => {
    if (!socket.url().includes("/terminal")) return;
    socket.on("framereceived", (frame) => {
      output = (output + String(frame.payload)).slice(-65536);
    });
  });
  return () => output;
}

test("Telnet verified TLS form, native Linux output, recording and bilingual UI", async ({
  page,
  request: api,
}) => {
  const fixture = await (await api.get("http://127.0.0.1:16526/health")).json();
  await signIn(page);
  await page.getByRole("button", { name: "Add asset", exact: false }).first().click();
  const form = page.getByRole("dialog");
  await form.getByLabel("Asset protocol", { exact: true }).selectOption("telnet");
  await expect(form.getByLabel("Telnet port", { exact: true })).toHaveValue("992");
  await expect(form.getByLabel("Telnet transport", { exact: true })).toHaveValue("verify-full");
  await form.getByLabel("Telnet transport", { exact: true }).selectOption("disable");
  await expect(form.getByLabel("Telnet port", { exact: true })).toHaveValue("23");
  await expect(
    form.getByText("Plaintext Telnet exposes credentials on the target link.", { exact: false }),
  ).toBeVisible();
  await form.getByLabel("Telnet transport", { exact: true }).selectOption("verify-full");
  await expect(form.getByLabel("Telnet port", { exact: true })).toHaveValue("992");
  await form.getByLabel("Name", { exact: true }).fill("Browser Telnet TLS");
  await form.getByLabel("Host address", { exact: true }).fill("127.0.0.1");
  await form.getByLabel("Telnet port", { exact: true }).fill("16994");
  await form.getByLabel("Telnet account", { exact: true }).fill("telnetqa");
  await form.getByLabel("Telnet password", { exact: true }).fill(password);
  await form
    .getByLabel("Certificate hostname (optional)", { exact: true })
    .fill(fixture.server_name);
  await form
    .getByLabel("Trusted CA certificate PEM (optional)", { exact: true })
    .fill(fixture.root_ca_pem);
  await form.getByText("Login prompt patterns", { exact: true }).click();
  await expect(form.getByLabel("Login success prompt pattern", { exact: true })).not.toHaveValue(
    "",
  );
  await form.getByRole("button", { name: "Save", exact: true }).click();
  await expect(form).not.toBeVisible();
  const row = page.getByRole("row").filter({ hasText: "Browser Telnet TLS" });
  await expect(row.getByRole("button", { name: "Files", exact: true })).toHaveCount(0);
  const created = page.waitForResponse(
    (r) => r.url().includes("/telnet/sessions") && r.request().method() === "POST",
  );
  const output = observeTerminal(page);
  await row.getByRole("button", { name: "Connect", exact: true }).click();
  const session = await (await created).json();
  const terminal = page.getByRole("dialog");
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
  await expect.poll(output).toMatch(/\$\s/);
  await terminal
    .locator(".xterm-helper-textarea")
    .pressSequentially("echo __TELNET_BROWSER_RESULT__; id -un; stty size");
  await terminal.locator(".xterm-helper-textarea").press("Enter");
  await expect.poll(output).toContain("\r\n__TELNET_BROWSER_RESULT__\r\n");
  expect(output()).not.toContain(password);
  const headers = { Authorization: `Bearer ${token}` };
  await expect
    .poll(async () =>
      (
        await (await api.get(`/api/v1/sessions/${session.session_id}/commands`, { headers })).text()
      ).includes("__TELNET_BROWSER_RESULT__"),
    )
    .toBe(true);
  await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
  await expect
    .poll(async () => {
      const data = await (await api.get("/api/v1/sessions", { headers })).json();
      return data.results.find((r: { session_id: string }) => r.session_id === session.session_id)
        ?.replay_available;
    })
    .toBe(true);
  const replay = await api.get(`/api/v1/sessions/${session.session_id}/replay`, { headers });
  expect(replay.status()).toBe(200);
  const recording = gunzipSync(await replay.body()).toString("utf8");
  expect(recording).toContain("__TELNET_BROWSER_RESULT__");
  expect(recording).not.toContain(password);
  await page.locator(".lang-switch").click();
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
  await row.getByRole("button", { name: "连接", exact: true }).click();
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText("已连接");
  await terminal.getByRole("button", { name: "关闭终端", exact: true }).click();
  expect(await (await api.get("/api/v1/assets", { headers })).text()).not.toContain(password);
});

test("Telnet Agent CLI reaches native Linux through a pinned SSH gateway", async ({
  page,
  request: api,
}) => {
  const headers = { Authorization: `Bearer ${token}` };
  const fixture = await (await api.get("http://127.0.0.1:16526/health")).json();
  const gateway = await (await api.get("http://127.0.0.1:12238/health")).json();
  const g = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "Telnet gateway",
      host: "127.0.0.1",
      port: 12237,
      username: gateway.username,
      password: "synthetic-gateway-password",
      host_key_fingerprint: gateway.fingerprint,
    },
  });
  expect(g.status()).toBe(201);
  const gatewayId = (await g.json()).id;
  const response = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "Telnet CLI routed",
      protocol: "telnet",
      host: "telnet.synthetic.invalid",
      port: 992,
      username: "telnetqa",
      password,
      gateway_id: gatewayId,
      telnet: { server_name: fixture.server_name, root_ca_pem: fixture.root_ca_pem },
    },
  });
  expect(response.status()).toBe(201);
  const asset = await response.json();
  const cli = execFile("go", ["run", "./cmd/jms", "telnet", asset.id], {
    cwd: fileURLToPath(new URL("../../server", import.meta.url)),
    env: {
      ...process.env,
      JMS_SERVER_URL: "http://127.0.0.1:8083",
      JMS_TOKEN: token,
      JMS_ORG_ID: "",
      JMS_ACCESS_KEY_ID: "",
      JMS_ACCESS_KEY_SECRET: "",
    },
    timeout: 30_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  cli.stdin?.end("echo __TELNET_CLI_NATIVE__; exit\n");
  const result = await new Promise<string>((resolve, reject) => {
    let out = "",
      err = "";
    cli.stdout?.on("data", (d) => (out += String(d)));
    cli.stderr?.on("data", (d) => (err += String(d)));
    cli.once("error", reject);
    cli.once("exit", (code) =>
      code === 0 ? resolve(out) : reject(new Error(`CLI ${code}: ${err}`)),
    );
  });
  expect(result).toContain("\r\n__TELNET_CLI_NATIVE__\r\n");
  expect(result).not.toContain(password);
  const records = await (await api.get("/api/v1/sessions", { headers })).json();
  const record = records.results.find((s: { asset_id: string }) => s.asset_id === asset.id);
  expect(record.protocol).toBe("telnet");
  expect(record.gateway_ids).toEqual([gatewayId]);
  await signIn(page);
  await page.getByRole("link", { name: "Audit", exact: true }).click();
  await expect(page.getByRole("row").filter({ hasText: asset.name })).toContainText("telnetqa");
});

test("Telnet view-only denial, independent login review and live grant revocation", async ({
  page,
  request: api,
}) => {
  const headers = { Authorization: `Bearer ${token}` };
  const fixture = await (await api.get("http://127.0.0.1:16526/health")).json();
  const identity = {
    username: "e2e.telnet.review",
    password: "synthetic-telnet-review-password-233",
  };
  const created = await api.post("/api/v1/users", {
    headers,
    data: { ...identity, role: "operator" },
  });
  expect(created.status()).toBe(201);
  const user = await created.json();
  const response = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "Telnet reviewed operator",
      protocol: "telnet",
      host: "127.0.0.1",
      port: 16994,
      username: "telnetqa",
      password,
      login_review_required: true,
      telnet: { root_ca_pem: fixture.root_ca_pem, server_name: fixture.server_name },
    },
  });
  expect(response.status()).toBe(201);
  const asset = await response.json();
  let g = await api.post("/api/v1/grants", {
    headers,
    data: { user_id: user.id, asset_id: asset.id, account: "telnetqa", actions: ["view"] },
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
  expect(
    (
      await page.request.post(`/api/v1/assets/${asset.id}/telnet/sessions`, {
        data: { cols: 80, rows: 24 },
      })
    ).status(),
  ).toBe(403);
  expect((await api.delete(`/api/v1/grants/${view.id}`, { headers })).status()).toBe(204);
  g = await api.post("/api/v1/grants", {
    headers,
    data: { user_id: user.id, asset_id: asset.id, account: "telnetqa", actions: ["connect"] },
  });
  expect(g.status()).toBe(201);
  const grant = await g.json();
  await page.getByRole("button", { name: "Refresh status", exact: true }).click();
  await expect(row.getByRole("button", { name: "Connect", exact: true })).toBeEnabled();
  const output = observeTerminal(page);
  await row.getByRole("button", { name: "Connect", exact: true }).click();
  const terminal = page.getByRole("dialog");
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Telnet login review pending");
  const reviews = await (await api.get("/api/v1/access-reviews", { headers })).json();
  const review = reviews.results.find((r: { asset_id: string }) => r.asset_id === asset.id);
  expect(review.action).toBe("telnet");
  expect(
    (await api.post(`/api/v1/access-reviews/${review.id}/approve`, { headers })).status(),
  ).toBe(204);
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
  await expect.poll(output).toMatch(/\$\s/);
  expect((await api.delete(`/api/v1/grants/${grant.id}`, { headers })).status()).toBe(204);
  await terminal.locator(".xterm-helper-textarea").pressSequentially("x");
  await expect(terminal.locator(".ssh-terminal-status")).toHaveClass(/\b(closed|failed)\b/);
  await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
  expect(
    (
      await page.request.post(`/api/v1/assets/${asset.id}/telnet/sessions`, {
        data: { cols: 80, rows: 24 },
      })
    ).status(),
  ).toBe(403);
});
