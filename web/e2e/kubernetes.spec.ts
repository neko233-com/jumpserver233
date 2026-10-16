import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const admin = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
let token = "";
let adminCookies: Parameters<import("@playwright/test").BrowserContext["addCookies"]>[0] = [];
test.describe.configure({ mode: "serial" });
test.use({ locale: "en-US" });
test.beforeAll(async () => {
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  try {
    let r = await api.post("/api/v1/authentication/bootstrap", { data: admin });
    if (r.status() !== 201) r = await api.post("/api/v1/authentication/auth/", { data: admin });
    expect(r.ok()).toBe(true);
    token = (await r.json()).access_token;
    adminCookies = (await api.storageState()).cookies;
  } finally {
    await api.dispose();
  }
});
async function signIn(page: import("@playwright/test").Page, credentials = admin) {
  if (credentials === admin && adminCookies.length) {
    await page.context().addCookies(adminCookies);
    await page.goto("/console");
    await expect(page).toHaveURL(/\/console$/);
    return;
  }
  await page.goto("/login");
  await page.getByLabel("Username", { exact: true }).fill(credentials.username);
  await page.getByLabel("Password", { exact: true }).fill(credentials.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
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
test("Kubernetes native TLS inventory, Pod/container choice, bilingual terminal and recording", async ({
  page,
  request: api,
}) => {
  const fixture = await (await api.get("http://127.0.0.1:16446/health")).json();
  await signIn(page);
  await page.getByRole("button", { name: "Add asset", exact: false }).first().click();
  const form = page.getByRole("dialog");
  await form.getByLabel("Asset protocol").selectOption("kubernetes");
  await expect(form.getByLabel("Kubernetes API port", { exact: true })).toHaveValue("6443");
  await form.getByLabel("Name", { exact: true }).fill("Browser Kubernetes TLS");
  await form.getByLabel("Allowed namespaces (comma-separated)", { exact: true }).fill("jms-qa");
  await form.getByLabel("Host address", { exact: true }).fill("127.0.0.1");
  await form.getByLabel("Kubernetes API port", { exact: true }).fill("16445");
  await form.getByLabel("Cluster account label", { exact: true }).fill("qadb");
  await form.getByLabel("Kubernetes bearer token", { exact: true }).fill(fixture.token);
  await form
    .getByLabel("Certificate hostname (optional)", { exact: true })
    .fill(fixture.server_name);
  await form
    .getByLabel("Trusted CA certificate PEM (optional)", { exact: true })
    .fill(fixture.root_ca_pem);
  await expect(
    form.getByText("TLS certificate and hostname verification are required.", { exact: false }),
  ).toBeVisible();
  await form.getByRole("button", { name: "Save", exact: true }).click();
  await expect(form).not.toBeVisible();
  const row = page.getByRole("row").filter({ hasText: "Browser Kubernetes TLS" });
  await expect(row.getByRole("button", { name: "Files", exact: true })).toHaveCount(0);
  await row.getByRole("button", { name: "Connect", exact: true }).click();
  const chooser = page.getByRole("dialog");
  await expect(chooser.getByLabel("Namespace", { exact: true })).toHaveValue("jms-qa");
  await expect(chooser.getByLabel("Pod", { exact: true })).toHaveValue("qa-shell");
  await chooser.getByLabel("Container", { exact: true }).selectOption("sidecar");
  const created = page.waitForResponse(
    (r) => r.url().includes("/kubernetes/sessions") && r.request().method() === "POST",
  );
  const output = observeTerminal(page);
  await chooser.getByRole("button", { name: "Connect", exact: true }).click();
  const session = await (await created).json();
  const terminal = page.getByRole("dialog");
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
  await expect.poll(output).toMatch(/\$\s/);
  await terminal
    .locator(".xterm-helper-textarea")
    .pressSequentially("echo __KUBE_BROWSER_RESULT__");
  await terminal.locator(".xterm-helper-textarea").press("Enter");
  await expect.poll(output).toContain("\r\n__KUBE_BROWSER_RESULT__\r\n");
  const headers = { Authorization: `Bearer ${token}` };
  await expect
    .poll(async () => {
      const r = await api.get(`/api/v1/sessions/${session.session_id}/commands`, { headers });
      return (await r.text()).includes("__KUBE_BROWSER_RESULT__");
    })
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
  expect(gunzipSync(await replay.body()).toString("utf8")).toContain("__KUBE_BROWSER_RESULT__");
  await page.locator(".lang-switch").click();
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
  await row.getByRole("button", { name: "连接", exact: true }).click();
  await expect(chooser.getByLabel("命名空间", { exact: true })).toHaveValue("jms-qa");
  await chooser.getByRole("button", { name: "连接", exact: true }).click();
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText("已连接");
  await terminal.getByRole("button", { name: "关闭终端", exact: true }).click();
  const assets = await api.get("/api/v1/assets", { headers });
  expect(await assets.text()).not.toContain(fixture.token);
});
test("Kubernetes Agent CLI uses server identity through a pinned SSH gateway", async ({
  page,
  request: api,
}) => {
  const headers = { Authorization: `Bearer ${token}` };
  const fixture = await (await api.get("http://127.0.0.1:16446/health")).json();
  const gateway = await (await api.get("http://127.0.0.1:12238/health")).json();
  const g = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "Kubernetes gateway",
      host: "127.0.0.1",
      port: 12237,
      username: gateway.username,
      password: "synthetic-gateway-password",
      host_key_fingerprint: gateway.fingerprint,
    },
  });
  expect(g.status()).toBe(201);
  const gatewayId = (await g.json()).id;
  const a = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "Kubernetes CLI routed",
      protocol: "kubernetes",
      host: "kubernetes.synthetic.invalid",
      port: 6443,
      username: "qadb",
      password: fixture.token,
      gateway_id: gatewayId,
      kubernetes: {
        namespaces: ["jms-qa"],
        shell: ["/bin/sh"],
        server_name: fixture.server_name,
        root_ca_pem: fixture.root_ca_pem,
      },
    },
  });
  expect(a.status()).toBe(201);
  const asset = await a.json();
  const cli = execFile(
    "go",
    [
      "run",
      "./cmd/jms",
      "k8s",
      asset.id,
      "--namespace",
      "jms-qa",
      "--pod",
      "qa-shell",
      "--container",
      "main",
    ],
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
      timeout: 30_000,
      maxBuffer: 2 * 1024 * 1024,
    },
  );
  cli.stdin?.end("echo __KUBE_CLI_NATIVE__; exit\n");
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
  expect(result).toContain("__KUBE_CLI_NATIVE__");
  expect(result).not.toContain(fixture.token);
  const sessions = await (await api.get("/api/v1/sessions", { headers })).json();
  const record = sessions.results.find((s: { asset_id: string }) => s.asset_id === asset.id);
  expect(record.kubernetes.namespace).toBe("jms-qa");
  expect(record.kubernetes.container).toBe("main");
  expect(record.gateway_ids).toEqual([gatewayId]);
  await signIn(page);
  await page.getByRole("link", { name: "Audit", exact: true }).click();
  await expect(page.getByRole("tab", { name: "Terminal sessions", exact: true })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Asset", exact: true })).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "Kubernetes CLI routed" })).toContainText(
    "jms-qa / qa-shell / main",
  );
  await page.locator(".lang-switch").click();
  await expect(page.getByRole("tab", { name: "终端会话", exact: true })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "资产", exact: true })).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "Kubernetes CLI routed" })).toContainText(
    "jms-qa / qa-shell / main",
  );
});

test("Kubernetes operator review and revoked connect grants remain authoritative", async ({
  page,
  request: api,
}) => {
  const headers = { Authorization: `Bearer ${token}` };
  const fixture = await (await api.get("http://127.0.0.1:16446/health")).json();
  const identity = { username: "e2e.kube.review", password: "synthetic-kube-review-password-233" };
  const created = await api.post("/api/v1/users", {
    headers,
    data: { ...identity, role: "operator" },
  });
  expect(created.status()).toBe(201);
  const user = await created.json();
  const response = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "Kubernetes reviewed operator",
      protocol: "kubernetes",
      host: "127.0.0.1",
      port: 16445,
      username: "qadb",
      password: fixture.token,
      login_review_required: true,
      kubernetes: {
        namespaces: ["jms-qa"],
        shell: ["/bin/sh"],
        root_ca_pem: fixture.root_ca_pem,
        server_name: fixture.server_name,
      },
    },
  });
  expect(response.status()).toBe(201);
  const asset = await response.json();
  const g = await api.post("/api/v1/grants", {
    headers,
    data: { user_id: user.id, asset_id: asset.id, account: "qadb", actions: ["connect"] },
  });
  expect(g.status()).toBe(201);
  const grant = await g.json();
  await signIn(page, identity);
  const outside = await page.request.get(
    `/api/v1/assets/${asset.id}/kubernetes/pods?namespace=jms-forbidden`,
  );
  expect(outside.status()).toBe(403);
  await page
    .getByRole("row")
    .filter({ hasText: asset.name })
    .getByRole("button", { name: "Connect", exact: true })
    .click();
  const chooser = page.getByRole("dialog");
  await expect(chooser.getByLabel("Pod", { exact: true })).toHaveValue("qa-shell");
  const output = observeTerminal(page);
  await chooser.getByRole("button", { name: "Connect", exact: true }).click();
  const terminal = page.getByRole("dialog");
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText(
    "Kubernetes login review pending",
  );
  const reviews = await (await api.get("/api/v1/access-reviews", { headers })).json();
  const review = reviews.results.find((r: { asset_id: string }) => r.asset_id === asset.id);
  expect(review.action).toBe("kubernetes");
  expect(
    (await api.post(`/api/v1/access-reviews/${review.id}/approve`, { headers })).status(),
  ).toBe(204);
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
  await expect.poll(output).toMatch(/\$\s/);
  expect((await api.delete(`/api/v1/grants/${grant.id}`, { headers })).status()).toBe(204);
  await terminal.locator(".xterm-helper-textarea").pressSequentially("x");
  await expect(terminal.locator(".ssh-terminal-status")).toHaveClass(/\b(closed|failed)\b/);
  await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
  const denied = await page.request.get(`/api/v1/assets/${asset.id}/kubernetes/pods`);
  expect(denied.status()).toBe(403);
});
