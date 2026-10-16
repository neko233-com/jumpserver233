import { expect, test, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
const admin = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
let adminToken = "",
  assetID = "",
  operatorToken = "",
  operatorID = "",
  fixture: { root_ca_pem: string; server_name: string; address: string };
test.describe.configure({ mode: "serial" });
test.use({ locale: "en-US" });
test.beforeAll(async () => {
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  try {
    const bootstrap = await api.post("/api/v1/authentication/bootstrap", { data: admin });
    if (bootstrap.status() === 201) adminToken = (await bootstrap.json()).access_token;
    else {
      const login = await api.post("/api/v1/authentication/auth/", { data: admin });
      expect(login.status()).toBe(200);
      adminToken = (await login.json()).access_token;
    }
    fixture = await (await api.get("http://127.0.0.1:15443/health")).json();
    const user = await api.post("/api/v1/users", {
      headers: { Authorization: `Bearer ${adminToken}` },
      data: { username: "db.operator", password: "synthetic-db-operator-2468", role: "operator" },
    });
    expect(user.status()).toBe(201);
    operatorID = (await user.json()).id;
    const login = await api.post("/api/v1/authentication/auth/", {
      data: { username: "db.operator", password: "synthetic-db-operator-2468" },
    });
    expect(login.status()).toBe(200);
    operatorToken = (await login.json()).access_token;
  } finally {
    await api.dispose();
  }
});
async function signIn(page: import("@playwright/test").Page) {
  await page.goto("/login");
  await page.getByLabel("Username").fill(admin.username);
  await page.getByLabel("Password").fill(admin.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/console$/);
}
test("creates TLS PostgreSQL inventory in browser and runs bound SQL in English and Chinese", async ({
  page,
}) => {
  await signIn(page);
  await page.getByRole("button", { name: "Add asset", exact: false }).first().click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Asset protocol").selectOption("postgresql");
  await dialog.getByLabel("Name", { exact: true }).fill("Browser PostgreSQL TLS");
  await dialog.getByLabel("Database name", { exact: true }).fill("qa");
  await dialog.getByLabel("Host address").fill("127.0.0.1");
  await dialog.getByLabel("Database port").fill("15444");
  await dialog.getByLabel("Database account").fill("qadb");
  await dialog
    .getByLabel("Database password", { exact: true })
    .fill("synthetic-postgres-query-233");
  await dialog.getByLabel("Trusted CA certificate PEM (optional)").fill(fixture.root_ca_pem);
  await dialog.getByRole("button", { name: "Save", exact: true }).click();
  await expect(dialog).not.toBeVisible();
  const row = page.getByRole("row").filter({ hasText: "Browser PostgreSQL TLS" });
  await expect(row).toBeVisible();
  const inventory = await page.request.get("/api/v1/assets");
  const asset = (await inventory.json()).find(
    (a: { name: string }) => a.name === "Browser PostgreSQL TLS",
  );
  assetID = asset.id;
  expect(asset.protocol).toBe("postgresql");
  expect(asset.postgresql.read_only).toBe(true);
  expect(JSON.stringify(asset)).not.toContain("synthetic-postgres-query-233");
  expect(asset.password_rotation).toBeUndefined();
  await expect(row.getByRole("button", { name: "Files", exact: true })).toHaveCount(0);
  await row.getByRole("button", { name: "Connect", exact: true }).click();
  const console = page.getByRole("dialog", { name: "PostgreSQL · Browser PostgreSQL TLS" });
  await expect(console.getByRole("button", { name: "Run SQL" })).toBeVisible();
  await console
    .getByLabel("SQL statement")
    .fill("SELECT $1::text AS message, NULL::text AS optional");
  await console.getByText("Parameters and execution options", { exact: true }).click();
  await console.getByLabel("JSON parameter array ($1, $2…)").fill('["bound-browser-value"]');
  await console.getByRole("button", { name: "Run SQL" }).click();
  await expect(
    console.getByRole("cell", { name: "bound-browser-value", exact: true }),
  ).toBeVisible();
  await expect(console.getByText("NULL", { exact: true })).toBeVisible();
  await console.getByRole("button", { name: "Close", exact: true }).click();
  await page.locator(".lang-switch").click();
  await row.getByRole("button", { name: "连接", exact: true }).click();
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
  await expect(console.getByRole("button", { name: "执行 SQL" })).toBeVisible();
  await console.getByRole("button", { name: "关闭", exact: true }).click();
  await page.getByRole("link", { name: "数据库查询审计", exact: true }).click();
  await expect(page.getByRole("heading", { name: "数据库查询审计" })).toBeVisible();
  await expect(
    page.getByText("SELECT $1::text AS message, NULL::text AS optional", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("bound-browser-value", { exact: true })).toHaveCount(0);
});
test("enforces database connect grants, SQL review, owner-only results and cancel rollback", async ({
  request: api,
}) => {
  const ah = { Authorization: `Bearer ${adminToken}` },
    oh = { Authorization: `Bearer ${operatorToken}` };
  const path = `/api/v1/assets/${assetID}/database-sessions`;
  expect((await api.post(path, { headers: oh })).status()).toBe(403);
  const grant = await api.post("/api/v1/grants", {
    headers: ah,
    data: { user_id: operatorID, asset_id: assetID, account: "qadb", actions: ["connect"] },
  });
  expect(grant.status()).toBe(201);
  const session = await api.post(path, { headers: oh });
  expect(session.status()).toBe(201);
  const token = (await session.json()).session_token;
  const filter = await api.post("/api/v1/command-filters", {
    headers: ah,
    data: {
      name: "SQL browser review",
      account: "qadb",
      asset_id: assetID,
      user_id: operatorID,
      match: "contains",
      pattern: "review-marker",
      action: "review",
    },
  });
  expect(filter.status()).toBe(201);
  const submitted = await api.post(`/api/v1/assets/${assetID}/database-queries`, {
    headers: { ...oh, "X-JMS-DB-SESSION": token },
    data: {
      sql: "SELECT $1::text /* review-marker */",
      parameters: ["private-result"],
      request_id: "browser-sql-reviewed",
      row_limit: 5,
      timeout_seconds: 10,
    },
  });
  expect(submitted.status()).toBe(201);
  const job = await submitted.json();
  expect(job.state).toBe("awaiting_review");
  expect(JSON.stringify(job)).not.toContain("private-result");
  expect(
    (
      await api.post(`/api/v1/database-queries/${job.id}/review`, {
        headers: oh,
        data: { approve: true },
      })
    ).status(),
  ).toBe(403);
  expect(
    (
      await api.post(`/api/v1/database-queries/${job.id}/review`, {
        headers: ah,
        data: { approve: true },
      })
    ).status(),
  ).toBe(204);
  await expect
    .poll(
      async () =>
        (await (await api.get(`/api/v1/database-queries/${job.id}`, { headers: oh })).json()).state,
    )
    .toBe("completed");
  const result = await (
    await api.get(`/api/v1/database-queries/${job.id}`, { headers: oh })
  ).json();
  expect(result.result.rows[0][0]).toBe("private-result");
  expect(
    (await (await api.get(`/api/v1/database-queries/${job.id}`, { headers: ah })).json()).result,
  ).toBeUndefined();
  const running = await api.post(`/api/v1/assets/${assetID}/database-queries`, {
    headers: { ...oh, "X-JMS-DB-SESSION": token },
    data: {
      sql: "SELECT pg_sleep(15)",
      request_id: "browser-sql-cancel",
      row_limit: 5,
      timeout_seconds: 20,
    },
  });
  const runningJob = await running.json();
  await expect
    .poll(
      async () =>
        (await (await api.get(`/api/v1/database-queries/${runningJob.id}`, { headers: oh })).json())
          .state,
    )
    .toBe("running");
  expect(
    (await api.post(`/api/v1/database-queries/${runningJob.id}/cancel`, { headers: oh })).status(),
  ).toBe(204);
  await expect
    .poll(
      async () =>
        (await (await api.get(`/api/v1/database-queries/${runningJob.id}`, { headers: oh })).json())
          .state,
    )
    .toBe("cancelled");
  await api.delete(`/api/v1/grants/${(await grant.json()).id}`, { headers: ah });
  expect((await api.get(`/api/v1/database-queries/${job.id}`, { headers: oh })).status()).toBe(403);
  await api.delete(`/api/v1/command-filters/${(await filter.json()).id}`, { headers: ah });
});
test("Agent CLI queries real TLS PostgreSQL through the pinned SSH gateway without target credentials", async ({
  request: api,
}) => {
  const headers = { Authorization: `Bearer ${adminToken}` };
  const gw = await (await api.get("http://127.0.0.1:12238/health")).json();
  const gateway = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "DB gateway",
      host: "127.0.0.1",
      port: 12237,
      username: gw.username,
      password: "synthetic-gateway-password",
      host_key_fingerprint: gw.fingerprint,
    },
  });
  expect(gateway.status()).toBe(201);
  const target = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "Gateway PostgreSQL",
      protocol: "postgresql",
      host: "postgres.synthetic.invalid",
      port: 5432,
      username: "qadb",
      password: "synthetic-postgres-query-233",
      gateway_id: (await gateway.json()).id,
      postgresql: {
        database: "qa",
        root_ca_pem: fixture.root_ca_pem,
        server_name: fixture.server_name,
      },
    },
  });
  expect(target.status()).toBe(201);
  const id = (await target.json()).id;
  const child = execFile("go", ["run", "./cmd/jms", "db", id, "--params", '["cli-bound-result"]'], {
    cwd: fileURLToPath(new URL("../../server", import.meta.url)),
    env: {
      ...process.env,
      JMS_SERVER_URL: "http://127.0.0.1:8083",
      JMS_TOKEN: adminToken,
      JMS_ACCESS_KEY_ID: "",
      JMS_ACCESS_KEY_SECRET: "",
      JMS_ORG_ID: "",
    },
    timeout: 30_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  child.stdin?.end("SELECT $1::text AS message");
  const output = await new Promise<string>((resolve, reject) => {
    let out = "",
      err = "";
    child.stdout?.on("data", (d) => (out += String(d)));
    child.stderr?.on("data", (d) => (err += String(d)));
    child.once("error", reject);
    child.once("exit", (code) =>
      code === 0 ? resolve(out) : reject(new Error(`CLI exit ${code}: ${err}`)),
    );
  });
  expect(JSON.parse(output).result.rows[0][0]).toBe("cli-bound-result");
  expect(output).not.toContain("synthetic-postgres-query-233");
  expect((await (await api.get("http://127.0.0.1:12238/health")).json()).forwards).toBeGreaterThan(
    0,
  );
});
