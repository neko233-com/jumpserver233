import { expect, test, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
const admin = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
let token = "",
  assetId = "";
test.describe.configure({ mode: "serial" });
test.use({ locale: "en-US" });
test.beforeAll(async () => {
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  try {
    const bootstrap = await api.post("/api/v1/authentication/bootstrap", { data: admin });
    if (bootstrap.status() === 201) token = (await bootstrap.json()).access_token;
    else {
      const login = await api.post("/api/v1/authentication/auth/", { data: admin });
      expect(login.status()).toBe(200);
      token = (await login.json()).access_token;
    }
  } finally {
    await api.dispose();
  }
});
async function signIn(page: import("@playwright/test").Page) {
  await page.goto("/login");
  await page.getByLabel("Username", { exact: true }).fill(admin.username);
  await page.getByLabel("Password", { exact: true }).fill(admin.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/console$/);
}
test("SQL Server verified TLS, bound parameters, multiple result sets and bilingual readonly policy", async ({
  page,
  request: api,
}) => {
  const fixture = await (await api.get("http://127.0.0.1:15474/health")).json();
  await signIn(page);
  await page.getByRole("button", { name: "Add asset", exact: false }).first().click();
  const form = page.getByRole("dialog");
  await form.getByLabel("Asset protocol").selectOption("sqlserver");
  await form.getByLabel("Name", { exact: true }).fill("Browser SQL Server TLS");
  await form.getByLabel("Database name", { exact: true }).fill("qa");
  await form.getByLabel("Host address").fill("127.0.0.1");
  await form.getByLabel("Database port").fill("15473");
  await form.getByLabel("Database account").fill("qadb");
  await form
    .getByLabel("Database password", { exact: true })
    .fill("Synthetic-SQLServer-Query-233!");
  await form.getByLabel("Certificate hostname (optional)").fill(fixture.server_name);
  await form.getByLabel("Trusted CA certificate PEM (optional)").fill(fixture.root_ca_pem);
  await form.getByRole("button", { name: "Save", exact: true }).click();
  await expect(form).not.toBeVisible();
  const assets = await (await page.request.get("/api/v1/assets")).json();
  const asset = assets.find((a: { name: string }) => a.name === "Browser SQL Server TLS");
  assetId = asset.id;
  expect(asset.sqlserver.read_only).toBe(true);
  expect(asset.mysql).toBeUndefined();
  expect(asset.password_rotation).toBeUndefined();
  const row = page.getByRole("row").filter({ hasText: "Browser SQL Server TLS" });
  await expect(row.getByRole("button", { name: "Files", exact: true })).toHaveCount(0);
  await row.getByRole("button", { name: "Connect", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("status")).toContainText("SELECT/CTE");
  await dialog
    .getByLabel("SQL statement")
    .fill(
      "SELECT @p1 AS message, CAST(NULL AS nvarchar(10)) AS optional; SELECT DB_NAME() AS database_name",
    );
  await dialog.getByText("Parameters and execution options", { exact: true }).click();
  await dialog.getByLabel("JSON parameter array (@p1, @p2…)").fill('["sqlserver-browser-bound"]');
  await dialog.getByRole("button", { name: "Run SQL", exact: true }).click();
  await expect(
    dialog.getByRole("cell", { name: "sqlserver-browser-bound", exact: true }),
  ).toBeVisible();
  await expect(dialog.getByText("Result set 2", { exact: true })).toBeVisible();
  await expect(dialog.getByRole("cell", { name: "qa", exact: true })).toBeVisible();
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await page.locator(".lang-switch").click();
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
  await row.getByRole("button", { name: "连接", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("status")).toContainText("SELECT/CTE");
  await page.getByRole("dialog").getByRole("button", { name: "关闭", exact: true }).click();
  const headers = { Authorization: `Bearer ${token}` };
  const session = await (
    await api.post(`/api/v1/assets/${assetId}/database-sessions`, { headers })
  ).json();
  const denied = await api.post(`/api/v1/assets/${assetId}/database-queries`, {
    headers: { ...headers, "X-JMS-DB-SESSION": session.session_token },
    data: {
      sql: "SELECT 1 INTO dbo.must_not_exist",
      read_only: false,
      row_limit: 5,
      timeout_seconds: 5,
      request_id: "sqlserver-readonly-authority",
    },
  });
  expect(denied.status()).toBe(201);
  const job = await denied.json();
  await expect
    .poll(
      async () =>
        (await (await api.get(`/api/v1/database-queries/${job.id}`, { headers })).json()).state,
    )
    .toBe("failed");
  const result = await (await api.get(`/api/v1/database-queries/${job.id}`, { headers })).json();
  expect(result.summary.error_code).toBe("read_only");
  expect(result.summary.result_sets).toBeUndefined();
});
test("SQL Server Agent CLI through pinned SSH gateway and explicit server-managed writes", async ({
  page,
  request: api,
}) => {
  const headers = { Authorization: `Bearer ${token}` };
  const gw = await (await api.get("http://127.0.0.1:12238/health")).json();
  const fixture = await (await api.get("http://127.0.0.1:15474/health")).json();
  const g = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "SQL Server gateway",
      host: "127.0.0.1",
      port: 12237,
      username: gw.username,
      password: "synthetic-gateway-password",
      host_key_fingerprint: gw.fingerprint,
    },
  });
  expect(g.status()).toBe(201);
  const gatewayId = (await g.json()).id;
  const a = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "SQL Server writable CLI",
      protocol: "sqlserver",
      host: "sqlserver.synthetic.invalid",
      port: 1433,
      username: "qadb",
      password: "Synthetic-SQLServer-Query-233!",
      gateway_id: gatewayId,
      sqlserver: {
        database: "qa",
        server_name: fixture.server_name,
        root_ca_pem: fixture.root_ca_pem,
        read_only: false,
      },
    },
  });
  expect(a.status()).toBe(201);
  const asset = await a.json();
  const cli = execFile(
    "go",
    ["run", "./cmd/jms", "db", asset.id, "--params", '["sqlserver-cli-bound"]'],
    {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      env: {
        ...process.env,
        JMS_SERVER_URL: "http://127.0.0.1:8083",
        JMS_TOKEN: token,
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
        JMS_ORG_ID: "",
      },
      timeout: 30_000,
      maxBuffer: 2 * 1024 * 1024,
    },
  );
  cli.stdin?.end("SELECT @p1 AS message; SELECT DB_NAME() AS database_name");
  const stdout = await new Promise<string>((resolve, reject) => {
    let out = "",
      err = "";
    cli.stdout?.on("data", (d) => (out += String(d)));
    cli.stderr?.on("data", (d) => (err += String(d)));
    cli.once("error", reject);
    cli.once("exit", (code) =>
      code === 0 ? resolve(out) : reject(new Error(`CLI ${code}: ${err}`)),
    );
  });
  const result = JSON.parse(stdout).result;
  expect(result.rows[0][0]).toBe("sqlserver-cli-bound");
  expect(result.result_sets[0].rows[0][0]).toBe("qa");
  expect(stdout).not.toContain("Synthetic-SQLServer-Query-233!");
  await signIn(page);
  await page
    .getByRole("row")
    .filter({ hasText: "SQL Server writable CLI" })
    .getByRole("button", { name: "Connect", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog.getByText("Parameters and execution options", { exact: true }).click();
  await dialog.getByRole("checkbox").uncheck();
  await expect(dialog.getByRole("status")).toContainText("transaction semantics");
  await dialog
    .getByLabel("SQL statement")
    .fill(
      "CREATE TABLE dbo.browser_mssql(id int); INSERT INTO dbo.browser_mssql VALUES(233); SELECT N'sqlserver-written' AS message",
    );
  await dialog.getByRole("button", { name: "Run SQL", exact: true }).click();
  await expect(dialog.getByRole("cell", { name: "sqlserver-written", exact: true })).toBeVisible();
  await expect(dialog.locator(".database-result")).toContainText("Server-managed transaction");
  await dialog.getByLabel("SQL statement").fill("DROP TABLE dbo.browser_mssql");
  const accepted = page.waitForResponse(
    (r) => r.url().includes("/database-queries") && r.request().method() === "POST",
  );
  await dialog.getByRole("button", { name: "Run SQL", exact: true }).click();
  const drop = await (await accepted).json();
  await expect
    .poll(
      async () =>
        (await (await page.request.get(`/api/v1/database-queries/${drop.id}`)).json()).state,
    )
    .toBe("completed");
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
});
