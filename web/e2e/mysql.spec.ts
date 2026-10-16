import { expect, test, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
const admin = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
let adminToken = "";
const assets: Record<string, string> = {};
test.describe.configure({ mode: "serial" });
test.use({ locale: "en-US" });
test.beforeAll(async () => {
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  try {
    const b = await api.post("/api/v1/authentication/bootstrap", { data: admin });
    if (b.status() === 201) adminToken = (await b.json()).access_token;
    else {
      const l = await api.post("/api/v1/authentication/auth/", { data: admin });
      expect(l.status()).toBe(200);
      adminToken = (await l.json()).access_token;
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
for (const engine of ["mysql", "mariadb"]) {
  test(`creates real ${engine} TLS inventory and verifies bilingual bound queries`, async ({
    page,
    request: api,
  }) => {
    const fixture = await (
      await api.get(`http://127.0.0.1:${engine === "mysql" ? 15466 : 15468}/health`)
    ).json();
    await signIn(page);
    await page.getByRole("button", { name: "Add asset", exact: false }).first().click();
    const form = page.getByRole("dialog");
    await form.getByLabel("Asset protocol").selectOption(engine);
    await form.getByLabel("Name", { exact: true }).fill(`Browser ${engine} TLS`);
    await form.getByLabel("Database name", { exact: true }).fill("qa");
    await form.getByLabel("Host address").fill("127.0.0.1");
    await form.getByLabel("Database port").fill(engine === "mysql" ? "15465" : "15467");
    await form.getByLabel("Database account").fill("qadb");
    await form.getByLabel("Database password", { exact: true }).fill("synthetic-mysql-query-233");
    await form.getByLabel("Trusted CA certificate PEM (optional)").fill(fixture.root_ca_pem);
    await form.getByRole("button", { name: "Save", exact: true }).click();
    await expect(form).not.toBeVisible();
    const inventory = await (await page.request.get("/api/v1/assets")).json();
    const asset = inventory.find((a: { name: string }) => a.name === `Browser ${engine} TLS`);
    assets[engine] = asset.id;
    expect(asset.protocol).toBe(engine);
    expect(asset.mysql.read_only).toBe(true);
    expect(asset.postgresql).toBeUndefined();
    expect(asset.password_rotation).toBeUndefined();
    const row = page.getByRole("row").filter({ hasText: `Browser ${engine} TLS` });
    await expect(row.getByRole("button", { name: "Files", exact: true })).toHaveCount(0);
    await row.getByRole("button", { name: "Connect", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByRole("button", { name: "Run SQL" })).toBeVisible();
    await dialog.getByLabel("SQL statement").fill("SELECT ? AS message, NULL AS optional");
    await dialog.getByText("Parameters and execution options", { exact: true }).click();
    await dialog
      .getByLabel("JSON parameter array (?)")
      .fill(JSON.stringify([`${engine}-browser-bound`]));
    await dialog.getByRole("button", { name: "Run SQL" }).click();
    await expect(
      dialog.getByRole("cell", { name: `${engine}-browser-bound`, exact: true }),
    ).toBeVisible();
    await expect(dialog.getByText("NULL", { exact: true })).toBeVisible();
    await dialog.getByRole("button", { name: "Close", exact: true }).click();
    await page.locator(".lang-switch").click();
    await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
    await row.getByRole("button", { name: "连接", exact: true }).click();
    await expect(page.getByRole("dialog").getByRole("button", { name: "执行 SQL" })).toBeVisible();
    await page.getByRole("dialog").getByRole("button", { name: "关闭", exact: true }).click();
  });
}
test("MySQL-family grants, dialect authority, auto-commit writes and read-only denial", async ({
  request: api,
}) => {
  const headers = { Authorization: `Bearer ${adminToken}` };
  const user = await api.post("/api/v1/users", {
    headers,
    data: {
      username: "mysql.operator",
      password: "synthetic-mysql-operator-233",
      role: "operator",
    },
  });
  expect(user.status()).toBe(201);
  const u = await user.json();
  const login = await api.post("/api/v1/authentication/auth/", {
    data: { username: u.username, password: "synthetic-mysql-operator-233" },
  });
  const oh = { Authorization: `Bearer ${(await login.json()).access_token}` };
  for (const engine of ["mysql", "mariadb"]) {
    const id = assets[engine],
      path = `/api/v1/assets/${id}`;
    expect((await api.post(`${path}/database-sessions`, { headers: oh })).status()).toBe(403);
    const grant = await api.post("/api/v1/grants", {
      headers,
      data: { user_id: u.id, asset_id: id, account: "qadb", actions: ["connect"] },
    });
    expect(grant.status()).toBe(201);
    const connection = await api.post(`${path}/database-sessions`, { headers: oh });
    expect(connection.status()).toBe(201);
    const session = await connection.json();
    expect(session.protocol).toBe(engine);
    const dbh = { ...oh, "X-JMS-DB-SESSION": session.session_token };
    expect(
      (
        await api.post(`${path}/database-queries`, {
          headers: dbh,
          data: {
            sql: "SELECT 1",
            dialect: "postgresql",
            row_limit: 1,
            timeout_seconds: 5,
            request_id: `${engine}-forged-dialect`,
          },
        })
      ).status(),
    ).toBe(400);
    const submitted = await api.post(`${path}/database-queries`, {
      headers: dbh,
      data: {
        sql: "CREATE TABLE blocked_write(id int)",
        read_only: false,
        row_limit: 1,
        timeout_seconds: 5,
        request_id: `${engine}-readonly-policy`,
      },
    });
    expect(submitted.status()).toBe(201);
    const job = await submitted.json();
    await expect
      .poll(
        async () =>
          (await (await api.get(`/api/v1/database-queries/${job.id}`, { headers: oh })).json())
            .state,
      )
      .toBe("failed");
    const result = await (
      await api.get(`/api/v1/database-queries/${job.id}`, { headers: oh })
    ).json();
    expect(result.summary.error_code).toBe("read_only");
    expect(result.summary.read_only).toBe(true);
    await api.delete(`/api/v1/grants/${(await grant.json()).id}`, { headers });
    expect((await api.get(`/api/v1/database-queries/${job.id}`, { headers: oh })).status()).toBe(
      403,
    );
  }
});
test("MySQL-family CLI uses pinned SSH gateways and auto-commit mode is explicit in UI", async ({
  page,
  request: api,
}) => {
  const headers = { Authorization: `Bearer ${adminToken}` };
  const gw = await (await api.get("http://127.0.0.1:12238/health")).json();
  const gateway = await api.post("/api/v1/assets", {
    headers,
    data: {
      name: "MySQL CLI gateway",
      host: "127.0.0.1",
      port: 12237,
      username: gw.username,
      password: "synthetic-gateway-password",
      host_key_fingerprint: gw.fingerprint,
    },
  });
  expect(gateway.status()).toBe(201);
  const gid = (await gateway.json()).id;
  let writeAsset = "";
  for (const engine of ["mysql", "mariadb"]) {
    const fixture = await (
      await api.get(`http://127.0.0.1:${engine === "mysql" ? 15466 : 15468}/health`)
    ).json();
    const target = await api.post("/api/v1/assets", {
      headers,
      data: {
        name: `CLI ${engine}`,
        protocol: engine,
        host: `${engine}.synthetic.invalid`,
        port: 3306,
        username: "qadb",
        password: "synthetic-mysql-query-233",
        gateway_id: gid,
        mysql: {
          database: "qa",
          root_ca_pem: fixture.root_ca_pem,
          server_name: fixture.server_name,
          read_only: false,
        },
      },
    });
    expect(target.status()).toBe(201);
    const id = (await target.json()).id;
    writeAsset = id;
    const child = execFile(
      "go",
      ["run", "./cmd/jms", "db", id, "--params", `["${engine}-cli-bound"]`],
      {
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
      },
    );
    child.stdin?.end("SELECT ? AS message");
    const stdout = await new Promise<string>((resolve, reject) => {
      let out = "",
        err = "";
      child.stdout?.on("data", (d) => (out += String(d)));
      child.stderr?.on("data", (d) => (err += String(d)));
      child.once("error", reject);
      child.once("exit", (code) =>
        code === 0 ? resolve(out) : reject(new Error(`CLI ${code}: ${err}`)),
      );
    });
    expect(JSON.parse(stdout).result.rows[0][0]).toBe(`${engine}-cli-bound`);
    expect(stdout).not.toContain("synthetic-mysql-query-233");
  }
  await signIn(page);
  const inventory = await (await page.request.get("/api/v1/assets")).json();
  const asset = inventory.find((a: { id: string }) => a.id === writeAsset);
  await page
    .getByRole("row")
    .filter({ hasText: asset.name })
    .getByRole("button", { name: "Connect", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("button", { name: "Run SQL" })).toBeVisible();
  await dialog.getByText("Parameters and execution options", { exact: true }).click();
  await dialog.getByRole("checkbox").uncheck();
  await expect(dialog.getByRole("status")).toContainText("auto-commit");
  await dialog.getByLabel("SQL statement").fill("CREATE TABLE browser_ddl(id int)");
  await dialog.getByRole("button", { name: "Run SQL" }).click();
  await expect(dialog.getByText("Completed", { exact: true })).toBeVisible();
  await expect(dialog.locator(".database-result")).toContainText("Committed");
  await dialog.getByLabel("SQL statement").fill("DROP TABLE browser_ddl");
  const accepted = page.waitForResponse(
    (r) => r.url().includes("/database-queries") && r.request().method() === "POST",
  );
  await dialog.getByRole("button", { name: "Run SQL" }).click();
  const drop = await (await accepted).json();
  await expect
    .poll(
      async () =>
        (await (await page.request.get(`/api/v1/database-queries/${drop.id}`)).json()).state,
    )
    .toBe("completed");
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
});
