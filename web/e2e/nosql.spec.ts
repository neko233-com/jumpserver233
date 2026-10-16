import { expect, test, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
const admin = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
let token = "";
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

for (const engine of ["redis", "mongodb"] as const) {
  const isRedis = engine === "redis",
    label = isRedis ? "Redis" : "MongoDB",
    port = isRedis ? 15493 : 15503,
    health = isRedis ? 15494 : 15504;
  const example = (value: string) =>
    isRedis
      ? JSON.stringify(["ECHO", value])
      : JSON.stringify({
          aggregate: 1,
          pipeline: [
            { $documents: [{ message: value, optional: null }, { message: "missing optional" }] },
          ],
          cursor: {},
        });
  test(`${label} native TLS browser JSON commands, nulls, bilingual UI and readonly authority`, async ({
    page,
    request: api,
  }) => {
    const fixture = await (await api.get(`http://127.0.0.1:${health}/health`)).json();
    await signIn(page);
    await page.getByRole("button", { name: "Add asset", exact: false }).first().click();
    const form = page.getByRole("dialog");
    await form.getByLabel("Asset protocol").selectOption(engine);
    await expect(form.getByLabel("Database port")).toHaveValue(isRedis ? "6379" : "27017");
    await form.getByLabel("Name", { exact: true }).fill(`Browser ${label} TLS`);
    await form
      .getByLabel(isRedis ? "Redis database index" : "Database name", { exact: true })
      .fill(fixture.database);
    if (!isRedis)
      await form
        .getByLabel("Authentication database (blank uses current database)", { exact: true })
        .fill("admin");
    await form.getByLabel("Host address").fill("127.0.0.1");
    await form.getByLabel("Database port").fill(String(port));
    await form.getByLabel("Database account").fill("qadb");
    await form
      .getByLabel("Database password", { exact: true })
      .fill(`synthetic-${engine}-query-233`);
    await form.getByLabel("Certificate hostname (optional)").fill(fixture.server_name);
    await form.getByLabel("Trusted CA certificate PEM (optional)").fill(fixture.root_ca_pem);
    await form.getByRole("button", { name: "Save", exact: true }).click();
    await expect(form).not.toBeVisible();
    const asset = (await (await page.request.get("/api/v1/assets")).json()).find(
      (a: { name: string }) => a.name === `Browser ${label} TLS`,
    );
    expect(asset[engine].read_only).toBe(true);
    expect(asset.password_rotation).toBeUndefined();
    const row = page.getByRole("row").filter({ hasText: `Browser ${label} TLS` });
    await row.getByRole("button", { name: "Connect", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await dialog
      .getByLabel("Command JSON", { exact: true })
      .fill(example(`${engine}-browser-private`));
    await dialog.getByRole("button", { name: "Run command", exact: true }).click();
    await expect(
      dialog.getByRole("cell", { name: `${engine}-browser-private`, exact: true }),
    ).toBeVisible();
    if (!isRedis) {
      await expect(dialog.getByRole("cell", { name: "NULL", exact: true })).toBeVisible();
      await expect(dialog.getByRole("cell", { name: "Missing field", exact: true })).toBeVisible();
    }
    await expect(dialog.locator(".database-result")).toContainText("Read-only query completed");
    await dialog
      .getByRole("button", { name: isRedis ? "Browse keys" : "Browse collections", exact: true })
      .click();
    await expect(dialog.getByLabel("Command JSON", { exact: true })).toHaveValue(
      isRedis ? '["SCAN","0","COUNT","100"]' : '{"listCollections":1,"nameOnly":true}',
    );
    const accepted = page.waitForResponse(
      (r) => r.url().includes("/database-queries") && r.request().method() === "POST",
    );
    await dialog.getByRole("button", { name: "Run command", exact: true }).click();
    const browse = await (await accepted).json();
    await expect
      .poll(
        async () =>
          (await (await page.request.get(`/api/v1/database-queries/${browse.id}`)).json()).state,
      )
      .toBe("completed");
    await dialog.getByRole("button", { name: "Close", exact: true }).click();
    await page.locator(".lang-switch").click();
    await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
    await row.getByRole("button", { name: "连接", exact: true }).click();
    await dialog.getByLabel("命令 JSON", { exact: true }).fill(example(`${label} 中文查询`));
    await dialog.getByRole("button", { name: "执行命令", exact: true }).click();
    await expect(
      dialog.getByRole("cell", { name: `${label} 中文查询`, exact: true }),
    ).toBeVisible();
    await dialog.getByRole("button", { name: "关闭", exact: true }).click();
    const headers = { Authorization: `Bearer ${token}` };
    const session = await (
      await api.post(`/api/v1/assets/${asset.id}/database-sessions`, { headers })
    ).json();
    const denied = await api.post(`/api/v1/assets/${asset.id}/database-queries`, {
      headers: { ...headers, "X-JMS-DB-SESSION": session.session_token },
      data: {
        sql: isRedis
          ? '["SET","must_not_exist","private-value"]'
          : '{"insert":"must_not_exist","documents":[{"value":"private-value"}]}',
        read_only: false,
        row_limit: 5,
        timeout_seconds: 5,
        request_id: `${engine}-readonly-authority`,
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
    expect(result.summary.columns).toBeNull();
    const audit = await api.get(`/api/v1/database-queries?asset_id=${asset.id}`, { headers });
    expect(await audit.text()).not.toContain(`${engine}-browser-private`);
  });
  test(`${label} Agent CLI through pinned SSH gateways and explicit writes`, async ({
    page,
    request: api,
  }) => {
    const headers = { Authorization: `Bearer ${token}` };
    const gw = await (await api.get("http://127.0.0.1:12238/health")).json();
    const fixture = await (await api.get(`http://127.0.0.1:${health}/health`)).json();
    const g = await api.post("/api/v1/assets", {
      headers,
      data: {
        name: `${label} gateway`,
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
        name: `${label} writable CLI`,
        protocol: engine,
        host: `${engine}.synthetic.invalid`,
        port: isRedis ? 6379 : 27017,
        username: "qadb",
        password: `synthetic-${engine}-query-233`,
        gateway_id: gatewayId,
        [engine]: {
          database: fixture.database,
          auth_database: fixture.auth_database,
          server_name: fixture.server_name,
          root_ca_pem: fixture.root_ca_pem,
          read_only: false,
        },
      },
    });
    expect(a.status()).toBe(201);
    const asset = await a.json();
    const run = async (sql: string, write = false) => {
      const cli = execFile(
        "go",
        ["run", "./cmd/jms", "db", asset.id, ...(write ? ["--write"] : [])],
        {
          cwd: fileURLToPath(new URL("../../server", import.meta.url)),
          env: {
            ...process.env,
            LANG: "en_US.UTF-8",
            LC_ALL: "",
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
      cli.stdin?.end(sql);
      return await new Promise<{ out: string; err: string }>((resolve, reject) => {
        let out = "",
          err = "";
        cli.stdout?.on("data", (d) => (out += String(d)));
        cli.stderr?.on("data", (d) => (err += String(d)));
        cli.once("error", reject);
        cli.once("exit", (code) =>
          code === 0 ? resolve({ out, err }) : reject(new Error(`CLI ${code}: ${err}`)),
        );
      });
    };
    const cli = await run(example(`${engine}-cli-private`));
    expect(cli.out).toContain(`${engine}-cli-private`);
    expect(cli.out).not.toContain(`synthetic-${engine}-query-233`);
    const write = await run(
      isRedis
        ? '["SET","browser_nosql_cli","nosql-cli-written"]'
        : '{"insert":"browser_nosql_cli","documents":[{"message":"nosql-cli-written","optional":null}]}',
      true,
    );
    expect(write.err).toContain("no guaranteed rollback");
    await signIn(page);
    await page
      .getByRole("row")
      .filter({ hasText: `${label} writable CLI` })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    const dialog = page.getByRole("dialog");
    await dialog.getByText("Parameters and execution options", { exact: true }).click();
    await dialog.getByRole("checkbox").uncheck();
    await expect(dialog.getByRole("status")).toContainText("without guaranteed rollback");
    await dialog
      .getByLabel("Command JSON", { exact: true })
      .fill(
        isRedis
          ? '["GET","browser_nosql_cli"]'
          : '{"find":"browser_nosql_cli","projection":{"_id":0}}',
      );
    await dialog.getByRole("button", { name: "Run command", exact: true }).click();
    await expect(
      dialog.getByRole("cell", { name: "nosql-cli-written", exact: true }),
    ).toBeVisible();
    await run(isRedis ? '["DEL","browser_nosql_cli"]' : '{"drop":"browser_nosql_cli"}', true);
    await dialog.getByRole("button", { name: "Close", exact: true }).click();
  });
}
