import { expect, test, type APIRequestContext } from "@playwright/test";
import { randomUUID } from "node:crypto";

test.use({ locale: "en-US" });
const administrator = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
const initial = "Synthetic-PAM-Initial-233!";
const fixtures = [
  {
    protocol: "postgresql",
    health: 15443,
    port: 15444,
    database: "qa",
    password: "synthetic-pam-admin-233",
  },
  {
    protocol: "mysql",
    health: 15466,
    port: 15465,
    database: "qa",
    password: "synthetic-pam-admin-233",
  },
  {
    protocol: "mariadb",
    health: 15468,
    port: 15467,
    database: "qa",
    password: "synthetic-pam-admin-233",
  },
  {
    protocol: "sqlserver",
    health: 15474,
    port: 15473,
    database: "master",
    password: "Synthetic-PAM-Admin-233!",
  },
];

for (const fixture of fixtures) {
  test(`PAM ${fixture.protocol}: real inventory, bilingual enrollment, batch rotation and idempotence`, async ({
    page,
  }) => {
    test.setTimeout(180_000);
    const api: APIRequestContext = page.request;
    const suffix = randomUUID().replaceAll("-", "").slice(0, 12);
    const name = `pamqa_${suffix}`;
    let source = "",
      managed = "",
      plan = "",
      remoteCreated = false;
    const sql = async (statement: string) => {
      const session = await api.post(`/api/v1/assets/${source}/database-sessions`);
      expect(session.status()).toBe(201);
      const submitted = await api.post(`/api/v1/assets/${source}/database-queries`, {
        headers: { "X-JMS-DB-SESSION": (await session.json()).session_token },
        data: {
          sql: statement,
          read_only: false,
          row_limit: 10,
          timeout_seconds: 10,
          request_id: randomUUID(),
        },
      });
      expect(submitted.status()).toBe(201);
      const job = await submitted.json();
      await expect
        .poll(
          async () => (await (await api.get(`/api/v1/database-queries/${job.id}`)).json()).state,
          { timeout: 25_000 },
        )
        .not.toMatch(/^(queued|running)$/);
      expect((await (await api.get(`/api/v1/database-queries/${job.id}`)).json()).state).toBe(
        "completed",
      );
    };
    const drop =
      fixture.protocol === "postgresql"
        ? `DROP ROLE IF EXISTS ${name}`
        : fixture.protocol === "sqlserver"
          ? `IF EXISTS(SELECT 1 FROM sys.sql_logins WHERE name='${name}') DROP LOGIN [${name}]`
          : `DROP USER IF EXISTS '${name}'@'%'`;
    try {
      await api.post("/api/v1/authentication/bootstrap", { data: administrator });
      await page.goto("/login");
      await page.getByLabel("Username", { exact: true }).fill(administrator.username);
      await page.getByLabel("Password", { exact: true }).fill(administrator.password);
      await page.getByRole("button", { name: "Sign in", exact: true }).click();
      await expect(page).toHaveURL(/\/console$/);
      const meta = await (await api.get(`http://127.0.0.1:${fixture.health}/health`)).json();
      const created = await api.post("/api/v1/assets", {
        data: {
          name: `PAM ${fixture.protocol} ${suffix}`,
          protocol: fixture.protocol,
          host: "127.0.0.1",
          port: fixture.port,
          username: "pam_admin",
          password: fixture.password,
          [fixture.protocol]: {
            database: fixture.database,
            tls_mode: "verify-full",
            server_name: meta.server_name,
            root_ca_pem: meta.root_ca_pem,
            read_only: false,
          },
        },
      });
      expect(created.status()).toBe(201);
      source = (await created.json()).id;
      const create =
        fixture.protocol === "postgresql"
          ? `CREATE ROLE ${name} LOGIN PASSWORD '${initial}'`
          : fixture.protocol === "sqlserver"
            ? `CREATE LOGIN [${name}] WITH PASSWORD='${initial}', CHECK_POLICY=OFF`
            : `CREATE USER '${name}'@'%' IDENTIFIED BY '${initial}'`;
      await sql(create);
      remoteCreated = true;
      await page.goto("/console/pam");
      await expect(
        page.getByRole("heading", { name: "Windows & database accounts", exact: true }),
      ).toBeVisible();
      await page.getByLabel("Managed asset", { exact: true }).selectOption(source);
      await page.getByRole("button", { name: "Collect accounts", exact: true }).click();
      await expect(page.getByRole("status")).toHaveText(
        "Accounts collected without password changes.",
      );
      await page.getByLabel("Find an account").fill(name);
      const row = page.getByRole("row").filter({ hasText: name });
      await row.getByRole("button", { name: "Enroll / bind", exact: true }).click();
      await page.getByLabel("Known current password (write only)", { exact: true }).fill(initial);
      await expect(
        page.getByRole("checkbox", { name: "Enable automatic seven-day password rotation" }),
      ).not.toBeChecked();
      await page.getByRole("button", { name: "Review enrollment", exact: true }).click();
      const saving = page.waitForResponse(
        (r) =>
          r.url().endsWith(`/assets/${source}/pam/import-commit`) &&
          r.request().method() === "POST",
      );
      await page.getByRole("button", { name: "Confirm enrollment", exact: true }).click();
      const saved = await saving;
      expect(saved.status()).toBe(200);
      const receipt = await saved.json();
      managed = receipt.rows[0].account_id;
      expect(JSON.stringify(receipt)).not.toContain(initial);
      const replay = await api.post(`/api/v1/assets/${source}/pam/import-commit`, {
        data: saved.request().postDataJSON(),
      });
      expect(replay.status()).toBe(200);
      expect(await replay.json()).toEqual(receipt);
      await expect(page.locator(".pam-enroll")).toHaveCount(0);
      await page.locator(".lang-switch").click();
      await expect(
        page.getByRole("heading", { name: "Windows 与数据库账号", exact: true }),
      ).toBeVisible();
      await page.setViewportSize({ width: 390, height: 844 });
      await expect(page.getByLabel("纳管资产", { exact: true })).toHaveValue(source);
      await page.setViewportSize({ width: 1280, height: 900 });
      await page.locator(".lang-switch").click();
      const prepared = await api.post("/api/v1/accounts/rotation-plans", {
        data: {
          name: `PAM batch ${suffix}`,
          kind: "manual",
          enabled: false,
          only_due: false,
          revision: 0,
          targets: [{ account_id: managed, collector_id: source }],
        },
      });
      expect(prepared.status()).toBe(201);
      plan = (await prepared.json()).id;
      const requestID = randomUUID();
      const run = await api.post(`/api/v1/accounts/rotation-plans/${plan}/runs`, {
        data: { request_id: requestID },
      });
      expect(run.status()).toBe(202);
      const execution = await run.json();
      await expect
        .poll(
          async () =>
            (await (await api.get(`/api/v1/accounts/rotation-runs/${execution.id}`)).json()).state,
          { timeout: 35_000 },
        )
        .not.toMatch(/^(queued|running)$/);
      const result = await (await api.get(`/api/v1/accounts/rotation-runs/${execution.id}`)).json();
      expect(result.items[0].state).toBe("succeeded");
      expect(result.items[0].after_revision).toBe(result.items[0].before_revision + 1);
      const repeated = await api.post(`/api/v1/accounts/rotation-plans/${plan}/runs`, {
        data: { request_id: requestID },
      });
      expect((await repeated.json()).id).toBe(execution.id);
      const check = await api.post(`/api/v1/accounts/rotation-plans/${plan}/checks`, {
        data: { request_id: randomUUID() },
      });
      expect(check.status()).toBe(202);
      const checkRun = await check.json();
      await expect
        .poll(
          async () =>
            (await (await api.get(`/api/v1/accounts/rotation-runs/${checkRun.id}`)).json()).items[0]
              ?.state,
          { timeout: 30_000 },
        )
        .toBe("succeeded");
    } finally {
      if (source && remoteCreated) {
        await sql(drop);
        await sql(drop);
      }
      if (plan) {
        const record = await api.get(`/api/v1/accounts/rotation-plans/${plan}`);
        if (record.ok())
          expect(
            (
              await api.delete(`/api/v1/accounts/rotation-plans/${plan}`, {
                data: { revision: (await record.json()).revision },
              })
            ).status(),
          ).toBe(204);
      }
      if (managed) {
        const path = `/api/v1/assets/${source}/accounts/${managed}`;
        const record = await api.get(path);
        if (record.ok())
          expect(
            (await api.delete(path, { data: { version: (await record.json()).version } })).status(),
          ).toBe(204);
      }
      if (source) expect((await api.delete(`/api/v1/assets/${source}`)).status()).toBe(204);
    }
  });
}
