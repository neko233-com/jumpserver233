import { test, expect, request } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const base = process.env.JMS_REPORTS_QA_BASE_URL || "http://127.0.0.1:8083";
const ui = process.env.JMS_REPORTS_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Reports QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });

test("reports use real SSH audit data, current source rights and verified export receipts across Web and CLI", async ({
  browser,
}, info) => {
  test.setTimeout(120_000);
  const api = await request.newContext({ baseURL: base }),
    admin = await browser.newContext({ locale: "en-US", viewport: { width: 1440, height: 1080 } }),
    guest = await browser.newContext({ locale: "en-US" });
  const page = await admin.newPage(),
    op = await guest.newPage(),
    errors: string[] = [];
  for (const p of [page, op]) p.on("pageerror", (e) => errors.push(e.message));
  const stamp = Date.now(),
    retain = process.env.JMS_REPORTS_QA_RETAIN === "true";
  let asset = "",
    user = "",
    role = "",
    grant = "",
    org = "";
  const credentials = {
    username: process.env.JMS_REPORTS_QA_USERNAME || "e2e.admin",
    password: process.env.JMS_REPORTS_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
  };
  const account = { username: `reports.qa.${stamp}`, password: "synthetic-report-operator-233" };
  try {
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok()).toBe(true);
    await admin.addCookies((await api.storageState()).cookies);
    const host = await (
      await api.get(process.env.JMS_REPORTS_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    const created = await api.post("/api/v1/assets", {
      data: {
        name: `Reports SSH ${stamp}`,
        host: process.env.JMS_REPORTS_QA_SSH_HOST || "127.0.0.1",
        port: Number(host.address.split(":").at(-1)),
        username: "keyqa",
        password: "synthetic-keyhost-password-233",
        host_key_fingerprint: host.fingerprint,
      },
    });
    expect(created.status()).toBe(201);
    asset = (await created.json()).id;
    const a = await (await api.get(`/api/v1/assets/${asset}/accounts/${asset}`)).json();
    expect(
      (
        await api.put(`/api/v1/assets/${asset}/accounts/${asset}`, {
          data: {
            version: a.version,
            password_rotation_enabled: false,
            key_rotation_enabled: false,
          },
        })
      ).status(),
    ).toBe(200);
    const u = await api.post("/api/v1/users", { data: { ...account, role: "operator" } });
    expect(u.status()).toBe(201);
    user = (await u.json()).id;
    const g = await api.post("/api/v1/grants", {
      data: {
        user_id: user,
        asset_id: asset,
        account: "keyqa",
        actions: ["view", "connect", "sftp"],
      },
    });
    expect(g.status()).toBe(201);
    grant = (await g.json()).id;
    const opLogin = await guest.request.post(base + "/api/v1/authentication/auth/", {
      data: account,
    });
    expect(opLogin.ok()).toBe(true);
    const opToken = (await opLogin.json()).access_token;
    for (const client of [api, guest.request]) {
      const r = await client.post(base + "/api/v1/ops/jobs", {
        data: {
          asset_id: asset,
          command: "printf report-private-output",
          timeout_seconds: 10,
          request_id: randomUUID(),
        },
      });
      expect(r.status(), await r.text()).toBe(201);
      const job = (await r.json()).id;
      await expect
        .poll(
          async () => (await (await client.get(base + "/api/v1/ops/jobs/" + job)).json()).state,
          { timeout: 20_000 },
        )
        .toBe("succeeded");
    }
    const own = await (
      await guest.request.get(base + "/api/v1/reports/overview?sources=ssh_jobs")
    ).json();
    expect(own.sources[0]).toMatchObject({ scope: "mine", matched: 1, status: "ok" });
    expect(JSON.stringify(own)).not.toContain("report-private-output");
    const all = await (await api.get("/api/v1/reports/overview?sources=ssh_jobs")).json();
    expect(all.sources[0].matched).toBeGreaterThanOrEqual(2);
    expect(
      (await guest.request.get(base + "/api/v1/reports/export.csv?sources=ssh_jobs")).status(),
    ).toBe(403);
    const r = await api.post("/api/v1/rbac/roles", {
      data: { name: `Report exporter ${stamp}`, permissions: ["reports.export"], revision: 0 },
    });
    expect(r.status()).toBe(201);
    role = (await r.json()).id;
    expect(
      (
        await api.put("/api/v1/rbac/bindings", {
          data: { subject_type: "user", subject_id: user, role_ids: [role], revision: 0 },
        })
      ).status(),
    ).toBe(200);
    await op.goto(ui + "/console/reports");
    await expect(
      op.getByRole("heading", { name: "Operations reports", exact: true }),
    ).toBeVisible();
    await op.getByRole("combobox", { name: "Sources", exact: true }).selectOption("ssh_jobs");
    await op.getByRole("button", { name: "Apply interval", exact: true }).click();
    await expect(
      op
        .getByRole("table", { name: "Sources", exact: true })
        .getByRole("row")
        .filter({ hasText: "SSH jobs and tool actions" }),
    ).toContainText("My records");
    await expect(op.getByRole("button", { name: "Export CSV", exact: true })).toBeEnabled();
    const dl = op.waitForEvent("download");
    await op.getByRole("button", { name: "Export CSV", exact: true }).click();
    const download = await dl;
    const csv = await readFile((await download.path())!);
    expect(csv.toString()).toContain("ssh_jobs,mine");
    expect(csv.toString()).not.toContain("report-private-output");
    await expect(op.getByText(/Export recorded: report-export-/)).toBeVisible();
    const receipts = await (await guest.request.get(base + "/api/v1/reports/exports")).json();
    expect(receipts.total).toBe(1);
    expect(receipts.results[0].sha256).toBe(createHash("sha256").update(csv).digest("hex"));
    const cli = await execute(
      "go",
      ["run", "./cmd/jms", "reports", "export", "--sources", "ssh_jobs"],
      {
        cwd: fileURLToPath(new URL("../../server", import.meta.url)),
        env: { ...process.env, JMS_SERVER_URL: base, JMS_TOKEN: opToken, JMS_ORG_ID: "" },
      },
    );
    expect(cli.stdout).toContain("ssh_jobs,mine");
    expect(cli.stdout).not.toContain("report-private-output");
    const organization = await api.post("/api/v1/organizations", {
      data: { name: `Report isolation ${stamp}`, enabled: true },
    });
    expect(organization.status()).toBe(201);
    org = (await organization.json()).id;
    const isolated = await (
      await api.get("/api/v1/reports/exports", { headers: { "X-JMS-ORG": org } })
    ).json();
    expect(isolated.total).toBe(0);
    expect((await api.delete("/api/v1/grants/" + grant)).status()).toBe(204);
    grant = "";
    const inventory = await (
      await guest.request.get(base + "/api/v1/reports/overview?sources=assets")
    ).json();
    expect(inventory.sources[0].matched).toBe(0);
    const currentRole = await (await api.get("/api/v1/rbac/roles")).json();
    const roleData = currentRole.find((v: any) => v.id === role);
    expect(
      (
        await api.put("/api/v1/rbac/roles/" + role, {
          data: { name: roleData.name, revision: roleData.revision, permissions: [] },
        })
      ).status(),
    ).toBe(200);
    await op.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(op.getByRole("button", { name: "Export CSV", exact: true })).toBeDisabled();
    expect(
      (await guest.request.get(base + "/api/v1/reports/export.csv?sources=ssh_jobs")).status(),
    ).toBe(403);
    await page.goto(ui + "/console/reports");
    await expect(
      page.getByRole("table", { name: "Sources", exact: true }).getByRole("row"),
    ).toHaveCount(13);
    await page
      .getByRole("checkbox", { name: "Include global platform identities", exact: true })
      .check();
    await page.getByRole("button", { name: "Apply interval", exact: true }).click();
    await expect(
      page.getByRole("table", { name: "Sources", exact: true }).getByRole("row"),
    ).toHaveCount(15);
    await page.screenshot({ path: info.outputPath("reports.en.png"), fullPage: true });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole("heading", { name: "运营报表", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    await page.screenshot({ path: info.outputPath("reports.zh.narrow.png"), fullPage: true });
    expect(errors).toEqual([]);
  } finally {
    if (!retain) {
      if (grant) await api.delete("/api/v1/grants/" + grant);
      if (user) await api.delete("/api/v1/users/" + user);
      if (asset) await api.delete("/api/v1/assets/" + asset);
      if (org) await api.delete("/api/v1/organizations/" + org);
      if (role) {
        const roles = await (await api.get("/api/v1/rbac/roles")).json();
        const r = roles.find((v: any) => v.id === role);
        if (r) await api.delete(`/api/v1/rbac/roles/${role}?revision=${r.revision}`);
      }
    }
    await admin.close();
    await guest.close();
    await api.dispose();
  }
});

test("login wordmark remains accessible with native animation and reduced motion", async ({
  browser,
}) => {
  for (const reducedMotion of ["reduce", "no-preference"] as const) {
    const context = await browser.newContext({ locale: "en-US", reducedMotion });
    const page = await context.newPage();
    const errors: string[] = [];
    page.on("pageerror", (e) => errors.push(e.message));
    await page.goto(ui + "/login");
    await expect(page.getByRole("heading", { name: "JumpServer233", exact: true })).toBeVisible();
    if (reducedMotion === "reduce")
      expect(
        await page
          .locator("[data-blur-segment]")
          .evaluateAll((es) => es.flatMap((e) => e.getAnimations()).length),
      ).toBe(0);
    await page.emulateMedia({ reducedMotion: "reduce" });
    expect(errors).toEqual([]);
    await context.close();
  }
});
