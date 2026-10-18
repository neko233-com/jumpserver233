import { test, expect, request } from "@playwright/test";
import { createHmac } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const base = process.env.JMS_USERS_QA_BASE_URL || "http://127.0.0.1:8083",
  ui = process.env.JMS_USERS_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base)) throw Error("User QA requires loopback isolation");
test.use({ locale: "en-US" });
test("platform user lifecycle revokes live SSH and all REST credentials, with atomic batches, audit and bilingual UI", async ({
  browser,
}, info) => {
  test.setTimeout(150000);
  const api = await request.newContext({ baseURL: base }),
    admin = await browser.newContext({ locale: "en-US", viewport: { width: 1440, height: 1000 } }),
    operator = await browser.newContext({ locale: "en-US" });
  const page = await admin.newPage(),
    op = await operator.newPage(),
    errors: string[] = [];
  for (const p of [page, op]) p.on("pageerror", (e) => errors.push(e.message));
  const account = {
    username: `lifecycle.${Date.now()}`,
    password: "synthetic-user-lifecycle-233",
    role: "operator",
  };
  let assetID = "",
    userID = "";
  try {
    const credentials = {
      username: process.env.JMS_USERS_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_USERS_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok()).toBe(true);
    const adminToken = (await login.json()).access_token as string;
    await admin.request.post(ui + "/api/v1/authentication/auth/", {
      data: credentials,
      headers: { "X-JMS-Browser-Session": "cookie" },
    });
    const created = await api.post("/api/v1/users", { data: account });
    expect(created.status()).toBe(201);
    userID = (await created.json()).id;
    const fixture = await (
      await api.get(process.env.JMS_USERS_QA_FIXTURE_URL || "http://127.0.0.1:12223/health")
    ).json();
    const name = `Lifecycle SSH ${Date.now()}`;
    const asset = await api.post("/api/v1/assets", {
      data: {
        name,
        host: process.env.JMS_USERS_QA_SSH_HOST || "127.0.0.1",
        port: Number(fixture.address.split(":").at(-1)),
        username: fixture.username,
        password: process.env.JMS_USERS_QA_SSH_PASSWORD || "synthetic-qa-only-password",
        host_key_fingerprint: fixture.fingerprint,
      },
    });
    expect(asset.status()).toBe(201);
    assetID = (await asset.json()).id;
    expect(
      (
        await api.post("/api/v1/grants", {
          data: {
            user_id: userID,
            asset_id: assetID,
            account: fixture.username,
            actions: ["view", "connect"],
          },
        })
      ).status(),
    ).toBe(201);
    const userLogin = await api.post("/api/v1/authentication/auth/", {
      data: { username: account.username, password: account.password },
    });
    expect(userLogin.ok()).toBe(true);
    const oldToken = (await userLogin.json()).access_token as string;
    // Keep the administrator context separate from the operator credentials.
    const headers = { Authorization: `Bearer ${adminToken}` },
      old = { Authorization: `Bearer ${oldToken}` };
    const current = async () => (await api.get("/api/v1/users/" + userID, { headers })).json();
    const change = async (data: object) =>
      api.put("/api/v1/users/" + userID, {
        headers,
        data: { revision: (await current()).revision, ...data },
      });
    const key = await (await api.post("/api/v1/users/me/access-keys", { headers: old })).json(),
      permanent = await (await api.post("/api/v1/users/me/tokens", { headers: old })).json();
    const signed = () => {
      const date = new Date().toUTCString(),
        signing = `(request-target): get /api/v1/users/me\ndate: ${date}`;
      return {
        Date: date,
        Authorization: `Signature keyId="${key.access_key_id}",algorithm="hmac-sha256",headers="(request-target) date",signature="${createHmac("sha256", key.access_key_secret).update(signing).digest("base64")}"`,
      };
    };
    expect((await api.get("/api/v1/users/me", { headers: signed() })).status()).toBe(200);
    await operator.request.post(ui + "/api/v1/authentication/auth/", {
      data: { username: account.username, password: account.password },
      headers: { "X-JMS-Browser-Session": "cookie" },
    });
    await op.goto(ui + "/console");
    await op
      .getByRole("row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    await expect(op.locator(".ssh-terminal-status")).toHaveText("Connected");
    await page.goto(ui + "/console/users");
    await expect(page.getByRole("heading", { name: "Platform users", exact: true })).toBeVisible();
    await page.getByLabel("Search users", { exact: true }).fill(account.username);
    await page.getByRole("button", { name: "Search users", exact: true }).click();
    const row = page.locator("tbody tr").filter({ hasText: account.username }).first();
    await row.getByRole("button", { name: "Edit", exact: true }).click();
    await page.getByLabel("Display name", { exact: true }).fill("Lifecycle display");
    await page.getByRole("button", { name: "Review change" }).click();
    await page.getByRole("button", { name: "Apply changes" }).click();
    await expect(page.getByRole("status")).toHaveText("Changes saved.");
    expect((await api.get("/api/v1/users/me", { headers: old })).status()).toBe(200);
    await row.getByRole("checkbox").check();
    await page.getByRole("button", { name: "Disable", exact: true }).click();
    await page.getByRole("button", { name: "Apply changes" }).click();
    await expect(op.locator(".ssh-terminal-status")).not.toHaveText("Connected", { timeout: 15000 });
    for (const auth of [old, { Authorization: `Token ${permanent.token}` }, signed()])
      expect((await api.get("/api/v1/users/me", { headers: auth })).status()).toBe(401);
    const denied = await api.post("/api/v1/authentication/auth/", {
      data: { username: account.username, password: account.password },
    });
    expect(denied.status()).toBe(401);
    expect((await change({ is_active: true })).status()).toBe(200);
    for (const auth of [old, { Authorization: `Token ${permanent.token}` }, signed()])
      expect((await api.get("/api/v1/users/me", { headers: auth })).status()).toBe(401);
    const before = await current();
    const conflict = await api.post("/api/v1/users/actions", {
      headers,
      data: {
        changes: [
          { id: userID, action: "update", revision: before.revision, name: "must roll back" },
          {
            id: (await api.get("/api/v1/users/me", { headers }).then((r) => r.json())).id,
            action: "revoke",
            revision: 999999,
          },
        ],
      },
    });
    expect(conflict.status()).toBe(409);
    expect((await current()).name).toBe("Lifecycle display");
    expect((await change({ date_expired: "2020-01-01T00:00:00Z" })).status()).toBe(200);
    expect((await current()).state).toBe("expired");
    expect((await change({ clear_date_expired: true })).status()).toBe(200);
    const archived = await api.delete(
      `/api/v1/users/${userID}?revision=${(await current()).revision}`,
      { headers },
    );
    expect(archived.status()).toBe(200);
    expect(
      (await (await api.get("/api/v1/users", { headers })).json()).some(
        (u: { id: string }) => u.id === userID,
      ),
    ).toBe(false);
    expect(
      (
        await api.post(`/api/v1/users/${userID}/restore`, {
          headers,
          data: { revision: (await current()).revision },
        })
      ).status(),
    ).toBe(200);
    expect((await current()).state).toBe("disabled");
    const audit = await (
      await api.get("/api/v1/users/audit?user_id=" + userID, { headers })
    ).json();
    expect(audit.total).toBeGreaterThanOrEqual(7);
    expect(JSON.stringify(audit)).not.toContain("Lifecycle display");
    expect(JSON.stringify(audit)).not.toContain(account.password);
    const cli = await execute("go", ["run", "./cmd/jms", "user", "show", userID], {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      env: { ...process.env, JMS_SERVER_URL: base, JMS_TOKEN: adminToken },
      timeout: 60000,
    });
    expect(JSON.parse(cli.stdout).state).toBe("disabled");
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(row).toContainText("Disabled");
    await page.screenshot({ path: info.outputPath("users.en.png") });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "平台用户", exact: true })).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: info.outputPath("users.zh-CN.mobile.png") });
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    expect(errors).toEqual([]);
  } finally {
    // Synthetic users are archived with revision protection; history remains inspectable.
    const credentials = {
      username: process.env.JMS_USERS_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_USERS_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    await api.post("/api/v1/authentication/auth/", { data: credentials }).catch(() => {});
    if (assetID) await api.delete("/api/v1/assets/" + assetID).catch(() => {});
    if (userID) {
      const r = await api.get("/api/v1/users/" + userID).catch(() => null);
      if (r?.ok()) {
        const u = await r.json();
        if (u.state !== "archived")
          await api.delete(`/api/v1/users/${userID}?revision=${u.revision}`).catch(() => {});
      }
    }
    await api.dispose();
    await admin.close();
    await operator.close();
  }
});
