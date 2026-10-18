import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const base = process.env.JMS_LOGIN_AUDIT_QA_BASE_URL || "http://127.0.0.1:8083";
const ui = process.env.JMS_LOGIN_AUDIT_QA_BASE_URL || "http://127.0.0.1:5177";
const capture = process.env.JMS_LOGIN_AUDIT_QA_CAPTURE_URL || "http://127.0.0.1:12604";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base) || !/^http:\/\/127\.0\.0\.1:\d+$/.test(capture))
  throw Error("Platform login audit QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });
test("platform login audit separates grants, native reviews, global notification delivery and current authorization", async ({
  browser,
}, info) => {
  test.setTimeout(150_000);
  const stamp = Date.now(),
    retain = process.env.JMS_LOGIN_AUDIT_QA_RETAIN === "true";
  const api = await request.newContext({ baseURL: base }),
    applicant = await request.newContext({ baseURL: base });
  const admin = await browser.newContext({
      locale: "en-US",
      viewport: { width: 1440, height: 1080 },
    }),
    operator = await browser.newContext({ locale: "en-US" });
  const page = await admin.newPage(),
    op = await operator.newPage(),
    errors: string[] = [];
  for (const p of [page, op]) p.on("pageerror", (e) => errors.push(e.message));
  const account = {
    username: `login.audit.${stamp}`,
    password: "synthetic-login-audit-operator-233",
    role: "operator",
  };
  let userID = "",
    roleID = "",
    policyID = "",
    policyRevision = 0,
    token = "",
    originalSettings: any,
    originalPreferences: any;
  const audit = async (q = "") =>
    (await (await api.get("/api/v1/audits/logins?limit=200&scope=all" + q)).json())
      .results as any[];
  const inbox = async () =>
    (await (await api.get("/api/v1/platform-notifications/inbox?limit=100")).json())
      .results as any[];
  try {
    const credentials = {
      username: process.env.JMS_LOGIN_AUDIT_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_LOGIN_AUDIT_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok()).toBe(true);
    token = (await login.json()).access_token;
    await admin.addCookies((await api.storageState()).cookies);
    originalSettings = await (await api.get("/api/v1/platform-notifications/settings")).json();
    originalPreferences = await (
      await api.get("/api/v1/platform-notifications/preferences")
    ).json();
    const orgSettings = await (await api.get("/api/v1/notifications/settings")).json();
    const health = await (await api.get(capture + "/health")).json();
    expect(
      (
        await api.put("/api/v1/platform-notifications/settings", {
          data: {
            ...originalSettings,
            webhook: {
              enabled: true,
              url: `https://${process.env.JMS_LOGIN_AUDIT_QA_TRANSPORT_HOST || "127.0.0.1"}:${health.https_port}/webhook`,
              ca: health.ca,
            },
            webhook_secret: "synthetic-platform-signing-233",
          },
        })
      ).status(),
    ).toBe(200);
    expect((await (await api.get("/api/v1/notifications/settings")).json()).revision).toBe(
      orgSettings.revision,
    );
    expect(
      (
        await api.put("/api/v1/platform-notifications/preferences", {
          data: {
            revision: originalPreferences.revision,
            language: "en",
            topics: {
              ...originalPreferences.topics,
              security: ["inbox", "webhook"],
              approvals: ["inbox", "webhook"],
            },
          },
        })
      ).status(),
    ).toBe(200);
    const created = await api.post("/api/v1/users", { data: account });
    expect(created.status()).toBe(201);
    userID = (await created.json()).id;
    expect(
      (
        await operator.request.post(base + "/api/v1/authentication/auth/", {
          data: { username: account.username, password: account.password },
        })
      ).status(),
    ).toBe(200);
    // One failed password attempt avoids tripping the shared production-suite sign-in limiter.
    expect(
      (
        await applicant.post("/api/v1/authentication/auth/", {
          data: { username: account.username, password: "synthetic-incorrect-password-233" },
        })
      ).status(),
    ).toBe(401);
    const own = (await (await operator.request.get(base + "/api/v1/audits/logins")).json())
      .results as any[];
    expect(own.some((v) => v.outcome === "succeeded" && v.user_id === userID)).toBe(true);
    expect(own.every((v) => v.user_id === userID)).toBe(true);
    expect((await operator.request.get(base + "/api/v1/audits/logins?scope=all")).status()).toBe(
      403,
    );
    const failure = (await audit("&outcome=failed")).find(
      (v) => v.attempted_name === account.username,
    );
    expect(failure).toBeTruthy();
    expect(failure.user_id).toBeUndefined();
    expect(
      (await operator.request.get(base + "/api/v1/audits/logins/" + failure.id)).status(),
    ).toBe(404);
    const success = (await audit("&outcome=succeeded&user_id=" + userID))[0];
    expect(success).toBeTruthy();
    await expect
      .poll(async () => (await inbox()).some((v) => v.source.id === success.id), {
        timeout: 15_000,
      })
      .toBe(true);
    const message = (await inbox()).find((v) => v.source.id === success.id);
    await expect
      .poll(
        async () => {
          const records = await (await api.get(capture + "/messages")).json();
          return records.some(
            (v: any) => v.channel === "webhook" && v.body.includes(message.source.event_id),
          );
        },
        { timeout: 15_000 },
      )
      .toBe(true);
    const delivered = (await (await api.get(capture + "/messages")).json()).filter(
      (v: any) => v.channel === "webhook" && v.body.includes(message.source.event_id),
    );
    for (const v of delivered) {
      expect(v.signature).toMatch(/^[a-f0-9]{64}$/);
      expect(v.body).not.toContain(account.username);
      expect(v.body).not.toContain(account.password);
      const payload = JSON.parse(v.body);
      expect(payload).not.toHaveProperty("source_ip");
      expect(payload.source).not.toHaveProperty("source_ip");
      // The configured site link can use the same loopback IP as the client.
      expect(payload.text.replace(/https?:\/\/\S+/g, "")).not.toContain(success.source_ip);
    }
    await page.goto(ui + "/console/login-audit");
    await expect(
      page.getByRole("heading", { name: "Platform sign-in audit", exact: true }),
    ).toBeVisible();
    await page.getByLabel("User or event ID", { exact: true }).fill(account.username);
    await page.getByRole("button", { name: "Apply filters", exact: true }).click();
    await expect(page.getByRole("row").filter({ hasText: account.username })).not.toHaveCount(0);
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export CSV", exact: true }).click();
    expect((await download).suggestedFilename()).toBe("platform-login-audit.csv");
    await page.screenshot({ path: info.outputPath("login-audit.en.png"), fullPage: true });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "平台登录审计", exact: true })).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await page.screenshot({ path: info.outputPath("login-audit.zh-CN.png"), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 1080 });
    await page.getByRole("button", { name: "EN", exact: true }).click();
    const role = await api.post("/api/v1/system/rbac/roles", {
      data: { name: `Global login audit ${stamp}`, permissions: ["audit.logins.view_all"] },
    });
    expect(role.status()).toBe(201);
    const r = await role.json();
    roleID = r.id;
    expect(
      (
        await api.put("/api/v1/system/rbac/bindings", {
          data: { subject_type: "user", subject_id: userID, role_ids: [roleID] },
        })
      ).status(),
    ).toBe(200);
    await op.goto(ui + "/console/login-audit");
    await expect(op.getByRole("combobox", { name: "Scope", exact: true })).toHaveValue("all");
    await expect(op.getByRole("button", { name: "Export CSV", exact: true })).toBeDisabled();
    await op.goto(ui + "/console/login-audit?event=" + failure.id);
    await expect(op.getByRole("dialog")).toContainText(failure.source_ip);
    expect(
      (
        await api.put("/api/v1/system/rbac/roles/" + roleID, {
          data: { name: r.name, revision: r.revision, permissions: [] },
        })
      ).status(),
    ).toBe(200);
    await expect(op.getByRole("dialog").getByRole("alert")).toContainText("unavailable");
    await expect(op.getByRole("dialog")).not.toContainText(failure.source_ip);
    await op.keyboard.press("Escape");
    await op.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(op.getByRole("combobox", { name: "Scope", exact: true })).toHaveValue("mine");
    const catalog = await (await api.get("/api/v1/organization-rbac/permissions")).json();
    expect(catalog).not.toContain("audit.logins.view_all");
    expect(catalog).not.toContain("audit.logins.export");
    const policy = await api.post("/api/v1/platform-access-policies", {
      data: {
        name: `Login audit review ${stamp}`,
        kind: "login",
        user_id: userID,
        action: "review",
        enabled: true,
        priority: 80,
        timezone: "UTC",
      },
    });
    expect(policy.status()).toBe(201);
    const pv = await policy.json();
    policyID = pv.id;
    policyRevision = pv.revision;
    const pending = await applicant.post("/api/v1/authentication/auth/", {
      data: { username: account.username, password: account.password },
    });
    expect(pending.status()).toBe(202);
    const review = await pending.json();
    expect(review.access_token).toBeUndefined();
    await expect
      .poll(
        async () =>
          (await audit("&user_id=" + userID)).find(
            (v) =>
              v.stage === "review" &&
              v.outcome === "review_pending" &&
              v.review_id === review.review_id,
          ),
        { timeout: 15_000 },
      )
      .toBeTruthy();
    const event = (await audit("&user_id=" + userID)).find(
      (v) =>
        v.stage === "review" && v.outcome === "review_pending" && v.review_id === review.review_id,
    );
    await page.goto(ui + "/console/login-audit?event=" + event.id);
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByRole("button", { name: "Approve", exact: true })).toBeVisible();
    await dialog.getByRole("button", { name: "Approve", exact: true }).click();
    await dialog.getByRole("button", { name: "Confirm decision", exact: true }).click();
    await expect(dialog.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);
    expect(
      (
        await applicant.post("/api/v1/authentication/login-review/complete", {
          data: { review_token: review.review_token },
        })
      ).status(),
    ).toBe(200);
    await expect
      .poll(
        async () =>
          (await audit("&user_id=" + userID)).some(
            (v) => v.outcome === "succeeded" && v.review_id === review.review_id,
          ),
        { timeout: 10_000 },
      )
      .toBe(true);
    await page.keyboard.press("Escape");
    await page.goto(ui + "/console/platform-notifications");
    await expect(
      page.getByRole("heading", { name: "Platform notifications", exact: true }),
    ).toBeVisible();
    await expect(page.locator(".notification-inbox")).toContainText("Platform session issued");
    await page.getByRole("link", { name: "Organization notifications", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Notifications", exact: true })).toBeVisible();
    await expect(page.locator(".notification-inbox")).not.toContainText("Platform session issued");
    const cli = await execute(
      "go",
      ["run", "./cmd/jms", "login-audit", "list", "--all", "--query", account.username],
      {
        cwd: fileURLToPath(new URL("../../server", import.meta.url)),
        timeout: 60_000,
        env: {
          ...process.env,
          JMS_SERVER_URL: base,
          JMS_TOKEN: token,
          JMS_ORG_ID: "",
          JMS_ACCOUNT: "",
          JMS_ACCESS_KEY_ID: "",
          JMS_ACCESS_KEY_SECRET: "",
        },
      },
    );
    expect(JSON.parse(cli.stdout).results.some((v: any) => v.user_id === userID)).toBe(true);
    expect(cli.stdout).not.toContain(account.password);
    expect(errors).toEqual([]);
    await info.attach("platform-login-result", {
      body: JSON.stringify({
        userID,
        eventID: event.id,
        reviewID: review.review_id,
        granted: true,
        globalWebhook: true,
        pageErrors: errors,
      }),
      contentType: "application/json",
    });
  } finally {
    if (policyID)
      await api.delete(`/api/v1/platform-access-policies/${policyID}?revision=${policyRevision}`);
    if (originalPreferences) {
      const p = await (await api.get("/api/v1/platform-notifications/preferences")).json();
      await api.put("/api/v1/platform-notifications/preferences", {
        data: {
          revision: p.revision,
          language: originalPreferences.language,
          email: originalPreferences.email,
          phone: originalPreferences.phone,
          topics: originalPreferences.topics,
        },
      });
    }
    if (originalSettings) {
      const s = await (await api.get("/api/v1/platform-notifications/settings")).json();
      await api.put("/api/v1/platform-notifications/settings", {
        data: {
          ...originalSettings,
          revision: s.revision,
          webhook_secret: "",
        },
      });
    }
    if (!retain) {
      if (userID) await api.delete("/api/v1/users/" + userID);
      if (roleID) {
        const roles = await (await api.get("/api/v1/system/rbac/roles")).json();
        const r = roles.find((v: any) => v.id === roleID);
        if (r) await api.delete(`/api/v1/system/rbac/roles/${roleID}?revision=${r.revision}`);
      }
    }
    await operator.close();
    await admin.close();
    await applicant.dispose();
    await api.dispose();
  }
});
