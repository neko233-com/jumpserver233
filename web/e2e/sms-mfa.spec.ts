import { test, expect, type BrowserContext, type Page } from "@playwright/test";
import { randomUUID } from "node:crypto";
test.use({ locale: "en-US", trace: "off", screenshot: "off" });
test("native SMS withholds local and enterprise SSO sessions, binds phones and revokes stale credentials", async ({
  page,
  browser,
}, info) => {
  test.setTimeout(120000);
  const api = page.request;
  const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
  let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
  if (login.status() !== 200) {
    expect([201, 409]).toContain(
      (await api.post("/api/v1/authentication/bootstrap", { data: credentials })).status(),
    );
    login = await api.post("/api/v1/authentication/auth/", { data: credentials });
  }
  expect(login.status()).toBe(200);
  const origin = new URL(info.project.use.baseURL as string).origin;
  await page.context().addCookies([
    {
      name: "jms_sessionid",
      value: (await login.json()).access_token,
      url: origin,
      httpOnly: true,
      sameSite: "Lax",
    },
  ]);
  const stamp = randomUUID();
  const seed = Number(BigInt("0x" + stamp.replaceAll("-", "").slice(0, 8)) % 999999n);
  const phone = (offset: number) =>
    "+8613800" + String((seed + offset) % 1_000_000).padStart(6, "0");
  const contexts: BrowserContext[] = [];
  const users: string[] = [];
  let sourceID = "";
  const oldSMS = await (await api.get("/api/v1/settings/security/sms-mfa")).json();
  const oldTOTP = await (await api.get("/api/v1/settings/security/mfa")).json();
  const notificationBase = "/api/v1/platform-notifications";
  const oldSettings = await (await api.get(notificationBase + "/settings")).json();
  expect(oldSettings.sms.secret_configured).toBe(false);
  const fixture = await (await api.get("http://127.0.0.1:12226/enterprise/health")).json();
  const errors: string[] = [];
  async function verify(user: Page, context: BrowserContext, number: string) {
    await expect(
      user.getByRole("heading", { name: "SMS verification", exact: true }),
    ).toBeVisible();
    expect((await context.request.get("/api/v1/users/me")).status()).toBe(401);
    const cookie = (await context.cookies()).find((c) => c.name === "jms_sms_factor");
    expect(Boolean(cookie?.httpOnly && cookie.path === "/api/v1/authentication/sms")).toBe(true);
    await user.getByLabel("Phone number (E.164)", { exact: true }).fill(number);
    await user.getByRole("button", { name: "Send code", exact: true }).click();
    let code = "";
    await expect
      .poll(
        async () => {
          const rows = await (
            await api.get("http://127.0.0.1:12226/enterprise/notifications")
          ).json();
          code =
            rows.findLast((v: { to: string; code: string }) => v.to === number && v.code)?.code ??
            "";
          return code.length;
        },
        { timeout: 20000 },
      )
      .toBe(6);
    const pending = await (await context.request.get("/api/v1/authentication/sms/pending")).json();
    expect(pending.masked_phone).toBe("***" + number.slice(-4));
    expect(Object.hasOwn(pending, "code")).toBe(false);
    await user
      .getByLabel("Six-digit SMS code", { exact: true })
      .fill(code === "000000" ? "111111" : "000000");
    await user.getByRole("button", { name: "Verify code", exact: true }).click();
    await expect(user.getByRole("alert")).toBeVisible();
    await user.getByLabel("Six-digit SMS code", { exact: true }).fill(code);
    const response = user.waitForResponse(
      (r) => r.url().endsWith("/sms/complete") && r.request().method() === "POST",
    );
    await user.getByRole("button", { name: "Verify code", exact: true }).click();
    const result = await response;
    expect(result.status()).toBe(200);
    const body = await result.json();
    expect(Object.hasOwn(body, "access_token")).toBe(false);
    await expect(user).toHaveURL(/\/console/);
    const current = await (await context.request.get("/api/v1/users/me")).json();
    expect(current.sms_mfa_enabled).toBe(true);
    expect(Object.hasOwn(current, "phone")).toBe(false);
    expect(
      (
        await context.request.post("/api/v1/authentication/sms/complete", {
          data: { code },
          headers: { Cookie: `jms_sms_factor=${cookie?.value ?? ""}` },
        })
      ).status(),
    ).toBe(401);
    return current;
  }
  try {
    expect(
      (
        await api.put(notificationBase + "/settings", {
          data: {
            ...oldSettings,
            request_id: randomUUID(),
            sms: {
              ...oldSettings.sms,
              enabled: true,
              provider: "aliyun",
              url: "",
              ca: fixture.ca_pem,
              native_sms: {
                access_key_id: "synthetic-sms-access-key",
                region: "",
                app_id: "",
                endpoint: "",
                sender: "",
                service_id: "",
                sign_name: "Synthetic",
                verification: { id: "verification-001", parameters: ["code"] },
                notification: { id: "notification-001", parameters: ["title", "state"] },
              },
            },
            sms_secret: "synthetic-native-notification-secret",
          },
        })
      ).status(),
    ).toBe(200);
    expect(
      (await api.put("/api/v1/settings/security/mfa", { data: { mode: "disabled" } })).status(),
    ).toBe(200);
    await page.goto("/console/sms-mfa");
    await page.getByLabel("Enable SMS factor", { exact: true }).check();
    await page.getByLabel("Required audience", { exact: true }).selectOption("all");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByRole("status")).toHaveText("SMS policy saved.");
    const username = "sms.qa." + stamp.slice(0, 8),
      password = "synthetic-sms-password-2468";
    const created = await api.post("/api/v1/users", {
      data: { username, password, role: "operator" },
    });
    expect(created.status()).toBe(201);
    users.push((await created.json()).id);
    const local = await browser.newContext({ baseURL: origin, locale: "en-US" });
    contexts.push(local);
    const localPage = await local.newPage();
    localPage.on("pageerror", (e) => errors.push(e.message));
    const primary = await local.request.post("/api/v1/authentication/auth/", {
      headers: { "X-JMS-Browser-Session": "cookie" },
      data: { username, password },
    });
    expect(primary.status()).toBe(202);
    const initial = await primary.json();
    expect(initial.sms_factor_required).toBe(true);
    expect(Object.hasOwn(initial, "factor_token")).toBe(false);
    expect(Object.hasOwn(initial, "access_token")).toBe(false);
    await localPage.goto("/login?factor=sms");
    await verify(localPage, local, phone(1));
    await localPage.goto("/console/profile");
    await expect(
      localPage.getByRole("heading", { name: "SMS multi-factor authentication", exact: true }),
    ).toBeVisible();
    await expect(
      localPage.getByText("Bound phone: ***" + phone(1).slice(-4), { exact: true }),
    ).toBeVisible();
    await localPage.setViewportSize({ width: 390, height: 844 });
    expect(await localPage.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    await localPage.screenshot({ path: info.outputPath("sms-mfa.en.png"), fullPage: true });
    await localPage.getByTitle("中文 / English", { exact: true }).click();
    await expect(
      localPage.getByRole("heading", { name: "短信多因素认证", exact: true }),
    ).toBeVisible();
    await localPage.screenshot({ path: info.outputPath("sms-mfa.zh-CN.png"), fullPage: true });
    const source = await api.post("/api/v1/identity-sources", {
      data: { name: "SMS SSO " + stamp, kind: "wecom", enabled: true, request_id: randomUUID() },
    });
    expect(source.status()).toBe(200);
    sourceID = (await source.json()).id;
    const prefix = "/api/v1/identity-sources/" + sourceID;
    expect(
      (
        await api.put(prefix + "/api/v1/settings/security/wecom", {
          data: {
            provider: "wecom",
            client_id: "synthetic-wecom-corp",
            tenant_id: "synthetic-wecom-corp",
            agent_id: "1000001",
            region: "cn",
            oauth_version: "v3",
            callback_url: origin + prefix + "/api/v1/authentication/wecom/callback",
            scopes: [],
            ca_pem: fixture.ca_pem,
            allow_loopback_http: true,
            enabled: true,
            provision_new: true,
            revision: 0,
            client_secret: "synthetic-enterprise-application-secret",
            request_id: randomUUID(),
          },
        })
      ).status(),
    ).toBe(200);
    const external = await browser.newContext({ baseURL: origin, locale: "en-US" });
    contexts.push(external);
    const externalPage = await external.newPage();
    externalPage.on("pageerror", (e) => errors.push(e.message));
    await externalPage.route(/^https:\/\/login\.work\.weixin\.qq\.com\//, async (route) => {
      const response = await api.get(
        "http://127.0.0.1:12226/enterprise/authorize/wecom" + new URL(route.request().url()).search,
      );
      await route.fulfill({ response });
    });
    await externalPage.goto(prefix + "/api/v1/authentication/wecom/start");
    await externalPage
      .getByRole("link", { name: "Continue as synthetic enterprise operator", exact: true })
      .click();
    await externalPage.getByRole("button", { name: "Complete sign-in", exact: true }).click();
    await expect(externalPage).toHaveURL(/factor=sms/);
    const current = await verify(externalPage, external, phone(2));
    users.push(current.id);
    expect(current.source).toBe("wecom");
    expect(current.source_id).toBe(sourceID);
    expect(errors).toEqual([]);
  } finally {
    for (const context of contexts) await context.close();
    const policy = await (await api.get("/api/v1/settings/security/sms-mfa")).json();
    expect(
      (
        await api.put("/api/v1/settings/security/sms-mfa", {
          data: { ...oldSMS, revision: policy.revision, request_id: randomUUID() },
        })
      ).status(),
    ).toBe(200);
    expect((await api.put("/api/v1/settings/security/mfa", { data: oldTOTP })).status()).toBe(200);
    const settings = await (await api.get(notificationBase + "/settings")).json();
    expect(
      (
        await api.put(notificationBase + "/settings", {
          data: {
            ...oldSettings,
            revision: settings.revision,
            request_id: randomUUID(),
            sms_secret: "",
            sms_bearer: "",
          },
        })
      ).status(),
    ).toBe(200);
    for (let round = 0; round < 2; round++) {
      if (sourceID) {
        const source = await (await api.get("/api/v1/identity-sources/" + sourceID)).json();
        if (source.id && !source.archived)
          expect(
            (
              await api.put("/api/v1/identity-sources/" + sourceID, {
                data: {
                  name: source.name,
                  kind: source.kind,
                  enabled: false,
                  archived: true,
                  revision: source.revision,
                  request_id: randomUUID(),
                },
              })
            ).status(),
          ).toBe(200);
      }
      for (const id of users) {
        const read = await api.get("/api/v1/users/" + id);
        if (read.status() === 404) continue;
        expect(read.status()).toBe(200);
        const user = await read.json();
        if (!user.archived_at) {
          const result = await api.delete(`/api/v1/users/${id}?revision=${user.revision}`);
          expect(result.status()).toBe(200);
        }
      }
    }
  }
});
