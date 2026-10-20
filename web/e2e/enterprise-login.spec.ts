import { test, expect } from "@playwright/test";
import { createHmac, randomUUID } from "node:crypto";
test.use({ locale: "en-US", trace: "off", screenshot: "off" });
function totp(secret: string) {
  let value = 0,
    bits = 0;
  const bytes: number[] = [];
  for (const ch of secret.replace(/=+$/, "")) {
    value = (value << 5) | "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 255);
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  return String(
    (digest.readUInt32BE(digest[digest.length - 1] & 15) & 0x7fffffff) % 1000000,
  ).padStart(6, "0");
}
test("completes native enterprise authorization through verified HTTPS with MFA, revocation and bilingual settings", async ({
  page,
  browser,
}, testInfo) => {
  test.setTimeout(150000);
  const api = page.request;
  const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
  let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
  if (login.status() !== 200) {
    const initialized = await api.post("/api/v1/authentication/bootstrap", { data: credentials });
    expect([201, 409]).toContain(initialized.status());
    login = await api.post("/api/v1/authentication/auth/", { data: credentials });
  }
  expect(login.status()).toBe(200);
  const origin = new URL(testInfo.project.use.baseURL as string).origin;
  await page.context().addCookies([
    {
      name: "jms_sessionid",
      value: (await login.json()).access_token,
      url: origin,
      httpOnly: true,
      sameSite: "Lax",
    },
  ]);
  const fixtureResponse = await api.get("http://127.0.0.1:12226/enterprise/health");
  expect(fixtureResponse.status()).toBe(200);
  const fixture = await fixtureResponse.json();
  const oldPolicy = await (await api.get("/api/v1/settings/security/mfa")).json();
  const sourceIDs: string[] = [];
  let lastPage = "";
  try {
    expect(
      (await api.put("/api/v1/settings/security/mfa", { data: { mode: "all" } })).status(),
    ).toBe(200);
    for (const tc of [
      {
        kind: "wecom",
        title: "WeCom",
        client: "synthetic-wecom-corp",
        tenant: "synthetic-wecom-corp",
        region: "cn",
      },
      {
        kind: "dingtalk",
        title: "DingTalk",
        client: "synthetic-dingtalk-app",
        tenant: "synthetic-enterprise-tenant",
        region: "cn",
      },
      {
        kind: "feishu",
        title: "Feishu / Lark",
        client: "cli_synthetic_feishu",
        tenant: "synthetic-enterprise-tenant",
        region: "cn",
      },
      {
        kind: "feishu",
        title: "Feishu / Lark",
        client: "cli_synthetic_feishu",
        tenant: "synthetic-enterprise-tenant",
        region: "global",
      },
    ]) {
      const name = tc.title + " " + tc.region + " " + randomUUID();
      const made = await api.post("/api/v1/identity-sources", {
        data: {
          name,
          kind: tc.kind,
          enabled: true,
          archived: false,
          revision: 0,
          request_id: "native-create-" + randomUUID(),
        },
      });
      expect(made.status()).toBe(201);
      const source = await made.json();
      sourceIDs.push(source.id);
      const base = "/api/v1/identity-sources/" + source.id;
      lastPage = `/console/enterprise-login?source_id=${source.id}&provider=${tc.kind}`;
      await page.goto(lastPage);
      await expect(
        page.getByRole("heading", { name: tc.title + " sign-in", exact: true }),
      ).toBeVisible();
      await page.getByLabel("Corp ID / App Key / App ID", { exact: true }).fill(tc.client);
      if (tc.kind === "wecom")
        await page.getByLabel("WeCom Agent ID", { exact: true }).fill("1000001");
      else await page.getByLabel("Corp ID / tenant_key", { exact: true }).fill(tc.tenant);
      if (tc.kind === "feishu")
        await page.getByLabel("Provider region", { exact: true }).selectOption(tc.region);
      await page
        .getByLabel("Application secret (write only)", { exact: true })
        .fill("synthetic-enterprise-application-secret");
      await page.getByText("Advanced", { exact: true }).click();
      await page
        .getByLabel("Additional CA certificates (PEM, optional)", { exact: true })
        .fill(fixture.ca_pem);
      await page
        .getByRole("checkbox", {
          name: "Allow literal loopback HTTP callbacks for local development",
          exact: true,
        })
        .check();
      await page.getByRole("checkbox", { name: "Enable provider sign-in", exact: true }).check();
      await page
        .getByRole("checkbox", { name: "Provision new operators on first sign-in", exact: true })
        .check();
      const saving = page.waitForResponse(
        (r) => r.url().endsWith("/settings/security/" + tc.kind) && r.request().method() === "PUT",
      );
      await page.getByRole("button", { name: "Save provider settings", exact: true }).click();
      const savedResponse = await saving;
      expect(savedResponse.status()).toBe(200);
      const saved = await savedResponse.json();
      const retry = await api.put(base + "/api/v1/settings/security/" + tc.kind, {
        data: savedResponse.request().postDataJSON(),
      });
      expect(await retry.json()).toEqual(saved);
      expect(JSON.stringify(saved)).not.toContain("synthetic-enterprise-application-secret");
      await expect(page.getByLabel("Application secret (write only)", { exact: true })).toHaveValue(
        "",
      );
      await page
        .getByRole("button", { name: "Check application credentials", exact: true })
        .click();
      await expect(page.getByRole("status")).toHaveText(
        "Application credentials are available. This does not establish actual QR sign-in or member permissions.",
      );
      const context = await browser.newContext({ baseURL: origin, locale: "en-US" });
      try {
        const user = await context.newPage();
        await user.route(
          /^https:\/\/(login\.work\.weixin\.qq\.com|login\.dingtalk\.com|accounts\.feishu\.cn|accounts\.larksuite\.com)\//,
          async (route) => {
            const u = new URL(route.request().url());
            const response = await api.get(
              "http://127.0.0.1:12226/enterprise/authorize/" + tc.kind + u.search,
            );
            expect(response.status()).toBe(200);
            await route.fulfill({ response });
          },
        );
        await user.goto("/login");
        await user.getByRole("link", { name: "Sign in with " + name, exact: true }).click();
        await expect(
          user.getByRole("heading", {
            name: "Synthetic " + tc.kind + " authorization",
            exact: true,
          }),
        ).toBeVisible();
        const flow = (await context.cookies()).find((c) => c.name === "jms_" + tc.kind + "_flow");
        expect(flow).toMatchObject({
          httpOnly: true,
          path: base + "/api/v1/authentication/" + tc.kind,
        });
        await user
          .getByRole("link", { name: "Continue as synthetic enterprise operator", exact: true })
          .click();
        await expect(user).toHaveURL(new RegExp("enterprise=" + tc.kind));
        await expect(
          user.getByRole("heading", { name: "Complete enterprise sign-in", exact: true }),
        ).toBeVisible();
        expect((await user.request.get("/api/v1/users/me")).status()).toBe(401);
        await user.getByRole("button", { name: "Complete sign-in", exact: true }).click();
        await expect(user.locator(".login-mfa-setup")).toBeVisible();
        const secret = await user.locator(".login-mfa-setup code").first().innerText();
        await user.getByLabel("Authenticator code", { exact: true }).fill(totp(secret));
        const completing = user.waitForResponse(
          (r) => r.url().endsWith("/" + tc.kind + "/complete") && r.request().method() === "POST",
        );
        await user.getByRole("button", { name: "Verify and sign in", exact: true }).click();
        const completed = await completing;
        expect(completed.status()).toBe(200);
        const result = await completed.json();
        expect(result.user).toMatchObject({
          source: tc.kind,
          source_id: source.id,
          role: "operator",
        });
        expect(result).not.toHaveProperty("access_token");
        await expect(user).toHaveURL(/\/console$/);
        await user.goto("/profile");
        await expect(
          user.getByText(
            "This account uses enterprise identity sign-in. Its primary credential is managed by the provider.",
            { exact: true },
          ),
        ).toBeVisible();
        await expect(
          user.getByRole("button", { name: "Change password", exact: true }),
        ).toHaveCount(0);
        const current = await (await api.get(base)).json();
        const off = await api.put(base, {
          data: {
            name: current.name,
            kind: tc.kind,
            enabled: false,
            archived: false,
            revision: current.revision,
            request_id: "native-disable-" + randomUUID(),
          },
        });
        expect(off.status()).toBe(200);
        expect((await user.request.get("/api/v1/users/me")).status()).toBe(401);
        const disabled = await off.json();
        expect(
          (
            await api.put(base, {
              data: {
                name: disabled.name,
                kind: tc.kind,
                enabled: true,
                archived: false,
                revision: disabled.revision,
                request_id: "native-enable-" + randomUUID(),
              },
            })
          ).status(),
        ).toBe(200);
        expect((await user.request.get("/api/v1/users/me")).status()).toBe(401);
      } finally {
        await context.close();
      }
    }
    await page.goto(lastPage);
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(
      page.getByRole("heading", { name: "Feishu / Lark sign-in", exact: true }),
    ).toBeVisible();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await expect(page.getByLabel("Application secret (write only)", { exact: true })).toHaveValue(
      "",
    );
    await page.screenshot({ path: testInfo.outputPath("enterprise-login-en.png"), fullPage: true });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "飞书 / Lark 登录", exact: true }),
    ).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("enterprise-login-zh.png"), fullPage: true });
  } finally {
    expect(
      (
        await api.put("/api/v1/settings/security/mfa", {
          data: { mode: oldPolicy.mode ?? "disabled" },
        })
      ).status(),
    ).toBe(200);
    for (const id of sourceIDs) {
      const base = "/api/v1/identity-sources/" + id;
      const response = await api.get(base);
      if (response.ok()) {
        const s = await response.json();
        if (!s.archived)
          expect(
            (
              await api.put(base, {
                data: {
                  name: s.name,
                  kind: s.kind,
                  enabled: false,
                  archived: true,
                  revision: s.revision,
                  request_id: "native-cleanup-" + randomUUID(),
                },
              })
            ).status(),
          ).toBe(200);
      }
    }
  }
});
