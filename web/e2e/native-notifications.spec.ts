import { test, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";
test.use({ locale: "en-US", trace: "off", screenshot: "off" });
const secret = "synthetic-native-notification-secret",
  botToken = "synthetic-bot-token";
type Template = { id: string; parameters: string[] };
function smsConfig(kind: string) {
  return {
    access_key_id: "synthetic-sms-access-key",
    region: kind === "tencent" ? "ap-guangzhou" : "",
    app_id: kind === "tencent" ? "1400000000" : "",
    endpoint: kind === "huawei" ? "https://smsapi.cn-north-4.myhuaweicloud.com" : "",
    sender: kind === "huawei" ? "csms100000001" : "",
    service_id: "",
    sign_name: "Synthetic",
    verification: { id: "verification-001", parameters: ["code"] } as Template,
    notification: { id: "notification-001", parameters: ["title", "state"] } as Template,
  };
}
test("native cloud SMS and signed enterprise bots retain queue authorization, receipts and bilingual settings", async ({
  page,
}, info) => {
  test.setTimeout(150000);
  const api = page.request;
  const creds = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
  let login = await api.post("/api/v1/authentication/auth/", { data: creds });
  if (login.status() !== 200) {
    expect([201, 409]).toContain(
      (await api.post("/api/v1/authentication/bootstrap", { data: creds })).status(),
    );
    login = await api.post("/api/v1/authentication/auth/", { data: creds });
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
  const created = await api.post("/api/v1/organizations", {
    data: { name: "Native notifications " + randomUUID(), enabled: true },
  });
  expect(created.status()).toBe(201);
  const org = await created.json();
  const headers = { "X-JMS-ORG": org.id };
  const base = "/api/v1/notifications";
  const ca = (await (await api.get("http://127.0.0.1:12226/enterprise/health")).json()).ca_pem;
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  async function config() {
    return (await api.get(base + "/settings", { headers })).json();
  }
  async function captures() {
    return (await api.get("http://127.0.0.1:12226/enterprise/notifications")).json();
  }
  async function save(payload: unknown) {
    const r = await api.put(base + "/settings", { headers, data: payload });
    expect(r.status()).toBe(200);
    return r.json();
  }
  try {
    await page.addInitScript((id) => localStorage.setItem("jms233.org", id), org.id);
    for (const [index, kind] of ["aliyun", "tencent", "huawei"].entries()) {
      const current = await config();
      const payload = {
        ...current,
        request_id: randomUUID(),
        webhook: { ...current.webhook, enabled: true, provider: "wecom", url: "", ca },
        webhook_bearer: botToken,
        webhook_secret: secret,
        sms: {
          ...current.sms,
          enabled: true,
          provider: kind,
          url: "",
          ca,
          native_sms: smsConfig(kind),
        },
        sms_secret: secret,
      };
      const a = await save(payload);
      const b = await save(payload);
      expect(b).toEqual(a);
      expect(JSON.stringify(b)).not.toContain(secret);
      expect(
        (
          await api.put(base + "/settings", {
            headers,
            data: {
              ...payload,
              sms: {
                ...payload.sms,
                native_sms: { ...payload.sms.native_sms, sign_name: "changed" },
              },
            },
          })
        ).status(),
      ).toBe(409);
      const p = await (await api.get(base + "/preferences", { headers })).json();
      const phone = "+861380000000" + index;
      expect(
        (
          await api.put(base + "/preferences", {
            headers,
            data: { revision: p.revision, language: "en", email: "", phone, topics: {} },
          })
        ).status(),
      ).toBe(200);
      expect(
        (
          await api.post(base + "/verification/request", { headers, data: { channel: "sms" } })
        ).status(),
      ).toBe(200);
      let code = "";
      await expect
        .poll(
          async () => {
            const list = await captures();
            code =
              list.findLast(
                (v: { provider: string; to: string; code: string }) =>
                  v.provider === kind && v.to === phone && v.code,
              )?.code ?? "";
            return code.length;
          },
          { timeout: 20000 },
        )
        .toBe(6);
      expect(
        (
          await api.post(base + "/verification/confirm", {
            headers,
            data: { channel: "sms", code },
          })
        ).status(),
      ).toBe(200);
      expect(
        (
          await api.post(base + "/verification/confirm", {
            headers,
            data: { channel: "sms", code },
          })
        ).status(),
      ).toBe(409);
      const verified = await (await api.get(base + "/preferences", { headers })).json();
      expect(
        (
          await api.put(base + "/preferences", {
            headers,
            data: {
              revision: verified.revision,
              language: "en",
              email: "",
              phone,
              topics: { system: ["inbox", "sms", "webhook"] },
            },
          })
        ).status(),
      ).toBe(200);
      const request_id = randomUUID();
      const first = await (
        await api.post(base + "/test", { headers, data: { request_id } })
      ).json();
      const second = await (
        await api.post(base + "/test", { headers, data: { request_id } })
      ).json();
      expect(second.id).toBe(first.id);
      await expect
        .poll(
          async () => {
            const list = await (await api.get(base + "/deliveries?limit=100", { headers })).json();
            return list.results.filter(
              (v: { message_id: string; state: string }) =>
                v.message_id === first.id && v.state === "sent",
            ).length;
          },
          { timeout: 20000 },
        )
        .toBe(2);
    }
    for (const provider of ["dingtalk", "feishu", "lark"]) {
      const c = await config();
      await save({
        ...c,
        request_id: randomUUID(),
        webhook: { ...c.webhook, provider, enabled: true, url: "", ca },
        webhook_bearer: botToken,
        webhook_secret: secret,
      });
      const result = await api.post(base + "/test", {
        headers,
        data: { request_id: randomUUID() },
      });
      expect(result.status()).toBe(200);
      const message = await result.json();
      await expect
        .poll(
          async () => {
            const d = await (await api.get(base + "/deliveries?limit=100", { headers })).json();
            return d.results.some(
              (v: { channel: string; message_id: string; state: string }) =>
                v.channel === "webhook" && v.message_id === message.id && v.state === "sent",
            );
          },
          { timeout: 20000 },
        )
        .toBe(true);
    }
    await page.goto("/console/notifications");
    await page.getByRole("button", { name: "Channel settings", exact: true }).click();
    await expect(page.getByLabel("Provider", { exact: true }).nth(0)).toHaveValue("lark");
    await expect(page.getByLabel("Provider", { exact: true }).nth(1)).toHaveValue("huawei");
    await expect(page.getByLabel("Webhook bearer token", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("SMS gateway signing secret", { exact: true })).toHaveValue("");
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    await page.screenshot({ path: info.outputPath("native-notifications.en.png"), fullPage: true });
    await page.getByTitle("中文 / English", { exact: true }).click();
    await expect(page.getByText("提供方", { exact: true }).first()).toBeVisible();
    await page.screenshot({
      path: info.outputPath("native-notifications.zh-CN.png"),
      fullPage: true,
    });
    expect(errors).toEqual([]);
  } finally {
    const current = await config();
    await save({
      ...current,
      request_id: randomUUID(),
      sms: { ...current.sms, enabled: false },
      webhook: { ...current.webhook, enabled: false },
      sms_secret: "",
      webhook_secret: "",
      webhook_bearer: "",
    });
    for (let attempt = 0; attempt < 2; attempt++) {
      const listed = await (await api.get("/api/v1/organizations?include_archived=true")).json();
      const owned = listed.results.find(
        (v: { id: string; archived_at?: string }) => v.id === org.id,
      );
      if (owned && !owned.archived_at)
        expect(
          (await api.delete(`/api/v1/organizations/${org.id}?revision=${owned.revision}`)).status(),
        ).toBe(204);
    }
  }
});
