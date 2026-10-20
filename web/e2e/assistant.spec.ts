import { test, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";
test.use({ locale: "en-US", trace: "off", screenshot: "off" });
test("assistant uses native verified HTTPS, one-use receipts, encrypted organization history and bilingual views", async ({
  page,
}, info) => {
  test.setTimeout(90000);
  const api = page.request,
    credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
  let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
  if (login.status() !== 200) {
    expect([201, 409]).toContain(
      (await api.post("/api/v1/authentication/bootstrap", { data: credentials })).status(),
    );
    login = await api.post("/api/v1/authentication/auth/", { data: credentials });
  }
  expect(login.status()).toBe(200);
  await page.context().addCookies([
    {
      name: "jms_sessionid",
      value: (await login.json()).access_token,
      url: new URL(info.project.use.baseURL as string).origin,
      httpOnly: true,
      sameSite: "Lax",
    },
  ]);
  const created = await api.post("/api/v1/organizations", {
    data: { name: "AI assistant " + randomUUID(), enabled: true },
  });
  expect(created.status()).toBe(201);
  const org = await created.json(),
    headers = { "X-JMS-ORG": org.id };
  const fixture = await (await api.get("http://127.0.0.1:12226/enterprise/health")).json();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  try {
    await page.addInitScript((id) => localStorage.setItem("jms233.org", id), org.id);
    await page.goto("/console/assistant");
    await expect(page.getByRole("heading", { name: "AI assistant", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Provider settings", exact: true }).click();
    await page
      .getByLabel("HTTPS Chat Completions endpoint", { exact: true })
      .fill(fixture.assistant_endpoint);
    await page.getByLabel("Model ID", { exact: true }).fill("synthetic-assistant-model");
    await page
      .getByLabel("API key (write only)", { exact: true })
      .fill("synthetic-assistant-provider-key");
    await page.getByText("Advanced settings", { exact: true }).click();
    await page.getByLabel("Additional trusted CA (PEM)", { exact: true }).fill(fixture.ca_pem);
    await page.getByLabel("Enable the assistant", { exact: true }).check();
    await page.getByRole("button", { name: "Save provider", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("Provider settings saved");
    await expect(page.getByLabel("API key (write only)", { exact: true })).toHaveValue("");
    const settingsResponse = await api.get("/api/v1/assistant/settings", { headers });
    expect(await settingsResponse.text()).not.toContain("synthetic-assistant-provider-key");
    await page.getByRole("button", { name: "Conversations", exact: true }).click();
    const question = "Explain pwd " + randomUUID();
    await page.getByLabel("Your message", { exact: true }).fill(question);
    await expect(page.getByRole("button", { name: "Send message", exact: true })).toBeDisabled();
    await page
      .getByLabel(
        "Send this text and recent completed exchanges to the configured provider and retain them in encrypted conversation audit.",
        { exact: true },
      )
      .check();
    const sent = page.waitForRequest(
      (r) => r.method() === "POST" && new URL(r.url()).pathname === "/api/v1/assistant/turns",
    );
    await page.getByRole("button", { name: "Send message", exact: true }).click();
    const input = (await sent).postDataJSON();
    await expect(page.getByRole("log")).toContainText("Synthetic advisory reply: " + question);
    expect(await page.locator(".assistant-conversation img").count()).toBe(0);
    const replay = await api.post("/api/v1/assistant/turns", { headers, data: input });
    expect(replay.status()).toBe(200);
    const result = await replay.json();
    expect(result.turn.status).toBe("completed");
    const changed = await api.post("/api/v1/assistant/turns", {
      headers,
      data: { ...input, message: "changed" },
    });
    expect(changed.status()).toBe(409);
    const foreign = await api.get(`/api/v1/assistant/conversations/${result.conversation_id}`);
    expect(foreign.status()).toBe(404);
    await page.screenshot({ path: info.outputPath("assistant.en.png"), fullPage: true });
    await page.getByRole("button", { name: "Conversation audit", exact: true }).click();
    await expect(page.getByRole("table")).toContainText("Message submitted");
    await expect(page.getByRole("table")).toContainText("Response recorded");
    await page.getByRole("button", { name: "Conversations", exact: true }).click();
    await page.evaluate(() => localStorage.setItem("jms233.lang", "zh-CN"));
    await page.reload();
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(page.getByRole("heading", { name: "AI 助手", exact: true })).toBeVisible();
    await page.getByRole("button", { name: question, exact: true }).click();
    await expect(page.getByRole("log")).toContainText("Synthetic advisory reply");
    expect(await page.locator("body").evaluate((e) => e.scrollWidth <= innerWidth + 1)).toBe(true);
    await page.screenshot({ path: info.outputPath("assistant.zh-CN.png"), fullPage: true });
    await page.getByRole("button", { name: "归档对话", exact: true }).click();
    await expect(page.getByRole("button", { name: question, exact: true })).toHaveCount(0);
    await page.getByLabel("包含已归档对话", { exact: true }).check();
    await expect(page.getByRole("button", { name: question, exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  } finally {
    const current = await (await api.get("/api/v1/assistant/settings", { headers })).json();
    if (current.revision > 0) {
      expect(
        (
          await api.put("/api/v1/assistant/settings", {
            headers,
            data: {
              endpoint: current.endpoint,
              model: current.model,
              root_ca_pem: current.root_ca_pem ?? "",
              max_completion_tokens: current.max_completion_tokens,
              revision: current.revision,
              enabled: false,
              secret: "",
              request_id: randomUUID(),
            },
          })
        ).status(),
      ).toBe(200);
    }
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
