import { test, expect, request } from "@playwright/test";

const base = process.env.JMS_LIVE_QA_BASE_URL || "http://127.0.0.1:8083";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw new Error("Update QA requires an isolated loopback instance");
const path = "/api/v1/settings/security/updates";
type Settings = { automatic: boolean; interval_hours: number; revision: number };
test.use({ locale: "en-US" });

test("update settings persist without installing software and show bilingual rate limits", async ({
  page,
}, info) => {
  const api = await request.newContext({ baseURL: base });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  let original: Settings | null = null;
  try {
    const admin = {
      username: process.env.JMS_LIVE_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_LIVE_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let login = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: admin });
      login = await api.post("/api/v1/authentication/auth/", { data: admin });
    }
    expect(login.ok()).toBe(true);
    await page.context().addCookies((await api.storageState()).cookies);
    const current = await api.get(path);
    expect(current.ok()).toBe(true);
    original = ((await current.json()) as { settings: Settings }).settings;
    await page.goto("/console/settings");
    await page.getByRole("tab", { name: "Security", exact: true }).click();
    const card = page
      .locator("section.settings-card")
      .filter({ has: page.getByRole("heading", { name: /^(Software updates|软件更新)$/ }) });
    await expect(
      card.getByRole("button", { name: "Check for updates", exact: true }),
    ).toBeVisible();
    await card.getByLabel("Check interval (hours)", { exact: true }).fill("48");
    await card.getByRole("button", { name: "Save update settings", exact: true }).click();
    await expect(
      card.getByRole("status").filter({ hasText: "Update settings saved." }),
    ).toBeVisible();
    expect(
      ((await (await api.get(path)).json()) as { settings: Settings }).settings.interval_hours,
    ).toBe(48);
    await page.reload();
    await page.getByRole("tab", { name: "Security", exact: true }).click();
    await expect(card.getByLabel("Check interval (hours)", { exact: true })).toHaveValue("48");
    await page.screenshot({ path: info.outputPath("updates.en.png") });
    // Deterministically exercise a UI error without consuming public API quota.
    // Provider checks, actual metadata and receipts are covered by Go/API tests.
    await page.route("**/api/v1/settings/security/updates/check", (route) =>
      route.fulfill({
        status: 429,
        contentType: "application/json",
        body: JSON.stringify({ error_code: "rate_limited" }),
      }),
    );
    await card.getByRole("button", { name: "Check for updates", exact: true }).click();
    await expect(card.getByRole("alert")).toContainText("Wait at least one minute");
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "软件更新", exact: true })).toBeVisible();
    await expect(card.getByRole("alert")).toContainText("至少等待一分钟");
    await page.screenshot({ path: info.outputPath("updates.zh-CN.png") });
    await page.setViewportSize({ width: 390, height: 844 });
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1),
    ).toBe(true);
    expect(errors).toEqual([]);
  } finally {
    if (original) {
      const value = (await (await api.get(path)).json()) as { settings: Settings };
      expect(
        (await api.put(path, { data: { ...original, revision: value.settings.revision } })).ok(),
      ).toBe(true);
    }
    await api.dispose();
  }
});
