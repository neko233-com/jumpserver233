import { expect, test } from "@playwright/test";

const failures = [
  {
    name: "origin",
    status: 403,
    body: { code: "origin_not_allowed" },
    en: "This address is not allowed",
    zh: "当前访问地址未被服务允许",
  },
  {
    name: "legacy origin",
    status: 403,
    body: { detail: "origin is not allowed" },
    en: "This address is not allowed",
    zh: "当前访问地址未被服务允许",
  },
  {
    name: "rate limit",
    status: 429,
    body: {},
    en: "Too many sign-in attempts",
    zh: "登录请求过于频繁",
  },
  {
    name: "service",
    status: 503,
    body: null,
    en: "temporarily unavailable",
    zh: "登录服务暂时不可用",
  },
  {
    name: "credentials",
    status: 401,
    body: {},
    en: "Check the username and password",
    zh: "请检查用户名和密码",
  },
  {
    name: "session cookie",
    status: 200,
    body: { browser_session: true },
    en: "session was not established",
    zh: "登录会话未建立",
  },
  { name: "network", status: 0, body: {}, en: "Could not connect", zh: "无法连接登录服务" },
];

for (const language of ["en-US", "zh-CN"]) {
  test.describe(language, () => {
    test.use({ locale: language });
    for (const failure of failures) {
      test(`reports ${failure.name} without confusing other login failures`, async ({ page }) => {
        await page.route("**/api/v1/authentication/status", (route) =>
          route.fulfill({ json: { bootstrap_required: false } }),
        );
        await page.route("**/api/v1/authentication/session/", (route) =>
          route.fulfill({ status: 401, json: {} }),
        );
        await page.route("**/api/v1/authentication/auth/", async (route) => {
          if (!failure.status) await route.abort("connectionfailed");
          else if (failure.body === null)
            await route.fulfill({
              status: failure.status,
              contentType: "text/html",
              body: "upstream unavailable",
            });
          else await route.fulfill({ status: failure.status, json: failure.body });
        });
        await page.goto("/login");
        const zh = language === "zh-CN";
        await page
          .getByRole("textbox", { name: zh ? "用户名" : "Username", exact: true })
          .fill("synthetic-login");
        await page
          .getByLabel(zh ? "密码" : "Password", { exact: true })
          .fill("synthetic-only-password");
        await page.getByRole("button", { name: zh ? "登录" : "Sign in", exact: true }).click();
        await expect(page.getByRole("alert")).toContainText(zh ? failure.zh : failure.en);
        await expect(page).toHaveURL(/\/login$/);
        await expect(
          page.getByRole("button", { name: zh ? "登录" : "Sign in", exact: true }),
        ).toBeEnabled();
      });
    }
  });
}
