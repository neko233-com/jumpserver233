import { test, expect } from "@playwright/test";

test.use({ baseURL: "http://127.0.0.1:15180", locale: "en-US" });
test("first startup root account signs in through normal browser authentication", async ({
  page,
}) => {
  await page.goto("/login");
  await expect(page.getByLabel("Username", { exact: true })).toHaveValue("root");
  await page.getByLabel("Password", { exact: true }).fill("root");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/console$/);
  const me = await page.request.get("/api/v1/users/me");
  expect(me.status()).toBe(200);
  expect(await me.json()).toMatchObject({ username: "root", role: "admin" });
  await page.reload();
  await expect(page.getByRole("button", { name: "Sign out", exact: true })).toBeVisible();
  await page.locator(".lang-switch").click();
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
  await page.getByRole("button", { name: "退出登录", exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel("密码", { exact: true }).fill("root");
  await page.getByRole("button", { name: "登录", exact: true }).click();
  await expect(page).toHaveURL(/\/console$/);
});
