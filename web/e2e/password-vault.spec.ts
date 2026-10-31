import { expect, test } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { join } from "node:path";

test.use({ locale: "en-US", trace: "off" });
test("account vault saves, authorizes and revokes a game account", async ({ browser }, info) => {
  const baseURL = info.project.use.baseURL;
  if (typeof baseURL !== "string" || !/^http:\/\/127\.0\.0\.\d+:\d+$/.test(baseURL))
    throw Error("Vault QA requires loopback");
  const context = await browser.newContext({ baseURL, locale: "en-US" });
  const teammate = await browser.newContext({ baseURL, locale: "en-US" });
  const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
  const headers = { "X-JMS-Browser-Session": "cookie" };
  try {
    let login = await context.request.post("/api/v1/authentication/auth/", {
      data: credentials,
      headers,
    });
    if (!login.ok()) {
      await context.request.post("/api/v1/authentication/bootstrap", {
        data: credentials,
        headers,
      });
      login = await context.request.post("/api/v1/authentication/auth/", {
        data: credentials,
        headers,
      });
    }
    expect(login.ok()).toBeTruthy();
    const page = await context.newPage();
    const title = `QA game ${randomUUID()}`;
    await page.goto("/console/password-vault");
    await expect(page.getByRole("heading", { name: "Account vault" })).toBeVisible();
    await page.getByRole("button", { name: "Add account" }).click();
    await page.getByLabel("Type").selectOption("game");
    await page.getByLabel("Name", { exact: true }).fill(title);
    await page.getByLabel("Username").fill("synthetic-user");
    await page.getByLabel("Password", { exact: true }).fill("synthetic-vault-password");
    await page.getByRole("button", { name: "Save", exact: true }).click();
    const row = page.locator("li").filter({ hasText: title }).first();
    await expect(row).toBeVisible();
    await page.reload();
    await expect(row).toBeVisible();
    const teammateCredentials = {
      username: `vault.${randomUUID()}`,
      password: "synthetic-vault-teammate-2468",
      role: "operator",
    };
    const createdUser = await context.request.post("/api/v1/users", { data: teammateCredentials });
    expect(createdUser.status()).toBe(201);
    const teammateLogin = await teammate.request.post("/api/v1/authentication/auth/", {
      data: { username: teammateCredentials.username, password: teammateCredentials.password },
      headers,
    });
    expect(teammateLogin.ok()).toBeTruthy();
    const teammatePage = await teammate.newPage();
    await teammatePage.goto("/console/password-vault");
    const sharedRow = teammatePage.locator("li").filter({ hasText: title }).first();
    await expect(sharedRow).toBeVisible();
    await sharedRow.getByRole("button", { name: "Show password" }).click();
    await expect(sharedRow.getByLabel("Password")).toHaveValue("synthetic-vault-password");
    await sharedRow.getByRole("button", { name: "Close" }).click();
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "账号保险库" })).toBeVisible();
    await page.getByRole("button", { name: "EN", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Account vault" })).toBeVisible();
    if (process.env.JMS_E2E_REPORT_DIR) {
      await page.screenshot({
        path: join(process.env.JMS_E2E_REPORT_DIR, "password-vault-desktop.png"),
      });
      await page.setViewportSize({ width: 390, height: 844 });
      await expect(row).toBeVisible();
      await page.screenshot({
        path: join(process.env.JMS_E2E_REPORT_DIR, "password-vault-mobile.png"),
      });
      await page.setViewportSize({ width: 1280, height: 720 });
    }
    await row.getByRole("button", { name: "Authorize Agent" }).click();
    await expect(page.getByText("Single-use authorization", { exact: false })).toBeVisible();
    await page.getByRole("button", { name: "Close", exact: true }).click();
    await page.getByRole("button", { name: "Revoke", exact: true }).click();
    await expect(page.getByRole("button", { name: "Revoke", exact: true })).toHaveCount(0);
    page.once("dialog", (d) => d.accept());
    await row.getByRole("button", { name: "Delete" }).click();
    await expect(row).toHaveCount(0);
  } finally {
    await teammate.close();
    await context.close();
  }
});
