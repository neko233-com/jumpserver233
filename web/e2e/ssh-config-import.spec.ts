import { expect, test } from "@playwright/test";

test("imports the authorized inventory into the selected local config and preserves existing settings", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.addInitScript(() => {
    const state = window as unknown as { sshConfigFixture: string; showOpenFilePicker: () => Promise<unknown[]> };
    state.sshConfigFixture = "Host personal\n  HostName example.test\n";
    state.showOpenFilePicker = async () => [{
      name: "config",
      getFile: async () => new File([state.sshConfigFixture], "config", { lastModified: 1 }),
      createWritable: async () => {
        let next = "";
        return { write: async (data: string) => { next = data; }, close: async () => { state.sshConfigFixture = next; }, abort: async () => {} };
      },
    }];
  });
  const inventory = [{ id: "asset-fixture", name: "Build host", protocol: "ssh", host: "fixture.invalid", port: 22, group: "", username: "gamer", remark: "", monitor: { state: "unknown" }, permissions: ["view", "connect"], accounts: [{ id: "asset-fixture", name: "gamer", username: "gamer", active: true, default: true, permissions: ["view", "connect"] }] }];
  await page.route("**/api/v1/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    let body: unknown = {};
    if (pathname === "/api/v1/assets") body = inventory;
    else if (pathname === "/api/v1/assets/nodes") body = [];
    else if (pathname === "/api/v1/rbac/me") body = { user_id: "fixture", permissions: [], system_permissions: [] };
    else if (pathname === "/api/v1/users/me" || pathname === "/api/v1/authentication/session/") body = { username: "operator" };
    else if (pathname.includes("organizations")) body = [];
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto("/console");
  const open = page.getByRole("button", { name: /导入本机 SSH 配置|Import local SSH config/ });
  await open.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: /选择配置并导入|Choose config and import/ }).click();
  await expect(dialog.getByRole("status")).toContainText(/已同步 1 个账号|Synced 1 accounts/);
  const config = await page.evaluate(() => (window as unknown as { sshConfigFixture: string }).sshConfigFixture);
  expect(config).toContain("Host personal\n  HostName example.test");
  expect(config).toContain("User operator#asset-fixture%00000000-0000-0000-0000-000000000002");
  expect(config).not.toContain("password");
  expect(errors).toEqual([]);
  await page.screenshot({ path: test.info().outputPath("ssh-config-desktop.png"), animations: "disabled" });
});

test("explains the local client fallback when the browser cannot edit files", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(() => { Object.defineProperty(window, "isSecureContext", { value: false }); });
  await page.route("**/api/v1/**", async (route) => {
    const pathname = new URL(route.request().url()).pathname;
    const body = pathname === "/api/v1/assets" || pathname === "/api/v1/assets/nodes" || pathname.includes("organizations") ? [] : pathname === "/api/v1/rbac/me" ? { user_id: "fixture", permissions: [] } : { username: "operator" };
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.goto("/console");
  await page.getByRole("button", { name: /筛选与主机操作|Filters & host actions/ }).click();
  await page.getByRole("button", { name: /导入本机 SSH 配置|Import local SSH config/ }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("jms ssh-config sync");
  await expect(dialog).toContainText("$env:JMS_SERVER_URL=");
  await expect(dialog).toContainText("macOS / Linux");
  await expect(dialog.getByRole("button", { name: /选择配置并导入|Choose config and import/ })).toHaveCount(0);
  await page.screenshot({ path: test.info().outputPath("ssh-config-mobile.png"), animations: "disabled" });
});
