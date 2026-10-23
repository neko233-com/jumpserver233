import { expect, test, request, type APIRequestContext } from "@playwright/test";
import { readFile } from "node:fs/promises";

test.use({ locale: "en-US", trace: "off" });

async function authenticate(api: APIRequestContext) {
  const data = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
  let response = await api.post("/api/v1/authentication/auth/", { data });
  if (response.status() === 401) {
    response = await api.post("/api/v1/authentication/bootstrap", { data });
    if (response.status() === 409)
      response = await api.post("/api/v1/authentication/auth/", { data });
  }
  expect(response.ok()).toBe(true);
}

test("workspace search, filters, density, dialogs, terminal and files use real isolated SSH data", async ({
  page,
}) => {
  test.setTimeout(120_000);
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  const owned: string[] = [];
  const errors: string[] = [];
  const terminalFrames: string[] = [];
  page.on("websocket", (socket) =>
    socket.on("framesent", (event) => {
      if (Buffer.isBuffer(event.payload)) terminalFrames.push(event.payload.toString("hex"));
    }),
  );
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await authenticate(api);
    const fixture = await (await api.get("http://127.0.0.1:12242/health")).json();
    const [host, port] = fixture.address.split(":");
    for (const suffix of ["A", "B"]) {
      const response = await api.post("/api/v1/assets", {
        data: {
          name: `Workspace UI ${suffix}`,
          host,
          port: Number(port),
          username: fixture.username,
          password: "synthetic-keyhost-password-233",
          host_key_fingerprint: fixture.fingerprint,
          remark: `Searchable workspace description ${suffix}`,
          group: "Workspace UI",
        },
      });
      expect(response.status()).toBe(201);
      owned.push((await response.json()).id);
    }
    expect((await api.post(`/api/v1/assets/${owned[0]}/probe`)).ok()).toBe(true);
    await page.context().addCookies((await api.storageState()).cookies);
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(`/console?asset_id=${owned[0]}`);
    await expect(page.getByRole("row").filter({ hasText: "Workspace UI A" })).toBeVisible();
    const search = page.getByRole("searchbox", {
      name: "Search name, address, or note",
      exact: true,
    });
    await search.fill("Workspace UI");
    await expect(page.locator(".asset-table tbody tr")).toHaveCount(2);
    await page.getByRole("combobox", { name: "Sort hosts", exact: true }).selectOption("cpu");
    await expect(page.getByRole("combobox", { name: "Sort hosts", exact: true })).toHaveValue(
      "cpu",
    );
    const firstRow = page.getByRole("row").filter({ hasText: "Workspace UI A" });
    await firstRow.locator("summary").click();
    await expect(firstRow.locator(".asset-more-menu")).toBeVisible();
    const menuBounds = await firstRow.locator(".asset-more-menu").boundingBox();
    expect(menuBounds!.y + menuBounds!.height).toBeLessThanOrEqual(1000);
    await firstRow.locator(".asset-more-menu button").first().focus();
    await firstRow.locator(".asset-more-menu button").first().press("Escape");
    await expect(firstRow.locator(".asset-more-menu")).toBeHidden();
    await search.fill("no-workspace-host");
    await expect(
      page.getByRole("heading", { name: "No matching hosts", exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Clear filters", exact: true }).first().click();
    await expect(search).toHaveValue("");
    const density = page.getByRole("button", { name: "Toggle table density", exact: true });
    await density.click();
    await expect(page.locator(".layout")).toHaveAttribute("data-density", "comfortable");
    await page.reload();
    await expect(page.locator(".layout")).toHaveAttribute("data-density", "comfortable");
    await density.click();

    await page.getByRole("button", { name: /^Quick search(?: Ctrl K)?$/ }).click();
    const commandSearch = page.getByRole("combobox", { name: /^Quick search(?: Ctrl K)?$/ });
    await commandSearch.fill("Searchable workspace description B");
    await expect(page.getByRole("option", { name: /Workspace UI B/ })).toBeVisible();
    await commandSearch.press("ArrowDown");
    await commandSearch.press("Enter");
    await expect(page).toHaveURL(new RegExp(owned[1]));
    await expect(page.locator(".asset-table tbody tr")).toHaveCount(1);
    await expect(page.getByRole("row").filter({ hasText: "Workspace UI B" })).toBeVisible();
    await page.keyboard.press("Control+k");
    await expect(commandSearch).toBeFocused();
    await commandSearch.fill("no-page-or-host");
    await expect(page.getByText("Nothing found", { exact: true })).toBeVisible();
    await commandSearch.press("Escape");
    await expect(page.getByRole("button", { name: /^Quick search(?: Ctrl K)?$/ })).toBeFocused();

    await page.getByRole("button", { name: "Add asset", exact: true }).click();
    const editor = page.getByRole("dialog");
    await editor.getByLabel("Name", { exact: true }).fill("Unsaved workspace draft");
    page.once("dialog", (dialog) => dialog.dismiss());
    await editor.getByLabel("Name", { exact: true }).press("Escape");
    await expect(editor).toBeVisible();
    await editor.getByRole("button", { name: "Cancel", exact: true }).click();
    await expect(editor).toHaveCount(0);
    expect(
      (await (await api.get("/api/v1/assets")).json()).some(
        (asset: { name: string }) => asset.name === "Unsaved workspace draft",
      ),
    ).toBe(false);

    const row = page.getByRole("row").filter({ hasText: "Workspace UI B" });
    await row.getByRole("button", { name: "Connect", exact: true }).click();
    const terminal = page.getByRole("dialog", { name: "Workspace UI B", exact: true });
    await expect(terminal.locator(".ssh-terminal-status")).toContainText("Connected");
    await terminal
      .getByRole("button", { name: "Increase terminal font size", exact: true })
      .click();
    await expect(terminal.getByLabel("Terminal font size", { exact: true })).toHaveText("15");
    await terminal.getByRole("button", { name: "Expand terminal", exact: true }).click();
    await expect(terminal).toHaveClass(/is-expanded/);
    await terminal.locator(".xterm-helper-textarea").press("Escape");
    await expect(terminal).toBeVisible();
    await terminal.locator(".xterm-helper-textarea").press("Tab");
    await expect.poll(() => terminalFrames.includes("09")).toBe(true);
    await terminal.locator(".xterm-helper-textarea").press("Control+Shift+Space");
    await expect(
      terminal.getByRole("button", { name: "Close terminal", exact: true }),
    ).toBeFocused();
    await terminal.getByRole("button", { name: "Restore terminal size", exact: true }).click();
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    await expect(terminal).toHaveCount(0);

    await row.getByRole("button", { name: "Files", exact: true }).click();
    const files = page.locator(".sftp-manager");
    await expect(files).toBeVisible();
    await expect(files.getByRole("button", { name: "Go to path", exact: true })).toBeEnabled();
    await files
      .getByRole("searchbox", { name: "Search this directory", exact: true })
      .fill("no-such-file-workspace");
    await files.getByRole("button", { name: "Go to path", exact: true }).click();
    await files
      .getByRole("textbox", { name: "Path relative to the workspace", exact: true })
      .fill("/");
    await files.getByRole("button", { name: "Open", exact: true }).click();
    await expect(
      files.getByRole("searchbox", { name: "Search this directory", exact: true }),
    ).toHaveValue("");
    const filename = `workspace-ui-${Date.now()}.txt`;
    const payload = Buffer.from("Owned workspace UI transfer verification.\n");
    const upload = files.locator('input[type="file"]');
    await expect(upload).toBeEnabled();
    await upload.setInputFiles({ name: filename, mimeType: "text/plain", buffer: payload });
    const transferred = files.getByRole("row").filter({ hasText: filename });
    await expect(transferred).toBeVisible();
    const downloading = page.waitForEvent("download");
    await transferred.getByRole("button", { name: "Download", exact: true }).click();
    const downloaded = await downloading;
    expect(await readFile((await downloaded.path())!)).toEqual(payload);
    page.once("dialog", (dialog) => dialog.accept());
    await transferred.getByRole("button", { name: "Delete", exact: true }).click();
    await expect(transferred).toHaveCount(0);
    await files.getByRole("button", { name: "Cancel", exact: true }).last().click();
    await expect(files).toHaveCount(0);
    await page.setViewportSize({ width: 375, height: 900 });
    await page.goto(`/console?asset_id=${owned[0]}`);
    const mobileMetrics = page.locator(".asset-metrics");
    await expect(mobileMetrics).toBeVisible();
    const detail = await mobileMetrics.locator(".metric-detail").first().boundingBox();
    expect(detail!.x + detail!.width).toBeLessThanOrEqual(375);
    expect((await page.locator(".asset-table tbody tr").first().boundingBox())!.y).toBeLessThan(
      340,
    );
    expect(
      (await page.getByRole("button", { name: "Connect", exact: true }).boundingBox())!.height,
    ).toBeGreaterThanOrEqual(44);
    await expect(page.getByRole("button", { name: "Quick search", exact: true })).toBeVisible();
    expect(errors).toEqual([]);
  } finally {
    await page.goto("/console");
    for (const id of owned)
      expect([204, 404]).toContain((await api.delete(`/api/v1/assets/${id}`)).status());
    // A second cleanup must remain a safe no-op.
    for (const id of owned) expect((await api.delete(`/api/v1/assets/${id}`)).status()).toBe(404);
    await api.dispose();
  }
});

test("every shipped console route uses the new bilingual responsive workspace without page overflow", async ({
  page,
}) => {
  test.setTimeout(180_000);
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await authenticate(api);
    await page.context().addCookies((await api.storageState()).cookies);
    const routes = [
      "/console",
      "/console/labels",
      "/console/agent-audit",
      "/console/account-risks",
      "/console/rotation-plans",
      "/console/access-tickets",
      "/console/notifications",
      "/console/platform-notifications",
      "/console/login-audit",
      "/console/reports",
      "/console/dashboard",
      "/console/monitoring",
      "/console/settings",
      "/console/ssh-certificates",
      "/console/roles",
      "/console/users",
      "/console/organizations",
      "/console/organization-roles",
      "/console/access-policies",
      "/console/login-reviews",
      "/console/passkeys",
      "/audit",
      "/audit/reports",
      "/workbench",
      "/profile",
    ];
    for (const width of [1440, 375]) {
      await page.setViewportSize({ width, height: 900 });
      for (const zh of [false, true]) {
        for (const route of routes) {
          await page.goto(route);
          await expect(page.locator("#console-main")).toBeVisible();
          if ((await page.locator("html").getAttribute("lang")) !== (zh ? "zh-CN" : "en"))
            await page.getByRole("button", { name: zh ? "中文" : "EN", exact: true }).click();
          await expect(page.locator("#console-main h1,#console-main h2").first()).toBeVisible();
          await expect
            .poll(
              () =>
                page.evaluate(
                  () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
                ),
              { message: `No page overflow at ${route} / ${width} / ${zh}` },
            )
            .toBe(0);
          expect(await page.locator("#console-main").innerText()).not.toMatch(
            /\bui\.(search|assets|terminal|files|login)\./,
          );
        }
      }
    }
    await page.goto("/console/settings");
    await page.getByRole("button", { name: "EN", exact: true }).click();
    const sections = page.getByRole("searchbox", { name: "Find a settings section", exact: true });
    await sections.fill("security");
    await expect(page.getByRole("tab")).toHaveCount(1);
    await sections.fill("");
    const tabs = page.getByRole("tab");
    await tabs.first().focus();
    await tabs.first().press("End");
    await expect(tabs.last()).toBeFocused();
    await expect(tabs.last()).toHaveAttribute("aria-selected", "true");
    await page.emulateMedia({ reducedMotion: "reduce" });
    expect(errors).toEqual([]);
  } finally {
    await api.dispose();
  }
});
