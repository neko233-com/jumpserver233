import { expect, request, test } from "@playwright/test";

// Reuses the suite's existing SSH fixture. One owned host is removed in finally;
// no extra container, report history or persistent product data is created.
test.use({ locale: "en-US", trace: "off" });

test("console navigation stays searchable, bilingual and usable on narrow screens", async ({
  page,
}) => {
  test.setTimeout(60_000);
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  const credentials = {
    username: "e2e.admin",
    password: "synthetic-e2e-admin-password-2468",
  };
  const errors: string[] = [];
  let layoutAsset = "";
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    let response = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (response.status() === 401) {
      response = await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      // Another suite file may have completed bootstrap in the meantime.
      if (response.status() === 409)
        response = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(response.ok()).toBe(true);
    const fixture = await (await api.get("http://127.0.0.1:12223/health")).json();
    const [host, port] = fixture.address.split(":");
    const created = await api.post("/api/v1/assets", {
      data: {
        name: `Mini layout QA ${Date.now()}`,
        host,
        port: Number(port),
        username: fixture.username,
        password: "synthetic-qa-only-password",
        host_key_fingerprint: fixture.fingerprint,
      },
    });
    expect(created.status()).toBe(201);
    layoutAsset = (await created.json()).id;
    expect((await api.post(`/api/v1/assets/${layoutAsset}/probe`)).ok()).toBe(true);
    await page.context().addCookies((await api.storageState()).cookies);
    for (const width of [1600, 1440, 1280, 900, 715, 375]) {
      await page.setViewportSize({ width, height: 900 });
      for (const zh of [false, true]) {
        await page.goto("/console");
        if ((await page.locator("html").getAttribute("lang")) !== (zh ? "zh-CN" : "en")) {
          await page.getByRole("button", { name: zh ? "中文" : "EN", exact: true }).click();
        }
        if (width >= 1280) {
          const row = page.getByRole("row").filter({ hasText: "Mini layout QA" });
          await expect(row.locator(".asset-metrics")).toBeVisible();
          const bounds = await row.evaluate((element) => {
            const rect = element.getBoundingClientRect();
            const actions = element.lastElementChild!.getBoundingClientRect();
            const wrapper = element.closest(".asset-table-wrap")!.getBoundingClientRect();
            return {
              height: rect.height,
              actionsRight: actions.right,
              visibleRight: wrapper.right,
            };
          });
          expect(bounds.height).toBeLessThanOrEqual(128);
          expect(bounds.actionsRight).toBeLessThanOrEqual(bounds.visibleRight + 2);
          if (width === 1280) {
            await page.screenshot({
              path: test.info().outputPath(zh ? "mini-console.zh.png" : "mini-console.en.png"),
            });
          }
        }
        const menu = page.getByRole("button", {
          name: zh ? "展开导航" : "Open navigation",
          exact: true,
        });
        if (width <= 760) {
          await expect(
            page.getByRole("searchbox", { name: zh ? "查找页面" : "Find a page", exact: true }),
          ).toBeHidden();
          await menu.click();
        }
        const nav = page.getByRole("navigation", {
          name: zh ? "控制台页面" : "Console pages",
          exact: true,
        });
        const search = page.getByRole("searchbox", {
          name: zh ? "查找页面" : "Find a page",
          exact: true,
        });
        await expect(nav.locator("section:visible")).toHaveCount(5);
        const more = nav.getByRole("button", {
          name: zh ? "更多功能" : "More features",
          exact: true,
        });
        await expect(more).toHaveAttribute("aria-expanded", "false");
        await expect(
          nav.getByRole("link", { name: zh ? "概览与报表" : "Overview & reports", exact: true }),
        ).toBeHidden();
        await expect(nav.getByRole("link").first()).toHaveAttribute("href", "/console");
        await expect(nav.locator('[aria-current="page"]')).toHaveCount(1);
        for (const path of ["asset-discovery", "assistant", "identity-sources", "pam"]) {
          await expect(nav.locator(`a[href="/console/${path}"]`)).toHaveCount(0);
        }
        await search.fill("no-such-page-233");
        await expect(nav.getByRole("link")).toHaveCount(0);
        await expect(
          page.getByText(zh ? "没有匹配的页面。" : "No matching pages.", { exact: true }),
        ).toBeVisible();
        await page
          .getByRole("button", { name: zh ? "清除搜索" : "Clear search", exact: true })
          .click();
        await expect(search).toBeFocused();
        await search.fill(zh ? "报表" : "reports");
        await expect(nav.getByRole("link")).toHaveCount(1);
        await search.press("Escape");
        await expect(search).toHaveValue("");
        await expect(nav.locator("section:visible")).toHaveCount(5);
        if (width <= 760) {
          await search.press("Escape");
          await expect(menu).toBeFocused();
          await expect(menu).toHaveAttribute("aria-expanded", "false");
          await menu.click();
        }
        await more.click();
        await nav.locator('a[href="/console/labels"]').click();
        await expect(page).toHaveURL(/\/console\/labels$/);
        await expect(
          page.getByRole("heading", { name: zh ? "标签" : "Labels", exact: true }),
        ).toBeVisible();
        if (width <= 760) await menu.click();
        await nav
          .getByRole("link", { name: zh ? "概览与报表" : "Overview & reports", exact: true })
          .click();
        await expect(page).toHaveURL(/\/console\/reports$/);
        if (width <= 760) {
          await expect(menu).toHaveAttribute("aria-expanded", "false");
          await expect(page.locator("#console-main")).toBeFocused();
        }
        await expect(
          page.getByRole("button", { name: zh ? "退出登录" : "Sign out", exact: true }),
        ).toBeVisible();
        await expect
          .poll(() =>
            page.evaluate(
              () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
            ),
          )
          .toBe(0);
      }
    }
    await page.emulateMedia({ reducedMotion: "reduce" });
    const skip = page.getByRole("link", { name: "跳转到正文", exact: true });
    await skip.focus();
    await expect(skip).toBeVisible();
    await skip.press("Enter");
    await expect(page.locator("#console-main")).toBeFocused();
    expect(errors).toEqual([]);
  } finally {
    if (layoutAsset)
      expect([204, 404]).toContain((await api.delete(`/api/v1/assets/${layoutAsset}`)).status());
    await api.dispose();
  }
});
