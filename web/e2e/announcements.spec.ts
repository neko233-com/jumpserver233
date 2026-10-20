import { test, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";

test.use({ locale: "en-US", trace: "off" });

test("platform notices preserve revisions, plain text, global permissions and bilingual reading receipts", async ({
  browser,
}, info) => {
  test.setTimeout(60_000);
  const baseURL = info.project.use.baseURL;
  if (typeof baseURL !== "string" || !/^http:\/\/127\.0\.0\.\d+:\d+$/.test(baseURL))
    throw Error("Announcement QA requires the owning loopback fixture");
  const admin = await browser.newContext({ baseURL, locale: "en-US" }),
    reader = await browser.newContext({
      baseURL,
      locale: "en-US",
      viewport: { width: 390, height: 844 },
    });
  const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
  const ids: string[] = [];
  let user = "";
  try {
    let login = await admin.request.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await admin.request.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await admin.request.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok(), await login.text()).toBe(true);
    const page = await admin.newPage();
    await page.goto("/console/announcements");
    await page.getByRole("checkbox", { name: "Manage announcements", exact: true }).check();
    await page.getByRole("button", { name: "New announcement", exact: true }).click();
    const title = "QA announcement " + randomUUID(),
      literal = "Plain text <img src=x onerror=alert(1)>";
    const form = page.locator("form.announcement-editor");
    await form.getByLabel("English title", { exact: true }).fill(title);
    await form.getByLabel("English content", { exact: true }).fill(literal);
    await form.getByRole("checkbox", { name: "Published", exact: true }).check();
    const pending = page.waitForResponse(
      (r) =>
        r.request().method() === "POST" && new URL(r.url()).pathname === "/api/v1/announcements",
    );
    await form.getByRole("button", { name: "Save", exact: true }).click();
    const saved = await pending;
    expect(saved.status(), await saved.text()).toBe(201);
    let notice = await saved.json();
    ids.push(notice.id);
    const username = "notice.reader." + Date.now(),
      password = "synthetic-notice-reader-password-233";
    const created = await admin.request.post("/api/v1/users", {
      data: { username, password, role: "operator" },
    });
    expect(created.status(), await created.text()).toBe(201);
    user = (await created.json()).id;
    const readLogin = await reader.request.post("/api/v1/authentication/auth/", {
      data: { username, password },
    });
    expect(readLogin.ok(), await readLogin.text()).toBe(true);
    const rp = await reader.newPage();
    await rp.goto("/console/announcements");
    const card = rp.getByRole("article", { name: title, exact: true });
    await expect(card).toBeVisible();
    await expect(card).toContainText(literal);
    await expect(card.locator("img,script")).toHaveCount(0);
    await expect(
      rp.getByRole("checkbox", { name: "Manage announcements", exact: true }),
    ).toHaveCount(0);
    const denied = await reader.request.get("/api/v1/announcements?manage=true");
    expect(denied.status()).toBe(403);
    await card.getByRole("button", { name: "Mark as read", exact: true }).click();
    await expect(card.getByRole("button", { name: "Mark as read", exact: true })).toHaveCount(0);
    const originalRequest = randomUUID();
    const update = {
      title: notice.title,
      body: { en: literal + " revised", "zh-CN": "" },
      severity: notice.severity,
      published: true,
      pinned: false,
      revision: notice.revision,
      request_id: originalRequest,
    };
    const revised = await admin.request.put(`/api/v1/announcements/${notice.id}`, { data: update });
    expect(revised.ok(), await revised.text()).toBe(true);
    notice = await revised.json();
    const replay = await admin.request.put(`/api/v1/announcements/${notice.id}`, { data: update });
    expect(replay.ok()).toBe(true);
    expect((await replay.json()).revision).toBe(notice.revision);
    await rp.reload();
    await expect(card.getByRole("button", { name: "Mark as read", exact: true })).toBeVisible();
    const stale = await reader.request.post(`/api/v1/announcements/${notice.id}/read`, {
      data: { revision: notice.revision - 1 },
    });
    expect(stale.status()).toBe(409);
    await rp.getByRole("button", { name: "中文", exact: true }).click();
    await expect(rp.getByRole("heading", { name: "平台公告", exact: true })).toBeVisible();
    await expect(card).toContainText(literal + " revised");
    await card.getByRole("button", { name: "标记已读", exact: true }).click();
    await expect(card.getByText("已读", { exact: true })).toBeVisible();
    const scoped = await reader.request.get("/api/v1/announcements", {
      headers: { "X-JMS-ORG": "unknown-org" },
    });
    expect(scoped.ok()).toBe(true);
    expect((await scoped.json()).results.find((n: { id: string }) => n.id === notice.id).read).toBe(
      true,
    );
    const future = await admin.request.post("/api/v1/announcements", {
      data: {
        title: { en: "Future " + title },
        body: { en: "Not active yet" },
        published: true,
        starts_at: new Date(Date.now() + 3600000).toISOString(),
        request_id: randomUUID(),
      },
    });
    expect(future.status()).toBe(201);
    const futureNotice = await future.json();
    ids.push(futureNotice.id);
    const visible = await reader.request.get("/api/v1/announcements");
    expect(
      (await visible.json()).results.some((n: { id: string }) => n.id === futureNotice.id),
    ).toBe(false);
  } finally {
    const all = await admin.request.get("/api/v1/announcements?manage=true&limit=100");
    if (all.ok()) {
      const rows = (await all.json()).results;
      for (const id of ids) {
        const n = rows.find((v: { id: string }) => v.id === id);
        if (n)
          await admin.request.delete(`/api/v1/announcements/${id}`, {
            data: { revision: n.revision, request_id: randomUUID() },
          });
      }
    }
    if (user) await admin.request.delete(`/api/v1/users/${user}`);
    await reader.close();
    await admin.close();
  }
});
