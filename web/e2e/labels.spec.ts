import { test, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";

test.use({ locale: "en-US", trace: "off" });
test("labels inherit, filter visible assets, retry idempotently and enforce current permissions in both languages", async ({
  browser,
}, info) => {
  test.setTimeout(90_000);
  const baseURL = info.project.use.baseURL;
  if (typeof baseURL !== "string" || !/^http:\/\/127\.0\.0\.\d+:\d+$/.test(baseURL))
    throw Error("Labels QA requires the owning loopback fixture");
  const admin = await browser.newContext({ baseURL, locale: "en-US" });
  const reader = await browser.newContext({
    baseURL,
    locale: "en-US",
    viewport: { width: 390, height: 844 },
  });
  const key = "QA-Environment-" + randomUUID();
  const labelIDs: string[] = [],
    resources: { type: string; id: string }[] = [];
  let host = "",
    user = "",
    grant = "",
    root = "",
    child = "";
  try {
    const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
    let login = await admin.request.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await admin.request.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await admin.request.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok(), await login.text()).toBe(true);
    const createLabel = async (value: string) => {
      const r = await admin.request.post("/api/v1/labels/labels", {
        data: { name: key, value, request_id: randomUUID() },
      });
      expect(r.status(), await r.text()).toBe(201);
      const v = await r.json();
      labelIDs.push(v.id);
      return v;
    };
    const production = await createLabel("production");
    const page = await admin.newPage();
    await page.goto("/console/labels");
    await page.getByRole("button", { name: "New label", exact: true }).click();
    const form = page.locator("form.labels-editor");
    await form.getByLabel("Key", { exact: true }).fill(key);
    await form.getByLabel("Value", { exact: true }).fill("staging");
    const pendingCreate = page.waitForResponse(
      (r) =>
        r.request().method() === "POST" && new URL(r.url()).pathname === "/api/v1/labels/labels",
    );
    await form.getByRole("button", { name: "Save label", exact: true }).click();
    const created = await pendingCreate;
    expect(created.status(), await created.text()).toBe(201);
    const staging = await created.json();
    labelIDs.push(staging.id);
    await createLabel("development");
    const createNode = async (name: string, parent_id = "") => {
      const r = await admin.request.post("/api/v1/assets/nodes", { data: { name, parent_id } });
      expect(r.status(), await r.text()).toBe(201);
      return (await r.json()).id as string;
    };
    root = await createNode("QA root " + randomUUID());
    child = await createNode("QA child " + randomUUID(), root);
    const asset = await admin.request.post("/api/v1/assets", {
      data: {
        name: "QA labeled " + randomUUID(),
        host: "127.0.0.1",
        port: 65530,
        username: "ops",
        password: "synthetic-label-target-password",
        node_id: child,
        host_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    });
    expect(asset.status(), await asset.text()).toBe(201);
    const a = await asset.json();
    host = a.id;
    resources.push(
      { type: "asset", id: host },
      { type: "node", id: child },
      { type: "node", id: root },
    );
    for (const [id, label] of [
      [root, production],
      [child, staging],
    ] as const) {
      const r = await admin.request.put(`/api/v1/labels/bindings/node/${id}`, {
        data: { label_ids: [label.id], revision: 0, request_id: randomUUID() },
      });
      expect(r.ok(), await r.text()).toBe(true);
    }
    await page.goto(`/console/labels?type=asset&id=${host}`);
    const effective = page.locator(".labels-effective");
    await expect(effective).toContainText(`${key}: staging`);
    await expect(effective).not.toContainText(`${key}: production`);
    const choices = page.locator(".labels-choices");
    await choices.getByRole("checkbox", { name: `${key}: development`, exact: true }).check();
    const path = `/api/v1/labels/bindings/asset/${host}`;
    const payloads: Record<string, unknown>[] = [];
    await page.route(`**${path}`, async (route) => {
      if (route.request().method() !== "PUT") {
        await route.continue();
        return;
      }
      payloads.push(route.request().postDataJSON());
      if (payloads.length === 1) {
        const response = await route.fetch();
        expect(response.ok(), await response.text()).toBe(true);
        await route.fulfill({
          status: 503,
          contentType: "application/json",
          body: JSON.stringify({ error_code: "labels_unavailable" }),
        });
      } else await route.continue();
    });
    await page.getByRole("button", { name: "Save bindings", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("Labels are unavailable");
    await page.getByRole("button", { name: "Save bindings", exact: true }).click();
    await expect(effective).toContainText(`${key}: development`);
    expect(payloads).toHaveLength(2);
    expect(payloads[1]).toEqual(payloads[0]);
    await page.unroute(`**${path}`);
    let details = await (await admin.request.get(path)).json();
    expect(details.binding.revision).toBe(1);
    const changed = await admin.request.put(path, {
      data: { label_ids: [staging.id], revision: 1, request_id: randomUUID() },
    });
    expect(changed.ok()).toBe(true);
    await choices.getByRole("checkbox", { name: `${key}: production`, exact: true }).check();
    await expect(
      choices.getByRole("checkbox", { name: `${key}: development`, exact: true }),
    ).not.toBeChecked();
    await page.getByRole("button", { name: "Save bindings", exact: true }).click();
    await expect(page.getByRole("alert")).toContainText("revision");
    await page.getByRole("button", { name: "Reload current revisions", exact: true }).click();
    await expect(
      choices.getByRole("checkbox", { name: `${key}: staging`, exact: true }),
    ).toBeChecked();
    await choices.getByRole("checkbox", { name: `${key}: production`, exact: true }).check();
    await page.getByRole("button", { name: "Save bindings", exact: true }).click();
    await expect(effective).toContainText(`${key}: production`);
    const inUse = await admin.request.delete(`/api/v1/labels/labels/${production.id}`, {
      data: { revision: production.revision, request_id: randomUUID() },
    });
    expect(inUse.status()).toBe(409);
    await page.goto(`/console?label=${production.id}`);
    await expect(page.getByRole("row").filter({ hasText: a.name })).toBeVisible();
    await page.getByRole("combobox", { name: "Resource labels", exact: true }).selectOption("");
    await page
      .getByRole("row")
      .filter({ hasText: a.name })
      .getByRole("link", { name: "Resource labels", exact: true })
      .click();
    await expect(effective).toContainText(`${key}: production`);
    const username = "labels.reader." + Date.now(),
      password = "synthetic-label-reader-password";
    const u = await admin.request.post("/api/v1/users", {
      data: { username, password, role: "operator" },
    });
    expect(u.status()).toBe(201);
    user = (await u.json()).id;
    const g = await admin.request.post("/api/v1/grants", {
      data: { user_id: user, asset_id: host, account: "ops", actions: ["view"] },
    });
    expect(g.status(), await g.text()).toBe(201);
    grant = (await g.json()).id;
    expect(
      (
        await reader.request.post("/api/v1/authentication/auth/", { data: { username, password } })
      ).ok(),
    ).toBe(true);
    const rp = await reader.newPage();
    await rp.goto(`/console/labels?type=asset&id=${host}`);
    await expect(rp.locator(".labels-effective")).toContainText(`${key}: production`);
    await expect(rp.getByRole("button", { name: "New label", exact: true })).toHaveCount(0);
    await expect(
      rp
        .locator(".labels-choices")
        .getByRole("checkbox", { name: `${key}: production`, exact: true }),
    ).toBeDisabled();
    const forbidden = await reader.request.put(path, {
      data: { label_ids: [], revision: 3, request_id: randomUUID() },
    });
    expect(forbidden.status()).toBe(404);
    await rp.getByRole("button", { name: "中文", exact: true }).click();
    await expect(rp.getByRole("heading", { name: "标签", exact: true })).toBeVisible();
    expect(await rp.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
      true,
    );
    await admin.request.delete(`/api/v1/grants/${grant}`);
    grant = "";
    expect((await reader.request.get(path)).status()).toBe(404);
    details = await (await admin.request.get(path)).json();
    expect(details.binding.revision).toBe(3);
  } finally {
    if (grant) await admin.request.delete(`/api/v1/grants/${grant}`);
    for (const resource of resources) {
      const path = `/api/v1/labels/bindings/${resource.type}/${resource.id}`;
      const r = await admin.request.get(path);
      if (r.ok()) {
        const v = await r.json();
        await admin.request.put(path, {
          data: { label_ids: [], revision: v.binding.revision, request_id: randomUUID() },
        });
      }
    }
    const catalog = await admin.request.get(
      "/api/v1/labels/labels?search=" + encodeURIComponent(key) + "&limit=100",
    );
    if (catalog.ok())
      for (const v of (await catalog.json()).results)
        if (labelIDs.includes(v.id))
          await admin.request.delete(`/api/v1/labels/labels/${v.id}`, {
            data: { revision: v.revision, request_id: randomUUID() },
          });
    if (host) await admin.request.delete(`/api/v1/assets/${host}`);
    if (child) await admin.request.delete(`/api/v1/assets/nodes/${child}`);
    if (root) await admin.request.delete(`/api/v1/assets/nodes/${root}`);
    if (user) await admin.request.delete(`/api/v1/users/${user}`);
    await reader.close();
    await admin.close();
  }
});
