import { test, expect } from "@playwright/test";
import { randomUUID } from "node:crypto";
test.use({ locale: "en-US", trace: "off" });

test("SSH CA management binds accounts, prepares rotation before activation, retries safely and renders both languages", async ({
  browser,
}, info) => {
  test.setTimeout(60_000);
  const baseURL = info.project.use.baseURL;
  if (typeof baseURL !== "string" || !/^http:\/\/127\.0\.0\.\d+:\d+$/.test(baseURL))
    throw Error("SSH certificate QA requires its owning loopback fixture");
  const context = await browser.newContext({
    baseURL,
    locale: "en-US",
    viewport: { width: 390, height: 844 },
  });
  let issuer = "",
    asset = "";
  try {
    const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
    let login = await context.request.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await context.request.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await context.request.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok(), await login.text()).toBe(true);
    const page = await context.newPage();
    await page.goto("/console/ssh-certificates");
    await page.getByRole("button", { name: "New issuer", exact: true }).click();
    const name = "QA CA " + randomUUID(),
      form = page.locator(".ssh-certificate-editor");
    await form.getByLabel("Name", { exact: true }).fill(name);
    const pending = page.waitForResponse(
      (r) =>
        r.request().method() === "POST" &&
        new URL(r.url()).pathname === "/api/v1/settings/ssh-certificates/issuers",
    );
    await form.getByRole("button", { name: "Save issuer", exact: true }).click();
    const response = await pending;
    expect(response.status(), await response.text()).toBe(201);
    let ca = await response.json();
    issuer = ca.id;
    expect(JSON.stringify(ca)).not.toContain("private_key");
    const card = page.getByRole("article", { name, exact: true });
    await expect(card).toBeVisible();
    await card.getByText("Target trust bundle", { exact: true }).click();
    await expect(card.locator("pre")).toContainText("ssh-ed25519");
    page.on("dialog", (d) => void d.accept());
    const prep = page.waitForResponse(
      (r) => r.request().method() === "POST" && new URL(r.url()).pathname.endsWith("/rotate"),
    );
    await card.getByRole("button", { name: "Prepare CA rotation", exact: true }).click();
    const prepared = await (await prep).json();
    expect(prepared.public_key).toBe(ca.public_key);
    expect(prepared.pending_public_key).toBeTruthy();
    await expect(
      card.getByRole("button", { name: "Activate prepared CA", exact: true }),
    ).toBeVisible();
    const activation = page.waitForResponse(
      (r) => r.request().method() === "POST" && new URL(r.url()).pathname.endsWith("/activate"),
    );
    await card.getByRole("button", { name: "Activate prepared CA", exact: true }).click();
    ca = await (await activation).json();
    expect(ca.public_key).toBe(prepared.pending_public_key);
    expect(ca.trust_bundle).toContain(prepared.public_key);
    const created = await context.request.post("/api/v1/assets", {
      data: {
        name: "QA certificate account " + randomUUID(),
        host: "127.0.0.1",
        port: 65530,
        username: "ops",
        password: "synthetic-unused-ca-bootstrap",
        host_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      },
    });
    expect(created.status()).toBe(201);
    asset = (await created.json()).id;
    await page.goto("/console/ssh-certificates?asset_id=" + asset);
    const binding = page.locator(".labels-bindings");
    await expect(
      binding.getByRole("combobox", { name: "Issuer policy", exact: true }),
    ).toBeVisible();
    await binding
      .getByRole("combobox", { name: "Issuer policy", exact: true })
      .selectOption(issuer);
    await binding.getByRole("button", { name: "Save account policy", exact: true }).click();
    await expect(page.getByRole("status")).toHaveText("Account policy saved.");
    const path = "/api/v1/settings/ssh-certificates/bindings/" + asset;
    const before = await (await context.request.get(path)).json();
    expect(before.binding.revision).toBe(1);
    const update = { issuer_id: issuer, revision: 1, request_id: randomUUID() };
    const first = await context.request.put(path, { data: update }),
      second = await context.request.put(path, { data: update });
    expect(first.ok()).toBe(true);
    expect(await second.json()).toEqual(await first.json());
    const stale = await context.request.put(path, {
      data: { issuer_id: "", revision: 1, request_id: randomUUID() },
    });
    expect(stale.status()).toBe(409);
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "SSH 证书", exact: true })).toBeVisible();
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
  } finally {
    if (asset) {
      const path = "/api/v1/settings/ssh-certificates/bindings/" + asset;
      const r = await context.request.get(path);
      if (r.ok()) {
        const b = await r.json();
        await context.request.put(path, {
          data: { issuer_id: "", revision: b.binding.revision, request_id: randomUUID() },
        });
      }
      await context.request.delete("/api/v1/assets/" + asset);
    }
    if (issuer) {
      const r = await context.request.get("/api/v1/settings/ssh-certificates/issuers");
      if (r.ok()) {
        const ca = (await r.json()).find((v: { id: string }) => v.id === issuer);
        if (ca)
          await context.request.delete("/api/v1/settings/ssh-certificates/issuers/" + issuer, {
            data: { revision: ca.revision, request_id: randomUUID() },
          });
      }
    }
    await context.close();
  }
});
