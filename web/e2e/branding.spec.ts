import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const base = process.env.JMS_BRANDING_QA_BASE_URL || "http://127.0.0.1:8083",
  ui = process.env.JMS_BRANDING_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Branding QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });
test("global branding validates raster images, persists bilingual identity and theme, and enforces current permissions", async ({
  browser,
}, info) => {
  test.setTimeout(90000);
  const api = await request.newContext({ baseURL: base }),
    admin = await browser.newContext({ locale: "en-US", viewport: { width: 1440, height: 1080 } }),
    guest = await browser.newContext({ locale: "zh-CN", viewport: { width: 390, height: 844 } }),
    viewer = await request.newContext({ baseURL: base });
  const page = await admin.newPage(),
    sibling = await admin.newPage(),
    login = await guest.newPage(),
    errors: string[] = [];
  for (const p of [page, sibling, login]) p.on("pageerror", (e) => errors.push(e.message));
  let original: any = null,
    originalLogo = "",
    originalIcon = "",
    originalMark = "",
    originalLogin = "",
    userID = "",
    assetID = "",
    token = "";
  const input = (settings: any) => ({
    revision: settings.revision,
    name_en: settings.name_en,
    name_zh: settings.name_zh,
    theme: settings.theme,
    accent: settings.accent,
    login_title_en: settings.login_title_en,
    login_title_zh: settings.login_title_zh,
    footer_en: settings.footer_en,
    footer_zh: settings.footer_zh,
    registration_label: settings.registration_label,
    registration_url: settings.registration_url,
  });
  try {
    const credentials = {
      username: process.env.JMS_BRANDING_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_BRANDING_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let response = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!response.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      response = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(response.ok()).toBe(true);
    token = (await response.json()).access_token;
    await admin.addCookies((await api.storageState()).cookies);
    await sibling.goto(ui + "/workbench");
    const before = await api.get("/api/v1/settings/branding");
    expect(before.status()).toBe(200);
    original = (await before.json()).settings;
    if (original.logo_digest)
      originalLogo = (
        await (await api.get(`/api/v1/branding/images/${original.logo_digest}`)).body()
      ).toString("base64");
    if (original.icon_digest)
      originalIcon = (
        await (await api.get(`/api/v1/branding/images/${original.icon_digest}`)).body()
      ).toString("base64");
    if (original.mark_digest)
      originalMark = (
        await (await api.get(`/api/v1/branding/images/${original.mark_digest}`)).body()
      ).toString("base64");
    if (original.login_digest)
      originalLogin = (
        await (await api.get(`/api/v1/branding/images/${original.login_digest}`)).body()
      ).toString("base64");
    await page.goto(ui + "/console/branding");
    await expect(page.getByRole("heading", { name: "Branding", exact: true })).toBeVisible();
    const save = page.getByRole("button", { name: "Save branding", exact: true });
    await expect(save).toBeDisabled();
    await page.getByRole("textbox", { name: "English name", exact: true }).fill("Operations Vault");
    await page.getByRole("textbox", { name: "Chinese name", exact: true }).fill("运维访问平台");
    await page.getByRole("combobox", { name: "Theme", exact: true }).selectOption("forest");
    await page.getByRole("textbox", { name: "Accent color", exact: true }).fill("#65d8a1");
    await page
      .getByRole("textbox", { name: "English sign-in title", exact: true })
      .fill("Welcome to operations");
    await page
      .getByRole("textbox", { name: "Chinese sign-in title", exact: true })
      .fill("欢迎进入运维平台");
    await page
      .getByRole("textbox", { name: "English footer", exact: true })
      .fill("Operations access");
    await page.getByRole("textbox", { name: "Chinese footer", exact: true }).fill("运维访问入口");
    await page
      .getByRole("textbox", { name: "Registration text", exact: true })
      .fill("QA registration");
    await page
      .getByRole("textbox", { name: "Registration link (HTTPS)", exact: true })
      .fill("https://registration.example.invalid/");
    const logo = Buffer.from(
      await page.evaluate(() => {
        const canvas = document.createElement("canvas");
        canvas.width = 160;
        canvas.height = 40;
        const c = canvas.getContext("2d")!;
        c.fillStyle = "#65d8a1";
        c.fillRect(0, 0, 160, 40);
        c.fillStyle = "#0b1410";
        c.font = "bold 23px sans-serif";
        c.fillText("QA VAULT", 10, 28);
        return canvas.toDataURL("image/png").split(",")[1];
      }),
      "base64",
    );
    const icon = Buffer.from(
      await page.evaluate(() => {
        const canvas = document.createElement("canvas");
        canvas.width = 32;
        canvas.height = 32;
        const c = canvas.getContext("2d")!;
        c.fillStyle = "#65d8a1";
        c.fillRect(0, 0, 32, 32);
        return canvas.toDataURL("image/png").split(",")[1];
      }),
      "base64",
    );
    await page
      .getByLabel("Site logo", { exact: true })
      .setInputFiles({ name: "qa-logo.png", mimeType: "image/png", buffer: logo });
    await expect(save).toBeEnabled();
    await page
      .getByLabel("Browser icon", { exact: true })
      .setInputFiles({ name: "qa-icon.png", mimeType: "image/png", buffer: icon });
    await expect(save).toBeEnabled();
    await page
      .getByLabel("Square terminal logo", { exact: true })
      .setInputFiles({ name: "qa-mark.png", mimeType: "image/png", buffer: icon });
    await expect(save).toBeEnabled();
    await page
      .getByLabel("Sign-in illustration", { exact: true })
      .setInputFiles({ name: "qa-login.png", mimeType: "image/png", buffer: logo });
    await expect(save).toBeEnabled();
    await save.click();
    await expect(page.getByRole("status")).toContainText("Branding saved.");
    await expect(page).toHaveTitle("Operations Vault");
    await expect(
      page.locator(".layout-header").getByRole("img", { name: "Operations Vault", exact: true }),
    ).toBeVisible();
    await expect(save).toBeDisabled();
    await expect(page.locator("html")).toHaveAttribute("data-brand-theme", "forest");
    await expect(sibling).toHaveTitle("Operations Vault");
    await expect(
      sibling.locator(".layout-header").getByRole("img", { name: "Operations Vault", exact: true }),
    ).toBeVisible();
    await page.screenshot({ path: info.outputPath("branding.en.png"), fullPage: true });
    const current = (await (await api.get("/api/v1/settings/branding")).json()).settings;
    const originalInput = {
      ...input(current),
      revision: original.revision,
      logo: logo.toString("base64"),
      icon: icon.toString("base64"),
      mark: icon.toString("base64"),
      login_image: logo.toString("base64"),
    };
    const retry = await api.put("/api/v1/settings/branding", { data: originalInput });
    expect(retry.status()).toBe(200);
    expect((await retry.json()).revision).toBe(current.revision);
    const auditBefore = await (await api.get("/api/v1/settings/branding/audit")).json();
    expect(auditBefore.results[0].after.logo_digest).toBe(current.logo_digest);
    expect(JSON.stringify(auditBefore)).not.toContain(logo.toString("base64"));
    expect(
      (
        await api.put("/api/v1/settings/branding", {
          data: { ...originalInput, name_en: "Stale overwrite" },
        })
      ).status(),
    ).toBe(409);
    expect(
      (
        await api.post("/api/v1/settings/branding/prepare-image", {
          data: { kind: "logo", data: Buffer.from('<svg onload="invalid()"/>').toString("base64") },
        })
      ).status(),
    ).toBe(400);
    const image = await api.get(`/api/v1/branding/images/${current.logo_digest}`);
    expect(image.status()).toBe(200);
    expect(image.headers()["content-type"]).toBe("image/png");
    expect(image.headers()["cache-control"]).toContain("immutable");
    expect(
      (
        await api.get(`/api/v1/branding/images/${current.logo_digest}`, {
          headers: { "If-None-Match": image.headers().etag },
        })
      ).status(),
    ).toBe(304);
    await login.goto(ui + "/login");
    await expect(
      login.getByRole("heading", { name: "欢迎进入运维平台", exact: true }),
    ).toBeVisible();
    await expect(login.getByRole("img", { name: "运维访问平台", exact: true })).toBeVisible();
    await expect(login).toHaveTitle("运维访问平台");
    await expect(login.locator("head link[data-branding-icon]")).toHaveAttribute(
      "href",
      `/api/v1/branding/images/${current.icon_digest}`,
    );
    await expect(login.locator("html")).toHaveAttribute("data-brand-theme", "forest");
    await expect(login.locator(".login-illustration img")).toHaveAttribute(
      "src",
      `/api/v1/branding/images/${current.login_digest}`,
    );
    await expect(login.getByText("运维访问入口", { exact: true })).toBeVisible();
    await expect(login.getByRole("link", { name: "QA registration", exact: true })).toHaveAttribute(
      "rel",
      "noopener noreferrer",
    );
    await login.screenshot({ path: info.outputPath("branding.zh-CN.png"), fullPage: true });
    await page.goto(ui + "/audit");
    await expect(
      page.locator(".layout-header").getByRole("img", { name: "Operations Vault", exact: true }),
    ).toBeVisible();
    await page.goto(ui + "/workbench");
    await expect(
      page.locator(".layout-header").getByRole("img", { name: "Operations Vault", exact: true }),
    ).toBeVisible();
    const fixture = await (
      await api.get(process.env.JMS_BRANDING_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    const hostName = `Branding SSH ${Date.now()}`;
    const host = await api.post("/api/v1/assets", {
      data: {
        name: hostName,
        host: process.env.JMS_BRANDING_QA_SSH_HOST || "127.0.0.1",
        port: Number(fixture.address.split(":").at(-1)),
        username: "keyqa",
        password: "synthetic-keyhost-password-233",
        host_key_fingerprint: fixture.fingerprint,
      },
    });
    expect(host.status()).toBe(201);
    assetID = (await host.json()).id;
    const account = await (await api.get(`/api/v1/assets/${assetID}/accounts/${assetID}`)).json();
    expect(
      (
        await api.put(`/api/v1/assets/${assetID}/accounts/${assetID}`, {
          data: {
            version: account.version,
            password_rotation_enabled: false,
            key_rotation_enabled: false,
          },
        })
      ).status(),
    ).toBe(200);
    await page.goto(ui + "/console");
    await page
      .getByRole("row")
      .filter({ hasText: hostName })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    const terminal = page.getByRole("dialog", { name: hostName, exact: true });
    await expect(terminal.locator(".ssh-terminal-status")).toHaveClass(/connected/);
    await expect(terminal.locator(".brand-mark")).toHaveAttribute(
      "src",
      `/api/v1/branding/images/${current.mark_digest}`,
    );
    await expect(terminal.locator(".brand-mark")).toBeVisible();
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    const username = `brand.viewer.${Date.now()}`,
      password = "synthetic-branding-viewer-password";
    const created = await api.post("/api/v1/users", {
      data: { username, password, role: "operator" },
    });
    expect(created.status()).toBe(201);
    userID = (await created.json()).id;
    expect(
      (
        await viewer.post("/api/v1/authentication/auth/", { data: { username, password } })
      ).status(),
    ).toBe(200);
    expect((await viewer.get("/api/v1/settings/branding")).status()).toBe(403);
    expect((await viewer.put("/api/v1/settings/branding", { data: input(current) })).status()).toBe(
      403,
    );
    expect(
      (
        await viewer.post("/api/v1/settings/branding/prepare-image", {
          data: { kind: "logo", data: logo.toString("base64") },
        })
      ).status(),
    ).toBe(403);
    const publicSettings = await (await guest.request.get(ui + "/api/v1/branding")).json();
    expect(publicSettings.name_en).toBe("Operations Vault");
    expect(JSON.stringify(publicSettings)).not.toContain("actor_id");
    const cli = await execute("go", ["run", "./cmd/jms", "branding", "show"], {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      env: {
        ...process.env,
        JMS_SERVER_URL: base,
        JMS_TOKEN: token,
        JMS_ORG_ID: "",
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
      },
    });
    expect(JSON.parse(cli.stdout).settings.name_en).toBe("Operations Vault");
    const fresh = (await (await api.get("/api/v1/settings/branding")).json()).settings;
    expect(fresh.revision).toBe(current.revision);
    expect((await (await api.get("/api/v1/settings/branding/audit")).json()).total).toBe(
      auditBefore.total,
    );
    expect(errors).toEqual([]);
  } finally {
    if (original) {
      const latest = await api.get("/api/v1/settings/branding");
      if (latest.ok()) {
        const settings = (await latest.json()).settings;
        const restore = await api.put("/api/v1/settings/branding", {
          data: {
            ...input(original),
            revision: settings.revision,
            logo: originalLogo,
            icon: originalIcon,
            mark: originalMark,
            login_image: originalLogin,
          },
        });
        expect(restore.ok()).toBe(true);
      }
    }
    if (assetID) await api.delete("/api/v1/assets/" + assetID);
    if (userID) await api.delete("/api/v1/users/" + userID);
    await viewer.dispose();
    await admin.close();
    await guest.close();
    await api.dispose();
  }
});
