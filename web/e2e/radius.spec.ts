import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { randomUUID } from "node:crypto";
const execute = promisify(execFile),
  base = process.env.JMS_RADIUS_QA_BASE_URL || "http://127.0.0.1:8083",
  ui = process.env.JMS_RADIUS_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("RADIUS QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });
test("native FreeRADIUS mTLS primary, challenges, browser factors and protected CLI state", async ({
  browser,
}, info) => {
  test.setTimeout(150000);
  const api = await request.newContext({ baseURL: base }),
    admin = await browser.newContext({ locale: "en-US", viewport: { width: 1440, height: 1080 } }),
    operator = await browser.newContext({ locale: "en-US" }),
    page = await admin.newPage(),
    op = await operator.newPage(),
    errors: string[] = [];
  for (const p of [page, op]) p.on("pageerror", (e) => errors.push(e.message));
  const stamp = Date.now(),
    account = {
      username: `radius.local.${stamp}`,
      password: "synthetic-radius-local-operator-233",
      role: "operator",
    };
  let original: any,
    asset = "",
    user = "";
  const state = resolve(tmpdir(), `jms233-radius-auth-${randomUUID()}.json`);
  const cleanConfig = (v: any) => {
    const { has_primary_secret, has_primary_key, has_factor_secret, has_factor_key, ...config } = v;
    return config;
  };
  try {
    const credentials = {
      username: process.env.JMS_RADIUS_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_RADIUS_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok()).toBe(true);
    original = await (await api.get("/api/v1/settings/security/radius")).json();
    const fixture = await (
      await api.get(process.env.JMS_RADIUS_QA_FIXTURE_URL || "http://127.0.0.1:18514/credentials")
    ).json();
    const created = await api.post("/api/v1/users", { data: account });
    expect(created.status(), await created.text()).toBe(201);
    user = (await created.json()).id;
    const endpoint = {
      host: process.env.JMS_RADIUS_QA_HOST || "127.0.0.1",
      port: fixture.tls_port,
      transport: "tls",
      allow_udp: false,
      server_name: fixture.server_name,
      ca_pem: fixture.root_ca_pem,
      client_certificate: fixture.client_certificate,
      nas_identifier: "jumpserver233-qa",
      timeout_seconds: 2,
      attempts: 2,
    };
    const configured = await api.put("/api/v1/settings/security/radius", {
      data: {
        ...cleanConfig(original),
        enabled: true,
        provision_new: true,
        realm: `qa-${stamp}`,
        primary: endpoint,
        factor: endpoint,
        factor_policy: "users",
        factor_user_ids: [user],
        bindings: { [user]: "radius.challenge.qa" },
        primary_secrets: { client_key: fixture.client_key },
        factor_secrets: { client_key: fixture.client_key },
      },
    });
    expect(configured.status(), await configured.text()).toBe(200);
    expect(await configured.text()).not.toContain(fixture.client_key);
    await admin.request.post(ui + "/api/v1/authentication/auth/", {
      data: credentials,
      headers: { "X-JMS-Browser-Session": "cookie" },
    });
    await page.goto(ui + "/console/radius");
    await expect(
      page.getByRole("heading", { name: "RADIUS authentication", exact: true }),
    ).toBeVisible();
    await expect(page.getByLabel("Identity realm", { exact: true })).toHaveValue(`qa-${stamp}`);
    await page.getByRole("button", { name: "Save RADIUS settings", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("RADIUS settings saved");
    const primary = page
      .locator(".radius-form > fieldset > details")
      .filter({ has: page.getByText("Primary server", { exact: true }) });
    await primary.locator("summary").click();
    await primary.getByRole("combobox").selectOption("udp");
    await primary.getByLabel("Server port", { exact: true }).fill(String(fixture.udp_port));
    await primary.getByLabel("Allow legacy UDP for this endpoint", { exact: true }).check();
    await primary
      .getByLabel("Shared secret (write only)", { exact: true })
      .fill(fixture.shared_secret);
    await page.getByRole("button", { name: "Save RADIUS settings", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("RADIUS settings saved");
    const udp = await (await api.get("/api/v1/settings/security/radius")).json();
    expect(udp.primary.transport).toBe("udp");
    expect(udp.primary.client_certificate).toBe("");
    expect(udp.primary.ca_pem).toBe("");
    const probe = await api.post("/api/v1/settings/security/radius/check", {
      data: {
        endpoint: "primary",
        username: "radius.qa",
        password: "synthetic-radius-password-233",
      },
    });
    expect(probe.status()).toBe(200);
    expect((await probe.json()).result).toBe(2);
    await primary.getByRole("combobox").selectOption("tls");
    await primary.getByLabel("Server port", { exact: true }).fill(String(fixture.tls_port));
    await primary.getByLabel("TLS server name", { exact: true }).fill(fixture.server_name);
    await primary.getByLabel("Trusted CA PEM", { exact: true }).fill(fixture.root_ca_pem);
    await primary
      .getByLabel("Client certificate PEM", { exact: true })
      .fill(fixture.client_certificate);
    await page.getByRole("button", { name: "Save RADIUS settings", exact: true }).click();
    await expect(page.getByRole("status")).toContainText("RADIUS settings saved");
    await primary.locator("summary").click();
    await page.screenshot({ path: info.outputPath("radius.en.png"), fullPage: false });
    await op.goto(ui + "/login");
    await op.getByRole("combobox").selectOption("radius");
    await op.getByLabel("Username", { exact: true }).fill("radius.challenge.qa");
    await op.getByLabel("Password", { exact: true }).fill("start");
    await op.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(op.getByText("Challenge round 1", { exact: true })).toBeVisible();
    await op.reload();
    await expect(op.getByText("Challenge round 1", { exact: true })).toBeVisible();
    await op.getByLabel("RADIUS response", { exact: true }).fill("654321");
    await op.getByRole("button", { name: "Verify response", exact: true }).click();
    await expect(
      op.getByRole("heading", { name: "Complete RADIUS sign-in", exact: true }),
    ).toBeVisible();
    await op.getByRole("button", { name: "Continue sign-in", exact: true }).click();
    await expect(op).toHaveURL(/\/console/);
    expect((await operator.request.get(ui + "/api/v1/users/me")).status()).toBe(200);
    await operator.clearCookies();
    await op.goto(ui + "/login");
    await op.getByLabel("Username", { exact: true }).fill(account.username);
    await op.getByLabel("Password", { exact: true }).fill(account.password);
    await op.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(
      op.getByRole("heading", { name: "RADIUS verification", exact: true }),
    ).toBeVisible();
    expect((await operator.request.get(ui + "/api/v1/users/me")).status()).toBe(401);
    await op.getByRole("button", { name: "Verify response", exact: true }).click();
    await expect(op.getByText("Challenge round 1", { exact: true })).toBeVisible();
    await op.reload();
    await expect(
      op.getByRole("heading", { name: "RADIUS verification", exact: true }),
    ).toBeVisible();
    await op.getByLabel("RADIUS response", { exact: true }).fill("654321");
    await op.getByRole("button", { name: "Verify response", exact: true }).click();
    await expect(op).toHaveURL(/\/console/);
    expect((await operator.request.get(ui + "/api/v1/settings/security/radius")).status()).toBe(
      403,
    );
    const host = await (
      await api.get(process.env.JMS_RADIUS_QA_SSH_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    const made = await api.post("/api/v1/assets", {
      data: {
        name: `RADIUS CLI host ${stamp}`,
        host: process.env.JMS_RADIUS_QA_SSH_HOST || "127.0.0.1",
        port: Number(host.address.split(":").at(-1)),
        username: "keyqa",
        password: "synthetic-keyhost-password-233",
        host_key_fingerprint: host.fingerprint,
      },
    });
    expect(made.status(), await made.text()).toBe(201);
    asset = (await made.json()).id;
    expect(
      (
        await api.post("/api/v1/grants", {
          data: { user_id: user, asset_id: asset, account: "keyqa", actions: ["view", "connect"] },
        })
      ).status(),
    ).toBe(201);
    const env = {
        ...process.env,
        JMS_SERVER_URL: base,
        JMS_TOKEN: "",
        JMS_TOKEN_FILE: "",
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
        JMS_ORG_ID: "",
        JMS_ACCOUNT: "",
      },
      cwd = fileURLToPath(new URL("../../server/", import.meta.url));
    const cli = async (args: string[], input: string) =>
      new Promise<string>((done, reject) => {
        const child = execFile(
          "go",
          ["run", "./cmd/jms", ...args],
          { cwd, env, timeout: 60000, maxBuffer: 262144 },
          (e, stdout) => (e ? reject(e) : done(stdout)),
        );
        child.stdin?.end(input);
      });
    const first = await cli(
      ["auth", "login", "--state-file", state, "--file", "-"],
      JSON.stringify({ username: account.username, password: account.password }),
    );
    expect(JSON.parse(first).next).toBe("factor-complete");
    expect(first).not.toContain("factor_token");
    expect(
      JSON.parse(
        await cli(["auth", "continue", "--state-file", state, "--file", "-"], '{"response":""}'),
      ).next,
    ).toBe("factor-complete");
    expect(
      JSON.parse(
        await cli(
          ["auth", "continue", "--state-file", state, "--file", "-"],
          '{"response":"654321"}',
        ),
      ).next,
    ).toBe("authenticated");
    const result = await execute(
      "go",
      ["run", "./cmd/jms", "exec", asset, "--json", "--", "printf radius-cli-ok"],
      { cwd, env: { ...env, JMS_TOKEN_FILE: state }, timeout: 60000, maxBuffer: 262144 },
    );
    expect(result.stdout).toContain("radius-cli-ok");
    const mobile = await browser.newContext({
      locale: "zh-CN",
      viewport: { width: 390, height: 844 },
    });
    try {
      await mobile.request.post(ui + "/api/v1/authentication/auth/", {
        data: credentials,
        headers: { "X-JMS-Browser-Session": "cookie" },
      });
      const p = await mobile.newPage();
      await p.goto(ui + "/console/radius");
      await expect(p.getByRole("heading", { name: "RADIUS 认证", exact: true })).toBeVisible();
      expect(await p.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await p.screenshot({ path: info.outputPath("radius.zh-CN.png"), fullPage: false });
    } finally {
      await mobile.close();
    }
    expect(errors).toEqual([]);
  } finally {
    await rm(state, { force: true });
    if (asset) await api.delete("/api/v1/assets/" + asset);
    if (original) {
      const current = await (await api.get("/api/v1/settings/security/radius")).json();
      await api.put("/api/v1/settings/security/radius", {
        data: {
          ...cleanConfig(original),
          revision: current.revision,
          primary_secrets: {
            clear_client_key: !original.has_primary_key,
            clear_shared_secret: !original.has_primary_secret,
          },
          factor_secrets: {
            clear_client_key: !original.has_factor_key,
            clear_shared_secret: !original.has_factor_secret,
          },
        },
      });
    }
    await admin.close();
    await operator.close();
    await api.dispose();
  }
});
