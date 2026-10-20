import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { randomUUID, createHmac } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
const base = process.env.JMS_PASSWORD_QA_BASE_URL || "http://127.0.0.1:8083",
  ui = process.env.JMS_PASSWORD_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Password QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });
test("password policy, browser and protected CLI recovery, history and TOTP resets revoke live SSH without exposing credentials", async ({
  browser,
}, info) => {
  test.setTimeout(180000);
  const api = await request.newContext({ baseURL: base }),
    admin = await browser.newContext({ locale: "en-US", viewport: { width: 1440, height: 1080 } }),
    operator = await browser.newContext({ locale: "en-US" }),
    page = await admin.newPage(),
    op = await operator.newPage(),
    errors: string[] = [];
  for (const p of [page, op]) p.on("pageerror", (e) => errors.push(e.message));
  const adminCredentials = {
      username: process.env.JMS_PASSWORD_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_PASSWORD_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    },
    username = `password.security.${Date.now()}`,
    initial = "Initial-Password-233",
    temporary = "Temporary-Password-233",
    changed = "Changed-Password-233",
    second = "Temporary-Again-233",
    final = "Final-Password-233",
    state = resolve(tmpdir(), `jms233-password-${randomUUID()}.json`);
  let token = "",
    userID = "",
    assetID = "",
    original: Record<string, unknown> | null = null;
  const headers = () => ({ Authorization: `Bearer ${token}` });
  async function rootLogin() {
    let r = await api.post("/api/v1/authentication/auth/", { data: adminCredentials });
    if (!r.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: adminCredentials });
      r = await api.post("/api/v1/authentication/auth/", { data: adminCredentials });
    }
    expect(r.status()).toBe(200);
    token = (await r.json()).access_token;
  }
  async function browserRoot() {
    const r = await admin.request.post(ui + "/api/v1/authentication/auth/", {
      data: adminCredentials,
      headers: { "X-JMS-Browser-Session": "cookie" },
    });
    expect(r.status()).toBe(200);
  }
  async function cli(args: string[], body: object = {}, auth = false) {
    return new Promise<string>((done, reject) => {
      const child = execFile(
        "go",
        ["run", "./cmd/jms", ...args],
        {
          cwd: fileURLToPath(new URL("../../server", import.meta.url)),
          timeout: 60000,
          env: {
            ...process.env,
            JMS_SERVER_URL: base,
            JMS_TOKEN: "",
            JMS_ACCESS_KEY_ID: "",
            JMS_ACCESS_KEY_SECRET: "",
            JMS_TOKEN_FILE: auth ? state : "",
          },
        },
        (e, stdout) => (e ? reject(Error("CLI operation rejected")) : done(stdout)),
      );
      child.stdin?.end(JSON.stringify(body));
    });
  }
  try {
    await rootLogin();
    await browserRoot();
    original = await (
      await api.get("/api/v1/settings/security/passwords", { headers: headers() })
    ).json();
    const created = await api.post("/api/v1/users", {
      headers: headers(),
      data: { username, password: initial, role: "operator" },
    });
    expect(created.status()).toBe(201);
    userID = (await created.json()).id;
    const fixture = await (
      await api.get(process.env.JMS_PASSWORD_QA_FIXTURE_URL || "http://127.0.0.1:12223/health")
    ).json();
    const name = `Password security SSH ${Date.now()}`;
    const asset = await api.post("/api/v1/assets", {
      headers: headers(),
      data: {
        name,
        host: process.env.JMS_PASSWORD_QA_SSH_HOST || "127.0.0.1",
        port: Number(fixture.address.split(":").at(-1)),
        username: fixture.username,
        password: process.env.JMS_PASSWORD_QA_SSH_PASSWORD || "synthetic-qa-only-password",
        host_key_fingerprint: fixture.fingerprint,
      },
    });
    expect(asset.status()).toBe(201);
    assetID = (await asset.json()).id;
    expect(
      (
        await api.post("/api/v1/grants", {
          headers: headers(),
          data: {
            user_id: userID,
            asset_id: assetID,
            account: fixture.username,
            actions: ["view", "connect"],
          },
        })
      ).status(),
    ).toBe(201);
    await operator.request.post(ui + "/api/v1/authentication/auth/", {
      data: { username, password: initial },
      headers: { "X-JMS-Browser-Session": "cookie" },
    });
    await op.goto(ui + "/console");
    await op
      .getByRole("row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    await expect(op.locator(".ssh-terminal-status")).toHaveText("Connected");
    await page.goto(ui + "/console/settings");
    await page.getByRole("tab", { name: "Security", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Password security", exact: true }),
    ).toBeVisible();
    await page.getByLabel("Minimum bytes (operator)", { exact: true }).fill("16");
    await page.getByLabel("Previous passwords disallowed", { exact: true }).fill("2");
    await page.getByLabel("Operator maximum age (days; 0 disables)", { exact: true }).fill("1");
    for (const label of ["Uppercase", "Lowercase", "Digits", "Symbols"])
      await page.getByLabel(label, { exact: true }).check();
    await page
      .getByRole("button", { name: "Save password policy and sign out", exact: true })
      .click();
    await expect(page).toHaveURL(ui + "/login");
    await expect
      .poll(() => op.locator(".ssh-terminal-status").allTextContents(), { timeout: 15000 })
      .not.toContain("Connected");
    await rootLogin();
    await browserRoot();
    await page.goto(ui + "/console/users");
    const signedIn = await operator.request.post(ui + "/api/v1/authentication/auth/", {
      data: { username, password: initial },
    });
    expect(signedIn.status()).toBe(200);
    const oldToken = (await signedIn.json()).access_token;
    const permanent = await (await operator.request.post(ui + "/api/v1/users/me/tokens")).json();
    await page.getByLabel("Search users", { exact: true }).fill(username);
    await page.getByRole("button", { name: "Search users", exact: true }).click();
    const row = page.locator("tbody tr").filter({ hasText: username }).first();
    await row.getByRole("button", { name: "Reset password", exact: true }).click();
    await page.getByLabel("New password", { exact: true }).fill(temporary);
    await page.getByRole("button", { name: "Confirm credential reset", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: new RegExp("Reset password: " + username) }),
    ).toHaveCount(0);
    expect((await operator.request.get(ui + "/api/v1/users/me")).status()).toBe(401);
    expect(
      (
        await api.get("/api/v1/users/me", { headers: { Authorization: `Bearer ${oldToken}` } })
      ).status(),
    ).toBe(401);
    expect(
      (
        await api.get("/api/v1/users/me", {
          headers: { Authorization: `Token ${permanent.token}` },
        })
      ).status(),
    ).toBe(401);
    await op.goto(ui + "/login");
    await op.getByLabel("Username", { exact: true }).fill(username);
    await op.getByLabel("Password", { exact: true }).fill(temporary);
    await op.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(op).toHaveURL(ui + "/password-change");
    await expect(
      op.getByRole("heading", { name: "Change your password", exact: true }),
    ).toBeVisible();
    await op.reload();
    await expect(op.getByText(username, { exact: true })).toBeVisible();
    for (const field of ["New password", "Confirm new password"])
      await op.getByLabel(field, { exact: true }).fill("short");
    await op.getByRole("button", { name: "Change password", exact: true }).click();
    await expect(op.getByRole("alert")).toContainText("does not meet");
    for (const field of ["New password", "Confirm new password"])
      await op.getByLabel(field, { exact: true }).fill(changed);
    await op.getByRole("button", { name: "Change password", exact: true }).click();
    await expect(op).toHaveURL(ui + "/login");
    const getUser = async () =>
      (await api.get("/api/v1/users/" + userID, { headers: headers() })).json();
    expect(
      (
        await api.post(`/api/v1/users/${userID}/password/reset`, {
          headers: headers(),
          data: { revision: (await getUser()).revision, new_password: second, force_change: true },
        })
      ).status(),
    ).toBe(200);
    const loginOutput = await cli(["auth", "login", "--state-file", state, "--file", "-"], {
      username,
      password: second,
    });
    expect(JSON.parse(loginOutput).next).toBe("password-complete");
    expect(/change_token|access_token/.test(loginOutput)).toBe(false);
    const status = JSON.parse(await cli(["auth", "status", "--state-file", state]));
    expect(status.password_policy.min_length).toBe(16);
    await expect(
      cli(["auth", "continue", "--state-file", state, "--file", "-"], { new_password: changed }),
    ).rejects.toThrow("CLI operation rejected");
    const complete = await cli(["auth", "continue", "--state-file", state, "--file", "-"], {
      new_password: final,
    });
    expect(JSON.parse(complete).next).toBe("login");
    const authenticated = await cli(["auth", "continue", "--state-file", state, "--file", "-"], {
      username,
      password: final,
    });
    expect(JSON.parse(authenticated).next).toBe("authenticated");
    const privateState = JSON.parse(await readFile(state, "utf8"));
    expect(Boolean(privateState.result.change_token)).toBe(false);
    expect(
      await cli(["exec", assetID, "--json", "--", "printf", "browser-job-ok"], {}, true),
    ).toContain("browser-job-ok");
    await operator.request.post(ui + "/api/v1/authentication/auth/", {
      data: { username, password: final },
      headers: { "X-JMS-Browser-Session": "cookie" },
    });
    const enrollment = await (
      await operator.request.post(ui + "/api/v1/users/me/mfa/enrollment")
    ).json();
    expect(
      (
        await operator.request.post(ui + "/api/v1/users/me/mfa/confirm", {
          data: { otp: totp(enrollment.secret) },
        })
      ).status(),
    ).toBe(200);
    const codes = await operator.request.post(ui + "/api/v1/users/me/mfa/recovery-codes", {
      data: { password: final, otp: totp(enrollment.secret, 1) },
    });
    expect(codes.status()).toBe(200);
    await page.reload();
    await page.getByLabel("Search users", { exact: true }).fill(username);
    await page.getByRole("button", { name: "Search users", exact: true }).click();
    await row.getByRole("button", { name: "Reset MFA", exact: true }).click();
    await page.getByRole("button", { name: "Confirm credential reset", exact: true }).click();
    await expect.poll(async () => (await getUser()).mfa_enabled).toBe(false);
    expect((await operator.request.get(ui + "/api/v1/users/me")).status()).toBe(401);
    const audit = await (
      await api.get("/api/v1/users/audit?user_id=" + userID, { headers: headers() })
    ).json();
    expect(audit.results.some((e: { action: string }) => e.action === "mfa_reset")).toBe(true);
    for (const secret of [initial, temporary, changed, second, final, enrollment.secret])
      expect(JSON.stringify(audit).includes(secret)).toBe(false);
    await page.screenshot({ path: info.outputPath("password-security.en.png") });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: info.outputPath("password-security.zh-CN.mobile.png") });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    expect(errors).toEqual([]);
  } finally {
    await rootLogin();
    if (original) {
      const current = await (
        await api.get("/api/v1/settings/security/passwords", { headers: headers() })
      ).json();
      await api.put("/api/v1/settings/security/passwords", {
        headers: headers(),
        data: { ...original, revision: current.revision },
      });
      await rootLogin();
    }
    if (assetID) await api.delete("/api/v1/assets/" + assetID, { headers: headers() });
    if (userID) {
      const u = await (await api.get("/api/v1/users/" + userID, { headers: headers() })).json();
      if (u.state !== "archived")
        await api.delete(`/api/v1/users/${userID}?revision=${u.revision}`, { headers: headers() });
    }
    await rm(state, { force: true });
    await api.dispose();
    await admin.close();
    await operator.close();
  }
});
function totp(secret: string, ahead = 0) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
    bits = [...secret].map((c) => alphabet.indexOf(c).toString(2).padStart(5, "0")).join(""),
    key = Buffer.from((bits.match(/.{8}/g) || []).map((b) => parseInt(b, 2))),
    counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + ahead));
  const digest = createHmac("sha1", key).update(counter).digest(),
    offset = digest.at(-1)! & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}
