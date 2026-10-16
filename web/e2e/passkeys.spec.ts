import { createHmac } from "node:crypto";
import { test, expect, request } from "@playwright/test";
const origin = "http://localhost:15178";
const admin = { username: "passkey.admin", password: "synthetic-passkey-admin-password-233" };
function totp(secret: string, offset = 0) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let value = 0,
    bits = 0;
  const bytes: number[] = [];
  for (const ch of secret.replace(/=+$/, "")) {
    value = (value << 5) | alphabet.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 255);
    }
  }
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000) + offset));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const pos = digest[digest.length - 1] & 15;
  return String((digest.readUInt32BE(pos) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
test("registers device-verified Passkeys, cancels ceremonies, enforces MFA/recovery and revokes sessions", async ({
  browser,
}) => {
  test.setTimeout(90_000);
  const api = await request.newContext({ baseURL: origin });
  const bootstrap = await api.post("/api/v1/authentication/bootstrap", { data: admin });
  expect(bootstrap.status()).toBe(201);
  const session = (await bootstrap.json()) as { access_token: string };
  const headers = { Authorization: `Bearer ${session.access_token}` };
  const context = await browser.newContext({ locale: "en-US", baseURL: origin });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: false,
    },
  });
  try {
    await page.goto("/login");
    await page.getByLabel("Username", { exact: true }).fill(admin.username);
    await page.getByLabel("Password", { exact: true }).fill(admin.password);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page).toHaveURL(/\/console$/);
    await page.getByRole("link", { name: "Passkey sign-in", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Passkey sign-in", exact: true })).toBeVisible();
    await page.getByRole("checkbox", { name: "Enable Passkey sign-in", exact: true }).check();
    const saved = page.waitForResponse(
      (r) => r.url().endsWith("/settings/security/passkeys") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save Passkey settings", exact: true }).click();
    expect((await saved).status()).toBe(200);
    await page.getByRole("link", { name: "Profile", exact: true }).click();
    await page.getByLabel("Passkey name", { exact: true }).fill("Laptop Passkey");
    await page
      .getByLabel("Current password for Passkey management", { exact: true })
      .fill(admin.password);
    await page.getByRole("button", { name: "Register Passkey", exact: true }).click();
    await expect(page.getByRole("button", { name: "Cancel", exact: true })).toBeVisible();
    const cancelled = page.waitForResponse(
      (r) => r.url().endsWith("/passkeys/registration") && r.request().method() === "DELETE",
    );
    await page.getByRole("button", { name: "Cancel", exact: true }).click();
    expect((await cancelled).status()).toBe(204);
    expect(
      (
        (await (await page.request.get("/api/v1/users/me/passkeys")).json()) as {
          credentials: unknown[];
        }
      ).credentials,
    ).toEqual([]);
    await cdp.send("WebAuthn.clearCredentials", { authenticatorId });
    await cdp.send("WebAuthn.setAutomaticPresenceSimulation", { authenticatorId, enabled: true });
    await page
      .getByLabel("Current password for Passkey management", { exact: true })
      .fill(admin.password);
    const registration = page.waitForResponse(
      (r) => r.url().endsWith("/passkeys/registration/finish") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Register Passkey", exact: true }).click();
    const registered = await registration;
    expect(registered.status()).toBe(201);
    const metadata = (await registered.json()) as { id: string; name: string };
    expect(metadata.name).toBe("Laptop Passkey");
    expect(metadata).not.toHaveProperty("publicKey");
    await expect(page.getByRole("status")).toContainText("Passkey registered.");
    await page.getByRole("button", { name: "Rename", exact: true }).click();
    await page.getByLabel("New Passkey name", { exact: true }).fill("QA device key");
    await page.getByRole("button", { name: "Save name", exact: true }).click();
    await expect(page.getByRole("cell", { name: /QA device key/ })).toBeVisible();
    expect(
      (await api.put("/api/v1/settings/security/mfa", { headers, data: { mode: "all" } })).status(),
    ).toBe(200);
    await page.getByRole("button", { name: "Sign out", exact: true }).click();
    await page.getByRole("button", { name: "Sign in with Passkey", exact: true }).click();
    await expect(
      page.getByRole("heading", { name: "Finish Passkey sign-in", exact: true }),
    ).toBeVisible();
    expect((await context.cookies()).find((c) => c.name === "jms_passkey_pending")).toMatchObject({
      httpOnly: true,
      path: "/api/v1/authentication/passkey",
      sameSite: "Strict",
    });
    expect((await page.request.get("/api/v1/users/me")).status()).toBe(401);
    await page.getByRole("button", { name: "Complete Passkey sign-in", exact: true }).click();
    await expect(page.locator(".login-mfa-setup")).toBeVisible();
    const secret = await page.locator(".login-mfa-setup code").first().innerText();
    await page.getByLabel("Authenticator code", { exact: true }).fill(totp(secret));
    const completed = page.waitForResponse(
      (r) =>
        r.url().endsWith("/authentication/passkey/complete") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Verify and sign in", exact: true }).click();
    const result = (await (await completed).json()) as {
      browser_session: boolean;
      user: { id: string; username: string; mfa_enabled: boolean };
    };
    expect(result).toMatchObject({
      browser_session: true,
      user: { username: admin.username, mfa_enabled: true },
    });
    expect(result).not.toHaveProperty("access_token");
    await expect(page).toHaveURL(/\/console$/);
    const recovery = await page.request.post("/api/v1/users/me/mfa/recovery-codes", {
      data: { password: admin.password, otp: totp(secret, 1) },
    });
    expect(recovery.status()).toBe(200);
    const codes = ((await recovery.json()) as { codes: string[] }).codes;
    expect(codes).toHaveLength(10);
    const config = (await (
      await api.get("/api/v1/settings/security/passkeys", { headers })
    ).json()) as { enabled: boolean; revision: number };
    let changed = await api.put("/api/v1/settings/security/passkeys", {
      headers,
      data: { enabled: false, revision: config.revision },
    });
    expect(changed.status()).toBe(200);
    const disabled = (await changed.json()) as { revision: number };
    changed = await api.put("/api/v1/settings/security/passkeys", {
      headers,
      data: { enabled: true, revision: disabled.revision },
    });
    expect(changed.status()).toBe(200);
    await changed.json();
    expect((await page.request.get("/api/v1/users/me")).status()).toBe(401);
    await page.goto("/login");
    await page.getByRole("button", { name: "Sign in with Passkey", exact: true }).click();
    await expect(page.getByLabel("Authenticator or recovery code", { exact: true })).toBeVisible();
    await page.getByLabel("Authenticator or recovery code", { exact: true }).fill(codes[0]);
    await page.getByRole("button", { name: "Complete Passkey sign-in", exact: true }).click();
    await expect(page).toHaveURL(/\/console$/);
    await page.getByRole("link", { name: "Profile", exact: true }).click();
    await page
      .getByLabel("Authenticator or recovery code for Passkey management", { exact: true })
      .fill(codes[1]);
    await page
      .getByLabel("Current password for Passkey management", { exact: true })
      .fill(admin.password);
    page.once("dialog", (dialog) => {
      void dialog.accept();
    });
    const removed = page.waitForResponse(
      (r) => r.url().endsWith("/passkeys/" + metadata.id) && r.request().method() === "DELETE",
    );
    await page.getByRole("button", { name: "Remove", exact: true }).click();
    expect((await removed).status()).toBe(204);
    await expect(page).toHaveURL(/\/login$/);
    const left = (await (await api.get("/api/v1/users/me/passkeys", { headers })).json()) as {
      credentials: unknown[];
    };
    expect(left.credentials).toEqual([]);
  } finally {
    await api.put("/api/v1/settings/security/mfa", { headers, data: { mode: "disabled" } });
    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
    await context.close();
    await api.dispose();
  }
});
