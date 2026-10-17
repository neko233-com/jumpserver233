import { test, expect, request } from "@playwright/test";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, rm } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const execute = promisify(execFile);
const base = process.env.JMS_SHARE_QA_BASE_URL || "http://127.0.0.1:8083";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Sharing QA requires an isolated loopback instance");
test.use({ locale: "en-US" });
test("named read-only and writable invitations preserve SSH, CLI, identity, bilingual UI and mobile layouts", async ({
  page,
  browser,
}, info) => {
  test.setTimeout(180_000);
  const api = await request.newContext({ baseURL: base });
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const watchResizeErrors = () => window.addEventListener("error", (e) => {
    if (e.message.includes("ResizeObserver")) console.error("terminal-resize-error: " + e.message);
  });
  await page.context().addInitScript(watchResizeErrors);
  page.on("console", (message) => { if(message.type()==="error" && message.text().includes("terminal-resize-error:")) errors.push(message.text()); });
  const admin = {
    username: process.env.JMS_SHARE_QA_USERNAME || "e2e.admin",
    password: process.env.JMS_SHARE_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
  };
  const guestName = `share.guest.${Date.now()}`,
    guestPassword = "synthetic-share-browser-password-233";
  const guestContext = await browser.newContext({ locale: "en-US" });
  await guestContext.addInitScript(watchResizeErrors);
  const guest = await guestContext.newPage();
  guest.on("pageerror", (e) => errors.push(e.message));
  guest.on("console", (message) => { if(message.type()==="error" && message.text().includes("terminal-resize-error:")) errors.push(message.text()); });
  let original: Record<string, unknown> | null = null,
    sessionID = "";
  let cli: ReturnType<typeof spawn> | null = null;
  const serverDir = resolve(fileURLToPath(new URL(".", import.meta.url)), "../../server");
  const binary = resolve(serverDir, "bin", `jms-sharing-${crypto.randomUUID()}.exe`);
  try {
    let auth = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!auth.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: admin });
      auth = await api.post("/api/v1/authentication/auth/", { data: admin });
    }
    expect(auth.ok()).toBe(true);
    await page.context().addCookies((await api.storageState()).cookies);
    original = (await (await api.get("/api/v1/settings/security/sessions")).json()) as Record<
      string,
      unknown
    >;
    expect(
      (
        await api.put("/api/v1/settings/security/sessions", {
          data: { ...original, sharing: true },
        })
      ).ok(),
    ).toBe(true);
    expect(
      (
        await api.post("/api/v1/users", {
          data: { username: guestName, password: guestPassword, role: "operator" },
        })
      ).status(),
    ).toBe(201);
    const fixture = await (
      await api.get(process.env.JMS_SHARE_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    const name = `Shared Linux SSH ${Date.now()}`;
    const asset = await api.post("/api/v1/assets", {
      data: {
        name,
        host: process.env.JMS_SHARE_QA_SSH_HOST || "127.0.0.1",
        port: Number(fixture.address.split(":").at(-1)),
        username: fixture.username,
        password: "synthetic-keyhost-password-233",
        host_key_fingerprint: fixture.fingerprint,
      },
    });
    expect(asset.status()).toBe(201);
    const assetID = (await asset.json()).id;
    await page.goto("/console");
    const created = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/sessions") && r.request().method() === "POST",
    );
    await page
      .getByRole("row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    sessionID = (await (await created).json()).session_id;
    const terminal = page.getByRole("dialog");
    await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
    const ownerInput = terminal.getByRole("textbox", { name: "Terminal input", exact: true });
    await ownerInput.pressSequentially("printf 'SHARE_%s\\n' READY\r");
    await expect(terminal.locator(".xterm-rows")).toContainText("SHARE_READY");
    await terminal.getByRole("button", { name: "Session collaboration", exact: true }).click();
    const panel = terminal.getByRole("complementary", {
      name: "Session collaboration",
      exact: true,
    });
    await panel.getByLabel("Invited usernames (comma separated)", { exact: true }).fill(guestName);
    async function invite(mode: string) {
      await panel.getByLabel("Access", { exact: true }).selectOption(mode);
      const response = page.waitForResponse(
        (r) => r.url().includes(`/sessions/${sessionID}/shares`) && r.request().method() === "POST",
      );
      await panel.getByRole("button", { name: "Create invitation", exact: true }).click();
      expect((await response).status()).toBe(201);
      const url = await panel.getByLabel("Invitation link", { exact: true }).inputValue();
      const code = await panel.getByLabel("Invitation code", { exact: true }).inputValue();
      expect(url).not.toContain(code);
      await panel.getByRole("button", { name: "Hide link and code", exact: true }).click();
      return { url, code };
    }
    const readonly = await invite("read_only");
    await guest.goto(readonly.url);
    await expect(guest).toHaveURL(/\/login\?next=/);
    await guest.getByRole("textbox", { name: "Username", exact: true }).fill(guestName);
    await guest.getByRole("textbox", { name: "Password", exact: true }).fill(guestPassword);
    await guest.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(guest).toHaveURL(/\/share\//);
    await guest.getByLabel("Invitation code", { exact: true }).fill(readonly.code);
    await guest.getByRole("button", { name: "Join session", exact: true }).click();
    await expect(guest.getByRole("status")).toContainText("Connected");
    await expect(guest.getByRole("status")).toContainText("Read only");
    expect(
      (
        await guest.request.post(`${base}/api/v1/sessions`, {
          data: { asset_id: assetID, cols: 80, rows: 24 },
        })
      ).status(),
    ).toBe(403);
    await ownerInput.pressSequentially("printf 'OBSERVE_%s\\n' ONLY\r");
    await expect(guest.locator(".xterm-rows")).toContainText("OBSERVE_ONLY");
    await guest.screenshot({ path: info.outputPath("session-sharing.en.png") });
    await guest.getByRole("button", { name: "中文", exact: true }).click();
    await expect(guest.getByRole("heading", { name: "共享终端", exact: true })).toBeVisible();
    await ownerInput.pressSequentially("printf 'LOCALE_%s\\n' LIVE\r");
    await expect(guest.locator(".xterm-rows")).toContainText("LOCALE_LIVE");
    await terminal.getByRole("button", { name: "中文", exact: true }).click();
    await expect(terminal.locator(".ssh-terminal-status")).toHaveText("已连接");
    await terminal.getByRole("button", { name: "EN", exact: true }).click();
    await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
    await ownerInput.pressSequentially("printf 'OWNER_LOCALE_%s\\n' LIVE\r");
    await expect(guest.locator(".xterm-rows")).toContainText("OWNER_LOCALE_LIVE");
    await guest.setViewportSize({ width: 390, height: 844 });
    expect(await guest.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(
      true,
    );
    await guest.screenshot({ path: info.outputPath("session-sharing.mobile.zh-CN.png") });
    await guest.setViewportSize({ width: 1280, height: 720 });
    const writable = await invite("read_write");
    await guest.goto(writable.url);
    await guest.getByLabel("邀请验证码", { exact: true }).fill(writable.code);
    await guest.getByRole("button", { name: "加入会话", exact: true }).click();
    await expect(guest.getByRole("status")).toContainText("已连接");
    await guest.getByRole("button", { name: "接管输入控制", exact: true }).click();
    await expect(guest.getByRole("status")).toContainText("当前由你输入");
    await guest.locator(".xterm-helper-textarea").pressSequentially("printf 'GUEST_%s\\n' WRITE\r");
    await expect(guest.locator(".xterm-rows")).toContainText("GUEST_WRITE");
    await expect(terminal.locator(".xterm-rows")).toContainText("GUEST_WRITE");
    await expect
      .poll(async () => {
        const rows = await (await api.get(`/api/v1/sessions/${sessionID}/commands`)).json();
        return rows.results.some(
          (v: { actor: string; command: string }) =>
            v.actor === guestName && v.command.includes("GUEST_%s"),
        );
      })
      .toBe(true);
    await expect(
      panel
        .locator(".session-share-row")
        .filter({ hasText: guestName })
        .getByRole("button", { name: "Remove participant", exact: true }),
    ).toHaveCount(1);
    await panel
      .locator(".session-share-row")
      .filter({ hasText: guestName })
      .getByRole("button", { name: "Remove participant", exact: true })
      .click();
    await expect(guest.getByRole("status")).toContainText("会话已结束");
    await panel.getByRole("button", { name: "Reclaim input control", exact: true }).click();
    await expect(ownerInput).toBeEditable();
    await ownerInput.pressSequentially("printf 'OWNER_%s\\n' RESUMED\r");
    await expect(terminal.locator(".xterm-rows")).toContainText("OWNER_RESUMED");
    const guestApi = await request.newContext({ baseURL: base });
    const guestLogin = await guestApi.post("/api/v1/authentication/auth/", {
      data: { username: guestName, password: guestPassword },
    });
    expect(guestLogin.ok()).toBe(true);
    const guestToken = (await guestLogin.json()).access_token;
    await guestApi.dispose();
    await mkdir(resolve(serverDir, "bin"), { recursive: true });
    await execute("go", ["build", "-trimpath", "-ldflags=-s -w", "-o", binary, "./cmd/jms"], {
      cwd: serverDir,
      timeout: 120000,
    });
    let stdout = "",
      stderr = "";
    const shareID = new URL(writable.url).pathname.split("/").at(-1)!;
    cli = spawn(binary, ["share", "join", shareID, "--control"], {
      cwd: serverDir,
      env: {
        ...process.env,
        JMS_SERVER_URL: base,
        JMS_TOKEN: guestToken,
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
        JMS_ORG_ID: new URL(writable.url).searchParams.get("org") || "",
        JMS_SHARE_CODE: writable.code,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    cli.stdout!.on("data", (chunk) => (stdout += chunk.toString()));
    cli.stderr!.on("data", (chunk) => (stderr += chunk.toString()));
    const cliExit = new Promise<number | null>((done, reject) => {
      cli!.once("error", reject);
      cli!.once("close", done);
    });
    cli.stdin!.end("printf 'CLI_%s\\n' SHARE\r");
    await expect.poll(() => stdout, { timeout: 30000 }).toContain("CLI_SHARE");
    await expect(terminal.locator(".xterm-rows")).toContainText("CLI_SHARE");
    await expect(
      panel
        .locator(".session-share-row")
        .filter({ hasText: guestName })
        .getByRole("button", { name: "Remove participant", exact: true }),
    ).toHaveCount(1);
    await panel
      .locator(".session-share-row")
      .filter({ hasText: guestName })
      .getByRole("button", { name: "Remove participant", exact: true })
      .click();
    expect(await cliExit).toBe(0);
    expect(stderr).not.toContain(writable.code);
    cli = null;
    await panel.getByRole("button", { name: "Reclaim input control", exact: true }).click();
    await panel
      .locator(".session-share-row")
      .filter({ hasText: "Read and write" })
      .getByRole("button", { name: "Revoke invitation", exact: true })
      .click();
    await panel.getByRole("button", { name: "Refresh activity", exact: true }).click();
    await expect(
      panel.getByRole("region", { name: "Collaboration activity", exact: true }),
    ).toContainText("Invitation revoked");
    await page.setViewportSize({ width: 390, height: 844 });
    const mobileClose = await terminal
      .getByRole("button", { name: "Close terminal", exact: true })
      .boundingBox();
    expect(mobileClose).not.toBeNull();
    expect(mobileClose!.x).toBeGreaterThanOrEqual(0);
    expect(mobileClose!.x + mobileClose!.width).toBeLessThanOrEqual(390);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(
      true,
    );
    await page.screenshot({ path: info.outputPath("session-sharing-owner.mobile.en.png") });
    await page.setViewportSize({ width: 1280, height: 720 });
    await panel.getByRole("button", { name: "Hide collaboration", exact: true }).click();
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    await page.goto("/audit");
    await page
      .getByRole("row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Collaboration activity", exact: true })
      .click();
    await expect(page.getByRole("dialog")).toContainText("Participant connected");
    expect(errors).toEqual([]);
  } finally {
    if (cli) cli.kill();
    await rm(binary, { force: true });
    await guestContext.close().catch(() => {});
    if (sessionID) await api.delete(`/api/v1/sessions/${sessionID}`);
    if (original) {
      const now = (await (await api.get("/api/v1/settings/security/sessions")).json()) as {
        revision: number;
      };
      await api.put("/api/v1/settings/security/sessions", {
        data: { ...original, revision: now.revision },
      });
    }
    await api.dispose();
  }
});
