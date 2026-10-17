import { test, expect, request } from "@playwright/test";
import { execFile, spawn } from "node:child_process";
import { generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtemp, readFile, writeFile, unlink, rmdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, dirname, basename } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execute = promisify(execFile);
const base = process.env.JMS_IMPORT_QA_BASE_URL || "http://127.0.0.1:8083";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base)) throw Error("Account import QA requires loopback isolation");
// Submitted files contain ephemeral private keys; never retain request traces.
test.use({ locale: "en-US", trace: "off" });

test("CSV and XLSX atomically import multi-host credentials with real CLI and Web SSH, version conflicts and bilingual receipts", async ({ browser }, info) => {
  test.setTimeout(180_000);
  const api = await request.newContext({ baseURL: base });
  const context = await browser.newContext({ locale: "en-US" });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const stamp = Date.now(), passwordUser = `managedqa_ip${stamp.toString(36)}`, keyUser = `managedqa_ik${stamp.toString(36)}`;
  const syntheticPassword = "synthetic-account-import-password-233";
  const retain = process.env.JMS_IMPORT_QA_RETAIN === "true";
  const serverDir = fileURLToPath(new URL("../../server", import.meta.url));
  const temporary = await mkdtemp(join(tmpdir(), "jms233-account-import-"));
  const files: string[] = [], assets: string[] = [], createdUsers: string[] = [];
  let token = "", cookie = "", hostName = "", owner = "";
  const cli = (args: string[]) => execute("go", ["run", "./cmd/jms", ...args], {
    cwd: serverDir, timeout: 60_000,
    env: { ...process.env, JMS_SERVER_URL: base, JMS_TOKEN: token, JMS_ORG_ID: "", JMS_ACCOUNT: "", JMS_ACCESS_KEY_ID: "", JMS_ACCESS_KEY_SECRET: "" },
  });
  const file = async (name: string, body: string | Buffer) => {
    const path = join(temporary, name); files.push(path); await writeFile(path, body, { mode: 0o600 }); return path;
  };
  const encodeCSV = (rows: string[][]) => rows.map((row) => row.map((cell) => `"${cell.replaceAll('"', '""')}"`).join(",")).join("\r\n");
  const encodeXLSX = (rows: string[][]) => new Promise<Buffer>((done, reject) => {
    const child = spawn("go", ["run", "./testsupport/accountimport", "--format", "xlsx"], { cwd: serverDir, stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    const timeout = setTimeout(() => { child.kill(); reject(Error("Account import fixture encoder timed out")); }, 60_000);
    child.stdout.on("data", (data: Buffer) => chunks.push(data));
    child.stderr.resume();
    child.on("error", () => { clearTimeout(timeout); reject(Error("Account import fixture encoder failed")); });
    child.on("exit", (code) => { clearTimeout(timeout); code === 0 ? done(Buffer.concat(chunks)) : reject(Error("Account import fixture encoder failed")); });
    child.stdin.on("error", () => {}); child.stdin.end(JSON.stringify(rows));
  });
  const verifyOwner = async () => {
    const labels = JSON.parse((await execute("docker", ["inspect", "--format", "{{json .Config.Labels}}", hostName])).stdout);
    expect(labels["com.jumpserver233.qa.owner"]).toBe(owner);
  };
  try {
    const admin = { username: process.env.JMS_IMPORT_QA_USERNAME || "e2e.admin", password: process.env.JMS_IMPORT_QA_PASSWORD || "synthetic-e2e-admin-password-2468" };
    let login = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!login.ok()) { await api.post("/api/v1/authentication/bootstrap", { data: admin }); login = await api.post("/api/v1/authentication/auth/", { data: admin }); }
    expect(login.ok()).toBe(true); token = (await login.json()).access_token;
    cookie = (await api.storageState()).cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    await context.addCookies((await api.storageState()).cookies);
    const host = await (await api.get(process.env.JMS_IMPORT_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")).json();
    hostName = host.container_name; owner = host.owner;
    expect(hostName).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
    expect(owner === hostName || /^jumpserver233-e2e-/.test(owner)).toBe(true); await verifyOwner();
    const pair = generateKeyPairSync("ed25519"), privateKey = pair.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const publicBytes = pair.publicKey.export({ type: "spki", format: "der" }).subarray(-32);
    const publicWire = Buffer.concat([Buffer.from([0, 0, 0, 11]), Buffer.from("ssh-ed25519"), Buffer.from([0, 0, 0, 32]), publicBytes]);
    const publicKey = `ssh-ed25519 ${publicWire.toString("base64")}`;
    for (const user of [passwordUser, keyUser]) {
      expect(user).toMatch(/^managedqa_i[pk][a-z0-9]+$/);
      await execute("docker", ["exec", hostName, "sh", "-ceu", 'useradd -m -s /bin/bash "$1"; printf "%s:%s\\n" "$1" "$2" | chpasswd; install -d -m 0700 -o "$1" -g "$1" "/home/$1/.ssh"; printf "%s\\n" "$3" > "/home/$1/.ssh/authorized_keys"; chmod 0600 "/home/$1/.ssh/authorized_keys"; chown "$1:$1" "/home/$1/.ssh/authorized_keys"', "qa-create", user, syntheticPassword, publicKey]);
      createdUsers.push(user);
    }
    const names = [`Imported password host ${stamp}`, `Imported key host ${stamp}`];
    for (const name of names) {
      const response = await api.post("/api/v1/assets", { data: { name, host: process.env.JMS_IMPORT_QA_SSH_HOST || "127.0.0.1", port: Number(host.address.split(":").at(-1)), username: "keyqa", password: "synthetic-keyhost-password-233", host_key_fingerprint: host.fingerprint } });
      expect(response.status()).toBe(201); assets.push((await response.json()).id);
    }
    const headers = ["action", "asset_id", "username", "name", "remark", "credential_type", "password", "private_key", "private_key_passphrase", "active", "password_rotation_enabled", "key_rotation_enabled", "version"];
    const csv = await file("accounts.csv", encodeCSV([headers,
      ["create", assets[0], passwordUser, "Imported password", "", "password", syntheticPassword, "", "", "true", "", "", ""],
      ["create", assets[1], keyUser, "Imported SSH key", "", "ssh_key", "", privateKey, "", "true", "", "true", ""],
    ]));
    await page.goto((process.env.JMS_IMPORT_QA_BASE_URL || "http://127.0.0.1:5177") + "/console");
    const trigger = page.getByRole("button", { name: "Import account credentials", exact: true });
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: "Import account credentials", exact: true });
    await expect(dialog.getByLabel("Account file", { exact: true })).toBeFocused();
    await page.keyboard.press("Escape"); await expect(dialog).toHaveCount(0); await expect(trigger).toBeFocused();
    await trigger.click();
    for (const format of ["CSV", "XLSX"]) {
      const downloaded = page.waitForEvent("download");
      await dialog.getByRole("button", { name: `Download ${format} template`, exact: true }).click();
      const download = await downloaded; expect(download.suggestedFilename()).toBe(`accounts-template.${format.toLowerCase()}`);
      const data = await readFile((await download.path())!); expect(data.byteLength).toBeGreaterThan(100);
      expect(data.includes(Buffer.from(syntheticPassword))).toBe(false); expect(data.includes(Buffer.from(privateKey))).toBe(false);
    }
    const upload = async (path: string) => {
      await dialog.getByLabel("Account file", { exact: true }).setInputFiles(path);
      await expect(dialog.getByRole("button", { name: "Preview import", exact: true })).toBeEnabled();
      const response = page.waitForResponse((r) => r.url().endsWith("/api/v1/accounts/imports/preview") && r.request().method() === "POST");
      await dialog.getByRole("button", { name: "Preview import", exact: true }).click(); expect((await response).status()).toBe(200);
      await expect(dialog.getByRole("button", { name: "Commit 2 accounts", exact: true })).toBeEnabled();
      expect((await dialog.textContent())?.includes(syntheticPassword)).toBe(false);
      expect((await dialog.textContent())?.includes("PRIVATE KEY")).toBe(false);
    };
    const commit = async () => {
      const posted = page.waitForRequest((r) => r.url().endsWith("/api/v1/accounts/imports") && r.method() === "POST");
      await dialog.getByRole("button", { name: "Commit 2 accounts", exact: true }).click();
      const body = (await posted).postDataJSON();
      await expect(dialog.getByRole("status").filter({ hasText: "Imported 2 accounts." })).toBeVisible();
      const receiptResponse = await api.get(`/api/v1/accounts/imports/${body.request_id}`); expect(receiptResponse.status()).toBe(200);
      const receipt = await receiptResponse.json(); expect(receipt.rows).toHaveLength(2);
      const retry = await api.post("/api/v1/accounts/imports", { data: body }); expect(retry.status()).toBe(201);
      expect((await retry.json()).created_at).toBe(receipt.created_at); return receipt;
    };
    await upload(csv); const created = await commit();
    const account = async (i: number) => (await (await api.get(`/api/v1/assets/${assets[i]}/accounts?username=${i ? keyUser : passwordUser}`)).json()).results[0];
    for (const i of [0, 1]) {
      const output = JSON.parse((await cli(["--account", i ? keyUser : passwordUser, "exec", assets[i], "--json", "--", "id -un"])).stdout);
      expect(output.stdout.trim()).toBe(i ? keyUser : passwordUser);
      const activity = await (await api.get(`/api/v1/assets/${assets[i]}/accounts/${created.rows[i].account_id}/activity`)).json();
      expect(activity.results.filter((v: any) => v.import_id === created.request_id)).toHaveLength(1);
      const cliActivity = JSON.parse((await cli(["account", "activity", assets[i], created.rows[i].account_id])).stdout);
      expect(cliActivity.results.find((v: any) => v.import_id === created.request_id)?.action).toBe("import_create");
    }
    await dialog.getByRole("button", { name: "Close", exact: true }).click();
    const hostRow = page.getByRole("row").filter({ hasText: names[1] });
    await hostRow.getByText("More", { exact: true }).click(); await hostRow.getByRole("button", { name: "Managed accounts", exact: true }).click();
    await page.getByRole("dialog").getByRole("row").filter({ hasText: keyUser }).getByRole("button", { name: "Account activity", exact: true }).click();
    const activityPanel = page.getByRole("region", { name: "Account activity", exact: true });
    await expect(activityPanel).toContainText("Credential binding imported"); await expect(activityPanel).toContainText(created.request_id);
    await page.getByRole("dialog").getByRole("row").filter({ hasText: keyUser }).getByRole("button", { name: "Use account", exact: true }).click();
    let received = "";
    page.on("websocket", (socket) => { if (socket.url().includes("/terminal")) socket.on("framereceived", (frame) => { received += Buffer.isBuffer(frame.payload) ? frame.payload.toString("utf8") : frame.payload; }); });
    await hostRow.getByRole("button", { name: "Connect", exact: true }).click();
    const terminal = page.getByRole("dialog"); await expect(terminal.locator(".ssh-terminal-status")).toHaveClass(/connected/);
    await terminal.locator(".xterm-helper-textarea").pressSequentially("printf 'IMPORT_WEB_%s\\n' \"$(id -un)\"\r");
    await expect.poll(() => received).toContain("IMPORT_WEB_" + keyUser);
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    await trigger.click();
    const xlsx = await file("updates.xlsx", await encodeXLSX([headers,
      ["update", assets[0], passwordUser, "Updated password metadata", "", "", "", "", "", "false", "", "", (await account(0)).version],
      ["update", assets[1], keyUser, "Updated key metadata", "", "", "", "", "", "true", "", "true", (await account(1)).version],
    ]));
    await upload(xlsx); await expect(dialog.getByText("Current credential retained", { exact: true })).toHaveCount(2); const updated = await commit();
    expect((await account(0)).active).toBe(false); expect((await account(1)).key_rotation_enabled).toBe(true);
    for (const i of [0, 1]) {
      const backups = await (await api.get(`/api/v1/assets/${updated.rows[i].account_id}/credential-backups`)).json();
      expect(backups).toHaveLength(0);
    }
    const disabled = await account(0);
    expect((await api.put(`/api/v1/assets/${assets[0]}/accounts/${disabled.id}`, { data: { active: true, version: disabled.version } })).status()).toBe(200);
    expect(JSON.parse((await cli(["--account", passwordUser, "exec", assets[0], "--json", "--", "id -un"])).stdout).stdout.trim()).toBe(passwordUser);
    const conflictRows = [headers,
      ["update", assets[0], passwordUser, "Must not partially apply", "", "", "", "", "", "", "", "", ""],
      ["update", assets[1], keyUser, "Must not partially apply", "", "", "", "", "", "", "", "", ""],
    ];
    const conflictFile = await file("conflict.csv", encodeCSV(conflictRows));
    const preview = JSON.parse((await cli(["account", "import-preview", "--file", conflictFile, "--request-id", randomUUID()])).stdout);
    expect(preview.preview_token).toBeTruthy(); const proof = await file("review.json", JSON.stringify(preview));
    const before = await account(1);
    expect((await api.put(`/api/v1/assets/${assets[1]}/accounts/${before.id}`, { data: { name: "Concurrent edit", version: before.version } })).status()).toBe(200);
    let failed = false;
    try { await cli(["account", "import-commit", "--file", conflictFile, "--preview-file", proof]); } catch { failed = true; }
    expect(failed).toBe(true); expect((await account(0)).name).toBe("Updated password metadata"); expect((await account(1)).name).toBe("Concurrent edit");
    const invalid = await api.post("/api/v1/accounts/imports/preview", { data: { format: "csv", request_id: randomUUID(), content: Buffer.from(encodeCSV([headers, conflictRows[1], conflictRows[1]])).toString("base64") } });
    expect(invalid.status()).toBe(200); expect((await invalid.json()).preview_token).toBeUndefined();
    await dialog.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(dialog.getByText(updated.request_id, { exact: true })).toHaveCount(2);
    await page.screenshot({ path: info.outputPath("account-import.en.png"), fullPage: true });
    await dialog.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "批量导入账号凭据", exact: true })).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath("account-import.zh-CN.png"), fullPage: true });
    expect(errors).toEqual([]);
    await writeFile(info.outputPath("import-result.json"), JSON.stringify({ assets, names, passwordUser, keyUser, createdRequest: created.request_id, updatedRequest: updated.request_id, fixture: hostName, atomic: true, csv: true, xlsx: true, cliSSH: true, webSSH: true, retained: retain }));
    if (!retain) for (const i of [0, 1]) {
      const current = await account(i);
      expect((await api.delete(`/api/v1/assets/${assets[i]}/accounts/${current.id}`, { data: { version: current.version } })).status()).toBe(204);
      expect((await api.delete(`/api/v1/assets/${assets[i]}`)).status()).toBe(204);
    }
  } finally {
    if (!retain && createdUsers.length) {
      await verifyOwner();
      for (const user of createdUsers) await execute("docker", ["exec", hostName, "sh", "-ceu", 'uid=$(id -u "$1"); test "$uid" -ge 1000; userdel "$1"', "qa-remove", user]);
    }
    if (cookie) await fetch(base + "/api/v1/authentication/expire-session/", { method: "POST", headers: { Cookie: cookie, Origin: base }, signal: AbortSignal.timeout(5000) }).catch(() => {});
    if (token) await fetch(base + "/api/v1/authentication/expire-session/", { method: "POST", headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) }).catch(() => {});
    if (dirname(resolve(temporary)) !== resolve(tmpdir()) || !basename(temporary).startsWith("jms233-account-import-")) throw Error("Unowned import fixture directory");
    for (const path of files) await unlink(path).catch(() => {}); await rmdir(temporary);
    await context.close(); await api.dispose();
  }
});
