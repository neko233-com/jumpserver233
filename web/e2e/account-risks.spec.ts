import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const base = process.env.JMS_RISK_QA_BASE_URL || "http://127.0.0.1:8083";
const ui = process.env.JMS_RISK_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base)) throw Error("Risk QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });

test("account risks scan, review, remediate real SSH credentials, record usage, enforce scoped permissions and run periodically", async ({ browser }, info) => {
  test.setTimeout(180_000);
  const api = await request.newContext({ baseURL: base });
  const context = await browser.newContext({ locale: "en-US", viewport: { width: 1440, height: 1080 } });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const stamp = Date.now(), users = [`managedqa_ra${stamp.toString(36)}`, `managedqa_rb${stamp.toString(36)}`];
  const names = [`Risk host A ${stamp}`, `Risk host B ${stamp}`], assets: string[] = [], createdUsers: string[] = [];
  const weak = "admin123", retain = process.env.JMS_RISK_QA_RETAIN === "true";
  let token = "", cookie = "", hostName = "", owner = "", operatorID = "", roleID = "", succeeded = false;
  const grantIDs: string[] = [];
  const verifyOwner = async () => {
    const labels = JSON.parse((await execute("docker", ["inspect", "--format", "{{json .Config.Labels}}", hostName])).stdout);
    expect(labels["com.jumpserver233.qa.owner"]).toBe(owner);
  };
  const cli = (args: string[]) => execute("go", ["run", "./cmd/jms", ...args], {
    cwd: fileURLToPath(new URL("../../server", import.meta.url)), timeout: 65_000,
    env: { ...process.env, JMS_SERVER_URL: base, JMS_TOKEN: token, JMS_ORG_ID: "", JMS_ACCOUNT: "", JMS_ACCESS_KEY_ID: "", JMS_ACCESS_KEY_SECRET: "" },
  });
  const findings = async (query = "") => {
    const r = await api.get("/api/v1/accounts/risks?limit=200" + query); expect(r.ok()).toBe(true); return (await r.json()).results as any[];
  };
  try {
    const admin = { username: process.env.JMS_RISK_QA_USERNAME || "e2e.admin", password: process.env.JMS_RISK_QA_PASSWORD || "synthetic-e2e-admin-password-2468" };
    let login = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!login.ok()) { await api.post("/api/v1/authentication/bootstrap", { data: admin }); login = await api.post("/api/v1/authentication/auth/", { data: admin }); }
    expect(login.ok()).toBe(true); token = (await login.json()).access_token;
    cookie = (await api.storageState()).cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    await context.addCookies((await api.storageState()).cookies);
    const startingPolicy = await (await api.get("/api/v1/accounts/risks/policy")).json();
    if (startingPolicy.enabled) expect((await api.put("/api/v1/accounts/risks/policy", { data: { ...startingPolicy, enabled: false } })).status()).toBe(200);
    const host = await (await api.get(process.env.JMS_RISK_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")).json();
    hostName = host.container_name; owner = host.owner;
    expect(hostName).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
    expect(owner === hostName || /^jumpserver233-e2e-/.test(owner)).toBe(true); await verifyOwner();
    for (const [i, user] of users.entries()) {
      expect(user).toMatch(/^managedqa_r[ab][a-z0-9]+$/);
      await execute("docker", ["exec", hostName, "sh", "-ceu", 'useradd -m -s /bin/bash "$1"; printf "%s:%s\\n" "$1" "$2" | chpasswd; printf "%s ALL=(root) NOPASSWD: /usr/sbin/chpasswd\n" "$1" > "/etc/sudoers.d/$1"; chmod 0440 "/etc/sudoers.d/$1"', "qa-create", user, weak]);
      createdUsers.push(user);
      const r = await api.post("/api/v1/assets", { data: { name: names[i], host: process.env.JMS_RISK_QA_SSH_HOST || "127.0.0.1", port: Number(host.address.split(":").at(-1)), username: user, password: weak, host_key_fingerprint: host.fingerprint } });
      expect(r.status()).toBe(201); assets.push((await r.json()).id);
    }
    await page.goto(ui + "/console/account-risks");
    await expect(page.getByRole("heading", { name: "Account risks", exact: true })).toBeVisible();
    const scan = async () => {
      const response = page.waitForResponse((r) => r.url().endsWith("/api/v1/accounts/risks/scans") && r.request().method() === "POST");
      await page.getByRole("button", { name: "Scan now", exact: true }).click();
      const r = await response; expect(r.status()).toBe(201);
      await expect(page.getByRole("status").filter({ hasText: "Scan finished" })).toBeVisible();
      return r.json();
    };
    const first = await scan();
    expect(first.accounts).toBeGreaterThanOrEqual(2);
    const initial = await findings("&kind=weak_password");
    expect(initial.filter((f) => assets.includes(f.account_id))).toHaveLength(2);
    const reuse = await findings("&kind=duplicate_password");
    expect(reuse.filter((f) => assets.includes(f.account_id))).toHaveLength(2);
    expect(JSON.stringify(initial)).not.toContain(weak);
    expect(JSON.stringify(reuse)).not.toMatch(/"group_id"|"binding"|"identity"/);
    const same = await api.post("/api/v1/accounts/risks/scans", { data: { revision: first.policy_revision, request_id: first.request_id } });
    expect(same.status()).toBe(201); expect((await same.json()).id).toBe(first.id);
    await page.getByLabel("Search host or username", { exact: true }).fill(names[0]);
    await page.getByRole("combobox", { name: "Risk type", exact: true }).selectOption("weak_password");
    await page.getByRole("button", { name: "Apply filters", exact: true }).click();
    const row = page.getByRole("row").filter({ hasText: names[0] });
    await expect(row).toHaveCount(1);
    const trigger = row.getByRole("button", { name: "Details", exact: true });
    await trigger.click();
    const dialog = page.getByRole("dialog");
    await expect(dialog.getByRole("button", { name: "Close", exact: true })).toBeFocused();
    await page.keyboard.press("Escape"); await expect(dialog).toHaveCount(0); await expect(trigger).toBeFocused();
    await trigger.click();
    await dialog.getByLabel("Review note", { exact: true }).fill("Synthetic QA review");
    for (const [action, state] of [["Confirm risk", "Confirmed"], ["Ignore risk", "Ignored"], ["Reopen risk", "Open"]]) {
      const response = page.waitForResponse((r) => r.url().endsWith("/review") && r.request().method() === "POST");
      await dialog.getByRole("button", { name: action, exact: true }).click(); expect((await response).status()).toBe(200);
      await expect(dialog.getByRole("status")).toContainText(state);
    }
    await dialog.getByRole("link", { name: "Open asset and account", exact: true }).click();
    await expect(page).toHaveURL(new RegExp("asset_id=" + assets[0]));
    const assetRow = page.getByRole("row").filter({ hasText: names[0] });
    await expect(assetRow).toBeVisible();
    expect(JSON.parse((await cli(["exec", assets[0], "--json", "--", "id -un"])).stdout).stdout.trim()).toBe(users[0]);
    let terminalOutput = "";
    page.on("websocket", (s) => { if (s.url().includes("/terminal")) s.on("framereceived", (f) => terminalOutput += Buffer.isBuffer(f.payload) ? f.payload.toString("utf8") : f.payload); });
    await assetRow.getByRole("button", { name: "Connect", exact: true }).click();
    const terminal = page.getByRole("dialog");
    await expect(terminal.locator(".ssh-terminal-status")).toHaveClass(/connected/);
    await terminal.locator(".xterm-helper-textarea").pressSequentially("printf 'RISK_WEB_%s\\n' \"$(id -un)\"\r");
    await expect.poll(() => terminalOutput).toContain("RISK_WEB_" + users[0]);
    // Monitor audit events intentionally have no asset_id; they must neither
    // abort risk collection nor count as proof that a remote account was used.
    const observer = await context.newPage();
    observer.on("pageerror", (e) => errors.push(e.message));
    try {
      await observer.goto(ui + "/audit");
      await observer.getByRole("row").filter({ hasText: names[0] }).getByRole("button", { name: "Monitor live", exact: true }).click();
      await expect(observer.getByRole("dialog").getByRole("status")).toHaveText("Connected");
      await observer.getByRole("dialog").getByRole("button", { name: "Close terminal", exact: true }).click();
    } finally { await observer.close(); }
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    await page.goto(ui + "/console/account-risks"); await scan();
    const used = (await findings("&kind=weak_password")).find((f) => f.account_id === assets[0]);
    expect(Date.parse(used.last_used_at)).toBeGreaterThan(stamp);
    const rotated = await api.post(`/api/v1/assets/${assets[0]}/password-rotation`);
    expect(rotated.status()).toBe(200);
    expect((await api.post(`/api/v1/accounts/risks/${used.id}/review`, { data: { revision: used.revision, action: "ignore", note: "" } })).status()).toBe(409);
    expect(JSON.parse((await cli(["exec", assets[0], "--json", "--", "id -un"])).stdout).stdout.trim()).toBe(users[0]);
    await scan();
    expect((await findings("&state=resolved&kind=weak_password")).some((f) => f.account_id === assets[0])).toBe(true);
    expect((await findings("&state=open&kind=duplicate_password")).some((f) => assets.includes(f.account_id))).toBe(false);
    const policy = JSON.parse((await cli(["account", "risks", "policy"])).stdout);
    expect(policy.revision).toBeGreaterThan(0);
    const cliRows = JSON.parse((await cli(["account", "risks", "findings", "--kind", "weak_password"])).stdout);
    expect(cliRows.results.some((f: any) => f.account_id === assets[1])).toBe(true);
    const operator = { username: `risks.viewer.${stamp}`, password: "synthetic-risk-platform-password-233" };
    const user = await api.post("/api/v1/users", { data: { ...operator, role: "operator" } }); expect(user.status()).toBe(201); operatorID = (await user.json()).id;
    const role = await api.post("/api/v1/rbac/roles", { data: { name: `Risk viewer ${stamp}`, permissions: ["accounts.risks.view"] } }); expect(role.status()).toBe(201); roleID = (await role.json()).id;
    expect((await api.put("/api/v1/rbac/bindings", { data: { subject_type: "user", subject_id: operatorID, role_ids: [roleID] } })).status()).toBe(200);
    const grant = await api.post("/api/v1/grants", { data: { user_id: operatorID, asset_id: assets[1], account: users[1], actions: ["view"] } }); expect(grant.status()).toBe(201); grantIDs.push((await grant.json()).id);
    const guest = await browser.newContext({ locale: "en-US" });
    try {
      expect((await guest.request.post(base + "/api/v1/authentication/auth/", { data: operator })).ok()).toBe(true);
      const scoped = await guest.request.get(base + "/api/v1/accounts/risks"); expect(scoped.status()).toBe(200);
      const raw = await scoped.text(); expect(raw).toContain(assets[1]); expect(raw).not.toContain(assets[0]);
      expect((await guest.request.get(base + "/api/v1/accounts/risks/export")).status()).toBe(403);
      expect((await guest.request.post(base + "/api/v1/accounts/risks/scans", { data: { revision: policy.revision, request_id: randomUUID() } })).status()).toBe(403);
      const guestPage = await guest.newPage(); await guestPage.goto(ui + "/console/account-risks");
      await expect(guestPage.getByRole("heading", { name: "Account risks", exact: true })).toBeVisible();
      await expect(guestPage.getByRole("button", { name: "Scan now", exact: true })).toHaveCount(0);
      await expect(guestPage.getByRole("button", { name: "Export filtered CSV", exact: true })).toHaveCount(0);
    } finally { await guest.close(); }
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export filtered CSV", exact: true }).click();
    const download = await downloadPromise; expect(download.suggestedFilename()).toMatch(/\.csv$/);
    const { readFile } = await import("node:fs/promises");
    const csv = await readFile((await download.path())!); expect(csv.toString("utf8")).not.toContain(weak); expect(csv.toString("utf8")).not.toContain("group_id");
    // Exercise the actual periodic worker after enabling it, then leave it disabled.
    await page.getByText("Detection policy and schedule", { exact: true }).click();
    await page.getByLabel("Run periodic detection", { exact: true }).check();
    const configured = page.waitForResponse((r) => r.url().endsWith("/risks/policy") && r.request().method() === "PUT");
    await page.getByRole("button", { name: "Save detection policy", exact: true }).click();
    const configuredResponse = await configured;
    expect(configuredResponse.status()).toBe(200);
    const configuredPolicy = await configuredResponse.json();
    await expect.poll(async () => {
      const r = await api.get("/api/v1/accounts/risks/scans");
      return (await r.json()).results.some((s: any) => s.policy_revision === configuredPolicy.revision && s.request_id.startsWith("auto-") && s.state === "succeeded");
    }, { timeout: 75_000, intervals: [1000, 2000, 3000] }).toBe(true);
    const scheduledPolicy = await (await api.get("/api/v1/accounts/risks/policy")).json();
    expect(scheduledPolicy.enabled).toBe(true);
    expect(Date.parse(scheduledPolicy.next_run)).toBeGreaterThan(Date.now());
    expect((await api.put("/api/v1/accounts/risks/policy", { data: { ...scheduledPolicy, enabled: false } })).status()).toBe(200);
    await page.getByRole("button", { name: "Refresh risks", exact: true }).click();
    await page.screenshot({ path: info.outputPath("account-risks.en.png"), fullPage: true });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "账号风险", exact: true })).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath("account-risks.zh-CN.png"), fullPage: true });
    expect(errors).toEqual([]);
    await writeFile(info.outputPath("risk-result.json"), JSON.stringify({ assets, names, users, fixture: hostName, realSSH: true, realRotation: true, periodic: true, retained: retain }));
    succeeded = true;
  } finally {
    if (!retain || !succeeded) {
      for (const id of grantIDs) await api.delete("/api/v1/grants/" + id);
      for (const id of assets) await api.delete("/api/v1/assets/" + id);
      if (operatorID) await api.delete("/api/v1/users/" + operatorID);
      if (roleID) await api.delete("/api/v1/rbac/roles/" + roleID);
      if (createdUsers.length) {
        await verifyOwner();
        for (const user of createdUsers) await execute("docker", ["exec", hostName, "sh", "-ceu", 'uid=$(id -u "$1"); test "$uid" -ge 1000; rm -f "/etc/sudoers.d/$1"; userdel "$1"', "qa-remove", user]);
      }
    }
    if (cookie) await fetch(base + "/api/v1/authentication/expire-session/", { method: "POST", headers: { Cookie: cookie, Origin: base }, signal: AbortSignal.timeout(5000) }).catch(() => {});
    if (token) await fetch(base + "/api/v1/authentication/expire-session/", { method: "POST", headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(5000) }).catch(() => {});
    await context.close(); await api.dispose();
  }
});
