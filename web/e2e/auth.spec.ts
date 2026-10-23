import { expect, test, request, type APIResponse } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { createHmac } from "node:crypto";
import { normalizeDateTimeLocal } from "./date-time.js";
const syntheticAdmin = {
  username: "e2e.admin",
  password: "synthetic-e2e-admin-password-2468",
};
const syntheticOperator = {
  username: "qa-operator",
  password: "synthetic-e2e-operator-password-8642",
};
let monitorAssetID = "";
let batchReplicaID = "";
let e2eInitialized = false;

test.describe.configure({ mode: "serial" });
test.use({ locale: "en-US" });

async function expectAPIStatus(response: APIResponse, expected: number, operation: string) {
  if (response.status() !== expected) {
    throw new Error(`${operation} returned HTTP ${response.status()}: ${await response.text()}`);
  }
}

test.beforeAll(async () => {
  if (e2eInitialized) return;
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  try {
    let response = await api.post("/api/v1/authentication/bootstrap", { data: syntheticAdmin });
    // Other independent files may already have initialized this isolated server.
    // Only the same synthetic administrator may resume setup after a conflict.
    if (response.status() === 409) {
      response = await api.post("/api/v1/authentication/auth/", { data: syntheticAdmin });
      await expectAPIStatus(response, 200, "existing synthetic administrator login");
    } else {
      await expectAPIStatus(response, 201, "administrator bootstrap");
    }
    const adminSession = (await response.json()) as { access_token: string };
    const adminHeaders = { Authorization: `Bearer ${adminSession.access_token}` };

    const fixtureResponse = await api.get("http://127.0.0.1:12223/health");
    await expectAPIStatus(fixtureResponse, 200, "synthetic SSH health endpoint");
    const fixture = (await fixtureResponse.json()) as {
      fingerprint: string;
      address: string;
      username: string;
    };
    const [host, portText] = fixture.address.split(":");
    const nodeResponse = await api.post("/api/v1/assets/nodes", {
      headers: adminHeaders,
      data: { name: "Browser QA" },
    });
    await expectAPIStatus(nodeResponse, 201, "synthetic Browser QA node creation");
    const node = (await nodeResponse.json()) as { id: string };

    const assetResponse = await api.post("/api/v1/assets", {
      headers: adminHeaders,
      data: {
        name: "Browser QA",
        host,
        port: Number(portText),
        group: "QA",
        node_id: node.id,
        username: fixture.username,
        password: "synthetic-qa-only-password",
        host_key_fingerprint: fixture.fingerprint,
        remark: "Synthetic SSH monitoring fixture",
      },
    });
    await expectAPIStatus(assetResponse, 201, "synthetic asset creation");
    const asset = (await assetResponse.json()) as { id: string };
    monitorAssetID = asset.id;
    const replicaResponse = await api.post("/api/v1/assets", {
      headers: adminHeaders,
      data: {
        name: "Batch replica",
        host,
        port: Number(portText),
        username: fixture.username,
        password: "synthetic-qa-only-password",
        host_key_fingerprint: fixture.fingerprint,
      },
    });
    await expectAPIStatus(replicaResponse, 201, "second synthetic batch target");
    batchReplicaID = ((await replicaResponse.json()) as { id: string }).id;

    const operatorResponse = await api.post("/api/v1/users", {
      headers: adminHeaders,
      data: { ...syntheticOperator, role: "operator" },
    });
    await expectAPIStatus(operatorResponse, 201, "operator creation");
    const operator = (await operatorResponse.json()) as { id: string };

    const grantResponse = await api.post("/api/v1/grants", {
      headers: adminHeaders,
      data: {
        user_id: operator.id,
        node_id: node.id,
        account: fixture.username,
        actions: ["view"],
      },
    });
    await expectAPIStatus(grantResponse, 201, "view-only grant creation");

    const probeResponse = await api.post(`/api/v1/assets/${asset.id}/probe`, {
      headers: adminHeaders,
    });
    await expectAPIStatus(probeResponse, 200, "synthetic SSH monitor probe");
    e2eInitialized = true;
  } finally {
    await api.dispose();
  }
});

async function signIn(page: import("@playwright/test").Page, account = syntheticAdmin) {
  await page.goto("/login");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await page.getByLabel("Username").fill(account.username);
  await page.getByLabel("Password").fill(account.password);
  const loginResponse = page.waitForResponse((response) =>
    response.url().includes("/api/v1/authentication/auth/"),
  );
  await page.getByRole("button", { name: "Sign in" }).click();
  const loginPayload = (await (await loginResponse).json()) as Record<string, unknown>;
  expect(loginPayload).toHaveProperty("browser_session", true);
  expect(loginPayload).not.toHaveProperty("access_token");
  await expect(page).toHaveURL(/\/console$/);
  await expect(page.locator(".layout-header")).toBeVisible();
}

test("protects console routes and restores the HttpOnly browser session after refresh", async ({
  page,
}) => {
  await page.goto("/console");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: "JumpServer233" })).toBeVisible();
  expect((await page.request.get("/api/v1/rbac/me")).status()).toBe(401);
  expect((await page.request.get("/api/v1/assets")).status()).toBe(401);
  await signIn(page);

  const sessionCookie = (await page.context().cookies()).find(
    (cookie) => cookie.name === "jms_sessionid",
  );
  expect(sessionCookie).toMatchObject({
    httpOnly: true,
    secure: false,
    sameSite: "Lax",
    path: "/",
  });

  await page.reload();
  await expect(page).toHaveURL(/\/console$/);
  await expect(page.locator(".layout-header")).toBeVisible();

  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.goto("/console");
  await expect(page).toHaveURL(/\/login$/);
});

test("creates a permanent API token once, authenticates with Token scheme, and revokes it", async ({
  page,
}) => {
  await signIn(page);
  await page.getByRole("link", { name: "Profile", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Permanent API tokens" })).toBeVisible();
  await page.getByRole("button", { name: "Create token" }).click();
  await expect(
    page.getByText("Save the token now. It cannot be shown again after you close it."),
  ).toBeVisible();

  const tokenBox = page.locator(".access-key-created code");
  await expect(tokenBox).toHaveCount(2);
  const token = await tokenBox.nth(1).innerText();
  expect(token.length).toBeGreaterThan(32);

  const authorizedStatus = await page.evaluate(async (tokenValue) => {
    const response = await fetch("/api/v1/users/me", {
      headers: { Authorization: `Token ${tokenValue}` },
    });
    return response.status;
  }, token);
  expect(authorizedStatus).toBe(200);

  const tokenRow = page.locator(".access-key-row").filter({ hasText: "pt-" });
  await expect(tokenRow).toHaveCount(1);
  await page.reload();
  await expect(page.getByRole("heading", { name: "Permanent API tokens" })).toBeVisible();
  await expect(page.locator(".access-key-row").filter({ hasText: "pt-" })).toHaveCount(1);
  await expect(page.locator("body")).not.toContainText(token);

  page.once("dialog", (dialog) => {
    void dialog.accept();
  });
  await page
    .locator(".access-key-row")
    .filter({ hasText: "pt-" })
    .getByRole("button", { name: "Revoke" })
    .click();
  await expect(page.getByText("No permanent tokens have been created.")).toBeVisible();
  const revokedStatus = await page.evaluate(async (tokenValue) => {
    const response = await fetch("/api/v1/users/me", {
      headers: { Authorization: `Token ${tokenValue}` },
    });
    return response.status;
  }, token);
  expect(revokedStatus).toBe(401);
});

test("shows SSH monitoring metrics for view-only operators and denies connection controls", async ({
  page,
}) => {
  await signIn(page, syntheticOperator);
  const assetRow = page.getByRole("row").filter({ hasText: "Browser QA" });
  await expect(assetRow).toBeVisible();
  await expect(assetRow.locator('[aria-label="CPU (4 cores) 5.3%"]')).toBeVisible();
  await expect(assetRow.locator('[aria-label="Memory 25.0%"]')).toBeVisible();
  await expect(assetRow.locator(".network-metric")).toContainText("Network");
  await expect(assetRow.locator('[aria-label="Disk 40.0%"]')).toBeVisible();
  await expect(assetRow.getByRole("button", { name: "Connect" })).toBeDisabled();
  await expect(assetRow.getByRole("button", { name: "Edit" })).toHaveCount(0);
  await expect(page.locator("body")).not.toContainText("synthetic-qa-only-password");
  expect(monitorAssetID).not.toBe("");
});

test("runs an audited SSH command from the workbench and noninteractive Agent CLI", async ({
  page,
}) => {
  await signIn(page);
  await page.goto("/workbench");
  await expect(page.getByRole("heading", { name: "SSH jobs" })).toBeVisible();
  await page.getByRole("combobox", { name: "Asset", exact: true }).selectOption(monitorAssetID);
  await page.getByLabel("Command", { exact: true }).fill("printf browser-job-ok");
  await page.getByRole("button", { name: "Run command", exact: true }).click();
  const result = page.getByRole("region", { name: "Execution result" });
  await expect(result).toContainText("Succeeded");
  await expect(result.locator("pre").first()).toHaveText("browser-job-ok\n");
  await expect(result).toContainText("Remote exit code: 0");
  await expect(page.locator("body")).not.toContainText("synthetic-qa-only-password");
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  try {
    const response = await api.post("/api/v1/authentication/auth/", { data: syntheticAdmin });
    await expectAPIStatus(response, 200, "CLI test sign-in");
    const session = (await response.json()) as { access_token: string };
    const { stdout } = await promisify(execFile)(
      "go",
      ["run", "./cmd/jms", "exec", monitorAssetID, "--json", "--", "printf", "browser-job-ok"],
      {
        cwd: fileURLToPath(new URL("../../server", import.meta.url)),
        env: {
          ...process.env,
          JMS_SERVER_URL: "http://127.0.0.1:8083",
          JMS_TOKEN: session.access_token,
          JMS_ACCESS_KEY_ID: "",
          JMS_ACCESS_KEY_SECRET: "",
        },
        timeout: 30_000,
      },
    );
    expect(JSON.parse(stdout)).toMatchObject({
      state: "succeeded",
      exit_code: 0,
      stdout: "browser-job-ok\n",
    });
  } finally {
    await api.dispose();
  }
});

test("denies SSH job execution and hides other users job history for view-only operators", async ({
  page,
}) => {
  await signIn(page, syntheticOperator);
  await page.goto("/workbench");
  await expect(page.getByText("No hosts with connect permission are available.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Run command" })).toBeDisabled();
  await expect(page.getByText("No SSH jobs yet.")).toBeVisible();
  const status = await page.evaluate(
    async (assetID) =>
      (
        await fetch("/api/v1/ops/jobs", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ asset_id: assetID, command: "printf browser-job-ok" }),
        })
      ).status,
    monitorAssetID,
  );
  expect(status).toBe(403);
  const planStatus = await page.evaluate(
    async (assetID) =>
      (
        await fetch("/api/v1/ops/plans", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            name: "forbidden plan",
            asset_ids: [assetID],
            command: "printf browser-job-ok",
            kind: "batch",
            request_id: "forbidden-plan",
          }),
        })
      ).status,
    monitorAssetID,
  );
  expect(planStatus).toBe(403);
  await page.locator(".operations-panel > summary").click();
  await expect(
    page.locator(".operations-panel").getByRole("button", { name: "Create plan", exact: true }),
  ).toBeDisabled();
  await expect(
    page.locator(".operations-panel").getByRole("table").nth(1).getByRole("row"),
  ).toHaveCount(1);
});

test("executes two-host batches, snapshots templates for a scheduled run, and pauses recurring plans", async ({
  page,
}) => {
  test.setTimeout(60_000);
  await signIn(page);
  await page.goto("/workbench");
  const panel = page.locator(".operations-panel");
  await panel.locator(":scope > summary").click();
  await panel.locator(".operations-templates > summary").click();
  await panel.getByLabel("Template name", { exact: true }).fill("QA health");
  await panel.getByLabel("Template command", { exact: true }).fill("printf browser-job-ok");
  await panel.getByRole("button", { name: "Save template", exact: true }).click();
  await expect(panel.getByRole("status")).toHaveText("Template saved.");
  await panel.getByLabel("Plan name", { exact: true }).fill("Two host batch");
  await panel.getByRole("checkbox", { name: "Browser QA (qa-monitor)", exact: true }).check();
  await panel.getByRole("checkbox", { name: "Batch replica (qa-monitor)", exact: true }).check();
  await panel
    .getByRole("combobox", { name: "Command source", exact: true })
    .selectOption({ label: "QA health · v1" });
  await panel.getByRole("button", { name: "Create plan", exact: true }).click();
  const runTable = panel.getByRole("table").nth(1);
  const batch = runTable.getByRole("row").filter({ hasText: "Two host batch" });
  await expect(batch).toContainText("Succeeded");
  await batch.getByRole("button", { name: "Details" }).click();
  const detail = panel.getByRole("region", { name: "Batch execution details" });
  await expect(detail.getByRole("listitem")).toHaveCount(2);
  await expect(detail.getByRole("button", { name: "Open execution" })).toHaveCount(2);
  await detail.getByRole("button", { name: "Open execution" }).first().click();
  await expect(
    page.getByRole("region", { name: "Execution result", exact: true }).locator("pre").first(),
  ).toHaveText("browser-job-ok\n");
  await panel.getByLabel("Plan name", { exact: true }).fill("Snapshot once");
  await panel.getByRole("checkbox", { name: "Batch replica (qa-monitor)", exact: true }).uncheck();
  await panel.getByRole("combobox", { name: "Schedule type", exact: true }).selectOption("once");
  const localTime = await page.evaluate(() => {
    const date = new Date(Date.now() + 12_000);
    return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 19);
  });
  await panel
    .getByLabel("Start time (local time)", { exact: true })
    .fill(normalizeDateTimeLocal(localTime));
  await panel.getByRole("button", { name: "Create plan", exact: true }).click();
  await expect(panel.getByRole("status")).toHaveText("Plan created with a saved command snapshot.");
  await panel
    .getByLabel("Template command", { exact: true })
    .fill("unsupported-new-template-command");
  await panel.getByRole("button", { name: "Save template", exact: true }).click();
  await expect(panel.getByRole("status")).toHaveText("Template saved.");
  await expect(runTable.getByRole("row").filter({ hasText: "Snapshot once" })).toContainText(
    "Succeeded",
    { timeout: 20_000 },
  );
  await panel.getByLabel("Plan name", { exact: true }).fill("Paused interval");
  await panel
    .getByRole("combobox", { name: "Schedule type", exact: true })
    .selectOption("interval");
  await panel.getByLabel("Interval (seconds, 60–2678400)", { exact: true }).fill("3600");
  await panel.getByRole("button", { name: "Create plan", exact: true }).click();
  const interval = panel
    .getByRole("table")
    .first()
    .getByRole("row")
    .filter({ hasText: "Paused interval" });
  await interval.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(interval.getByRole("button", { name: "Resume", exact: true })).toBeVisible();
  await interval.getByRole("button", { name: "Resume", exact: true }).click();
  await expect(interval.getByRole("button", { name: "Pause", exact: true })).toBeVisible();
  expect(batchReplicaID).not.toBe("");
  await expect(panel.getByRole("alert")).toHaveCount(0);
});

test("keeps older scheduled plans manageable through pagination", async ({ page }) => {
  await signIn(page);
  for (let index = 0; index < 51; index++) {
    const response = await page.request.post("/api/v1/ops/plans", {
      data: {
        name: `Pagination plan ${index}`,
        asset_ids: [monitorAssetID],
        command: "printf browser-job-ok",
        kind: "interval",
        interval_seconds: 3600,
        request_id: `pagination-${index}`,
      },
    });
    await expectAPIStatus(response, 201, "paginated future plan creation");
  }
  await page.goto("/workbench");
  const panel = page.locator(".operations-panel");
  await panel.locator(":scope > summary").click();
  await panel
    .getByRole("navigation", { name: "Plan pages" })
    .getByRole("button", { name: "Next", exact: true })
    .click();
  const older = panel
    .getByRole("table")
    .first()
    .getByRole("row")
    .filter({ hasText: "Pagination plan 0" });
  await older.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(older.getByRole("button", { name: "Resume", exact: true })).toBeVisible();
});

test.describe("Chinese browser locale", () => {
  test.use({ locale: "zh-CN" });

  test("auto-detects Chinese and renders authorized monitoring in Chinese", async ({ page }) => {
    await page.goto("/login");
    await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
    await expect(page.getByLabel("用户名")).toBeVisible();
    await expect(page.getByRole("button", { name: "登录" })).toBeVisible();

    await page.getByLabel("用户名").fill(syntheticOperator.username);
    await page.getByLabel("密码").fill(syntheticOperator.password);
    const loginResponse = page.waitForResponse((response) =>
      response.url().includes("/api/v1/authentication/auth/"),
    );
    await page.getByRole("button", { name: "登录" }).click();
    const loginPayload = (await (await loginResponse).json()) as Record<string, unknown>;
    expect(loginPayload).toHaveProperty("browser_session", true);
    expect(loginPayload).not.toHaveProperty("access_token");
    await expect(page).toHaveURL(/\/console$/);
    await expect(page.getByRole("columnheader", { name: "监控" })).toBeVisible();
    const assetRow = page.getByRole("row").filter({ hasText: "Browser QA" });
    await expect(assetRow.locator(".network-metric")).toContainText("网速");
    await expect(assetRow.getByRole("button", { name: "连接" })).toBeDisabled();
    await page.goto("/workbench");
    await page.getByText("批量命令与定时任务", { exact: true }).click();
    await expect(page.getByRole("button", { name: "创建计划", exact: true })).toBeDisabled();
  });
});

test("delegates a custom system role through the UI and revokes it for an existing session", async ({
  page,
  browser,
}) => {
  const delegated = { username: "qa-rbac", password: "synthetic-rbac-browser-password-7531" };
  await signIn(page);
  const userResponse = await page.request.post("/api/v1/users", {
    data: { ...delegated, role: "operator" },
  });
  await expectAPIStatus(userResponse, 201, "delegated synthetic account");
  const user = (await userResponse.json()) as { id: string };
  await page.goto("/console/roles");
  await expect(page.getByRole("heading", { name: "Role management", exact: true })).toBeVisible();
  await page.getByLabel("Role name", { exact: true }).fill("QA user manager");
  await page.getByLabel("Role description", { exact: true }).fill("Synthetic role validation");
  await page
    .getByRole("group", { name: "System permissions", exact: true })
    .getByRole("checkbox", { name: /^List users and create accounts/ })
    .check();
  const savedRole = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/system/rbac/roles") && r.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Save role", exact: true }).click();
  expect((await savedRole).status()).toBe(201);
  await page.getByRole("combobox", { name: "Subject", exact: true }).selectOption(user.id);
  const assigned = page.getByRole("group", { name: "Assigned roles", exact: true });
  await assigned.getByRole("checkbox", { name: "QA user manager", exact: true }).check();
  const savedBinding = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/system/rbac/bindings") && r.request().method() === "PUT",
  );
  await page.getByRole("button", { name: "Save binding", exact: true }).click();
  expect((await savedBinding).status()).toBe(200);
  await expect(page.getByRole("table")).toContainText("Update role binding");
  const operatorContext = await browser.newContext({
    locale: "en-US",
    baseURL: "http://127.0.0.1:5177",
  });
  try {
    const operatorPage = await operatorContext.newPage();
    await signIn(operatorPage, delegated);
    await operatorPage.goto("/console/settings");
    await expect(operatorPage.getByRole("tab", { name: "Users", exact: true })).toBeVisible();
    await expect(operatorPage.getByRole("tab")).toHaveCount(1);
    await expect(
      operatorPage
        .getByRole("combobox", { name: "Role", exact: true })
        .getByRole("option", { name: "Administrator", exact: true }),
    ).toHaveCount(0);
    const escalation = await operatorPage.request.post("/api/v1/users", {
      data: {
        username: "forbidden.admin",
        password: "synthetic-forbidden-password",
        role: "admin",
      },
    });
    expect(escalation.status()).toBe(403);
    await assigned.getByRole("checkbox", { name: "QA user manager", exact: true }).uncheck();
    const revoked = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/system/rbac/bindings") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save binding", exact: true }).click();
    expect((await revoked).status()).toBe(200);
    expect((await operatorPage.request.get("/api/v1/users")).status()).toBe(403);
    await operatorPage.reload();
    await expect(
      operatorPage.getByText("No system-settings permissions are assigned.", { exact: true }),
    ).toBeVisible();
    await operatorPage.goto("/console/roles");
    await expect(
      operatorPage.getByText("Role-management permission is required.", { exact: true }),
    ).toBeVisible();
    await expect(page.getByRole("alert")).toHaveCount(0);
  } finally {
    await operatorContext.close();
  }
});

function totpForSecret(secret: string) {
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
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const digest = createHmac("sha1", Buffer.from(bytes)).update(counter).digest();
  const offset = digest[digest.length - 1] & 15;
  return String((digest.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("signs in over real LDAPS with mandatory local MFA and revokes directory sessions", async ({
  page,
  browser,
}) => {
  test.setTimeout(60_000);
  await signIn(page);
  const fixtureResponse = await page.request.get("http://127.0.0.1:12230/health");
  expect(fixtureResponse.status()).toBe(200);
  const fixture = (await fixtureResponse.json()) as { url: string; ca_pem: string };
  await page.goto("/console/directory");
  await expect(page.getByRole("heading", { name: "Directory login", exact: true })).toBeVisible();
  await page.getByLabel("Directory URL", { exact: true }).fill(fixture.url);
  await page.getByLabel("User search base DN", { exact: true }).fill("dc=example,dc=test");
  await page.getByLabel("Search account DN", { exact: true }).fill("cn=reader,dc=example,dc=test");
  await page
    .getByLabel("Search account password (write only)", { exact: true })
    .fill("synthetic-directory-reader-password");
  await page
    .getByLabel("Additional CA certificates (PEM, optional)", { exact: true })
    .fill(fixture.ca_pem);
  await page.getByRole("checkbox", { name: "Enable directory sign-in", exact: true }).check();
  const saved = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/settings/security/ldap") && r.request().method() === "PUT",
  );
  await page.getByRole("button", { name: "Save directory settings", exact: true }).click();
  const savedResult = await saved;
  expect(savedResult.status()).toBe(200);
  expect(await savedResult.text()).not.toContain("synthetic-directory-reader-password");
  await expect(
    page.getByLabel("Search account password (write only)", { exact: true }),
  ).toHaveValue("");
  await page
    .getByRole("button", { name: "Check saved TLS and search-account bind", exact: true })
    .click();
  await expect(page.getByRole("status")).toHaveText(
    "TLS and search-account bind succeeded. This does not verify a user login.",
  );
  await page.getByLabel("Directory username", { exact: true }).fill("directory.user");
  await page.getByLabel("External username (optional)", { exact: true }).fill("ldap.operator");
  await page.getByRole("button", { name: "Prepare external operator", exact: true }).click();
  await expect(
    page.getByText("External account ready: ldap.operator", { exact: true }),
  ).toBeVisible();
  expect(
    (await page.request.put("/api/v1/settings/security/mfa", { data: { mode: "all" } })).status(),
  ).toBe(200);
  const context = await browser.newContext({ locale: "en-US", baseURL: "http://127.0.0.1:5177" });
  try {
    const login = await context.newPage();
    await login.goto("/login");
    await login.getByLabel("Sign-in source", { exact: true }).selectOption("ldap");
    await login.getByLabel("Username", { exact: true }).fill("directory.user");
    await login.getByLabel("Password", { exact: true }).fill("synthetic-directory-user-password");
    await login.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(login.locator(".login-mfa-setup")).toBeVisible();
    expect((await context.cookies()).find((c) => c.name === "jms_ldap_pending")).toMatchObject({
      httpOnly: true,
      path: "/api/v1/authentication/ldap",
    });
    await expect(login.getByLabel("Password", { exact: true })).toBeDisabled();
    await expect(login.getByLabel("Password", { exact: true })).toHaveValue("");
    expect((await login.request.get("/api/v1/users/me")).status()).toBe(401);
    const secret = await login.locator(".login-mfa-setup code").first().innerText();
    await login.getByLabel("Authenticator code", { exact: true }).fill(totpForSecret(secret));
    const complete = login.waitForResponse(
      (r) =>
        r.url().endsWith("/api/v1/authentication/ldap/complete") && r.request().method() === "POST",
    );
    await login.getByRole("button", { name: "Verify and sign in", exact: true }).click();
    const result = (await (await complete).json()) as {
      browser_session: boolean;
      user: { role: string; source: string; username: string };
    };
    expect(result).toMatchObject({
      browser_session: true,
      user: { role: "operator", source: "ldap", username: "ldap.operator" },
    });
    expect(result).not.toHaveProperty("access_token");
    await expect(login).toHaveURL(/\/console$/);
    expect(await (await login.request.get("/api/v1/assets")).json()).toEqual([]);
    await login.goto("/profile");
    await expect(
      login.getByText("This account uses LDAP. Its primary password is managed by the directory.", {
        exact: true,
      }),
    ).toBeVisible();
    await expect(login.getByRole("button", { name: "Change password", exact: true })).toHaveCount(
      0,
    );
    await page.getByRole("checkbox", { name: "Enable directory sign-in", exact: true }).uncheck();
    const disabled = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/settings/security/ldap") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save directory settings", exact: true }).click();
    expect((await disabled).status()).toBe(200);
    expect((await login.request.get("/api/v1/users/me")).status()).toBe(401);
  } finally {
    await context.close();
    await page.request.put("/api/v1/settings/security/mfa", { data: { mode: "disabled" } });
  }
});

test("signs in through a real synthetic OIDC provider with local MFA and no inherited administrator grants", async ({
  page,
  browser,
}) => {
  test.setTimeout(60_000);
  await signIn(page);
  await page.goto("/console/identity");
  await expect(page.getByRole("heading", { name: "Single sign-on", exact: true })).toBeVisible();
  await page.getByLabel("Issuer URL", { exact: true }).fill("http://127.0.0.1:12226");
  await page.getByLabel("Client ID", { exact: true }).fill("synthetic-oidc-client");
  await page
    .getByLabel("Callback URL", { exact: true })
    .fill("http://127.0.0.1:5177/api/v1/authentication/oidc/callback");
  await page
    .getByLabel("Client secret (write only)", { exact: true })
    .fill("synthetic-oidc-client-secret-only");
  await page
    .getByRole("checkbox", {
      name: "Allow HTTP on literal loopback addresses for local development",
      exact: true,
    })
    .check();
  await page.getByRole("checkbox", { name: "Enable OIDC sign-in", exact: true }).check();
  const saved = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/settings/security/oidc") && r.request().method() === "PUT",
  );
  await page.getByRole("button", { name: "Save OIDC settings", exact: true }).click();
  const savedResponse = await saved;
  expect(savedResponse.status()).toBe(200);
  expect(await savedResponse.text()).not.toContain("synthetic-oidc-client-secret-only");
  await expect(page.getByLabel("Client secret (write only)", { exact: true })).toHaveValue("");
  await page.getByRole("button", { name: "Check saved discovery", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText(
    "Discovery and endpoint metadata are available. This does not verify an actual sign-in.",
  );
  await page.getByLabel("Provider subject (sub)", { exact: true }).fill("synthetic-oidc-subject");
  await page.getByLabel("External username (optional)", { exact: true }).fill("sso.operator");
  await page.getByRole("button", { name: "Prepare external operator", exact: true }).click();
  await expect(
    page.getByText("External account ready: sso.operator", { exact: true }),
  ).toBeVisible();
  const policy = await page.request.put("/api/v1/settings/security/mfa", { data: { mode: "all" } });
  await expectAPIStatus(policy, 200, "require MFA for SSO account");
  const context = await browser.newContext({ locale: "en-US", baseURL: "http://127.0.0.1:5177" });
  try {
    const sso = await context.newPage();
    await sso.goto("/login");
    await sso.getByRole("link", { name: "Sign in with SSO", exact: true }).click();
    await expect(sso).toHaveURL(/127\.0\.0\.1:12226\/authorize/);
    await sso.getByRole("button", { name: "Continue as synthetic operator", exact: true }).click();
    await expect(sso).toHaveURL(/\/login\?sso=continue$/);
    const pendingCookie = (await context.cookies()).find((c) => c.name === "jms_oidc_pending");
    expect(pendingCookie).toMatchObject({ httpOnly: true, path: "/api/v1/authentication/oidc" });
    expect((await sso.request.get("/api/v1/users/me")).status()).toBe(401);
    await sso.getByRole("button", { name: "Complete sign-in", exact: true }).click();
    await expect(sso.locator(".login-mfa-setup")).toBeVisible();
    const secret = await sso.locator(".login-mfa-setup code").first().innerText();
    await sso.getByLabel("Authenticator code", { exact: true }).fill(totpForSecret(secret));
    const complete = sso.waitForResponse(
      (r) =>
        r.url().endsWith("/api/v1/authentication/oidc/complete") && r.request().method() === "POST",
    );
    await sso.getByRole("button", { name: "Verify and sign in", exact: true }).click();
    const completeResult = (await (await complete).json()) as {
      browser_session: boolean;
      user: { role: string; source: string; username: string };
      access_token?: string;
    };
    expect(completeResult).toMatchObject({
      browser_session: true,
      user: { role: "operator", source: "oidc", username: "sso.operator" },
    });
    expect(completeResult).not.toHaveProperty("access_token");
    await expect(sso).toHaveURL(/\/console$/);
    expect((await context.cookies()).find((c) => c.name === "jms_sessionid")).toMatchObject({
      httpOnly: true,
      path: "/",
    });
    expect(await (await sso.request.get("/api/v1/assets")).json()).toEqual([]);
    await sso.goto("/profile");
    await expect(
      sso.getByText(
        "This account uses OIDC. Its primary password is managed by the identity provider.",
        { exact: true },
      ),
    ).toBeVisible();
    await expect(sso.getByRole("button", { name: "Change password", exact: true })).toHaveCount(0);
    await page.getByRole("checkbox", { name: "Enable OIDC sign-in", exact: true }).uncheck();
    const disabled = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/settings/security/oidc") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save OIDC settings", exact: true }).click();
    expect((await disabled).status()).toBe(200);
    expect((await sso.request.get("/api/v1/users/me")).status()).toBe(401);
    await expect(page.getByRole("alert")).toHaveCount(0);
  } finally {
    await context.close();
    await page.request.put("/api/v1/settings/security/mfa", { data: { mode: "disabled" } });
  }
});

test("completes CAS service-ticket login with browser cancellation, mandatory MFA and disablement", async ({
  page,
  browser,
}) => {
  test.setTimeout(60_000);
  await signIn(page);
  await page.goto("/console/cas");
  await expect(page.getByRole("heading", { name: "CAS sign-in", exact: true })).toBeVisible();
  await page.getByLabel("CAS base URL", { exact: true }).fill("http://127.0.0.1:12233/cas");
  await page
    .getByLabel("Callback URL", { exact: true })
    .fill("http://127.0.0.1:5177/api/v1/authentication/cas/callback");
  await page
    .getByRole("checkbox", {
      name: "Allow HTTP on literal loopback addresses for local development",
      exact: true,
    })
    .check();
  await page.getByRole("checkbox", { name: "Enable CAS sign-in", exact: true }).check();
  const saved = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/settings/security/cas") && r.request().method() === "PUT",
  );
  await page.getByRole("button", { name: "Save CAS settings", exact: true }).click();
  expect((await saved).status()).toBe(200);
  await page.getByRole("button", { name: "Check saved CAS login endpoint", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText(
    "The CAS login endpoint is reachable. This does not verify a service ticket or sign-in.",
  );
  await page.getByLabel("CAS user identifier", { exact: true }).fill("synthetic-cas-subject");
  await page.getByLabel("External username (optional)", { exact: true }).fill("cas.operator");
  await page.getByRole("button", { name: "Prepare external operator", exact: true }).click();
  await expect(
    page.getByText("External account ready: cas.operator", { exact: true }),
  ).toBeVisible();
  expect(
    (await page.request.put("/api/v1/settings/security/mfa", { data: { mode: "all" } })).status(),
  ).toBe(200);
  const context = await browser.newContext({ locale: "en-US", baseURL: "http://127.0.0.1:5177" });
  try {
    const login = await context.newPage();
    await login.goto("/login");
    await login.getByRole("link", { name: "Sign in with CAS", exact: true }).click();
    await expect(login).toHaveURL(/127\.0\.0\.1:12233\/cas\/login/);
    await login
      .getByRole("button", { name: "Continue as synthetic CAS user", exact: true })
      .click();
    await expect(login).toHaveURL(/\/login\?cas=continue$/);
    expect((await context.cookies()).find((c) => c.name === "jms_cas_pending")).toMatchObject({
      httpOnly: true,
      path: "/api/v1/authentication/cas",
    });
    await login.getByRole("button", { name: "Use password sign-in", exact: true }).click();
    await expect(login.getByRole("button", { name: "Sign in", exact: true })).toBeVisible();
    expect((await context.cookies()).find((c) => c.name === "jms_cas_pending")).toBeUndefined();
    await login.getByRole("link", { name: "Sign in with CAS", exact: true }).click();
    await login
      .getByRole("button", { name: "Continue as synthetic CAS user", exact: true })
      .click();
    await expect(login).toHaveURL(/\/login\?cas=continue$/);
    expect((await login.request.get("/api/v1/users/me")).status()).toBe(401);
    await login.getByRole("button", { name: "Complete CAS sign-in", exact: true }).click();
    await expect(login.locator(".login-mfa-setup")).toBeVisible();
    const secret = await login.locator(".login-mfa-setup code").first().innerText();
    await login.getByLabel("Authenticator code", { exact: true }).fill(totpForSecret(secret));
    const complete = login.waitForResponse(
      (r) =>
        r.url().endsWith("/api/v1/authentication/cas/complete") && r.request().method() === "POST",
    );
    await login.getByRole("button", { name: "Verify and sign in", exact: true }).click();
    const result = (await (await complete).json()) as {
      browser_session: boolean;
      user: { role: string; source: string; username: string };
    };
    expect(result).toMatchObject({
      browser_session: true,
      user: { role: "operator", source: "cas", username: "cas.operator" },
    });
    expect(result).not.toHaveProperty("access_token");
    await expect(login).toHaveURL(/\/console$/);
    expect((await context.cookies()).find((c) => c.name === "jms_sessionid")).toMatchObject({
      httpOnly: true,
      path: "/",
    });
    expect(await (await login.request.get("/api/v1/assets")).json()).toEqual([]);
    await login.goto("/profile");
    await expect(
      login.getByText(
        "This account uses CAS. Its primary password is managed by the CAS provider.",
        { exact: true },
      ),
    ).toBeVisible();
    await expect(login.getByRole("button", { name: "Change password", exact: true })).toHaveCount(
      0,
    );
    await page.getByRole("checkbox", { name: "Enable CAS sign-in", exact: true }).uncheck();
    const disabled = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/settings/security/cas") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save CAS settings", exact: true }).click();
    expect((await disabled).status()).toBe(200);
    expect((await login.request.get("/api/v1/users/me")).status()).toBe(401);
    await expect(page.getByRole("alert")).toHaveCount(0);
  } finally {
    await context.close();
    await page.request.put("/api/v1/settings/security/mfa", { data: { mode: "disabled" } });
  }
});

test("completes SAML signed-assertion login with browser cancellation, mandatory MFA and disablement", async ({
  page,
  browser,
}) => {
  test.setTimeout(60_000);
  await signIn(page);
  await page.goto("/console/saml");
  await expect(page.getByRole("heading", { name: "SAML sign-in", exact: true })).toBeVisible();
  const fixture = (await (await page.request.get("http://127.0.0.2:12235/health")).json()) as {
    metadata_xml: string;
  };
  await page.getByLabel("SP entity ID", { exact: true }).fill("http://127.0.0.1:5177/sp");
  await page
    .getByLabel("Assertion consumer URL", { exact: true })
    .fill("http://127.0.0.1:5177/api/v1/authentication/saml/acs");
  await page.getByLabel("IdP metadata XML", { exact: true }).fill(fixture.metadata_xml);
  await page
    .getByRole("checkbox", {
      name: "Allow HTTP on literal loopback addresses for local development",
      exact: true,
    })
    .check();
  await page.getByRole("checkbox", { name: "Enable SAML sign-in", exact: true }).check();
  const saved = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/settings/security/saml") && r.request().method() === "PUT",
  );
  await page.getByRole("button", { name: "Save SAML settings", exact: true }).click();
  expect((await saved).status()).toBe(200);
  await page.getByLabel("Persistent NameID", { exact: true }).fill("synthetic-saml-subject");
  await page.getByLabel("External username (optional)", { exact: true }).fill("saml.operator");
  await page.getByRole("button", { name: "Prepare external operator", exact: true }).click();
  await expect(
    page.getByText("External account ready: saml.operator", { exact: true }),
  ).toBeVisible();
  expect(
    (await page.request.put("/api/v1/settings/security/mfa", { data: { mode: "all" } })).status(),
  ).toBe(200);
  const context = await browser.newContext({ locale: "en-US", baseURL: "http://127.0.0.1:5177" });
  try {
    const login = await context.newPage();
    await login.goto("/login");
    await login.getByRole("link", { name: "Sign in with SAML", exact: true }).click();
    await expect(login).toHaveURL(/127\.0\.0\.2:12235\/sso/);
    const crossSitePost = login.waitForRequest(
      (r) => r.url().endsWith("/api/v1/authentication/saml/acs") && r.method() === "POST",
    );
    await login
      .getByRole("button", { name: "Continue as synthetic SAML user", exact: true })
      .click();
    const posted = await crossSitePost;
    expect((await posted.allHeaders()).cookie ?? "").not.toContain("jms_saml_flow=");
    await expect(login).toHaveURL(/\/login\?saml=continue$/);
    expect((await context.cookies()).find((c) => c.name === "jms_saml_pending")).toMatchObject({
      httpOnly: true,
      path: "/api/v1/authentication/saml",
    });
    await login.getByRole("button", { name: "Use password sign-in", exact: true }).click();
    await expect(login.getByRole("button", { name: "Sign in", exact: true })).toBeVisible();
    expect((await context.cookies()).find((c) => c.name === "jms_saml_pending")).toBeUndefined();
    await login.getByRole("link", { name: "Sign in with SAML", exact: true }).click();
    await login
      .getByRole("button", { name: "Continue as synthetic SAML user", exact: true })
      .click();
    await expect(login).toHaveURL(/\/login\?saml=continue$/);
    expect((await login.request.get("/api/v1/users/me")).status()).toBe(401);
    await login.getByRole("button", { name: "Complete SAML sign-in", exact: true }).click();
    await expect(login.locator(".login-mfa-setup")).toBeVisible();
    const secret = await login.locator(".login-mfa-setup code").first().innerText();
    await login.getByLabel("Authenticator code", { exact: true }).fill(totpForSecret(secret));
    const complete = login.waitForResponse(
      (r) =>
        r.url().endsWith("/api/v1/authentication/saml/complete") && r.request().method() === "POST",
    );
    await login.getByRole("button", { name: "Verify and sign in", exact: true }).click();
    const result = (await (await complete).json()) as {
      browser_session: boolean;
      user: { role: string; source: string; username: string };
    };
    expect(result).toMatchObject({
      browser_session: true,
      user: { role: "operator", source: "saml", username: "saml.operator" },
    });
    expect(result).not.toHaveProperty("access_token");
    await expect(login).toHaveURL(/\/console$/);
    expect((await context.cookies()).find((c) => c.name === "jms_sessionid")).toMatchObject({
      httpOnly: true,
      path: "/",
    });
    expect(await (await login.request.get("/api/v1/assets")).json()).toEqual([]);
    await login.goto("/profile");
    await expect(
      login.getByText(
        "This account uses SAML. Its primary password is managed by the identity provider.",
        { exact: true },
      ),
    ).toBeVisible();
    await expect(login.getByRole("button", { name: "Change password", exact: true })).toHaveCount(
      0,
    );
    await page.getByRole("checkbox", { name: "Enable SAML sign-in", exact: true }).uncheck();
    const disabled = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/settings/security/saml") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save SAML settings", exact: true }).click();
    expect((await disabled).status()).toBe(200);
    expect((await login.request.get("/api/v1/users/me")).status()).toBe(401);
    await expect(page.getByRole("alert")).toHaveCount(0);
  } finally {
    await context.close();
    await page.request.put("/api/v1/settings/security/mfa", { data: { mode: "disabled" } });
  }
});

test("routes monitoring, Web SSH and Agent CLI through a pinned gateway with target-only grants", async ({
  page,
  browser,
}) => {
  test.setTimeout(90_000);
  await signIn(page);
  const health = (await (await page.request.get("http://127.0.0.1:12238/health")).json()) as {
    address: string;
    fingerprint: string;
    username: string;
    forwards: number;
  };
  const host = (await (await page.request.get("http://127.0.0.1:12223/health")).json()) as {
    fingerprint: string;
    username: string;
  };
  const [address, port] = health.address.split(":");
  const gatewayInput = {
    name: "QA infrastructure gateway",
    host: address,
    port: Number(port),
    username: health.username,
    password: "synthetic-gateway-password",
    host_key_fingerprint: health.fingerprint,
  };
  const created = await page.request.post("/api/v1/assets", { data: gatewayInput });
  await expectAPIStatus(created, 201, "gateway creation");
  const gateway = (await created.json()) as { id: string };
  await page.reload();
  await page.getByRole("button", { name: "Add asset", exact: true }).click();
  const form = page.locator(".asset-modal");
  await form.getByLabel("Name", { exact: true }).fill("Private routed host");
  await form.getByLabel("Host address", { exact: true }).fill("private.synthetic.invalid");
  await form.getByLabel("SSH username", { exact: true }).fill(host.username);
  await form.getByLabel("SSH password", { exact: true }).fill("synthetic-qa-only-password");
  await form.getByLabel("Host-key fingerprint (SHA256)").fill(host.fingerprint);
  await form.getByLabel("SSH gateway").selectOption(gateway.id);
  const saving = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/assets") && r.request().method() === "POST",
  );
  await form.getByRole("button", { name: "Save", exact: true }).click();
  const saved = await saving;
  expect(saved.status()).toBe(201);
  await expect(form).toHaveCount(0);
  const inventory = (await (await page.request.get("/api/v1/assets")).json()) as {
    id: string;
    name: string;
    gateway_id?: string;
  }[];
  const target = inventory.find((asset) => asset.name === "Private routed host");
  expect(target).toBeDefined();
  if (!target) throw new Error("The asset saved through the UI is missing");
  expect(target.gateway_id).toBe(gateway.id);
  expect((await page.request.delete(`/api/v1/assets/${gateway.id}`)).status()).toBe(409);
  expect(
    (
      await page.request.put(`/api/v1/assets/${gateway.id}`, {
        data: { ...gatewayInput, gateway_id: target.id },
      })
    ).status(),
  ).toBe(400);
  await page.request.put(`/api/v1/assets/${gateway.id}`, {
    data: {
      ...gatewayInput,
      host_key_fingerprint: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    },
  });
  const failed = await page.request.post(`/api/v1/assets/${target.id}/probe`);
  expect(await failed.json()).toMatchObject({
    monitor: { state: "offline", error_code: "gateway_failed" },
  });
  await page.request.put(`/api/v1/assets/${gateway.id}`, { data: gatewayInput });
  const probe = await page.request.post(`/api/v1/assets/${target.id}/probe`);
  expect(await probe.json()).toMatchObject({
    monitor: {
      state: "online",
      metrics: { cpu_percent: 5.25, memory_percent: 25, disk_percent: 40 },
    },
  });
  await page.reload();
  const row = page.getByRole("row").filter({ hasText: "Private routed host" });
  await expect(row).toContainText("Via QA infrastructure gateway");
  const account = { username: "gateway.operator", password: "synthetic-gateway-operator-password" };
  const userResponse = await page.request.post("/api/v1/users", {
    data: { ...account, role: "operator" },
  });
  await expectAPIStatus(userResponse, 201, "gateway operator creation");
  const user = (await userResponse.json()) as { id: string };
  const grant = await page.request.post("/api/v1/grants", {
    data: {
      user_id: user.id,
      asset_id: target.id,
      account: host.username,
      actions: ["view", "connect"],
    },
  });
  await expectAPIStatus(grant, 201, "target-only grant");
  const context = await browser.newContext({ locale: "en-US" });
  try {
    const operator = await context.newPage();
    await signIn(operator, account);
    const visible = await operator.request.get("/api/v1/assets");
    expect(await visible.json()).toEqual([expect.objectContaining({ id: target.id })]);
    expect(await visible.text()).not.toContain("synthetic-gateway-password");
    expect(
      (
        await operator.request.post("/api/v1/sessions", {
          data: { asset_id: gateway.id, cols: 80, rows: 24 },
        })
      ).status(),
    ).toBe(403);
    expect((await operator.request.put(`/api/v1/assets/${target.id}`, { data: {} })).status()).toBe(
      403,
    );
    const targetRow = operator.getByRole("row").filter({ hasText: "Private routed host" });
    await expect(targetRow).toContainText("Via Managed gateway");
    await targetRow.getByRole("button", { name: "Connect", exact: true }).click();
    const terminal = operator.getByRole("dialog", { name: "Private routed host" });
    await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
    await expect(terminal.locator(".xterm-screen")).toBeVisible();
    await terminal.getByRole("button", { name: "Close terminal" }).click();
    const audit = await operator.request.get("/api/v1/sessions");
    expect(await audit.text()).toContain(`"gateway_ids":["${gateway.id}"]`);
    await operator.goto("/workbench");
    await operator.getByRole("combobox", { name: "Asset", exact: true }).selectOption(target.id);
    await operator.getByLabel("Command", { exact: true }).fill("printf browser-job-ok");
    await operator.getByRole("button", { name: "Run command", exact: true }).click();
    await expect(
      operator.getByRole("region", { name: "Execution result" }).locator("pre").first(),
    ).toHaveText("browser-job-ok\n");
  } finally {
    await context.close();
  }
  const auth = await page.request.post("/api/v1/authentication/auth/", { data: syntheticAdmin });
  const login = (await auth.json()) as { access_token: string };
  const { stdout } = await promisify(execFile)(
    "go",
    ["run", "./cmd/jms", "exec", target.id, "--json", "--", "printf", "browser-job-ok"],
    {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      env: {
        ...process.env,
        JMS_SERVER_URL: "http://127.0.0.1:8083",
        JMS_TOKEN: login.access_token,
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
      },
      timeout: 30_000,
    },
  );
  expect(JSON.parse(stdout)).toMatchObject({ state: "succeeded", stdout: "browser-job-ok\n" });
  const after = (await (await page.request.get("http://127.0.0.1:12238/health")).json()) as {
    forwards: number;
  };
  expect(after.forwards).toBeGreaterThan(health.forwards + 3);
});

test("imports an encrypted SSH key for target and gateway, preserves it on edit and verifies backup restore", async ({
  page,
}) => {
  test.setTimeout(90_000);
  await signIn(page);
  const { stdout: privateKey } = await promisify(execFile)(
    "go",
    ["run", "./testsupport/sshidentity/cmd"],
    { cwd: fileURLToPath(new URL("../../server", import.meta.url)), timeout: 30_000 },
  );
  const passphrase = "synthetic-import-key-passphrase";
  const health = (await (await page.request.get("http://127.0.0.1:12223/health")).json()) as {
    fingerprint: string;
    key_username: string;
    key_fingerprint: string;
  };
  const gatewayHealth = (await (
    await page.request.get("http://127.0.0.1:12238/health")
  ).json()) as { fingerprint: string };
  const gatewayResponse = await page.request.post("/api/v1/assets", {
    data: {
      name: "Key-auth gateway",
      host: "127.0.0.1",
      port: 12237,
      username: "qa-gateway",
      host_key_fingerprint: gatewayHealth.fingerprint,
      credential_type: "ssh_key",
      private_key: privateKey,
      private_key_passphrase: passphrase,
    },
  });
  await expectAPIStatus(gatewayResponse, 201, "private-key gateway import");
  const gateway = (await gatewayResponse.json()) as { id: string };
  await page.reload();
  await page.getByRole("button", { name: "Add asset", exact: true }).click();
  const form = page.locator(".asset-modal");
  await form.getByLabel("Name", { exact: true }).fill("Key-auth host");
  await form.getByLabel("Host address", { exact: true }).fill("private.synthetic.invalid");
  await form.getByLabel("SSH username", { exact: true }).fill(health.key_username);
  await form.getByLabel("SSH authentication", { exact: true }).selectOption("ssh_key");
  await expect(form.getByLabel("SSH password", { exact: true })).toHaveCount(0);
  await form.getByLabel("Private key (PEM / OpenSSH)", { exact: true }).fill(privateKey);
  await form.getByLabel("Private-key passphrase (optional)", { exact: true }).fill(passphrase);
  await form.getByLabel("Host-key fingerprint (SHA256)").fill(health.fingerprint);
  await form.getByLabel("SSH gateway").selectOption(gateway.id);
  await form.getByRole("button", { name: "Save", exact: true }).click();
  await expect(form).toHaveCount(0);
  const inventoryResponse = await page.request.get("/api/v1/assets");
  expect(await inventoryResponse.text()).not.toContain("PRIVATE KEY");
  expect(await inventoryResponse.text()).not.toContain(passphrase);
  const inventory = (await inventoryResponse.json()) as {
    id: string;
    name: string;
    credential_type: string;
    key_fingerprint: string;
  }[];
  const asset = inventory.find((item) => item.name === "Key-auth host");
  expect(asset).toBeDefined();
  if (!asset) throw new Error("Private-key asset missing after UI import");
  expect(asset).toMatchObject({
    credential_type: "ssh_key",
    key_fingerprint: health.key_fingerprint,
  });
  expect(asset).not.toHaveProperty("password_rotation");
  expect((await page.request.post(`/api/v1/assets/${asset.id}/password-rotation`)).status()).toBe(
    400,
  );
  const probe = await page.request.post(`/api/v1/assets/${asset.id}/probe`);
  expect(await probe.json()).toMatchObject({
    monitor: { state: "online", metrics: { cpu_percent: 5.25 } },
  });
  await page.reload();
  let row = page.getByRole("row").filter({ hasText: "Key-auth host" });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(form.getByLabel("Private key (PEM / OpenSSH)", { exact: true })).toHaveValue("");
  await expect(form.getByLabel("Private-key passphrase (optional)", { exact: true })).toHaveValue(
    "",
  );
  await expect(form).toContainText(health.key_fingerprint);
  await form.getByLabel("Note", { exact: true }).fill("Synthetic imported key retained");
  await form.getByRole("button", { name: "Save", exact: true }).click();
  await expect(form).toHaveCount(0);
  await row.locator("summary").click();
  await expect(row.getByRole("button", { name: "Rotate password", exact: true })).toHaveCount(0);
  await row.getByRole("button", { name: "Credential history", exact: true }).click();
  const backups = page.getByRole("dialog", { name: "Credential history · Key-auth host" });
  await backups.getByRole("button", { name: "Save current credential", exact: true }).click();
  await expect(backups.locator(".credential-backup-row")).toHaveCount(1);
  await expect(backups).toContainText("SSH private key");
  await expect(backups).toContainText(health.key_fingerprint);
  page.once("dialog", (dialog) => {
    void dialog.accept();
  });
  await backups.getByRole("button", { name: "Restore", exact: true }).click();
  await expect(backups.getByRole("status")).toHaveText(
    "SSH key authentication was verified and the vault credential was restored.",
  );
  await backups.getByRole("button", { name: "Cancel", exact: true }).click();
  await row.getByRole("button", { name: "Connect", exact: true }).click();
  const terminal = page.getByRole("dialog", { name: "Key-auth host", exact: true });
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
  await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
  const login = (await (
    await page.request.post("/api/v1/authentication/auth/", { data: syntheticAdmin })
  ).json()) as { access_token: string };
  const { stdout } = await promisify(execFile)(
    "go",
    ["run", "./cmd/jms", "exec", asset.id, "--json", "--", "printf", "browser-job-ok"],
    {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      env: {
        ...process.env,
        JMS_SERVER_URL: "http://127.0.0.1:8083",
        JMS_TOKEN: login.access_token,
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
      },
      timeout: 30_000,
    },
  );
  expect(JSON.parse(stdout)).toMatchObject({ state: "succeeded", stdout: "browser-job-ok\n" });
  await page.getByRole("button", { name: "中文", exact: true }).click();
  row = page.getByRole("row").filter({ hasText: "Key-auth host" });
  await expect(row).toContainText("SSH 私钥");
  await row.getByRole("button", { name: "编辑", exact: true }).click();
  await expect(form.getByLabel("SSH 认证方式", { exact: true })).toHaveValue("ssh_key");
  await expect(form.getByLabel("私钥（PEM / OpenSSH）", { exact: true })).toHaveValue("");
  await expect(form).toContainText("七天密码轮换不会修改私钥");
  await form.getByRole("button", { name: "取消", exact: true }).click();
});

test("installs and rotates a real Linux OpenSSH key through the gateway with server-enforced operator denial", async ({
  page,
  browser,
}) => {
  test.setTimeout(120_000);
  await signIn(page);
  const host = (await (await page.request.get("http://127.0.0.1:12242/health")).json()) as {
    fingerprint: string;
    username: string;
    container_name: string;
    owner: string;
  };
  expect(host.container_name).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
  const gatewayFixture = (await (
    await page.request.get("http://127.0.0.1:12238/health")
  ).json()) as { fingerprint: string };
  const gatewayResponse = await page.request.post("/api/v1/assets", {
    data: {
      name: "Linux lifecycle gateway",
      host: "127.0.0.1",
      port: 12237,
      username: "qa-gateway",
      password: "synthetic-gateway-password",
      host_key_fingerprint: gatewayFixture.fingerprint,
    },
  });
  await expectAPIStatus(gatewayResponse, 201, "Linux lifecycle gateway");
  const gateway = (await gatewayResponse.json()) as { id: string };
  await page.reload();
  await page.getByRole("button", { name: "Add asset", exact: true }).click();
  const form = page.locator(".asset-modal");
  await form.getByLabel("Name", { exact: true }).fill("Linux key lifecycle");
  await form.getByLabel("Host address", { exact: true }).fill("keyhost.synthetic.invalid");
  await form.getByLabel("SSH username", { exact: true }).fill(host.username);
  await form.getByLabel("SSH password", { exact: true }).fill("synthetic-keyhost-password-233");
  await form.getByLabel("Host-key fingerprint (SHA256)").fill(host.fingerprint);
  await form.getByLabel("SSH gateway").selectOption(gateway.id);
  await form.getByRole("button", { name: "Save", exact: true }).click();
  await expect(form).toHaveCount(0);
  const loadAsset = async () => {
    const response = await page.request.get("/api/v1/assets");
    expect(await response.text()).not.toContain("PRIVATE KEY");
    const assets = (await response.json()) as {
      id: string;
      name: string;
      credential_type: string;
      credential_revision: number;
      key_fingerprint?: string;
      key_rotation_enabled?: boolean;
      ssh_key_rotation?: { pending: boolean; state: string };
    }[];
    const asset = assets.find((item) => item.name === "Linux key lifecycle");
    if (!asset) throw new Error("Linux lifecycle asset missing");
    return asset;
  };
  const initial = await loadAsset();
  expect(initial.credential_revision).toBe(1);
  let row = page.getByRole("row").filter({ hasText: "Linux key lifecycle" });
  await row.locator("summary").click();
  page.once("dialog", (dialog) => {
    void dialog.accept();
  });
  const installing = page.waitForResponse(
    (r) =>
      r.url().endsWith(`/assets/${initial.id}/ssh-key-rotation`) && r.request().method() === "POST",
  );
  await row.getByRole("button", { name: "Install SSH key", exact: true }).click();
  expect((await installing).status()).toBe(200);
  await expect(row).toContainText("SSH private key");
  const installed = await loadAsset();
  expect(installed).toMatchObject({ credential_type: "ssh_key", credential_revision: 2 });
  expect(installed.key_fingerprint).toMatch(/^SHA256:/);
  await row.locator("summary").click();
  page.once("dialog", (dialog) => {
    void dialog.accept();
  });
  const rotating = page.waitForResponse(
    (r) =>
      r.url().endsWith(`/assets/${initial.id}/ssh-key-rotation`) && r.request().method() === "POST",
  );
  await row.getByRole("button", { name: "Rotate SSH key", exact: true }).click();
  expect((await rotating).status()).toBe(200);
  await expect.poll(async () => (await loadAsset()).credential_revision).toBe(3);
  const rotated = await loadAsset();
  expect(rotated.key_fingerprint).not.toBe(installed.key_fingerprint);
  expect(rotated.ssh_key_rotation?.pending).toBe(false);
  const execute = promisify(execFile);
  const labels = await execute("docker", [
    "inspect",
    "--format",
    "{{json .Config.Labels}}",
    host.container_name,
  ]);
  expect(JSON.parse(labels.stdout)["com.jumpserver233.qa.owner"]).toBe(host.owner);
  const keys = await execute("docker", [
    "exec",
    host.container_name,
    "ssh-keygen",
    "-l",
    "-E",
    "sha256",
    "-f",
    "/home/keyqa/.ssh/authorized_keys",
  ]);
  expect(keys.stdout).toContain(rotated.key_fingerprint);
  expect(keys.stdout).not.toContain(installed.key_fingerprint);
  const probe = await page.request.post(`/api/v1/assets/${initial.id}/probe`);
  const probed = (await probe.json()) as {
    monitor: { state: string; metrics: { cpu_cores: number } };
  };
  expect(probed.monitor.state).toBe("online");
  expect(probed.monitor.metrics.cpu_cores).toBeGreaterThan(0);
  await page.reload();
  row = page.getByRole("row").filter({ hasText: "Linux key lifecycle" });
  await row.getByRole("button", { name: "Edit", exact: true }).click();
  await expect(form.getByLabel("Private key (PEM / OpenSSH)", { exact: true })).toHaveValue("");
  await form
    .getByRole("checkbox", { name: /Generate and rotate an Ed25519 SSH key every 7 days/ })
    .check();
  await form.getByRole("button", { name: "Save", exact: true }).click();
  await expect(form).toHaveCount(0);
  await expect(row).toContainText("Key rotation scheduled");
  expect((await loadAsset()).key_rotation_enabled).toBe(true);
  const login = (await (
    await page.request.post("/api/v1/authentication/auth/", { data: syntheticAdmin })
  ).json()) as { access_token: string };
  const result = await execute(
    "go",
    ["run", "./cmd/jms", "exec", initial.id, "--json", "--", "printf", "real-key-lifecycle-ok"],
    {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      env: {
        ...process.env,
        JMS_SERVER_URL: "http://127.0.0.1:8083",
        JMS_TOKEN: login.access_token,
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
      },
      timeout: 30_000,
    },
  );
  expect(JSON.parse(result.stdout)).toMatchObject({
    state: "succeeded",
    stdout: "real-key-lifecycle-ok",
  });
  await row.getByRole("button", { name: "Connect", exact: true }).click();
  const terminal = page.getByRole("dialog", { name: "Linux key lifecycle", exact: true });
  await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
  await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
  const account = { username: "key.lifecycle.viewer", password: "synthetic-key-viewer-password" };
  const createdUser = await page.request.post("/api/v1/users", {
    data: { ...account, role: "operator" },
  });
  await expectAPIStatus(createdUser, 201, "key lifecycle viewer");
  const user = (await createdUser.json()) as { id: string };
  const granted = await page.request.post("/api/v1/grants", {
    data: { user_id: user.id, asset_id: initial.id, account: host.username, actions: ["view"] },
  });
  await expectAPIStatus(granted, 201, "key lifecycle view grant");
  const context = await browser.newContext({ locale: "en-US" });
  try {
    const viewer = await context.newPage();
    await signIn(viewer, account);
    const visible = (await (await viewer.request.get("/api/v1/assets")).json()) as Record<
      string,
      unknown
    >[];
    expect(visible).toHaveLength(1);
    expect(visible[0]).not.toHaveProperty("ssh_key_rotation");
    expect(
      (
        await viewer.request.post(`/api/v1/assets/${initial.id}/ssh-key-rotation`, {
          data: { request_id: "forbidden-viewer-request", expected_revision: 3 },
        })
      ).status(),
    ).toBe(403);
    await expect(viewer.getByRole("button", { name: "Rotate SSH key", exact: true })).toHaveCount(
      0,
    );
  } finally {
    await context.close();
  }
  await page.getByRole("button", { name: "中文", exact: true }).click();
  await expect(row).toContainText("密钥轮换计划中");
});

test("manages bilingual access policies and enforces them across sign-in, SSH, CLI and file actions", async ({
  page,
  browser,
}, testInfo) => {
  test.setTimeout(120_000);
  await signIn(page);
  const account = { username: "acl.integration", password: "synthetic-acl-operator-password" };
  const created = await page.request.post("/api/v1/users", {
    data: { ...account, role: "operator" },
  });
  await expectAPIStatus(created, 201, "ACL operator");
  const user = (await created.json()) as { id: string };
  await expectAPIStatus(
    await page.request.post("/api/v1/grants", {
      data: {
        user_id: user.id,
        asset_id: monitorAssetID,
        account: "qa-monitor",
        actions: ["view", "connect", "sftp"],
      },
    }),
    201,
    "ACL target grant",
  );
  await page.goto("/console/access-policies");
  await expect(page.getByRole("heading", { name: "Access policies", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Connection channels", exact: true }).click();
  await page.getByRole("button", { name: "Create policy", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "Access policy editor", exact: true });
  await editor.getByLabel("Name", { exact: true }).fill("Block interactive and CLI execution");
  await editor.getByRole("combobox", { name: "User scope", exact: true }).selectOption("user");
  await editor
    .getByRole("combobox", { name: "Selected user or group", exact: true })
    .selectOption(user.id);
  await editor.getByRole("checkbox", { name: "Command execution", exact: true }).check();
  await editor.getByRole("button", { name: "Save policy", exact: true }).click();
  await expect(editor).toHaveCount(0);
  let ruleRow = page
    .getByRole("table", { name: "Policy rules", exact: true })
    .getByRole("row")
    .filter({ hasText: "Block interactive and CLI execution" });
  await expect(ruleRow).toContainText("acl.integration");
  const context = await browser.newContext({ locale: "en-US" });
  try {
    const operator = await context.newPage();
    await signIn(operator, account);
    const login = await operator.request.post("/api/v1/authentication/auth/", { data: account });
    expect(login.status()).toBe(200);
    const token = ((await login.json()) as { access_token: string }).access_token;
    expect(
      (
        await operator.request.post("/api/v1/sessions", {
          data: { asset_id: monitorAssetID, cols: 80, rows: 24 },
          headers: { "X-Forwarded-For": "198.51.100.5" },
        })
      ).status(),
    ).toBe(403);
    expect(
      (
        await operator.request.post("/api/v1/ops/jobs", {
          data: { asset_id: monitorAssetID, command: "printf browser-job-ok" },
        })
      ).status(),
    ).toBe(403);
    const execute = promisify(execFile);
    const cliEnvironment = {
      ...process.env,
      JMS_SERVER_URL: "http://127.0.0.1:8083",
      JMS_TOKEN: token,
      JMS_ACCESS_KEY_ID: "",
      JMS_ACCESS_KEY_SECRET: "",
    };
    await expect(
      execute(
        "go",
        ["run", "./cmd/jms", "exec", monitorAssetID, "--json", "--", "printf", "browser-job-ok"],
        {
          cwd: fileURLToPath(new URL("../../server", import.meta.url)),
          env: cliEnvironment,
          timeout: 30_000,
        },
      ),
    ).rejects.toMatchObject({ code: 1, stderr: expect.stringContaining("SSH job API:") });
    const filePolicy = await page.request.post("/api/v1/access-policies", {
      data: {
        name: "Block file mutations",
        kind: "method",
        user_id: user.id,
        methods: ["upload", "download", "delete", "mkdir"],
        action: "deny",
        enabled: true,
        priority: 50,
        timezone: "UTC",
      },
    });
    await expectAPIStatus(filePolicy, 201, "file action policy");
    expect(
      (await operator.request.post(`/api/v1/assets/${monitorAssetID}/files/session`)).status(),
    ).toBe(200);
    for (const method of ["PUT", "GET", "DELETE"]) {
      expect(
        (
          await operator.request.fetch(
            `/api/v1/assets/${monitorAssetID}/files/content?path=blocked`,
            { method },
          )
        ).status(),
      ).toBe(403);
    }
    expect(
      (
        await operator.request.post(`/api/v1/assets/${monitorAssetID}/directories`, {
          data: { path: "blocked" },
        })
      ).status(),
    ).toBe(403);
    await ruleRow.getByRole("button", { name: "Disable", exact: true }).click();
    await expect(ruleRow).toContainText("No");
    const result = await execute(
      "go",
      ["run", "./cmd/jms", "exec", monitorAssetID, "--json", "--", "printf", "browser-job-ok"],
      {
        cwd: fileURLToPath(new URL("../../server", import.meta.url)),
        env: cliEnvironment,
        timeout: 30_000,
      },
    );
    expect(JSON.parse(result.stdout).state).toBe("succeeded");
    await operator
      .getByRole("row")
      .filter({ hasText: "Browser QA" })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    const terminal = operator.getByRole("dialog", { name: "Browser QA", exact: true });
    await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    await page.getByRole("button", { name: "User sign-in", exact: true }).click();
    await page.getByRole("button", { name: "Create policy", exact: true }).click();
    await editor.getByLabel("Name", { exact: true }).fill("Block local source sign-in");
    await editor.getByRole("combobox", { name: "User scope", exact: true }).selectOption("user");
    await editor
      .getByRole("combobox", { name: "Selected user or group", exact: true })
      .selectOption(user.id);
    await editor.getByLabel("Source addresses", { exact: true }).fill("127.0.0.0/8");
    await editor.getByRole("button", { name: "Save policy", exact: true }).click();
    await expect(editor).toHaveCount(0);
    expect((await operator.request.get("/api/v1/assets")).status()).toBe(403);
    await operator.goto("/login");
    await operator.getByLabel("Username", { exact: true }).fill(account.username);
    await operator.getByLabel("Password", { exact: true }).fill(account.password);
    await operator.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(operator.getByRole("alert")).toHaveText(
      "Sign-in is blocked by an access policy. Contact your administrator.",
    );
    const loginRow = page
      .getByRole("table", { name: "Policy rules", exact: true })
      .getByRole("row")
      .filter({ hasText: "Block local source sign-in" });
    await loginRow.getByRole("button", { name: "Edit", exact: true }).click();
    await editor.getByLabel("Priority", { exact: true }).fill("40");
    await editor.getByRole("button", { name: "Save policy", exact: true }).click();
    await expect(editor).toHaveCount(0);
    await expect(loginRow).toContainText("40");
    await page.screenshot({ path: testInfo.outputPath("access-policies-en.png"), fullPage: true });
    await loginRow.getByRole("button", { name: "Disable", exact: true }).click();
    await expect(loginRow).toContainText("No");
    await operator.getByLabel("Password", { exact: true }).fill(account.password);
    await operator.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(operator).toHaveURL(/\/console$/);
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "访问策略", exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("access-policies-zh.png"), fullPage: true });
    await page
      .getByRole("table", { name: "策略规则", exact: true })
      .getByRole("row")
      .filter({ hasText: "Block local source sign-in" })
      .getByRole("button", { name: "删除", exact: true })
      .click();
    const confirmation = page.getByRole("dialog", { name: "删除策略", exact: true });
    await confirmation.getByRole("button", { name: "删除策略", exact: true }).click();
    await expect(confirmation).toHaveCount(0);
    const list = await page.request.get("/api/v1/access-policies");
    const rules = (await list.json()) as { id: string; name: string; revision: number }[];
    expect(rules.some((rule) => rule.name === "Block local source sign-in")).toBe(false);
    for (const rule of rules.filter((rule) =>
      ["Block file mutations", "Block interactive and CLI execution"].includes(rule.name),
    )) {
      expect(
        (
          await page.request.delete(`/api/v1/access-policies/${rule.id}?revision=${rule.revision}`)
        ).status(),
      ).toBe(204);
    }
    expect((await operator.request.get("/api/v1/access-policies")).status()).toBe(403);
  } finally {
    await context.close();
  }
});

test("reviews platform sign-in with reload recovery, one-use completion, cancellation, denial and console notifications", async ({
  page,
  browser,
}, testInfo) => {
  test.setTimeout(120_000);
  await signIn(page);
  const account = {
    username: "review.integration",
    password: "synthetic-platform-review-password",
  };
  const created = await page.request.post("/api/v1/users", {
    data: { ...account, role: "operator" },
  });
  await expectAPIStatus(created, 201, "platform review user");
  const user = (await created.json()) as { id: string };
  await expectAPIStatus(
    await page.request.post("/api/v1/grants", {
      data: {
        user_id: user.id,
        asset_id: monitorAssetID,
        account: "qa-monitor",
        actions: ["view"],
      },
    }),
    201,
    "review user view grant",
  );
  await page.goto("/console/access-policies");
  await page.getByRole("button", { name: "User sign-in", exact: true }).click();
  await page.getByRole("button", { name: "Create policy", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "Access policy editor", exact: true });
  await editor.getByLabel("Name", { exact: true }).fill("Platform approval integration");
  await editor.getByRole("combobox", { name: "User scope", exact: true }).selectOption("user");
  await editor
    .getByRole("combobox", { name: "Selected user or group", exact: true })
    .selectOption(user.id);
  await editor.getByRole("combobox", { name: "Action", exact: true }).selectOption("review");
  await expect(
    editor.getByRole("group", { name: "Approval reviewers", exact: true }),
  ).toBeVisible();
  await editor.getByRole("button", { name: "Save policy", exact: true }).click();
  await expect(editor).toHaveCount(0);
  const context = await browser.newContext({ locale: "en-US", baseURL: "http://127.0.0.1:5177" });
  const applicant = await context.newPage();
  async function submit() {
    await applicant.goto("/login");
    await applicant.getByLabel("Username", { exact: true }).fill(account.username);
    await applicant.getByLabel("Password", { exact: true }).fill(account.password);
    await applicant.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(
      applicant.getByRole("heading", { name: "Waiting for sign-in approval", exact: true }),
    ).toBeVisible();
  }
  const pending = () =>
    page
      .getByRole("table", { name: /^(Platform sign-in requests|平台登录请求)$/, exact: true })
      .getByRole("row")
      .filter({ hasText: account.username });
  try {
    await submit();
    expect((await applicant.request.get("/api/v1/authentication/session/")).status()).toBe(401);
    const cookies = await context.cookies();
    const ticket = cookies.find((c) => c.name === "jms_login_review");
    expect(ticket?.httpOnly).toBe(true);
    expect(cookies.some((c) => c.name === "jms_sessionid")).toBe(false);
    expect(await applicant.locator("body").innerText()).not.toContain(ticket!.value);
    await applicant.reload();
    await expect(
      applicant.getByRole("heading", { name: "Waiting for sign-in approval", exact: true }),
    ).toBeVisible();
    await page.goto("/console/login-reviews");
    await expect(pending()).toHaveCount(1);
    await page.screenshot({ path: testInfo.outputPath("platform-review-en.png"), fullPage: true });
    await pending().getByRole("button", { name: "Approve", exact: true }).click();
    const approval = page.getByRole("dialog", { name: "Approve platform sign-in", exact: true });
    await approval.getByRole("button", { name: "Approve", exact: true }).click();
    await expect(applicant).toHaveURL(/\/console$/);
    expect((await applicant.request.get("/api/v1/users/me")).status()).toBe(200);
    expect((await applicant.request.get("/api/v1/login-reviews")).status()).toBe(403);
    expect(
      (
        await applicant.request.post("/api/v1/authentication/login-review/complete", {
          data: { review_token: ticket!.value },
        })
      ).status(),
    ).toBe(409);
    const apiApplicant = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
    try {
      const initiated = await apiApplicant.post("/api/v1/authentication/auth/", { data: account });
      await expectAPIStatus(initiated, 202, "non-browser platform review");
      const apiPending = (await initiated.json()) as {
        review_id: string;
        review_token: string;
        expires_at: string;
      };
      await page.getByRole("button", { name: "Refresh", exact: true }).click();
      await pending()
        .filter({ hasText: apiPending.review_id })
        .getByRole("button", { name: "Approve", exact: true })
        .click();
      await approval.getByRole("button", { name: "Approve", exact: true }).click();
      await expect(approval).toHaveCount(0);
      const approved = (await (
        await apiApplicant.post("/api/v1/authentication/login-review/status", {
          data: { review_token: apiPending.review_token },
        })
      ).json()) as { state: string; expires_at: string };
      expect(approved.state).toBe("approved");
      expect(Date.parse(approved.expires_at) - Date.now()).toBeLessThanOrEqual(60_000);
      expect(Date.parse(apiPending.expires_at) - Date.parse(approved.expires_at)).toBeGreaterThan(
        180_000,
      );
      await page.getByRole("button", { name: "History", exact: true }).click();
      const approvedRow = page
        .getByRole("table", { name: "Platform sign-in requests", exact: true })
        .getByRole("row")
        .filter({ hasText: apiPending.review_id });
      await expect(approvedRow).toContainText(new Date(approved.expires_at).toLocaleString("en"));
      const completed = await apiApplicant.post("/api/v1/authentication/login-review/complete", {
        data: { review_token: apiPending.review_token },
        headers: { "X-JMS-Browser-Session": "cookie" },
      });
      await expectAPIStatus(completed, 200, "non-browser review completion");
      const apiSession = (await completed.json()) as {
        access_token?: string;
        browser_session?: boolean;
      };
      expect(apiSession.access_token).toBeTruthy();
      expect(apiSession.browser_session).toBeUndefined();
      await page.getByRole("button", { name: "Pending", exact: true }).click();
    } finally {
      await apiApplicant.dispose();
    }
    await applicant.request.post("/api/v1/authentication/expire-session/");
    await submit();
    await applicant.getByRole("button", { name: "Cancel request", exact: true }).click();
    await expect(applicant.getByLabel("Username", { exact: true })).toBeVisible();
    await submit();
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(pending()).toHaveCount(1);
    await pending().getByRole("button", { name: "Deny", exact: true }).click();
    const denial = page.getByRole("dialog", { name: "Deny platform sign-in", exact: true });
    await denial.getByRole("button", { name: "Deny", exact: true }).click();
    await expect(applicant.getByRole("status")).toHaveText("Sign-in denied");
    await applicant.getByRole("button", { name: "Start sign-in again", exact: true }).click();
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "平台登录复核", exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("platform-review-zh.png"), fullPage: true });
    const rules = (await (await page.request.get("/api/v1/access-policies")).json()) as {
      id: string;
      name: string;
      revision: number;
    }[];
    const rule = rules.find((r) => r.name === "Platform approval integration")!;
    await expectAPIStatus(
      await page.request.put(`/api/v1/access-policies/${rule.id}`, {
        data: {
          name: rule.name,
          revision: rule.revision,
          kind: "login",
          user_id: user.id,
          action: "notify",
          enabled: true,
          priority: 50,
          timezone: "UTC",
          approver_ids: [],
          approver_group_ids: [],
        },
      }),
      200,
      "switch to console notification",
    );
    await applicant.getByLabel("Username", { exact: true }).fill(account.username);
    await applicant.getByLabel("Password", { exact: true }).fill(account.password);
    await applicant.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(applicant).toHaveURL(/\/console$/);
    await page.getByRole("button", { name: "登录通知", exact: true }).click();
    await expect(pending()).toHaveCount(1);
    expect(await pending().innerText()).toContain(account.username);
    await expectAPIStatus(
      await page.request.delete(`/api/v1/access-policies/${rule.id}?revision=${rule.revision + 1}`),
      204,
      "remove review test policy",
    );
  } finally {
    await context.close();
  }
});

test("rotates a shared SSH key only after all organization vaults switch and connects through the new key", async ({
  page,
}, testInfo) => {
  test.setTimeout(120_000);
  await signIn(page);
  const execute = promisify(execFile);
  const fixture = (await (await page.request.get("http://127.0.0.1:12242/health")).json()) as {
    address: string;
    fingerprint: string;
    container_name: string;
    owner: string;
  };
  expect(fixture.container_name).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
  const labels = await execute("docker", [
    "inspect",
    "--format",
    "{{json .Config.Labels}}",
    fixture.container_name,
  ]);
  expect(JSON.parse(labels.stdout)["com.jumpserver233.qa.owner"]).toBe(fixture.owner);
  const options = { cwd: fileURLToPath(new URL("../../server", import.meta.url)), timeout: 30_000 };
  const secret = await execute("go", ["run", "./testsupport/sshidentity/cmd"], options);
  const publicKey = await execute(
    "go",
    ["run", "./testsupport/sshidentity/cmd", "--public"],
    options,
  );
  const filename = "/home/sharedkeyqa/.ssh/authorized_keys";
  const original = await execute("docker", ["exec", fixture.container_name, "cat", filename]);
  const write = async (content: string) =>
    execute("docker", [
      "exec",
      fixture.container_name,
      "sh",
      "-c",
      'printf "%s\\n" "$1" > /home/sharedkeyqa/.ssh/authorized_keys; chown sharedkeyqa:sharedkeyqa /home/sharedkeyqa/.ssh/authorized_keys; chmod 0600 /home/sharedkeyqa/.ssh/authorized_keys',
      "fixture",
      content,
    ]);
  await write(
    "# shared key browser fixture\nno-agent-forwarding " +
      publicKey.stdout.trim() +
      " old-browser-key\n",
  );
  try {
    const [host, port] = fixture.address.split(":");
    const input = {
      name: "Shared key source",
      host,
      port: Number(port),
      username: "sharedkeyqa",
      host_key_fingerprint: fixture.fingerprint,
      credential_type: "ssh_key",
      private_key: secret.stdout,
      private_key_passphrase: "synthetic-import-key-passphrase",
    };
    const orgResponse = await page.request.post("/api/v1/organizations", {
      data: { name: "Shared key browser QA", enabled: true },
    });
    await expectAPIStatus(orgResponse, 201, "shared key organization");
    const org = (await orgResponse.json()) as { id: string };
    const headers = { "X-JMS-ORG": org.id };
    const create = async (name: string, scope: Record<string, string> = {}) => {
      const response = await page.request.post("/api/v1/assets", {
        headers: scope,
        data: { ...input, name },
      });
      await expectAPIStatus(response, 201, "shared SSH key asset");
      return (await response.json()) as { id: string; key_fingerprint: string };
    };
    const first = await create(input.name);
    const replica = await create("Shared key replica");
    const peer = await create("Other organization shared key", headers);
    await page.goto("/console");
    const row = page.getByRole("row").filter({ hasText: input.name });
    await expect(row).toContainText("Coordinated key rotation");
    await row.locator("summary.asset-more-trigger").click();
    let confirmation = "";
    page.once("dialog", async (dialog) => {
      confirmation = dialog.message();
      await dialog.accept();
    });
    const rotation = page.waitForResponse(
      (r) =>
        r.url().endsWith(`/api/v1/assets/${first.id}/ssh-key-rotation`) &&
        r.request().method() === "POST",
    );
    await row.getByRole("button", { name: "Rotate SSH key", exact: true }).click();
    expect((await rotation).status()).toBe(200);
    expect(confirmation).toContain("every vault");
    let next = "";
    for (const [id, scope] of [
      [first.id, {}],
      [replica.id, {}],
      [peer.id, headers],
    ] as const) {
      const inventory = (await (
        await page.request.get("/api/v1/assets", { headers: scope })
      ).json()) as {
        id: string;
        key_fingerprint: string;
        credential_revision: number;
        ssh_key_rotation: { shared: boolean; pending: boolean };
      }[];
      const item = inventory.find((a) => a.id === id)!;
      expect(item.credential_revision).toBe(2);
      expect(item.ssh_key_rotation.shared).toBe(true);
      expect(item.ssh_key_rotation.pending).toBe(false);
      expect(item.key_fingerprint).not.toBe(first.key_fingerprint);
      if (next) expect(item.key_fingerprint).toBe(next);
      next = item.key_fingerprint;
      const probe = await page.request.post(`/api/v1/assets/${id}/probe`, { headers: scope });
      await expectAPIStatus(probe, 200, "new shared SSH key probe");
      expect((await probe.json()).monitor.state).toBe("online");
    }
    const authorized = await execute("docker", ["exec", fixture.container_name, "cat", filename]);
    expect(authorized.stdout).not.toContain(publicKey.stdout.trim());
    expect(authorized.stdout).toContain("no-agent-forwarding ");
    expect(authorized.stdout).toContain("# shared key browser fixture");
    await page
      .getByRole("combobox", { name: "Current organization", exact: true })
      .selectOption(org.id);
    const peerRow = page.getByRole("row").filter({ hasText: "Other organization shared key" });
    await expect(peerRow).toContainText("Coordinated key rotation");
    await peerRow.getByRole("button", { name: "Connect", exact: true }).click();
    const terminal = page.getByRole("dialog", {
      name: "Other organization shared key",
      exact: true,
    });
    await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    const login = await page.request.post("/api/v1/authentication/auth/", { data: syntheticAdmin });
    await expectAPIStatus(login, 200, "shared key CLI login");
    const token = (await login.json()) as { access_token: string };
    const command = await execute(
      "go",
      ["run", "./cmd/jms", "exec", peer.id, "--json", "--", "printf", "shared-key-cli"],
      {
        ...options,
        env: {
          ...process.env,
          JMS_SERVER_URL: "http://127.0.0.1:8083",
          JMS_TOKEN: token.access_token,
          JMS_ORG_ID: org.id,
          JMS_ACCESS_KEY_ID: "",
          JMS_ACCESS_KEY_SECRET: "",
        },
      },
    );
    expect(JSON.parse(command.stdout).state).toBe("succeeded");
    expect(JSON.parse(command.stdout).stdout).toBe("shared-key-cli");
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(peerRow).toContainText("密钥协同轮换");
    await page.screenshot({ path: testInfo.outputPath("shared-key-zh.png"), fullPage: true });
  } finally {
    await write(original.stdout);
  }
});

test("coordinates shared SSH password rotation across organizations without exposing credentials", async ({
  page,
}, testInfo) => {
  test.setTimeout(90_000);
  await signIn(page);
  const fixture = (await (await page.request.get("http://127.0.0.1:12242/health")).json()) as {
    address: string;
    fingerprint: string;
  };
  const [host, port] = fixture.address.split(":");
  const input = {
    name: "Coordinated password QA",
    host,
    port: Number(port),
    username: "rotationqa",
    password: "synthetic-keyhost-password-233",
    host_key_fingerprint: fixture.fingerprint,
  };
  const organizationResponse = await page.request.post("/api/v1/organizations", {
    data: { name: "Shared account QA", enabled: true },
  });
  await expectAPIStatus(organizationResponse, 201, "shared password organization");
  const organization = (await organizationResponse.json()) as { id: string };
  const headers = { "X-JMS-ORG": organization.id };
  const firstResponse = await page.request.post("/api/v1/assets", { data: input });
  await expectAPIStatus(firstResponse, 201, "first shared account");
  const first = (await firstResponse.json()) as { id: string };
  const secondResponse = await page.request.post("/api/v1/assets", {
    headers,
    data: { ...input, name: "Other organization password QA" },
  });
  await expectAPIStatus(secondResponse, 201, "second shared account");
  const second = (await secondResponse.json()) as { id: string };
  const backupResponse = await page.request.post(`/api/v1/assets/${first.id}/credential-backups`);
  await expectAPIStatus(backupResponse, 201, "shared account restore point");
  const backup = (await backupResponse.json()) as { backup_id: string };
  try {
    await page.goto("/console");
    const row = page.getByRole("row").filter({ hasText: input.name });
    await expect(row).toContainText("Coordinated account rotation");
    await row.locator("summary.asset-more-trigger").click();
    let confirmation = "";
    page.once("dialog", async (dialog) => {
      confirmation = dialog.message();
      await dialog.accept();
    });
    const rotated = page.waitForResponse(
      (r) =>
        r.url().endsWith(`/api/v1/assets/${first.id}/password-rotation`) &&
        r.request().method() === "POST",
    );
    await row.getByRole("button", { name: "Rotate password", exact: true }).click();
    expect((await rotated).status()).toBe(200);
    expect(confirmation).toContain("all managed copies");
    for (const [id, scope] of [
      [first.id, {}],
      [second.id, headers],
    ] as const) {
      const response = await page.request.post(`/api/v1/assets/${id}/probe`, { headers: scope });
      await expectAPIStatus(response, 200, "shared password probe");
      const item = (await response.json()) as {
        credential_revision: number;
        monitor: { state: string };
      };
      expect(item.credential_revision).toBe(2);
      expect(item.monitor.state).toBe("online");
      const inventory = (await (
        await page.request.get("/api/v1/assets", { headers: scope })
      ).json()) as { id: string; password_rotation?: { shared: boolean } }[];
      expect(inventory.find((asset) => asset.id === id)?.password_rotation?.shared).toBe(true);
      expect(await response.text()).not.toContain("synthetic-keyhost-password-233");
    }
    const conflict = await page.request.post("/api/v1/assets", {
      headers,
      data: { ...input, name: "Conflicting copy", password: "wrong-account-password" },
    });
    await expectAPIStatus(conflict, 409, "conflicting managed account");
    expect(await conflict.json()).toEqual({ detail: "shared_credential_conflict" });
    await row.getByRole("button", { name: "Edit", exact: true }).click();
    const conflictEditor = page.locator("form.asset-modal");
    await expect(
      conflictEditor.getByRole("heading", { name: "Edit asset", exact: true }),
    ).toBeVisible();
    await conflictEditor
      .getByLabel("SSH password", { exact: false })
      .fill("wrong-account-password");
    await conflictEditor.getByRole("button", { name: "Save", exact: true }).click();
    await expect(conflictEditor.getByRole("alert")).toContainText("No remote password was changed");
    await conflictEditor.getByRole("button", { name: "Cancel", exact: true }).click();
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(row).toContainText("账号协同改密");
    await page.screenshot({ path: testInfo.outputPath("shared-password-zh.png"), fullPage: true });
    await page
      .getByRole("combobox", { name: "当前组织", exact: true })
      .selectOption(organization.id);
    const otherRow = page.getByRole("row").filter({ hasText: "Other organization password QA" });
    await expect(otherRow).toContainText("账号协同改密");
    await expect(page.getByRole("row").filter({ hasText: input.name })).toHaveCount(0);
  } finally {
    await expectAPIStatus(
      await page.request.post(
        `/api/v1/assets/${first.id}/credential-backups/${backup.backup_id}/restore`,
        { headers: { "X-JMS-ORG": "00000000-0000-0000-0000-000000000002" } },
      ),
      200,
      "restore synthetic shared account",
    );
  }
});

test("isolates organization inventory, roles, monitoring, Web SSH and CLI, then revokes and archives safely", async ({
  page,
  browser,
}, testInfo) => {
  test.setTimeout(150_000);
  await signIn(page);
  const account = {
    username: "organization.integration",
    password: "synthetic-organization-browser-password",
  };
  const createdUser = await page.request.post("/api/v1/users", {
    data: { ...account, role: "operator" },
  });
  await expectAPIStatus(createdUser, 201, "organization member account");
  const user = (await createdUser.json()) as { id: string };
  await page.goto("/console/organizations");
  await expect(page.getByRole("heading", { name: "Organizations", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Create organization", exact: true }).click();
  const editor = page.getByRole("dialog", { name: "Organization editor", exact: true });
  await editor.getByLabel("Name", { exact: true }).fill("Enterprise QA organization");
  await editor
    .getByLabel("Description", { exact: true })
    .fill("Isolated synthetic host operations");
  const creation = page.waitForResponse(
    (r) => r.url().endsWith("/api/v1/organizations") && r.request().method() === "POST",
  );
  await editor.getByRole("button", { name: "Save organization", exact: true }).click();
  const creationResponse = await creation;
  expect(creationResponse.status()).toBe(201);
  await expect(editor).toHaveCount(0);
  const organizationData = (await (await page.request.get("/api/v1/organizations")).json()) as {
    results: { id: string; name: string }[];
  };
  const organization = organizationData.results.find(
    (item) => item.name === "Enterprise QA organization",
  )!;
  expect(organization).toBeTruthy();
  const orgRow = () =>
    page
      .getByRole("table", { name: /^(Organizations list|组织列表)$/, exact: true })
      .getByRole("row")
      .filter({ hasText: "Enterprise QA organization" });
  await orgRow().getByRole("button", { name: "Manage members", exact: true }).click();
  await page.getByLabel("Username", { exact: true }).fill(account.username);
  await page.getByRole("button", { name: "Add existing user", exact: true }).click();
  await expect(
    page.getByRole("table", { name: "Organization members", exact: true }),
  ).toContainText(account.username);
  await page
    .getByRole("combobox", { name: "Current organization", exact: true })
    .selectOption(organization.id);
  await expect(page).toHaveURL(/\/console$/);
  await expect(page.getByText("No assets yet", { exact: true })).toBeVisible();
  const health = (await (await page.request.get("http://127.0.0.1:12223/health")).json()) as {
    fingerprint: string;
    address: string;
  };
  const [host, port] = health.address.split(":");
  const headers = { "X-JMS-ORG": organization.id };
  const assetResponse = await page.request.post("/api/v1/assets", {
    headers,
    data: {
      name: "Organization QA host",
      host,
      port: Number(port),
      username: "qa-monitor",
      password: "synthetic-qa-only-password",
      host_key_fingerprint: health.fingerprint,
    },
  });
  await expectAPIStatus(assetResponse, 201, "scoped synthetic asset");
  const asset = (await assetResponse.json()) as { id: string };
  await expectAPIStatus(
    await page.request.post("/api/v1/grants", {
      headers,
      data: {
        user_id: user.id,
        asset_id: asset.id,
        account: "qa-monitor",
        actions: ["view", "connect", "sftp"],
      },
    }),
    201,
    "scoped host grant",
  );
  await expectAPIStatus(
    await page.request.post(`/api/v1/assets/${asset.id}/probe`, { headers }),
    200,
    "scoped monitoring probe",
  );
  await page.reload();
  const hostRow = page.getByRole("row").filter({ hasText: "Organization QA host" });
  await expect(hostRow).toContainText("CPU (4 cores)");
  await expect(page.getByRole("row").filter({ hasText: "Browser QA" })).toHaveCount(0);
  await page.goto("/console/organization-roles");
  await expect(
    page.getByRole("heading", { name: "Organization roles", exact: true }),
  ).toBeVisible();
  const catalog = (await (
    await page.request.get("/api/v1/organization-rbac/permissions", { headers })
  ).json()) as string[];
  expect(catalog).not.toContain("security.manage");
  expect(catalog).not.toContain("users.manage");
  expect(catalog).not.toContain("organizations.manage");
  await page.getByLabel("Role name", { exact: true }).fill("Scoped QA reviewer");
  const auditPermission = page
    .getByRole("group", { name: "Current organization permissions", exact: true })
    .getByRole("checkbox", { name: /View every session audit/ });
  await auditPermission.check();
  await page.getByRole("button", { name: "Save role", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "Edit role", exact: true })).toContainText(
    "Scoped QA reviewer",
  );
  expect(await (await page.request.get("/api/v1/rbac/roles")).text()).not.toContain(
    "Scoped QA reviewer",
  );
  const context = await browser.newContext({ locale: "en-US", baseURL: "http://127.0.0.1:5177" });
  const operator = await context.newPage();
  try {
    await signIn(operator, account);
    await operator
      .getByRole("combobox", { name: "Current organization", exact: true })
      .selectOption(organization.id);
    const row = operator.getByRole("row").filter({ hasText: "Organization QA host" });
    await expect(row).toContainText("CPU (4 cores)");
    expect((await operator.request.get("/api/v1/assets")).status()).toBe(200);
    const defaultAssets = (await (await operator.request.get("/api/v1/assets")).json()) as {
      id: string;
    }[];
    expect(defaultAssets.some((item) => item.id === asset.id)).toBe(false);
    await row.getByRole("button", { name: "Connect", exact: true }).click();
    const terminal = operator.getByRole("dialog", { name: "Organization QA host", exact: true });
    await expect(terminal.locator(".ssh-terminal-status")).toHaveText("Connected");
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    const login = await operator.request.post("/api/v1/authentication/auth/", { data: account });
    await expectAPIStatus(login, 200, "organization CLI login");
    const session = (await login.json()) as { access_token: string };
    const execute = promisify(execFile);
    const result = await execute(
      "go",
      ["run", "./cmd/jms", "exec", asset.id, "--json", "--", "printf", "browser-job-ok"],
      {
        cwd: fileURLToPath(new URL("../../server", import.meta.url)),
        env: {
          ...process.env,
          JMS_SERVER_URL: "http://127.0.0.1:8083",
          JMS_TOKEN: session.access_token,
          JMS_ORG_ID: organization.id,
          JMS_ACCESS_KEY_ID: "",
          JMS_ACCESS_KEY_SECRET: "",
        },
        timeout: 30_000,
      },
    ).catch(async (error: unknown) => {
      const failure = error as {
        code?: string | number;
        signal?: string;
        killed?: boolean;
        stdout?: string;
      };
      let job: Record<string, unknown> = {};
      try {
        const raw = JSON.parse(failure.stdout || "{}");
        job = {
          state: raw.state,
          error_code: raw.error_code,
          exit_code: raw.exit_code,
          command: raw.command,
        };
      } catch {
        /* Capture only structured synthetic-job diagnostics. */
      }
      const diagnostic = {
        code: failure.code,
        signal: failure.signal,
        killed: failure.killed,
        job,
      };
      await testInfo.attach("organization-cli-failure", {
        body: JSON.stringify(diagnostic),
        contentType: "application/json",
      });
      throw new Error(`Organization CLI failed: ${JSON.stringify(diagnostic)}`);
    });
    expect(JSON.parse(result.stdout).state).toBe("succeeded");
    await page.goto("/console/organizations");
    await orgRow().getByRole("button", { name: "Manage members", exact: true }).click();
    await page
      .getByRole("combobox", {
        name: `Change organization role for ${account.username}`,
        exact: true,
      })
      .selectOption("none");
    await expect(
      page.getByRole("table", { name: "Organization members", exact: true }),
    ).toContainText("Removed");
    expect((await operator.request.get("/api/v1/assets", { headers })).status()).toBe(403);
    await page.screenshot({ path: testInfo.outputPath("organizations-en.png"), fullPage: true });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "组织管理", exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("organizations-zh.png"), fullPage: true });
    await orgRow().getByRole("button", { name: "归档组织", exact: true }).click();
    const archive = page.getByRole("dialog", { name: "归档组织", exact: true });
    await archive.getByRole("button", { name: "归档组织", exact: true }).click();
    await expect(archive).toHaveCount(0);
    await expect(orgRow()).toHaveCount(0);
    expect((await page.request.get("/api/v1/assets", { headers })).status()).toBe(404);
    await page.getByRole("checkbox", { name: "显示归档组织", exact: true }).check();
    await orgRow().getByRole("button", { name: "恢复组织", exact: true }).click();
    const restore = page.getByRole("dialog", { name: "恢复组织", exact: true });
    await restore.getByRole("button", { name: "恢复组织", exact: true }).click();
    await expect(restore).toHaveCount(0);
    await expect(orgRow()).toContainText("停用");
    expect((await page.request.get("/api/v1/assets", { headers })).status()).toBe(404);
  } finally {
    await context.close();
  }
});

test("renders native SFTP rename audit in English and Chinese and cleans owned remote files", async ({ page }) => {
  await signIn(page);
  const source = `native-audit-${Date.now()}.txt`;
  const destination = source + ".renamed";
  const fixture = await (await page.request.get("http://127.0.0.1:12242/health")).json() as {address:string;fingerprint:string};
  const [host, portText] = fixture.address.split(":");
  const created = await page.request.post("/api/v1/assets", {data:{name:"Native SFTP audit QA", host,port:Number(portText),username:"keyqa",password:"synthetic-keyhost-password-233",host_key_fingerprint:fixture.fingerprint}});
  expect(created.status()).toBe(201);
  const assetID = ((await created.json()) as {id:string}).id;
  const endpoint = `/api/v1/assets/${assetID}/files`;
  try {
    expect((await page.request.put(endpoint + "/content?path=" + source, { data: "native audit proof" })).status()).toBe(201);
    expect((await page.request.post(endpoint + "/rename", { data: { source, destination, overwrite: false } })).status()).toBe(204);
    await page.goto("/audit");
    await page.getByRole("tab", { name: "File transfers", exact: true }).click();
    const row = page.locator(".file-transfer-table tbody tr").filter({ hasText: source + " -> " + destination });
    await expect(row).toHaveCount(1);
    await expect(row).toContainText("Rename");
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(row).toContainText("重命名");
    await expect(page.locator("body")).not.toContainText("audit.fileActions.rename");
  } finally {
    await Promise.allSettled([page.request.delete(endpoint + "/content?path=" + source),page.request.delete(endpoint + "/content?path=" + destination)]);
    await page.request.delete(`/api/v1/assets/${assetID}`);
  }
});
