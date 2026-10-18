import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const base = process.env.JMS_MONITOR_QA_BASE_URL || "http://127.0.0.1:8083";
const ui = process.env.JMS_MONITOR_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Monitoring QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });

test("monitoring rules track real SSH failure and recovery with native acknowledgement and current asset grants", async ({
  browser,
}, info) => {
  test.setTimeout(120_000);
  const api = await request.newContext({ baseURL: base }),
    admin = await browser.newContext({ locale: "en-US", viewport: { width: 1440, height: 1080 } }),
    operator = await browser.newContext({ locale: "en-US" });
  const page = await admin.newPage(),
    op = await operator.newPage(),
    errors: string[] = [];
  for (const p of [page, op]) p.on("pageerror", (e) => errors.push(e.message));
  const stamp = Date.now(),
    name = `Monitored SSH ${stamp}`,
    ruleName = `SSH availability ${stamp}`,
    retain = process.env.JMS_MONITOR_QA_RETAIN === "true";
  let hostName = "",
    owner = "",
    assetID = "",
    ruleID = "",
    userID = "",
    roleID = "",
    grantID = "",
    token = "",
    paused = false;
  const owned = async () => {
    const labels = JSON.parse(
      (await execute("docker", ["inspect", "--format", "{{json .Config.Labels}}", hostName]))
        .stdout,
    );
    expect(labels["com.jumpserver233.qa.owner"]).toBe(owner);
  };
  const probe = async () => {
    const response = await api.post(`/api/v1/assets/${assetID}/probe`);
    expect(response.ok()).toBe(true);
    return (await response.json()).monitor;
  };
  const list = async () =>
    ((await (await api.get("/api/v1/monitoring/alerts?limit=100")).json()).results as any[]).filter(
      (v) => v.rule_id === ruleID,
    );
  try {
    const credentials = {
      username: process.env.JMS_MONITOR_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_MONITOR_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok()).toBe(true);
    token = (await login.json()).access_token;
    await admin.addCookies((await api.storageState()).cookies);
    const host = await (
      await api.get(process.env.JMS_MONITOR_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    hostName = host.container_name;
    owner = host.owner;
    expect(hostName).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
    expect(owner === hostName || /^jumpserver233-e2e-/.test(owner)).toBe(true);
    await owned();
    const created = await api.post("/api/v1/assets", {
      data: {
        name,
        host: process.env.JMS_MONITOR_QA_SSH_HOST || "127.0.0.1",
        port: Number(host.address.split(":").at(-1)),
        username: "keyqa",
        password: "synthetic-keyhost-password-233",
        host_key_fingerprint: host.fingerprint,
      },
    });
    expect(created.status()).toBe(201);
    assetID = (await created.json()).id;
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
    expect((await probe()).state).toBe("online");
    await page.goto(ui + "/console/monitoring");
    await expect(
      page.getByRole("heading", { name: "Monitoring alerts", exact: true }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Rules", exact: true }).click();
    await page.getByRole("button", { name: "Create rule", exact: true }).click();
    const editor = page.getByRole("dialog");
    await editor.getByRole("textbox", { name: "Rule name", exact: true }).fill(ruleName);
    await editor.getByRole("combobox", { name: "Metric", exact: true }).selectOption("offline");
    await editor.getByRole("combobox", { name: "Scope", exact: true }).selectOption("assets");
    await editor.getByRole("checkbox", { name, exact: true }).check();
    await editor.getByRole("spinbutton", { name: "Consecutive trigger samples", exact: true }).fill("1");
    await editor.getByRole("spinbutton", { name: "Consecutive recovery samples", exact: true }).fill("1");
    await editor.getByRole("button", { name: "Save", exact: true }).click();
    await expect(editor).toHaveCount(0);
    const rules = await (await api.get("/api/v1/monitoring/rules")).json();
    ruleID = rules.find((v: any) => v.name === ruleName).id;
    const row = page.getByRole("row").filter({ hasText: ruleName });
    await row.getByRole("button", { name: "Edit", exact: true }).click();
    await editor
      .getByRole("textbox", { name: "Rule name", exact: true })
      .fill(ruleName + " edited");
    await editor.getByRole("button", { name: "Save", exact: true }).click();
    await expect(editor).toHaveCount(0);
    await owned();
    await execute("docker", ["pause", hostName]);
    paused = true;
    expect((await probe()).state).toBe("offline");
    await expect
      .poll(async () => (await list()).filter((v) => v.state === "firing").length, {
        timeout: 15_000,
      })
      .toBe(1);
    const alert = (await list())[0];
    await expect
      .poll(
        async () =>
          (
            (await (await api.get("/api/v1/notifications/inbox?limit=100")).json()).results as any[]
          ).some((v) => v.source.id === alert.id),
        { timeout: 15_000 },
      )
      .toBe(true);
    await page.goto(ui + `/console/monitoring?alert=${alert.id}`);
    const detail = page.getByRole("dialog");
    await expect(detail).toContainText(name);
    await expect(detail).toContainText("Firing");
    await detail
      .getByRole("textbox", { name: "Note", exact: true })
      .fill("Synthetic investigation");
    await detail.getByRole("button", { name: "Acknowledge", exact: true }).click();
    await expect(detail).toContainText("Acknowledged");
    await expect(detail.getByRole("button", { name: "Acknowledge", exact: true })).toHaveCount(0);
    await page.screenshot({ path: info.outputPath("monitoring.en.png") });
    await detail.getByRole("button", { name: "Close", exact: true }).click();
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await page.goto(ui + `/console/monitoring?alert=${alert.id}`);
    await expect(detail).toContainText("已确认");
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    await page.screenshot({ path: info.outputPath("monitoring.zh-CN.png") });
    // A delegated monitoring role still needs a current asset view grant.
    const username = `monitor.operator.${stamp}`,
      password = "synthetic-monitor-operator-233";
    const user = await api.post("/api/v1/users", {
      data: { username, password, role: "operator" },
    });
    expect(user.status()).toBe(201);
    userID = (await user.json()).id;
    const role = await api.post("/api/v1/rbac/roles", {
      data: {
        name: `Monitor viewer ${stamp}`,
        permissions: ["monitoring.view", "monitoring.ack"],
        revision: 0,
      },
    });
    expect(role.status()).toBe(201);
    roleID = (await role.json()).id;
    expect(
      (
        await api.put("/api/v1/rbac/bindings", {
          data: { subject_type: "user", subject_id: userID, role_ids: [roleID], revision: 0 },
        })
      ).status(),
    ).toBe(200);
    expect(
      (
        await operator.request.post(base + "/api/v1/authentication/auth/", {
          data: { username, password },
        })
      ).ok(),
    ).toBe(true);
    expect(
      (await operator.request.get(base + `/api/v1/monitoring/alerts/${alert.id}`)).status(),
    ).toBe(404);
    const grant = await api.post("/api/v1/grants", {
      data: { user_id: userID, asset_id: assetID, account: "keyqa", actions: ["view"] },
    });
    expect(grant.status()).toBe(201);
    grantID = (await grant.json()).id;
    await op.goto(ui + `/console/monitoring?alert=${alert.id}`);
    await expect(op.getByRole("dialog")).toContainText(name);
    expect((await api.delete("/api/v1/grants/" + grantID)).status()).toBe(204);
    grantID = "";
    await expect(op.getByRole("dialog").getByRole("alert")).toContainText("outside your current permissions", {
      timeout: 10_000,
    });
    await expect(op.getByRole("dialog")).not.toContainText(name);
    await owned();
    await execute("docker", ["unpause", hostName]);
    paused = false;
    expect((await probe()).state).toBe("online");
    await expect.poll(async () => (await list())[0]?.state, { timeout: 15_000 }).toBe("resolved");
    const cli = await execute("go", ["run", "./cmd/jms", "monitor", "alert", alert.id], {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      timeout: 60_000,
      env: {
        ...process.env,
        JMS_SERVER_URL: base,
        JMS_TOKEN: token,
        JMS_ORG_ID: "",
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
      },
    });
    expect(JSON.parse(cli.stdout).state).toBe("resolved");
    expect(cli.stdout).not.toContain("synthetic-keyhost-password");
    expect(errors).toEqual([]);
    await info.attach("monitoring-result", {
      body: JSON.stringify({
        assetID,
        ruleID,
        alertID: alert.id,
        state: "resolved",
        pageErrors: errors,
      }),
      contentType: "application/json",
    });
  } finally {
    if (paused) {
      await owned();
      await execute("docker", ["unpause", hostName]);
    }
    if (grantID) await api.delete("/api/v1/grants/" + grantID);
    if (!retain) {
      if (ruleID) {
        const rules = await (await api.get("/api/v1/monitoring/rules")).json();
        const r = rules.find((v: any) => v.id === ruleID);
        if (r) await api.delete(`/api/v1/monitoring/rules/${ruleID}?revision=${r.revision}`);
      }
      if (assetID) await api.delete("/api/v1/assets/" + assetID);
      if (userID) await api.delete("/api/v1/users/" + userID);
      if (roleID) {
        const roles = await (await api.get("/api/v1/rbac/roles")).json();
        const r = roles.find((v: any) => v.id === roleID);
        if (r) await api.delete(`/api/v1/rbac/roles/${roleID}?revision=${r.revision}`);
      }
    }
    await operator.close();
    await admin.close();
    await api.dispose();
  }
});
