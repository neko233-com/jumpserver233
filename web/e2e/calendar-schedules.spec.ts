import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
const execute = promisify(execFile);
const base = process.env.JMS_CALENDAR_QA_BASE_URL || "http://127.0.0.1:8083";
const ui = process.env.JMS_CALENDAR_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Calendar QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });

test("calendar schedules execute real SSH, preserve immutable requests, enforce current rights and expose revisioned bilingual changes", async ({
  browser,
}, info) => {
  test.setTimeout(180_000);
  test
    .info()
    .annotations.push({
      type: "acceptance",
      description: "real SSH minute trigger and schedule lifecycle",
    });
  const api = await request.newContext({ baseURL: base });
  const context = await browser.newContext({
    locale: "en-US",
    viewport: { width: 1440, height: 1080 },
  });
  const page = await context.newPage(),
    errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const stamp = Date.now(),
    name = `Calendar SSH ${stamp}`,
    planName = `Calendar plan ${stamp}`;
  const credentials = {
    username: process.env.JMS_CALENDAR_QA_USERNAME || "e2e.admin",
    password: process.env.JMS_CALENDAR_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
  };
  const account = { username: `calendar.qa.${stamp}`, password: "synthetic-calendar-operator-233" };
  const retain = process.env.JMS_CALENDAR_QA_RETAIN === "true";
  let asset = "",
    user = "",
    grant = "",
    planID = "",
    token = "";
  try {
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok()).toBe(true);
    const host = await (
      await api.get(process.env.JMS_CALENDAR_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    const created = await api.post("/api/v1/assets", {
      data: {
        name,
        host: process.env.JMS_CALENDAR_QA_SSH_HOST || "127.0.0.1",
        port: Number(host.address.split(":").at(-1)),
        username: "keyqa",
        password: "synthetic-keyhost-password-233",
        host_key_fingerprint: host.fingerprint,
      },
    });
    expect(created.status(), await created.text()).toBe(201);
    asset = (await created.json()).id;
    const managed = await (await api.get(`/api/v1/assets/${asset}/accounts/${asset}`)).json();
    expect(
      (
        await api.put(`/api/v1/assets/${asset}/accounts/${asset}`, {
          data: {
            version: managed.version,
            password_rotation_enabled: false,
            key_rotation_enabled: false,
          },
        })
      ).status(),
    ).toBe(200);
    const u = await api.post("/api/v1/users", { data: { ...account, role: "operator" } });
    expect(u.status()).toBe(201);
    user = (await u.json()).id;
    const g = await api.post("/api/v1/grants", {
      data: { user_id: user, asset_id: asset, account: "keyqa", actions: ["view", "connect"] },
    });
    expect(g.status()).toBe(201);
    grant = (await g.json()).id;
    const opLogin = await context.request.post(base + "/api/v1/authentication/auth/", {
      data: account,
    });
    expect(opLogin.ok()).toBe(true);
    token = (await opLogin.json()).access_token;
    await page.goto(ui + "/workbench");
    const panel = page.locator(".operations-panel");
    await panel.locator(":scope > summary").click();
    await panel.getByLabel("Plan name", { exact: true }).fill(planName);
    await panel.getByRole("checkbox", { name: `${name} (keyqa)`, exact: true }).check();
    await panel.getByLabel("Plan command", { exact: true }).fill("printf calendar-real-ssh");
    await panel.getByRole("combobox", { name: "Schedule type", exact: true }).selectOption("cron");
    await panel.getByLabel("Cron expression (5 fields)", { exact: true }).fill("* * * * *");
    await panel.getByLabel("Schedule timezone (IANA)", { exact: true }).fill("Asia/Shanghai");
    await panel.getByRole("button", { name: "Preview next times", exact: true }).click();
    await expect(
      panel.getByRole("heading", { name: "Upcoming occurrences", exact: true }),
    ).toBeVisible();
    await panel.getByRole("button", { name: "Create plan", exact: true }).click();
    await expect(panel.getByRole("status")).toHaveText(
      "Plan created with a saved command snapshot.",
    );
    let plan = (await (await context.request.get(base + "/api/v1/ops/plans")).json()).find(
      (v: any) => v.name === planName,
    );
    expect(plan).toBeTruthy();
    const original = {
      name: planName,
      asset_ids: [asset],
      command: "printf calendar-real-ssh",
      timeout_seconds: 60,
      kind: "cron",
      cron_expression: "* * * * *",
      timezone: "Asia/Shanghai",
      request_id: plan.request_id,
    };
    planID = plan.id;
    expect(plan).toMatchObject({
      kind: "cron",
      timezone: "Asia/Shanghai",
      config_revision: 1,
      fold_policy: "once",
      misfire_policy: "coalesce",
    });
    await expect
      .poll(
        async () =>
          (await (await context.request.get(base + "/api/v1/ops/plans/" + planID)).json())
            .last_run_id,
        { timeout: 75_000, intervals: [500, 1000] },
      )
      .toBeTruthy();
    plan = await (await context.request.get(base + "/api/v1/ops/plans/" + planID)).json();
    await expect
      .poll(
        async () =>
          (await (await context.request.get(base + "/api/v1/ops/runs/" + plan.last_run_id)).json())
            .state,
        { timeout: 20_000 },
      )
      .toBe("succeeded");
    const run = await (
      await context.request.get(base + "/api/v1/ops/runs/" + plan.last_run_id)
    ).json();
    expect(run).toMatchObject({ plan_revision: 1, scheduled_for: plan.last_scheduled_at });
    const job = await (
      await context.request.get(base + "/api/v1/ops/jobs/" + run.items[0].job_id)
    ).json();
    expect(job.stdout).toBe("calendar-real-ssh");
    const row = panel
      .getByRole("table")
      .filter({ has: page.getByRole("columnheader", { name: "Next run", exact: true }) })
      .getByRole("row")
      .filter({ hasText: planName });
    await row.getByRole("button", { name: "Schedule and changes", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: `Plan schedule · ${planName}`, exact: true });
    await expect(dialog.getByText("Configuration revision: 1", { exact: false })).toBeVisible();
    // An independent edit makes the displayed revision stale; the UI must show a conflict.
    expect(
      (
        await context.request.put(base + `/api/v1/ops/plans/${planID}/schedule`, {
          data: { revision: 1, kind: "cron", cron_expression: "0 3 * * *", timezone: "UTC" },
        })
      ).status(),
    ).toBe(200);
    await dialog.getByRole("button", { name: "Save schedule", exact: true }).click();
    await expect(dialog.getByRole("alert")).toHaveText(
      "The plan changed. Reload its current schedule before saving.",
    );
    await dialog.getByRole("button", { name: "Reload current schedule", exact: true }).click();
    await expect(dialog.getByLabel("Cron expression (5 fields)", { exact: true })).toHaveValue(
      "0 3 * * *",
    );
    await dialog.getByRole("button", { name: "Weekdays at 09:00", exact: true }).click();
    await dialog.getByLabel("Schedule timezone (IANA)", { exact: true }).fill("America/New_York");
    await dialog.getByRole("button", { name: "Save schedule", exact: true }).click();
    await expect(dialog).not.toBeVisible();
    plan = await (await context.request.get(base + "/api/v1/ops/plans/" + planID)).json();
    expect(plan.config_revision).toBe(3);
    expect(plan.command).toBe("printf calendar-real-ssh");
    const replay = await context.request.post(base + "/api/v1/ops/plans", { data: original });
    expect(replay.status()).toBe(201);
    expect((await replay.json()).id).toBe(planID);
    await row.getByRole("button", { name: "Pause", exact: true }).click();
    await expect(row.getByRole("button", { name: "Resume", exact: true })).toBeVisible();
    await row.getByRole("button", { name: "Resume", exact: true }).click();
    await expect(row.getByRole("button", { name: "Pause", exact: true })).toBeVisible();
    const events = await (
      await context.request.get(base + `/api/v1/ops/plans/${planID}/events?offset=0&limit=20`)
    ).json();
    expect(events.total).toBe(5);
    expect(events.results[0].action).toBe("resumed");
    expect(events.results[0].actor.id).toBe(user);
    const file = info.outputPath("preview.json");
    await writeFile(
      file,
      JSON.stringify({
        kind: "cron",
        cron_expression: "30 1 * * *",
        timezone: "America/New_York",
        fold_policy: "both",
        after: "2026-11-01T04:00:00Z",
        limit: 2,
      }),
    );
    const env = {
      ...process.env,
      JMS_SERVER_URL: base,
      JMS_TOKEN: token,
      JMS_ORG_ID: "",
      JMS_ACCOUNT: "",
      JMS_ACCESS_KEY_ID: "",
      JMS_ACCESS_KEY_SECRET: "",
    };
    const cli = (args: string[]) =>
      execute("go", ["run", "./cmd/jms", "ops", ...args], {
        cwd: fileURLToPath(new URL("../../server", import.meta.url)),
        timeout: 60_000,
        env,
      });
    const preview = JSON.parse((await cli(["preview", "--file", file])).stdout);
    expect(preview.occurrences.map((v: any) => v.at)).toEqual([
      "2026-11-01T05:30:00Z",
      "2026-11-01T06:30:00Z",
    ]);
    expect(JSON.parse((await cli(["events", planID])).stdout).total).toBe(5);
    await row.getByRole("button", { name: "Schedule and changes", exact: true }).click();
    await expect(dialog.getByRole("table").getByRole("row")).toHaveCount(6);
    await page.screenshot({ path: info.outputPath("calendar.en.png"), fullPage: false });
    await page.keyboard.press("Escape");
    await expect(dialog).not.toBeVisible();
    await expect(
      row.getByRole("button", { name: "Schedule and changes", exact: true }),
    ).toBeFocused();
    const zh = await browser.newContext({ locale: "zh-CN", viewport: { width: 390, height: 844 } });
    await zh.addCookies((await context.storageState()).cookies);
    const mobile = await zh.newPage();
    mobile.on("pageerror", (e) => errors.push(e.message));
    await mobile.goto(ui + "/workbench");
    await expect(mobile.locator("html")).toHaveAttribute("lang", "zh-CN");
    const cn = mobile.locator(".operations-panel");
    await cn.locator(":scope > summary").click();
    await cn.getByRole("button", { name: "计划时间与变更", exact: true }).click();
    await expect(
      mobile.getByRole("heading", { name: `计划调度 · ${planName}`, exact: true }),
    ).toBeVisible();
    expect(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    await mobile.screenshot({ path: info.outputPath("calendar.zh-CN.png"), fullPage: false });
    await zh.close();
    expect((await api.delete("/api/v1/grants/" + grant)).status()).toBe(204);
    grant = "";
    plan = await (await context.request.get(base + "/api/v1/ops/plans/" + planID)).json();
    expect(
      (
        await context.request.put(base + `/api/v1/ops/plans/${planID}/schedule`, {
          data: {
            revision: plan.config_revision,
            kind: "cron",
            cron_expression: "* * * * *",
            timezone: "UTC",
          },
        })
      ).status(),
    ).toBe(403);
    expect(
      (
        await context.request.put(base + "/api/v1/ops/plans/" + planID, {
          data: { enabled: false, revision: plan.config_revision },
        })
      ).status(),
    ).toBe(200);
    expect(
      (
        await context.request.put(base + "/api/v1/ops/plans/" + planID, {
          data: { enabled: true, revision: plan.config_revision + 1 },
        })
      ).status(),
    ).toBe(403);
    expect(errors).toEqual([]);
  } finally {
    if (planID) {
      const p = await api.get("/api/v1/ops/plans/" + planID);
      if (p.ok()) {
        const v = await p.json();
        if (v.enabled)
          await api.put("/api/v1/ops/plans/" + planID, {
            data: { enabled: false, revision: v.config_revision },
          });
      }
    }
    if (!retain) {
      if (grant) await api.delete("/api/v1/grants/" + grant);
      if (asset) await api.delete("/api/v1/assets/" + asset);
      if (user) await api.delete("/api/v1/users/" + user);
    }
    await context.close().catch(() => {});
    await api.dispose();
  }
});
