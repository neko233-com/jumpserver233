import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { writeFile } from "node:fs/promises";

const execute = promisify(execFile);
const base = process.env.JMS_SCHEDULE_QA_BASE_URL || "http://127.0.0.1:8083";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Schedule QA requires loopback isolation");
test.use({ locale: "en-US" });

test("scheduled native SSH account discovery isolates approvals, refreshes credentials, archives runs and stops after revocation", async ({
  browser,
}, info) => {
  test.setTimeout(180_000);
  const api = await request.newContext({ baseURL: base });
  const context = await browser.newContext({ locale: "en-US" });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const stamp = Date.now();
  let adminToken = "",
    guestToken = "",
    adminCookie = "",
    guestCookie = "",
    asset = "",
    planID = "",
    filterID = "";
  const expire = async (token: string, cookie: string) => {
    if (cookie)
      await fetch(base + "/api/v1/authentication/expire-session/", {
        method: "POST",
        headers: { Cookie: cookie, Origin: base },
        signal: AbortSignal.timeout(5000),
      }).catch(() => {});
    if (token)
      await fetch(base + "/api/v1/authentication/expire-session/", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(5000),
      }).catch(() => {});
  };
  try {
    const admin = {
      username: process.env.JMS_SCHEDULE_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_SCHEDULE_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let login = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: admin });
      login = await api.post("/api/v1/authentication/auth/", { data: admin });
    }
    expect(login.ok()).toBe(true);
    adminToken = (await login.json()).access_token;
    adminCookie = (await api.storageState()).cookies.map((c) => `${c.name}=${c.value}`).join("; ");
    const host = await (
      await api.get(process.env.JMS_SCHEDULE_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    expect(host.container_name).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
    const labels = JSON.parse(
      (
        await execute("docker", [
          "inspect",
          "--format",
          "{{json .Config.Labels}}",
          host.container_name,
        ])
      ).stdout,
    );
    expect(labels["com.jumpserver233.qa.owner"]).toBe(host.owner);
    const name = `Scheduled Linux accounts ${stamp}`;
    const input = {
      name,
      host: process.env.JMS_SCHEDULE_QA_SSH_HOST || "127.0.0.1",
      port: Number(host.address.split(":").at(-1)),
      username: "pluginqa",
      password: "synthetic-keyhost-password-233",
      host_key_fingerprint: host.fingerprint,
      login_review_required: true,
    };
    const created = await api.post("/api/v1/assets", { data: input });
    expect(created.status()).toBe(201);
    asset = (await created.json()).id;
    const operator = {
      username: `schedule.operator.${stamp}`,
      password: "synthetic-schedule-platform-password-233",
    };
    const u = await api.post("/api/v1/users", { data: { ...operator, role: "operator" } });
    expect(u.status()).toBe(201);
    const user = (await u.json()).id;
    const auth = await page.request.post(base + "/api/v1/authentication/auth/", { data: operator });
    expect(auth.ok()).toBe(true);
    guestToken = (await auth.json()).access_token;
    guestCookie = (await context.cookies()).map((c) => `${c.name}=${c.value}`).join("; ");
    const headers = { Authorization: `Bearer ${guestToken}` },
      path = `/api/v1/assets/${asset}/account-discovery`;
    expect(
      (
        await api.post(path + "/plans", { headers, data: { request_id: `no-permission-${stamp}` } })
      ).status(),
    ).toBe(403);
    expect(
      (
        await api.post("/api/v1/grants", {
          data: {
            user_id: user,
            asset_id: asset,
            account: "pluginqa",
            actions: ["view", "connect"],
          },
        })
      ).status(),
    ).toBe(201);
    const roleResponse = await api.post("/api/v1/system/rbac/roles", {
      data: {
        name: `Scheduled collection ${stamp}`,
        permissions: ["accounts.view", "accounts.discover", "accounts.schedule"],
      },
    });
    expect(roleResponse.status()).toBe(201);
    const role = (await roleResponse.json()).id;
    const binding = await (
      await api.put("/api/v1/system/rbac/bindings", {
        data: { subject_type: "user", subject_id: user, role_ids: [role] },
      })
    ).json();
    const filterResponse = await api.post("/api/v1/command-filters", {
      data: {
        name: `Scheduled discovery approval ${stamp}`,
        user_id: user,
        asset_id: asset,
        account: "pluginqa",
        match: "contains",
        pattern: "account-discovery",
        action: "review",
        priority: 100,
      },
    });
    expect(filterResponse.status()).toBe(201);
    filterID = (await filterResponse.json()).id;
    await page.goto("/console");
    const row = page.getByRole("row").filter({ hasText: name });
    await row.getByText("More", { exact: true }).click();
    await row.getByRole("button", { name: "Collected accounts", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByText("Scheduled account discovery", { exact: true }).click();
    const section = dialog.locator("details.account-discovery-schedule");
    await section.getByRole("button", { name: "Create collection plan", exact: true }).click();
    await section.getByLabel("Interval (minutes)", { exact: true }).fill("60");
    const submission = page.waitForResponse(
      (r) => r.url().endsWith(path + "/plans") && r.request().method() === "POST",
    );
    await section.getByRole("button", { name: "Save", exact: true }).click();
    const submitted = await submission;
    expect(submitted.status()).toBe(201);
    planID = (await (await api.get(path + "/plans", { headers })).json())[0].id;
    const plan = async () =>
      (await (await api.get(path + "/plans", { headers })).json()).find(
        (p: { id: string }) => p.id === planID,
      );
    await expect
      .poll(async () => (await plan())?.last_run?.items[0]?.state, { timeout: 15000 })
      .toBe("waiting_review");
    const first = await plan(),
      firstReview = first.last_run.items[0].review_id;
    const review = await (await api.get(`/api/v1/access-reviews/${firstReview}`)).json();
    expect(review.action).toBe("account_discovery");
    expect(review.request_scope).toBe(planID + ":1");
    await expect(section).toContainText(firstReview, { timeout: 12000 });
    await section.getByRole("button", { name: "Pause", exact: true }).click();
    await expect.poll(async () => (await plan()).enabled).toBe(false);
    expect((await (await api.get(`/api/v1/access-reviews/${firstReview}`)).json()).state).toBe(
      "expired",
    );
    await expect(section.getByRole("button", { name: "Resume", exact: true })).toBeVisible();
    await section.getByRole("button", { name: "Resume", exact: true }).click();
    await expect
      .poll(
        async () => {
          const p = await plan();
          return (
            p.last_run?.items[0]?.review_id !== firstReview &&
            p.last_run?.items[0]?.state === "waiting_review"
          );
        },
        { timeout: 15000 },
      )
      .toBe(true);
    const secondReview = (await plan()).last_run.items[0].review_id;
    expect(
      (await (await api.get(`/api/v1/access-reviews/${secondReview}`)).json()).request_scope,
    ).toBe(planID + ":2");
    expect((await api.post(`/api/v1/access-reviews/${secondReview}/approve`)).status()).toBe(204);
    await expect
      .poll(async () => (await plan()).last_run?.items[0]?.state, { timeout: 15000 })
      .toBe("pending_review");
    const jobID = (await plan()).last_run.items[0].job_id;
    await expect(section).toContainText("Command approval required: " + jobID, { timeout: 12000 });
    expect(
      (await api.post(`/api/v1/ops/jobs/${jobID}/review`, { data: { approve: true } })).status(),
    ).toBe(200);
    await expect
      .poll(
        async () => (await (await api.get(`/api/v1/ops/jobs/${jobID}`, { headers })).json()).state,
        { timeout: 45000 },
      )
      .toBe("succeeded");
    await expect
      .poll(
        async () =>
          (await (await api.get(path + "/collections", { headers })).json()).results.length,
      )
      .toBe(2);
    const receipts = await (await api.get(path + "/collections", { headers })).json();
    expect(receipts.results[0].receipt.state).toBe("succeeded");
    expect(receipts.results[1].receipt.state).toBe("cancelled");
    await expect(section).toContainText("Succeeded", { timeout: 12000 });
    await expect(dialog).toContainText("pluginqa");
    await page.screenshot({ path: info.outputPath("scheduled-account-discovery.en.png") });
    await dialog.getByRole("button", { name: "中文", exact: true }).click();
    await expect(section).toContainText("采集运行记录");
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(
      true,
    );
    await page.screenshot({
      path: info.outputPath("scheduled-account-discovery.mobile.zh-CN.png"),
    });
    await page.setViewportSize({ width: 1440, height: 1050 });
    await page.screenshot({ path: info.outputPath("scheduled-account-discovery.zh-CN.png") });
    // A platform-authenticated CLI pauses the same plan, and safe DTOs omit internal typed commands.
    const cli = async (args: string[]) =>
      execute("go", ["run", "./cmd/jms", "accounts", ...args], {
        cwd: fileURLToPath(new URL("../../server", import.meta.url)),
        timeout: 60000,
        env: {
          ...process.env,
          JMS_SERVER_URL: base,
          JMS_TOKEN: guestToken,
          JMS_ORG_ID: "",
          JMS_ACCOUNT: "",
          JMS_ACCESS_KEY_ID: "",
          JMS_ACCESS_KEY_SECRET: "",
        },
      });
    const current = await plan();
    const paused = await cli([
      "plan",
      asset,
      planID,
      "--enabled=false",
      "--revision",
      String(current.config_revision),
    ]);
    expect(JSON.parse(paused.stdout).enabled).toBe(false);
    expect((await api.delete(`/api/v1/command-filters/${filterID}`)).status()).toBe(204);
    filterID = "";
    expect(
      (
        await api.put(`/api/v1/assets/${asset}`, {
          data: { ...input, login_review_required: false },
        })
      ).status(),
    ).toBe(200);
    const before = await plan();
    expect(
      (
        await api.put(path + "/plans/" + planID, {
          headers,
          data: { enabled: true, revision: before.config_revision },
        })
      ).status(),
    ).toBe(200);
    await expect
      .poll(
        async () =>
          (await (await api.get(path + "/collections", { headers })).json()).results.length,
        { timeout: 45000 },
      )
      .toBe(3);
    const list = await cli(["collections", asset, "--limit", "10"]);
    expect(JSON.parse(list.stdout).results[0].receipt.sequence).toBe(3);
    expect(list.stdout).not.toContain("synthetic-keyhost-password");
    expect(
      (
        await api.put("/api/v1/system/rbac/bindings", {
          data: {
            subject_type: "user",
            subject_id: user,
            role_ids: [],
            revision: binding.revision,
          },
        })
      ).ok(),
    ).toBe(true);
    const active = await plan();
    expect(
      (
        await api.put(path + "/plans/" + planID, {
          headers,
          data: { enabled: false, revision: active.config_revision },
        })
      ).status(),
    ).toBe(200);
    const stopped = await plan();
    expect(
      (
        await api.put(path + "/plans/" + planID, {
          headers,
          data: { enabled: true, revision: stopped.config_revision },
        })
      ).status(),
    ).toBe(403);
    expect((await api.get(path + "/collections", { headers })).status()).toBe(404);
    await writeFile(
      info.outputPath("schedule-result.json"),
      JSON.stringify({
        asset,
        name,
        plan: planID,
        host: host.container_name,
        owner: host.owner,
        approvalScope: "plan-and-run",
        sequences: 3,
        retained: process.env.JMS_SCHEDULE_QA_RETAIN === "true",
      }),
    );
    expect(errors).toEqual([]);
  } finally {
    if (asset && planID) {
      const plans = await api
        .get(`/api/v1/assets/${asset}/account-discovery/plans`)
        .catch(() => null);
      if (plans?.ok()) {
        const p = (await plans.json()).find((v: { id: string }) => v.id === planID);
        if (p?.enabled)
          await api
            .put(`/api/v1/assets/${asset}/account-discovery/plans/${planID}`, {
              data: { enabled: false, revision: p.config_revision },
            })
            .catch(() => {});
      }
    }
    if (filterID) await api.delete(`/api/v1/command-filters/${filterID}`).catch(() => {});
    await expire(guestToken, guestCookie);
    await expire(adminToken, adminCookie);
    await context.close();
    await api.dispose();
  }
});
