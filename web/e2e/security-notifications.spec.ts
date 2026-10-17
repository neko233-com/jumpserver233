import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const base = process.env.JMS_SECURITY_QA_BASE_URL || "http://127.0.0.1:8083";
const ui = process.env.JMS_SECURITY_QA_BASE_URL || "http://127.0.0.1:5177";
const capture = process.env.JMS_SECURITY_QA_CAPTURE_URL || "http://127.0.0.1:12604";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base) || !/^http:\/\/127\.0\.0\.1:\d+$/.test(capture))
  throw Error("Security notification QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });

test("security notifications link real SSH access, filtered PTY input, native reviews and risk results with live authorization", async ({
  browser,
}, info) => {
  test.setTimeout(180_000);
  const stamp = Date.now(),
    retain = process.env.JMS_SECURITY_QA_RETAIN === "true";
  const remoteUser = `managedqa_s${stamp.toString(36)}`,
    password = "synthetic-security-operator-233";
  const api = await request.newContext({ baseURL: base });
  const admin = await browser.newContext({
    locale: "en-US",
    viewport: { width: 1440, height: 1080 },
  });
  const operator = await browser.newContext({ locale: "en-US" });
  const page = await admin.newPage(),
    op = await operator.newPage(),
    errors: string[] = [];
  for (const p of [page, op]) p.on("pageerror", (e) => errors.push(e.message));
  let hostName = "",
    owner = "",
    assetID = "",
    userID = "",
    roleID = "",
    token = "",
    createdRemote = false;
  let settings: any, preferences: any;
  const filters: string[] = [];
  const inbox = async () =>
    (await (await api.get("/api/v1/notifications/inbox?limit=100")).json()).results as any[];
  const owned = async () => {
    const labels = JSON.parse(
      (await execute("docker", ["inspect", "--format", "{{json .Config.Labels}}", hostName]))
        .stdout,
    );
    expect(labels["com.jumpserver233.qa.owner"]).toBe(owner);
  };
  const cli = (args: string[]) =>
    execute("go", ["run", "./cmd/jms", ...args], {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      timeout: 60_000,
      env: {
        ...process.env,
        JMS_SERVER_URL: base,
        JMS_TOKEN: token,
        JMS_ORG_ID: "",
        JMS_ACCOUNT: "",
        JMS_ACCESS_KEY_ID: "",
        JMS_ACCESS_KEY_SECRET: "",
      },
    });
  const detail = (kind: string, id: string) => ui + `/console/notification-sources/${kind}/${id}`;
  const decide = async (approve: boolean) => {
    await page.getByRole("button", { name: approve ? "Approve" : "Deny", exact: true }).click();
    await page.getByRole("button", { name: "Confirm decision", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "Decision saved" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve", exact: true })).toHaveCount(0);
  };
  try {
    const credentials = {
      username: process.env.JMS_SECURITY_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_SECURITY_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok()).toBe(true);
    token = (await login.json()).access_token;
    await admin.addCookies((await api.storageState()).cookies);
    const health = await (await api.get(capture + "/health")).json();
    settings = await (await api.get("/api/v1/notifications/settings")).json();
    preferences = await (await api.get("/api/v1/notifications/preferences")).json();
    expect(
      (
        await api.put("/api/v1/notifications/settings", {
          data: {
            revision: settings.revision,
            smtp: settings.smtp,
            sms: settings.sms,
            webhook: {
              enabled: true,
              url: `https://${process.env.JMS_SECURITY_QA_TRANSPORT_HOST || "127.0.0.1"}:${health.https_port}/webhook`,
              ca: health.ca,
            },
            webhook_secret: "synthetic-security-signing-233",
          },
        })
      ).status(),
    ).toBe(200);
    const topics = {
      ...preferences.topics,
      approvals: ["inbox", "webhook"],
      security: ["inbox", "webhook"],
    };
    expect(
      (
        await api.put("/api/v1/notifications/preferences", {
          data: { revision: preferences.revision, language: "en", topics },
        })
      ).status(),
    ).toBe(200);
    const host = await (
      await api.get(process.env.JMS_SECURITY_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    hostName = host.container_name;
    owner = host.owner;
    expect(hostName).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
    expect(owner === hostName || /^jumpserver233-e2e-/.test(owner)).toBe(true);
    await owned();
    await execute("docker", [
      "exec",
      hostName,
      "sh",
      "-ceu",
      'useradd -m -s /bin/bash "$1"; printf "%s:%s\\n" "$1" "$2" | chpasswd',
      "qa-security-create",
      remoteUser,
      "synthetic-security-ssh-233",
    ]);
    createdRemote = true;
    const name = `Security SSH ${stamp}`;
    const asset = await api.post("/api/v1/assets", {
      data: {
        name,
        host: process.env.JMS_SECURITY_QA_SSH_HOST || "127.0.0.1",
        port: Number(host.address.split(":").at(-1)),
        username: remoteUser,
        password: "synthetic-security-ssh-233",
        host_key_fingerprint: host.fingerprint,
        login_review_required: true,
      },
    });
    expect(asset.status()).toBe(201);
    assetID = (await asset.json()).id;
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
    const username = `security.operator.${stamp}`;
    const user = await api.post("/api/v1/users", {
      data: { username, password, role: "operator" },
    });
    expect(user.status()).toBe(201);
    userID = (await user.json()).id;
    expect(
      (
        await api.post("/api/v1/grants", {
          data: {
            user_id: userID,
            asset_id: assetID,
            account: remoteUser,
            actions: ["view", "connect"],
          },
        })
      ).status(),
    ).toBe(201);
    expect(
      (
        await operator.request.post(base + "/api/v1/authentication/auth/", {
          data: { username, password },
        })
      ).ok(),
    ).toBe(true);
    const pendingAccess = await operator.request.post(base + "/api/v1/sessions", {
      data: { asset_id: assetID, cols: 100, rows: 30 },
    });
    expect(pendingAccess.status()).toBe(202);
    const accessID = (await pendingAccess.json()).review_id;
    await expect
      .poll(
        async () =>
          (await inbox()).some((v) => v.source.id === accessID && v.topic === "approvals"),
        { timeout: 15_000 },
      )
      .toBe(true);
    await page.goto(detail("access-reviews", accessID));
    await expect(
      page.getByRole("heading", { name: "Asset access review", exact: true }),
    ).toBeVisible();
    await decide(true);
    for (const [pattern, action] of [
      ["SYNTHETIC_DENIED", "deny"],
      ["SYNTHETIC_REVIEW", "review"],
    ]) {
      const r = await api.post("/api/v1/command-filters", {
        data: {
          name: `Synthetic ${action} ${stamp}`,
          user_id: userID,
          asset_id: assetID,
          account: remoteUser,
          match: "contains",
          pattern,
          action,
          priority: 100,
        },
      });
      expect(r.status()).toBe(201);
      filters.push((await r.json()).id);
    }
    let received = "";
    op.on("websocket", (ws) => {
      if (ws.url().includes("/terminal"))
        ws.on("framereceived", (frame) => {
          if (typeof frame.payload !== "string") received += frame.payload.toString("utf8");
        });
    });
    await op.goto(ui + "/console");
    await op
      .getByRole("row")
      .filter({ hasText: name })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    const terminal = op.getByRole("dialog"),
      input = terminal.locator(".xterm-helper-textarea");
    await expect(terminal.locator(".ssh-terminal-status")).toHaveClass(/connected/);
    await expect.poll(() => received).toContain("$ ");
    await input.pressSequentially("printf 'SYNTHETIC_DENIED_%s\\n' NEVER\r");
    await expect
      .poll(
        async () => (await inbox()).some((v) => v.state === "command_denied" && v.name === name),
        { timeout: 15_000 },
      )
      .toBe(true);
    expect(received).not.toContain("SYNTHETIC_DENIED_NEVER");
    const deniedMessage = (await inbox()).find(
      (v) => v.state === "command_denied" && v.name === name,
    );
    await page.goto(ui + deniedMessage.link);
    await expect(
      page.getByRole("heading", { name: "Interactive SSH security event", exact: true }),
    ).toBeVisible();
    expect(await page.locator("section.notifications-page").innerText()).not.toContain(
      "SYNTHETIC_DENIED",
    );
    expect(
      (
        await operator.request.get(
          base + "/api/v1/notifications/sources/command-alerts/" + deniedMessage.source.id,
        )
      ).status(),
    ).toBe(200);
    await input.pressSequentially("printf 'SYNTHETIC_REVIEW_%s\\n' OK\r");
    let reviewMessage: any;
    await expect
      .poll(
        async () => {
          reviewMessage = (await inbox()).find(
            (v) => v.source.kind === "command-reviews" && v.name === name,
          );
          return !!reviewMessage;
        },
        { timeout: 15_000 },
      )
      .toBe(true);
    expect(received).not.toContain("SYNTHETIC_REVIEW_OK");
    await page.goto(ui + reviewMessage.link);
    await expect(
      page.getByRole("heading", { name: "Interactive command review", exact: true }),
    ).toBeVisible();
    await expect(page.locator(".notification-command")).toContainText("SYNTHETIC_REVIEW");
    // A delayed pending GET must not restore approval buttons after a decision.
    const sourceURL = "**/api/v1/notifications/sources/command-reviews/" + reviewMessage.source.id;
    let release!: () => void, intercepted!: () => void;
    const held = new Promise<void>((r) => (release = r)),
      arrived = new Promise<void>((r) => (intercepted = r));
    await page.route(
      sourceURL,
      async (route) => {
        const r = await api.get(route.request().url());
        const body = await r.text();
        intercepted();
        await held;
        await route
          .fulfill({ status: r.status(), contentType: "application/json", body })
          .catch(() => {});
      },
      { times: 1 },
    );
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await arrived;
    await decide(true);
    release();
    await expect.poll(() => received, { timeout: 15_000 }).toContain("SYNTHETIC_REVIEW_OK");
    await page.screenshot({ path: info.outputPath("security-review.en.png"), fullPage: true });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "交互命令复核", exact: true })).toBeVisible();
    await page.screenshot({ path: info.outputPath("security-review.zh-CN.png"), fullPage: true });
    await page.getByRole("button", { name: "EN", exact: true }).click();
    const jobInput = {
      asset_id: assetID,
      command: "printf SYNTHETIC_REVIEW_JOB",
      request_id: `security-job-${stamp}`,
      timeout_seconds: 30,
    };
    let job = await operator.request.post(base + "/api/v1/ops/jobs", { data: jobInput });
    // The earlier permit was consumed by Web SSH; a new job needs new access approval.
    expect(job.status()).toBe(202);
    const jobAccessID = (await job.json()).review_id;
    await page.goto(detail("access-reviews", jobAccessID));
    await decide(true);
    job = await operator.request.post(base + "/api/v1/ops/jobs", { data: jobInput });
    expect(job.status()).toBe(201);
    const jobValue = await job.json();
    expect(jobValue.state).toBe("pending_review");
    await page.goto(detail("job-security", jobValue.id));
    await decide(false);
    expect(
      (await (await operator.request.get(base + "/api/v1/ops/jobs/" + jobValue.id)).json()).state,
    ).toBe("denied");
    const policy = await (await api.get("/api/v1/accounts/risks/policy")).json();
    const scan = await api.post("/api/v1/accounts/risks/scans", {
      data: { revision: policy.revision, request_id: `security-risk-${stamp}` },
    });
    expect(scan.status()).toBe(201);
    const scanValue = await scan.json();
    await expect
      .poll(
        async () =>
          (await inbox()).some(
            (v) => v.source.kind === "account-risks" && v.source.id === scanValue.id,
          ),
        { timeout: 15_000 },
      )
      .toBe(true);
    await page.goto(detail("account-risks", scanValue.id));
    await expect(page.getByRole("link", { name: "Open account risks", exact: true })).toBeVisible();
    expect(
      (
        await operator.request.get(
          base + "/api/v1/notifications/sources/account-risks/" + scanValue.id,
        )
      ).status(),
    ).toBe(404);
    const source = JSON.parse(
      (await cli(["notifications", "source", "command-alerts", deniedMessage.source.id])).stdout,
    );
    expect(source).toMatchObject({ state: "command_denied", asset_id: assetID });
    expect(source).not.toHaveProperty("command");
    // Later role membership sees pending snapshot tasks; removal hides them immediately.
    await terminal.getByRole("button", { name: "Close terminal", exact: true }).click();
    const adminID = (await (await api.get("/api/v1/rbac/me")).json()).user_id;
    const adminFilter = await api.post("/api/v1/command-filters", {
      data: {
        name: `Synthetic admin review ${stamp}`,
        user_id: adminID,
        asset_id: assetID,
        account: remoteUser,
        match: "contains",
        pattern: "SYNTHETIC_REVIEW_ADMIN",
        action: "review",
        priority: 100,
      },
    });
    expect(adminFilter.status()).toBe(201);
    filters.push((await adminFilter.json()).id);
    const mine = await api.post("/api/v1/ops/jobs", {
      data: {
        asset_id: assetID,
        command: "printf SYNTHETIC_REVIEW_ADMIN",
        request_id: `security-admin-${stamp}`,
        timeout_seconds: 30,
      },
    });
    expect(mine.status()).toBe(201);
    const mineValue = await mine.json();
    expect(mineValue.state).toBe("pending_review");
    const role = await api.post("/api/v1/rbac/roles", {
      data: { name: `Security reviewer ${stamp}`, permissions: ["jobs.review"], revision: 0 },
    });
    expect(role.status()).toBe(201);
    const roleValue = await role.json();
    roleID = roleValue.id;
    expect(
      (
        await api.put("/api/v1/rbac/bindings", {
          data: { subject_type: "user", subject_id: userID, role_ids: [roleID], revision: 0 },
        })
      ).status(),
    ).toBe(200);
    await expect
      .poll(
        async () =>
          (
            await (
              await operator.request.get(base + "/api/v1/notifications/inbox?limit=100")
            ).json()
          ).results.some((v: any) => v.source.id === mineValue.id && v.topic === "approvals"),
        { timeout: 15_000 },
      )
      .toBe(true);
    await op.goto(detail("job-security", mineValue.id));
    await expect(op.locator(".notification-command")).toContainText("SYNTHETIC_REVIEW_ADMIN");
    expect(
      (
        await api.put("/api/v1/rbac/roles/" + roleID, {
          data: {
            name: roleValue.name,
            permissions: ["notifications.audit"],
            revision: roleValue.revision,
          },
        })
      ).status(),
    ).toBe(200);
    await op.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(op.getByRole("alert")).toContainText("outside your current permissions");
    await expect(op.locator(".notification-command")).toHaveCount(0);
    expect(
      (
        await api.post("/api/v1/ops/jobs/" + mineValue.id + "/review", { data: { approve: false } })
      ).status(),
    ).toBe(200);
    const deliveries = async () =>
      (await (await api.get("/api/v1/notifications/deliveries?limit=100")).json()).results;
    await expect
      .poll(
        async () =>
          (await deliveries()).some(
            (v: any) => v.message_id === deniedMessage.id && v.state === "sent",
          ),
        { timeout: 15_000 },
      )
      .toBe(true);
    const records = (await (await api.get(capture + "/messages")).json()).filter(
      (v: any) => v.channel === "webhook" && v.body.includes(deniedMessage.source.event_id),
    );
    expect(records).toHaveLength(1);
    expect(records[0].signature).toMatch(/^[a-f0-9]{64}$/);
    expect(records[0].body).not.toMatch(
      /SYNTHETIC_DENIED|SYNTHETIC_REVIEW|command"|stdout|synthetic-security-ssh/,
    );
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    expect(errors).toEqual([]);
    await info.attach("security-result", {
      body: JSON.stringify({
        assetID,
        accessID,
        commandSource: deniedMessage.source.id,
        reviewSource: reviewMessage.source.id,
        jobID: jobValue.id,
        scanID: scanValue.id,
        pageErrors: errors,
      }),
      contentType: "application/json",
    });
  } finally {
    for (const id of filters) await api.delete("/api/v1/command-filters/" + id).catch(() => {});
    if (!retain) {
      if (assetID) await api.delete("/api/v1/assets/" + assetID).catch(() => {});
      if (userID) await api.delete("/api/v1/users/" + userID).catch(() => {});
      if (roleID) {
        const r = (await (await api.get("/api/v1/rbac/roles")).json()).find(
          (v: any) => v.id === roleID,
        );
        if (r?.revision)
          await api.delete("/api/v1/rbac/roles/" + roleID + "?revision=" + r.revision);
      }
      if (createdRemote) {
        await owned();
        await execute("docker", ["exec", hostName, "userdel", "-r", remoteUser]);
      }
    }
    if (preferences) {
      const current = await (await api.get("/api/v1/notifications/preferences")).json();
      await api.put("/api/v1/notifications/preferences", {
        data: { ...preferences, revision: current.revision },
      });
    }
    if (settings) {
      const current = await (await api.get("/api/v1/notifications/settings")).json();
      await api.put("/api/v1/notifications/settings", {
        data: {
          revision: current.revision,
          smtp: settings.smtp,
          sms: settings.sms,
          webhook: settings.webhook,
        },
      });
    }
    await operator.close();
    await admin.close();
    await api.dispose();
  }
});
