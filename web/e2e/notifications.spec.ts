import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const base = process.env.JMS_NOTIFICATIONS_QA_BASE_URL || "http://127.0.0.1:8083";
const ui = process.env.JMS_NOTIFICATIONS_QA_BASE_URL || "http://127.0.0.1:5177";
const capture = process.env.JMS_NOTIFICATIONS_QA_CAPTURE_URL || "http://127.0.0.1:12604";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base) || !/^http:\/\/127\.0\.0\.1:\d+$/.test(capture))
  throw Error("Notification QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });
test("notifications verify TLS contacts, deliver signed messages, link real SSH jobs and gate approval notifications", async ({
  browser,
}, info) => {
  test.setTimeout(180_000);
  const stamp = Date.now(),
    retain = process.env.JMS_NOTIFICATIONS_QA_RETAIN === "true",
    email = `notification.${stamp}@jumpserver233.invalid`,
    phone = "+1555" + String(stamp).slice(-7);
  const remoteUser = `managedqa_n${stamp.toString(36)}`,
    password = "synthetic-notification-platform-233",
    remotePassword = "synthetic-notification-ssh-233";
  const api = await request.newContext({ baseURL: base }),
    admin = await browser.newContext({ locale: "en-US", viewport: { width: 1440, height: 1080 } }),
    operator = await browser.newContext({ locale: "en-US" });
  const page = await admin.newPage(),
    op = await operator.newPage(),
    errors: string[] = [];
  for (const p of [page, op]) p.on("pageerror", (e) => errors.push(e.message));
  let hostName = "",
    owner = "",
    assetID = "",
    userID = "",
    policyID = "",
    token = "",
    createdRemote = false,
    originalSettings: any,
    originalPrefs: any;
  const records = async () => await (await api.get(capture + "/messages")).json();
  const cli = (args: string[]) =>
    execute("go", ["run", "./cmd/jms", ...args], {
      cwd: fileURLToPath(new URL("../../server", import.meta.url)),
      timeout: 60000,
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
  const owned = async () => {
    const labels = JSON.parse(
      (await execute("docker", ["inspect", "--format", "{{json .Config.Labels}}", hostName]))
        .stdout,
    );
    expect(labels["com.jumpserver233.qa.owner"]).toBe(owner);
  };
  try {
    const credentials = {
      username: process.env.JMS_NOTIFICATIONS_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_NOTIFICATIONS_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
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
    const transportHost = process.env.JMS_NOTIFICATIONS_QA_TRANSPORT_HOST || "127.0.0.1";
    originalSettings = await (await api.get("/api/v1/notifications/settings")).json();
    originalPrefs = await (await api.get("/api/v1/notifications/preferences")).json();
    await page.goto(ui + "/console/notifications");
    await expect(page.getByRole("heading", { name: "Notifications", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Channel settings", exact: true }).click();
    const mail = page.getByRole("group", { name: "Email", exact: true }),
      webhook = page.getByRole("group", { name: "Webhook", exact: true }),
      sms = page.getByRole("group", { name: "SMS gateway", exact: true });
    await mail.getByLabel("Enable channel", { exact: true }).check();
    await mail.getByLabel("SMTP host", { exact: true }).fill(transportHost);
    await mail.getByLabel("Port", { exact: true }).fill(String(health.smtp_port));
    await mail.getByLabel("Transport", { exact: true }).selectOption("tls");
    await mail.getByLabel("Username", { exact: true }).fill("synthetic-user");
    await mail.getByLabel("Sender address", { exact: true }).fill("sender@jumpserver233.invalid");
    await mail.getByLabel("SMTP password", { exact: true }).fill("synthetic-capture-only");
    await mail
      .getByLabel("Additional trusted CA certificates (PEM, optional)", { exact: true })
      .fill(health.ca);
    for (const [group, path] of [
      [webhook, "webhook"],
      [sms, "sms"],
    ] as const) {
      await group.getByLabel("Enable channel", { exact: true }).check();
      await group
        .getByLabel("HTTPS endpoint", { exact: true })
        .fill(`https://${transportHost}:${health.https_port}/${path}`);
      await group
        .getByLabel("Additional trusted CA certificates (PEM, optional)", { exact: true })
        .fill(health.ca);
    }
    await webhook
      .getByLabel("Webhook signing secret", { exact: true })
      .fill("synthetic-webhook-signing-233");
    await sms
      .getByLabel("SMS gateway signing secret", { exact: true })
      .fill("synthetic-sms-signing-233");
    let saved = page.waitForResponse(
      (r) => r.url().endsWith("/notifications/settings") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save", exact: true }).click();
    expect((await saved).status()).toBe(200);
    await expect(mail.getByLabel("SMTP password", { exact: true })).toHaveValue("");
    await page.getByRole("button", { name: "Subscriptions & contacts", exact: true }).click();
    await page.getByLabel("Email address", { exact: true }).fill(email);
    await page.getByLabel("Phone number (E.164)", { exact: true }).fill(phone);
    for (const channel of ["email", "sms"]) {
      const group = page.getByRole("group", {
        name: channel === "email" ? "Email" : "SMS gateway",
        exact: true,
      });
      await group.getByRole("button", { name: "Send verification code", exact: true }).click();
      let code = "";
      await expect
        .poll(
          async () => {
            const found = (await records()).findLast(
              (v: any) =>
                v.channel === channel &&
                (channel === "email" ? v.to === email : JSON.parse(v.body).to === phone),
            );
            if (!found) return false;
            code =
              channel === "email"
                ? found.body.match(/Verification code: (\d{6})/)?.[1]
                : JSON.parse(found.body).code;
            return Boolean(code);
          },
          { timeout: 15000 },
        )
        .toBe(true);
      await group.getByLabel("Verification code", { exact: true }).fill(code);
      saved = page.waitForResponse((r) => r.url().endsWith("/verification/confirm"));
      await group.getByRole("button", { name: "Verify contact", exact: true }).click();
      expect((await saved).status()).toBe(200);
      await expect(group.getByText("Verified", { exact: true })).toBeVisible();
    }
    for (const topic of ["System", "SSH jobs"]) {
      const group = page.getByRole("group", { name: topic, exact: true });
      for (const channel of ["Email", "Webhook", "SMS gateway"])
        await group.getByLabel(channel, { exact: true }).check();
    }
    saved = page.waitForResponse(
      (r) => r.url().endsWith("/notifications/preferences") && r.request().method() === "PUT",
    );
    await page.getByRole("button", { name: "Save", exact: true }).click();
    expect((await saved).status()).toBe(200);
    const tested = page.waitForResponse((r) => r.url().endsWith("/notifications/test"));
    await page.getByRole("button", { name: "Send test to my subscriptions", exact: true }).click();
    const testedReply = await tested;
    expect(testedReply.status()).toBe(200);
    const testMessage = await testedReply.json();
    await expect
      .poll(
        async () => {
          const result = await (await api.get("/api/v1/notifications/deliveries?limit=100")).json();
          return result.results.filter(
            (v: any) => v.message_id === testMessage.id && v.state === "sent",
          ).length;
        },
        { timeout: 15000 },
      )
      .toBe(3);
    const testRecords = (await records()).filter((v: any) =>
      v.channel === "email"
        ? v.to === email && v.body.includes("System notification")
        : v.body.includes(testMessage.source.event_id),
    );
    expect(testRecords).toHaveLength(3);
    for (const v of testRecords.filter((v: any) => v.channel !== "email"))
      expect(v.signature).toMatch(/^[a-f0-9]{64}$/);
    const host = await (
      await api.get(process.env.JMS_NOTIFICATIONS_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
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
      "qa-notification-create",
      remoteUser,
      remotePassword,
    ]);
    createdRemote = true;
    const asset = await api.post("/api/v1/assets", {
      data: {
        name: `Notification SSH ${stamp}`,
        host: process.env.JMS_NOTIFICATIONS_QA_SSH_HOST || "127.0.0.1",
        port: Number(host.address.split(":").at(-1)),
        username: remoteUser,
        password: remotePassword,
        host_key_fingerprint: host.fingerprint,
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
    const job = JSON.parse((await cli(["exec", assetID, "--json", "--", "id -un"])).stdout);
    expect(job.stdout.trim()).toBe(remoteUser);
    const jobID = job.id;
    await expect
      .poll(
        async () => {
          const inbox = await (await api.get("/api/v1/notifications/inbox?limit=100")).json();
          return inbox.results.some((v: any) => v.source.id === jobID);
        },
        { timeout: 15000 },
      )
      .toBe(true);
    await page.getByRole("button", { name: "Inbox", exact: true }).click();
    const jobRow = page.locator(".notification-inbox li").filter({ hasText: jobID });
    await expect(jobRow).toBeVisible();
    await jobRow.getByRole("link", { name: "Open related page", exact: true }).click();
    await expect(page).toHaveURL(/workbench\?job=/);
    await expect(page.locator("pre").filter({ hasText: remoteUser })).toBeVisible();
    const username = `notification.operator.${stamp}`;
    const user = await api.post("/api/v1/users", {
      data: { username, password, role: "operator" },
    });
    expect(user.status()).toBe(201);
    userID = (await user.json()).id;
    expect(
      (
        await operator.request.post(base + "/api/v1/authentication/auth/", {
          data: { username, password },
        })
      ).ok(),
    ).toBe(true);
    expect((await operator.request.get(base + "/api/v1/notifications/settings")).status()).toBe(
      403,
    );
    const adminID = (await (await api.get("/api/v1/rbac/me")).json()).user_id;
    const policy = await api.post("/api/v1/tickets/policies", {
      data: {
        name: `Notification policy ${stamp}`,
        enabled: true,
        all_members: true,
        requesters: [],
        cc: [],
        stages: [{ name: "Review", subjects: [{ kind: "user", id: adminID }] }],
        scopes: [{ kind: "asset", id: assetID, accounts: [remoteUser], actions: ["connect"] }],
        max_duration_minutes: 60,
        approval_ttl_minutes: 60,
      },
    });
    expect(policy.status()).toBe(200);
    const policyValue = await policy.json();
    policyID = policyValue.id;
    const ticket = await operator.request.post(base + "/api/v1/tickets/requests", {
      data: {
        policy_id: policyID,
        policy_revision: policyValue.revision,
        request_id: `notification-${stamp}`,
        name: `Notification request ${stamp}`,
        reason: "Synthetic approval notification",
        targets: [{ kind: "asset", id: assetID, account: remoteUser, actions: ["connect"] }],
        ends_at: new Date(Date.now() + 1800000).toISOString(),
      },
    });
    expect(ticket.status()).toBe(200);
    const ticketValue = await ticket.json();
    await expect
      .poll(
        async () => {
          const inbox = await (await api.get("/api/v1/notifications/inbox?limit=100")).json();
          return inbox.results.some(
            (v: any) => v.topic === "approvals" && v.source.id === ticketValue.id,
          );
        },
        { timeout: 15000 },
      )
      .toBe(true);
    await page.goto(ui + "/console/notifications");
    await page
      .locator(".notification-inbox li")
      .filter({ hasText: ticketValue.name })
      .getByRole("link", { name: "Open related page", exact: true })
      .click();
    await expect(page.getByRole("dialog", { name: "Request details", exact: true })).toBeVisible();
    expect(
      (
        await api.post(`/api/v1/tickets/requests/${ticketValue.id}/decisions`, {
          data: {
            revision: ticketValue.revision,
            request_id: `notification-reject-${stamp}`,
            action: "reject",
            comment: "Synthetic notification checked",
          },
        })
      ).status(),
    ).toBe(200);
    await expect
      .poll(async () => {
        const inbox = await (await api.get("/api/v1/notifications/inbox?limit=100")).json();
        return inbox.results.some(
          (v: any) => v.topic === "approvals" && v.source.id === ticketValue.id,
        );
      })
      .toBe(false);
    await op.goto(ui + "/console/notifications");
    await expect
      .poll(
        async () => {
          await op.getByRole("button", { name: "Refresh", exact: true }).click();
          return await op.locator(".notification-inbox").innerText();
        },
        { timeout: 15000 },
      )
      .toContain("Rejected");
    await expect(op.getByRole("button", { name: "Channel settings", exact: true })).toHaveCount(0);
    const listed = JSON.parse((await cli(["notifications", "list", "--limit", "100"])).stdout);
    expect(listed.results.some((v: any) => v.source.id === jobID)).toBe(true);
    await page.goto(ui + "/console/notifications");
    await page.getByRole("button", { name: "Mark all read", exact: true }).click();
    await expect(page.getByText("0 unread", { exact: true })).toBeVisible();
    await page.screenshot({ path: info.outputPath("notifications.en.png"), fullPage: true });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "通知中心", exact: true })).toBeVisible();
    await page.screenshot({ path: info.outputPath("notifications.zh-CN.png"), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    expect(errors).toEqual([]);
    await info.attach("notification-result", {
      body: JSON.stringify({
        assetID,
        jobID,
        policyID,
        ticketID: ticketValue.id,
        deliveredChannels: 3,
        pageErrors: errors,
      }),
      contentType: "application/json",
    });
  } finally {
    if (!retain) {
      if (policyID) {
        const p = await (await api.get(`/api/v1/tickets/policies/${policyID}`)).json();
        if (p.id)
          await api.delete(`/api/v1/tickets/policies/${policyID}`, {
            data: { revision: p.revision },
          });
      }
      if (assetID) await api.delete(`/api/v1/assets/${assetID}`);
      if (userID) await api.delete(`/api/v1/users/${userID}`);
      if (originalPrefs) {
        const p = await (await api.get("/api/v1/notifications/preferences")).json();
        await api.put("/api/v1/notifications/preferences", {
          data: {
            revision: p.revision,
            language: originalPrefs.language,
            email: originalPrefs.email,
            phone: originalPrefs.phone,
            topics: originalPrefs.topics,
          },
        });
      }
      if (originalSettings) {
        const s = await (await api.get("/api/v1/notifications/settings")).json();
        await api.put("/api/v1/notifications/settings", {
          data: {
            ...originalSettings,
            revision: s.revision,
            smtp_password: "",
            webhook_secret: "",
            webhook_bearer: "",
            sms_secret: "",
            sms_bearer: "",
          },
        });
      }
      if (createdRemote) {
        await owned();
        await execute("docker", [
          "exec",
          hostName,
          "sh",
          "-ceu",
          'userdel -r "$1"',
          "qa-notification-clean",
          remoteUser,
        ]);
      }
    }
    await admin.close();
    await operator.close();
    await api.dispose();
  }
});
