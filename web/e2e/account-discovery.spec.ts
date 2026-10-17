import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { writeFile } from "node:fs/promises";
const execute = promisify(execFile);
const base = process.env.JMS_ACCOUNTS_QA_BASE_URL || "http://127.0.0.1:8083";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Account discovery QA requires loopback isolation");
test.use({ locale: "en-US" });
test("native account discovery enforces grants and both reviews, persists findings and supports bilingual Web/CLI without passwords", async ({
  browser,
}, info) => {
  test.setTimeout(180_000);
  const api = await request.newContext({ baseURL: base });
  const guestContext = await browser.newContext({ locale: "en-US" });
  const guest = await guestContext.newPage();
  const errors: string[] = [];
  guest.on("pageerror", (e) => errors.push(e.message));
  const stamp = Date.now(),
    suffix = stamp.toString(36),
    names = Array.from(
      { length: 40 },
      (_, i) => `discoveryqa${String(i).padStart(2, "0")}_${suffix}`,
    );
  let hostName = "",
    hostOwner = "",
    filterID = "",
    createdUsers = false;
  const admin = {
    username: process.env.JMS_ACCOUNTS_QA_USERNAME || "e2e.admin",
    password: process.env.JMS_ACCOUNTS_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
  };
  try {
    let login = await api.post("/api/v1/authentication/auth/", { data: admin });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: admin });
      login = await api.post("/api/v1/authentication/auth/", { data: admin });
    }
    expect(login.ok()).toBe(true);
    const host = await (
      await api.get(process.env.JMS_ACCOUNTS_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    hostName = host.container_name;
    hostOwner = host.owner;
    expect(hostName).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
    expect(hostOwner === hostName || /^jumpserver233-e2e-/.test(hostOwner)).toBe(true);
    const verifyOwner = async () => {
      const inspected = await execute("docker", [
        "inspect",
        "--format",
        "{{json .Config.Labels}}",
        hostName,
      ]);
      expect(JSON.parse(inspected.stdout)["com.jumpserver233.qa.owner"]).toBe(hostOwner);
    };
    await verifyOwner();
    for (const n of names) expect(n).toMatch(/^discoveryqa\d\d_[a-z0-9]+$/);
    await writeFile(
      info.outputPath("created-accounts.json"),
      JSON.stringify({ name: hostName, owner: hostOwner, users: names }),
    );
    createdUsers = true;
    await execute("docker", [
      "exec",
      hostName,
      "sh",
      "-ceu",
      'for name in "$@"; do useradd -M -s /usr/sbin/nologin "$name"; done',
      "qa-create",
      ...names,
    ]);
    const gateway = await api.post("/api/v1/assets", {
      data: {
        name: `Account gateway ${stamp}`,
        host: process.env.JMS_ACCOUNTS_QA_SSH_HOST || "127.0.0.1",
        port: Number(host.address.split(":").at(-1)),
        username: "keyqa",
        password: "synthetic-keyhost-password-233",
        host_key_fingerprint: host.fingerprint,
      },
    });
    expect(gateway.status()).toBe(201);
    const gatewayID = (await gateway.json()).id;
    const assetInput = {
      name: `Account inventory ${stamp}`,
      host: "127.0.0.1",
      port: 22,
      username: "pluginqa",
      password: "synthetic-keyhost-password-233",
      host_key_fingerprint: host.fingerprint,
      gateway_id: gatewayID,
      login_review_required: true,
    };
    const assetResponse = await api.post("/api/v1/assets", { data: assetInput });
    expect(assetResponse.status()).toBe(201);
    const asset = (await assetResponse.json()).id;
    const account = {
      username: `inventory.operator.${stamp}`,
      password: "synthetic-inventory-operator-233",
    };
    const userResponse = await api.post("/api/v1/users", {
      data: { ...account, role: "operator" },
    });
    expect(userResponse.status()).toBe(201);
    const user = (await userResponse.json()).id;
    const auth = await guest.request.post(base + "/api/v1/authentication/auth/", { data: account });
    expect(auth.ok()).toBe(true);
    const token = (await auth.json()).access_token;
    const headers = { Authorization: `Bearer ${token}` };
    const collect = `/api/v1/assets/${asset}/account-discovery/jobs`,
      records = `/api/v1/assets/${asset}/discovered-accounts`;
    expect(
      (await api.post(collect, { headers, data: { request_id: "no-permission" } })).status(),
    ).toBe(403);
    const roleResponse = await api.post("/api/v1/system/rbac/roles", {
      data: {
        name: `Account collection ${stamp}`,
        permissions: ["accounts.view", "accounts.discover", "accounts.review"],
      },
    });
    expect(roleResponse.status()).toBe(201);
    const role = (await roleResponse.json()).id;
    let binding = await (
      await api.put("/api/v1/system/rbac/bindings", {
        data: { subject_type: "user", subject_id: user, role_ids: [role] },
      })
    ).json();
    expect(
      (await api.post(collect, { headers, data: { request_id: "missing-connect" } })).status(),
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
    const filterResponse = await api.post("/api/v1/command-filters", {
      data: {
        name: `Review inventory ${stamp}`,
        user_id: user,
        asset_id: asset,
        account: "pluginqa",
        match: "contains",
        pattern: "account-discovery",
        action: "review",
        priority: 100,
      },
    });
    expect(filterResponse.status(), await filterResponse.text()).toBe(201);
    filterID = (await filterResponse.json()).id;
    await guest.goto("/console");
    const row = guest.getByRole("row").filter({ hasText: assetInput.name });
    await row.getByText("More", { exact: true }).click();
    await row.getByRole("button", { name: "Collected accounts", exact: true }).click();
    const dialog = guest.getByRole("dialog");
    await expect(dialog).toContainText("No accounts collected");
    const pending = guest.waitForResponse(
      (r) => r.url().endsWith(collect) && r.request().method() === "POST",
    );
    await dialog.getByRole("button", { name: "Collect now", exact: true }).click();
    const pendingResponse = await pending;
    expect(pendingResponse.status()).toBe(202);
    const review = (await pendingResponse.json()).review_id;
    expect((await api.post(`/api/v1/access-reviews/${review}/approve`)).status()).toBe(204);
    const submitted = guest.waitForResponse(
      (r) => r.url().endsWith(collect) && r.request().method() === "POST",
    );
    await dialog.getByRole("button", { name: "Retry after login approval", exact: true }).click();
    const submittedResponse = await submitted;
    expect(submittedResponse.status()).toBe(201);
    const job = await submittedResponse.json();
    expect(job.state).toBe("pending_review");
    let failedPoll = false;
    await guest.route(`**/api/v1/ops/jobs/${job.id}`, async (route) => {
      if (!failedPoll) {
        failedPoll = true;
        await route.fulfill({ status: 503, json: { detail: "synthetic transient failure" } });
      } else await route.continue();
    });
    await expect.poll(() => failedPoll).toBe(true);
    let changed = await api.put("/api/v1/system/rbac/bindings", {
      data: { subject_type: "user", subject_id: user, role_ids: [], revision: binding.revision },
    });
    expect(changed.ok()).toBe(true);
    binding = await changed.json();
    expect(
      (await api.post(`/api/v1/ops/jobs/${job.id}/review`, { data: { approve: true } })).status(),
    ).toBe(403);
    changed = await api.put("/api/v1/system/rbac/bindings", {
      data: {
        subject_type: "user",
        subject_id: user,
        role_ids: [role],
        revision: binding.revision,
      },
    });
    expect(changed.ok()).toBe(true);
    binding = await changed.json();
    expect(
      (await api.post(`/api/v1/ops/jobs/${job.id}/review`, { data: { approve: true } })).status(),
    ).toBe(200);
    await expect
      .poll(
        async () => (await (await api.get(`/api/v1/ops/jobs/${job.id}`, { headers })).json()).state,
        { timeout: 45000 },
      )
      .toBe("succeeded");
    await expect(dialog).toContainText(names[0]);
    const findingRow = dialog.getByRole("row").filter({ hasText: names[0] });
    await findingRow.getByRole("button", { name: "Edit", exact: true }).click();
    await dialog.getByLabel("Review", { exact: true }).selectOption("ignored");
    await dialog.getByLabel("Review note", { exact: true }).fill("Known QA service account");
    await dialog.getByRole("button", { name: "Save", exact: true }).click();
    await expect(findingRow).toContainText("Ignored");
    const nextPage = await (await api.get(records + "?offset=20&limit=20", { headers })).json();
    await dialog.getByRole("button", { name: "Next", exact: true }).click();
    await expect(dialog).toContainText(nextPage.results[0].username);
    await expect(dialog).toContainText(`Showing 21–40 of ${nextPage.total}`);
    await dialog.getByRole("button", { name: "Previous", exact: true }).click();
    await guest.screenshot({ path: info.outputPath("account-discovery.en.png") });
    await dialog.getByRole("button", { name: "中文", exact: true }).click();
    await expect(dialog).toContainText("已忽略");
    await guest.setViewportSize({ width: 390, height: 844 });
    expect(await guest.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(
      true,
    );
    await guest.screenshot({ path: info.outputPath("account-discovery.mobile.zh-CN.png") });
    // Subsequent scans use an explicit test-only policy change, preserving target identity across credential revisions.
    expect((await api.delete(`/api/v1/command-filters/${filterID}`)).status()).toBe(204);
    filterID = "";
    expect(
      (
        await api.put(`/api/v1/assets/${asset}`, {
          data: { ...assetInput, login_review_required: false },
        })
      ).status(),
    ).toBe(200);
    await verifyOwner();
    await execute("docker", ["exec", hostName, "userdel", names[0]]);
    const cli = await execute(
      "go",
      ["run", "./cmd/jms", "accounts", "discover", asset, "--request-id", `cli-${stamp}`],
      {
        cwd: fileURLToPath(new URL("../../server", import.meta.url)),
        timeout: 45000,
        env: {
          ...process.env,
          JMS_SERVER_URL: base,
          JMS_TOKEN: token,
          JMS_ORG_ID: "",
          JMS_ACCESS_KEY_ID: "",
          JMS_ACCESS_KEY_SECRET: "",
        },
      },
    );
    expect(JSON.parse(cli.stdout).state).toBe("succeeded");
    expect(cli.stdout + cli.stderr).not.toContain("synthetic-keyhost-password-233");
    const listed = await (await api.get(records + "?limit=100", { headers })).json();
    const missing = listed.results.find((v: { username: string }) => v.username === names[0]);
    expect(missing.present).toBe(false);
    expect(missing.review).toBe("ignored");
    expect(missing.note).toBe("Known QA service account");
    expect(listed.results.length).toBeGreaterThan(32);
    expect(
      listed.results.some(
        (v: { username: string; uid: number }) => v.username === "root" && v.uid === 0,
      ),
    ).toBe(true);
    expect(JSON.stringify(listed)).not.toMatch(/password|gecos|synthetic-keyhost-password/);
    await dialog.getByRole("button", { name: "刷新", exact: true }).click();
    await dialog.getByRole("button", { name: "账号收集活动", exact: true }).click();
    await expect(dialog.getByRole("region", { name: "账号收集活动" })).toContainText(
      account.username,
    );
    changed = await api.put("/api/v1/system/rbac/bindings", {
      data: { subject_type: "user", subject_id: user, role_ids: [], revision: binding.revision },
    });
    expect(changed.ok()).toBe(true);
    expect((await api.get(records, { headers })).status()).toBe(404);
    expect((await api.post(collect, { headers, data: { request_id: "revoked" } })).status()).toBe(
      403,
    );
    expect(errors).toEqual([]);
  } finally {
    await guest.request.post(base + "/api/v1/authentication/expire-session/").catch(() => {});
    await guestContext.close().catch(() => {});
    if (filterID) await api.delete(`/api/v1/command-filters/${filterID}`).catch(() => {});
    if (createdUsers) {
      const inspected = await execute("docker", [
        "inspect",
        "--format",
        "{{json .Config.Labels}}",
        hostName,
      ]);
      if (JSON.parse(inspected.stdout)["com.jumpserver233.qa.owner"] !== hostOwner)
        throw Error("QA account cleanup owner changed");
      await execute("docker", [
        "exec",
        hostName,
        "sh",
        "-ceu",
        'for name in "$@"; do if id "$name" >/dev/null 2>&1; then userdel "$name"; fi; done',
        "qa-clean",
        ...names,
      ]);
    }
    await api.post("/api/v1/authentication/expire-session/").catch(() => {});
    await api.dispose();
  }
});
