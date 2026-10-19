import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { basename, resolve } from "node:path";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile),
  base = process.env.JMS_DISCOVERY_QA_BASE_URL || "http://127.0.0.1:8083",
  ui = process.env.JMS_DISCOVERY_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Discovery QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });

test("LAN discovery imports a real SSH fixture with bilingual UI, exact retries, scheduling, CLI and Web SSH", async ({
  browser,
}, info) => {
  test.setTimeout(150_000);
  const testRoot = process.env.JMS_E2E_DATA_DIR;
  if (!testRoot || !/^jumpserver233-e2e-[\w-]+$/.test(basename(testRoot)))
    throw Error("Owned E2E root required");
  const owner = basename(testRoot),
    name = `jms233-keyhost-${randomUUID()}`,
    workspace = fileURLToPath(new URL("../../", import.meta.url)),
    server = resolve(workspace, "server");
  writeFileSync(resolve(testRoot, "discovery-container.json"), JSON.stringify({ name, owner }));
  let api = await request.newContext({ baseURL: base });
  const context = await browser.newContext({
      locale: "en-US",
      viewport: { width: 1440, height: 1080 },
    }),
    page = await context.newPage(),
    errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  let containerStarted = false,
    sourceID = "",
    assetID = "",
    token = "",
    sessionID = "",
    policyID = "";
  const data = async (method: string, path: string, input?: unknown) => {
    const response = await api.fetch(path, { method, data: input });
    expect(response.ok(), `${method} ${path} HTTP ${response.status()}`).toBeTruthy();
    return response.status() === 204 ? undefined : response.json();
  };
  try {
    await execute("docker", [
      "run",
      "--detach",
      "--pull",
      "never",
      "--name",
      name,
      "--label",
      `com.jumpserver233.qa.owner=${owner}`,
      "--label",
      `com.jumpserver233.qa.workspace=${workspace}`,
      "--publish",
      "127.0.0.1::22",
      "jms233-openssh-qa:local",
    ]);
    containerStarted = true;
    const inspect = JSON.parse((await execute("docker", ["inspect", name])).stdout)[0],
      port = Number(inspect.NetworkSettings.Ports["22/tcp"][0].HostPort);
    expect(inspect.Config.Labels["com.jumpserver233.qa.owner"]).toBe(owner);
    let fingerprint = "";
    await expect
      .poll(
        async () => {
          try {
            fingerprint = (
              await execute("docker", [
                "exec",
                name,
                "ssh-keygen",
                "-l",
                "-E",
                "sha256",
                "-f",
                "/run/keyhost-ed25519.pub",
              ])
            ).stdout
              .trim()
              .split(/\s+/)[1];
            return fingerprint;
          } catch {
            return "";
          }
        },
        { timeout: 15_000 },
      )
      .toMatch(/^SHA256:/);
    const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/register/", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok()).toBeTruthy();
    token = (await login.json()).access_token;
    const storage = await api.storageState();
    await context.addCookies(storage.cookies);
    await api.dispose();
    api = await request.newContext({
      baseURL: base,
      storageState: storage,
      extraHTTPHeaders: { Authorization: `Bearer ${token}` },
    });
    await page.goto(ui + "/console/asset-discovery");
    await expect(page.getByRole("heading", { name: "Asset discovery and sync" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "Actions", exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Add source", exact: true }).click();
    const form = page.locator("form.discovery-editor");
    const sourceName = `Discovery QA ${Date.now()}`;
    await form.getByLabel("Name", { exact: true }).fill(sourceName);
    await form.getByLabel("IP ranges", { exact: true }).fill("127.0.0.1");
    await form.getByLabel("Ports, separated by commas").fill(String(port));
    await form.getByRole("button", { name: "Save", exact: true }).click();
    await expect(form).toHaveCount(0);
    const sources = await data("GET", "/api/v1/asset-discovery/sources");
    sourceID = sources.results.find((s: any) => s.name === sourceName).id;
    expect(sources.results.find((s: any) => s.id === sourceID).credential_configured).toBe(false);
    const firstScan = page.waitForResponse(
      (r) => r.url().endsWith("/asset-discovery/runs") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Start scan", exact: true }).click();
    const run = await (await firstScan).json();
    await expect
      .poll(async () => (await data("GET", `/api/v1/asset-discovery/runs/${run.id}`)).state, {
        timeout: 20_000,
      })
      .toBe("completed");
    let findings = (await data("GET", `/api/v1/asset-discovery/findings?source_id=${sourceID}`))
      .results;
    expect(findings).toHaveLength(1);
    expect(findings[0].host_key_fingerprint).toBe(fingerprint);
    expect(findings[0].ssh_verified).toBe(true);
    const source = await data("GET", `/api/v1/asset-discovery/sources/${sourceID}`);
    const configured = await data("PUT", `/api/v1/asset-discovery/sources/${sourceID}`, {
      revision: source.revision,
      name: source.name,
      description: source.description,
      enabled: true,
      targets: source.targets,
      exclude: source.exclude,
      ports: source.ports,
      timeout_ms: source.timeout_ms,
      concurrency: source.concurrency,
      template: { protocol: "ssh", username: "keyqa" },
      credential: { password: "synthetic-keyhost-password-233" },
    });
    expect(JSON.stringify(configured)).not.toContain("synthetic-keyhost-password-233");
    const scanned = await data("POST", "/api/v1/asset-discovery/runs", {
      source_id: sourceID,
      source_revision: configured.revision,
      request_id: randomUUID(),
    });
    await expect
      .poll(async () => (await data("GET", `/api/v1/asset-discovery/runs/${scanned.id}`)).state)
      .toBe("completed");
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(page.getByRole("button", { name: "Refresh", exact: true })).toBeEnabled();
    await page.getByRole("button", { name: "Sync policies", exact: true }).click();
    await page.getByRole("button", { name: "Add policy", exact: true }).click();
    const policyForm = page.locator("form.discovery-editor");
    await policyForm.getByLabel("Name", { exact: true }).fill("QA manual policy");
    await policyForm.getByLabel("Asset name prefix").fill("discovery-qa-");
    await policyForm.getByLabel("Update source-owned asset metadata").check();
    await policyForm.getByRole("button", { name: "Save", exact: true }).click();
    await expect(policyForm).toHaveCount(0);
    const policies = (await data("GET", "/api/v1/asset-discovery/policies")).results;
    const policy = policies.find((p: any) => p.source_id === sourceID);
    policyID = policy.id;
    await page.getByRole("button", { name: "Discovered hosts", exact: true }).click();
    await page.getByLabel(`Select 127.0.0.1:${port}`, { exact: true }).check();
    await page.getByRole("button", { name: "Preview import", exact: true }).click();
    await expect(page.locator(".discovery-preview")).toContainText(fingerprint);
    await page
      .getByLabel("I verified these endpoints and explicitly trust the displayed SSH fingerprints.")
      .check();
    const importResponse = page.waitForResponse(
      (r) => r.url().endsWith("/asset-discovery/import") && r.request().method() === "POST",
    );
    await page.getByRole("button", { name: "Import selected hosts", exact: true }).click();
    const importedResponse = await importResponse,
      importInput = importedResponse.request().postDataJSON(),
      imported = await importedResponse.json();
    expect(importedResponse.status()).toBe(200);
    expect(imported.imported).toBe(1);
    assetID = imported.results[0].asset_id;
    const retry = await data("POST", "/api/v1/asset-discovery/import", importInput);
    expect(retry).toEqual(imported);
    expect(
      (
        await api.post("/api/v1/asset-discovery/import", {
          data: { ...importInput, request_id: randomUUID() },
        })
      ).status(),
    ).toBe(409);
    await page.screenshot({ path: info.outputPath("asset-discovery.en.png"), fullPage: true });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "资产发现与同步" })).toBeVisible();
    await page.getByRole("button", { name: "来源", exact: true }).click();
    await expect(page.getByRole("columnheader", { name: "操作", exact: true })).toBeVisible();
    await page.setViewportSize({ width: 390, height: 844 });
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBeTruthy();
    await page.screenshot({ path: info.outputPath("asset-discovery.zh.png"), fullPage: true });
    await page.setViewportSize({ width: 1440, height: 1080 });
    await page.getByRole("button", { name: "EN", exact: true }).click();
    const cli = async (args: string[]) =>
      execute("go", ["run", "./cmd/jms", ...args], {
        cwd: server,
        timeout: 60_000,
        windowsHide: true,
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
    const cliSources = JSON.parse((await cli(["discover", "sources"])).stdout);
    expect(cliSources.results.some((s: any) => s.id === sourceID)).toBe(true);
    expect(JSON.stringify(cliSources)).not.toContain("synthetic-keyhost-password-233");
    expect(
      JSON.parse((await cli(["exec", assetID, "--json", "--", "id -un"])).stdout).stdout.trim(),
    ).toBe("keyqa");
    let received = "";
    page.on("websocket", (socket) => {
      if (socket.url().includes("/terminal"))
        socket.on("framereceived", (frame) => {
          received += Buffer.isBuffer(frame.payload) ? frame.payload.toString() : frame.payload;
        });
    });
    await page.goto(ui + "/console");
    const created = page.waitForResponse(
      (r) => r.url().endsWith("/api/v1/sessions") && r.request().method() === "POST",
    );
    await page
      .getByRole("row")
      .filter({ hasText: `discovery-qa-127.0.0.1-${port}` })
      .getByRole("button", { name: "Connect", exact: true })
      .click();
    sessionID = (await (await created).json()).session_id;
    const terminal = page.getByRole("dialog");
    await expect(terminal.locator(".ssh-terminal-status")).toHaveClass(/connected/);
    await terminal
      .locator(".xterm-helper-textarea")
      .pressSequentially("id -un; printf 'DISCOVERY_%s\\n' READY\r");
    await expect.poll(() => received).toContain("DISCOVERY_READY");
    expect(received).toContain("keyqa");
    await page.getByRole("button", { name: "Close terminal", exact: true }).click();
    const scheduled = await data("PUT", `/api/v1/asset-discovery/policies/${policyID}`, {
      revision: policy.revision,
      source_id: sourceID,
      source_revision: configured.revision,
      name: policy.name,
      enabled: true,
      name_prefix: policy.name_prefix,
      group: policy.group,
      match_cidrs: [],
      update_existing: true,
      auto_import: false,
      trust_new_ssh_keys: false,
      missing_action: "retain",
      missing_threshold: 2,
      schedule: { kind: "once", run_at: new Date(Date.now() + 1500).toISOString() },
    });
    await expect
      .poll(
        async () =>
          (await data("GET", `/api/v1/asset-discovery/runs?source_id=${sourceID}`)).results.filter(
            (r: any) => r.trigger === "schedule" && r.state === "completed",
          ).length,
        { timeout: 20_000 },
      )
      .toBe(1);
    const policyAfter = await data("GET", `/api/v1/asset-discovery/policies/${policyID}`);
    expect(policyAfter.next_run_at).toBeFalsy();
    expect(policyAfter.revision).toBe(scheduled.revision);
    findings = (await data("GET", `/api/v1/asset-discovery/findings?source_id=${sourceID}`))
      .results;
    expect(findings).toHaveLength(1);
    expect(findings[0].asset_id).toBe(assetID);
    expect(
      (await data("GET", "/api/v1/assets")).filter((a: any) => a.discovery?.source_id === sourceID),
    ).toHaveLength(1);
    const csv = await api.get(`/api/v1/asset-discovery/findings.csv?source_id=${sourceID}`);
    expect(csv.ok()).toBeTruthy();
    expect(await csv.text()).toContain(fingerprint);
    expect(await csv.text()).not.toContain("synthetic-keyhost-password-233");
    expect(errors).toEqual([]);
  } finally {
    if (sessionID) await api.delete(`/api/v1/sessions/${sessionID}`).catch(() => undefined);
    if (sourceID) {
      const sourceResponse = await api.get(`/api/v1/asset-discovery/sources/${sourceID}`);
      if (sourceResponse.ok()) {
        const source = await sourceResponse.json();
        await api.delete(`/api/v1/asset-discovery/sources/${sourceID}?revision=${source.revision}`);
      }
    }
    if (assetID) await api.delete(`/api/v1/assets/${assetID}`);
    await api.post("/api/v1/authentication/expire-session/").catch(() => undefined);
    await page.close();
    await context.close();
    await api.dispose();
    if (containerStarted) {
      const labels = JSON.parse(
        (await execute("docker", ["inspect", "--format", "{{json .Config.Labels}}", name])).stdout,
      );
      expect(labels["com.jumpserver233.qa.owner"]).toBe(owner);
      await execute("docker", ["rm", "--force", "--volumes", name]);
    }
  }
});
