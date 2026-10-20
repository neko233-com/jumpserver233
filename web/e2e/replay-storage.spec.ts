import { test, expect, type APIRequestContext } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { gunzipSync } from "node:zlib";

test.use({ locale: "en-US", trace: "off" });
type Config = {
  provider: string;
  enabled: boolean;
  prefix: string;
  revision: number;
  cloud?: { secret_access_key?: string; session_token?: string };
  sftp_target?: string;
};
const base = "/api/v1/settings/replay-storage";
async function removeOwnedTree(
  api: APIRequestContext,
  asset: string,
  root: string,
  current = root,
  depth = 0,
): Promise<void> {
  if (
    !/^replayqa-[a-f0-9-]{36}$/.test(root) ||
    (current !== root && !current.startsWith(root + "/")) ||
    depth > 8
  )
    throw Error("Replay QA cleanup escaped its owned directory");
  const response = await api.get(
    `/api/v1/assets/${asset}/files?path=${encodeURIComponent(current)}`,
  );
  if (response.status() === 404) return;
  expect(response.ok(), await response.text()).toBe(true);
  const { entries } = await response.json();
  for (const entry of entries as {
    name: string;
    is_dir: boolean;
    is_regular: boolean;
    is_symlink: boolean;
  }[]) {
    if (
      !/^[A-Za-z0-9_.-]+$/.test(entry.name) ||
      entry.name === "." ||
      entry.name === ".." ||
      entry.is_symlink ||
      (!entry.is_dir && !entry.is_regular)
    )
      throw Error("Replay QA cleanup found an unfamiliar entry");
    const path = current + "/" + entry.name;
    if (entry.is_dir) await removeOwnedTree(api, asset, root, path, depth + 1);
    else
      expect(
        (
          await api.delete(`/api/v1/assets/${asset}/files/content?path=${encodeURIComponent(path)}`)
        ).status(),
      ).toBe(204);
  }
  expect(
    (
      await api.delete(`/api/v1/assets/${asset}/files/content?path=${encodeURIComponent(current)}`)
    ).status(),
  ).toBe(204);
}

test("encrypted SFTP replay survives local eviction with idempotent settings, authorized playback and bilingual mobile UI", async ({
  browser,
}, info) => {
  test.setTimeout(90_000);
  const origin = info.project.use.baseURL;
  if (typeof origin !== "string" || !/^http:\/\/127\.0\.0\.\d+:\d+$/.test(origin))
    throw Error("Replay QA requires its owning loopback fixture");
  const context = await browser.newContext({
      baseURL: origin,
      locale: "en-US",
      viewport: { width: 390, height: 844 },
    }),
    page = await context.newPage(),
    api = context.request,
    errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const directory = "replayqa-" + randomUUID();
  let asset = "",
    session = "",
    initial: Config | undefined,
    changed = false;
  try {
    const credentials = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok(), await login.text()).toBe(true);
    const original = await api.get(base);
    expect(original.ok()).toBe(true);
    initial = (await original.json()).config;
    expect(initial?.provider).toBe("local");
    const health = await api.get(
      process.env.JMS_REPLAY_QA_FIXTURE_URL || "http://127.0.0.1:12242/health",
    );
    expect(health.ok()).toBe(true);
    const host = await health.json();
    expect(host.container_name).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
    const created = await api.post("/api/v1/assets", {
      data: {
        name: "Replay QA " + randomUUID(),
        host: process.env.JMS_REPLAY_QA_SSH_HOST || "127.0.0.1",
        port: Number(host.address.split(":").at(-1)),
        username: "keyqa",
        password: "synthetic-keyhost-password-233",
        host_key_fingerprint: host.fingerprint,
      },
    });
    expect(created.status(), await created.text()).toBe(201);
    asset = (await created.json()).id;
    await page.goto("/console/replay-storage");
    await page.getByRole("button", { name: "Edit storage", exact: true }).click();
    const form = page.locator(".replay-storage-form");
    await form.getByLabel("Storage provider", { exact: true }).selectOption("s3");
    await form.getByLabel("Enabled", { exact: true }).uncheck();
    await form
      .getByLabel("HTTPS storage origin", { exact: true })
      .fill("https://replay-qa.example.com");
    await form.getByLabel("Region", { exact: true }).fill("us-east-1");
    await form.getByLabel("Bucket", { exact: true }).fill("replay-qa");
    await form.getByLabel("Access key ID", { exact: true }).fill("synthetic-replay-key");
    await form
      .getByLabel("Write-only secret access key", { exact: true })
      .fill("synthetic-replay-secret");
    const saving = page.waitForResponse(
      (r) => r.request().method() === "PUT" && new URL(r.url()).pathname === base,
    );
    await form.getByRole("button", { name: "Save storage", exact: true }).click();
    const saved = await saving;
    expect(saved.status(), await saved.text()).toBe(200);
    changed = true;
    const cloud = await saved.json();
    expect(cloud.has_secret).toBe(true);
    expect(JSON.stringify(cloud)).not.toContain("synthetic-replay-secret");
    const originalRequest = saved.request().postDataJSON();
    const replayed = await api.put(base, { data: originalRequest });
    expect(await replayed.json()).toEqual(cloud);
    expect(
      (await api.put(base, { data: { ...originalRequest, request_id: randomUUID() } })).status(),
    ).toBe(409);
    await page.getByRole("button", { name: "Edit storage", exact: true }).click();
    await form.getByLabel("Storage provider", { exact: true }).selectOption("sftp");
    await form.getByLabel("Storage asset or account ID", { exact: true }).fill(asset);
    await form.getByLabel("Relative SFTP directory", { exact: true }).fill(directory);
    const sftpSaving = page.waitForResponse(
      (r) => r.request().method() === "PUT" && new URL(r.url()).pathname === base,
    );
    await form.getByRole("button", { name: "Save storage", exact: true }).click();
    const sftpSaved = await sftpSaving;
    expect(sftpSaved.status(), await sftpSaved.text()).toBe(200);
    expect((await sftpSaved.json()).sftp_target).toMatch(/^[a-f0-9]{64}$/);
    const opened = await api.post("/api/v1/sessions", {
      data: { asset_id: asset, cols: 80, rows: 24 },
    });
    expect(opened.status(), await opened.text()).toBe(201);
    session = (await opened.json()).session_id;
    expect((await api.delete("/api/v1/sessions/" + session)).status()).toBe(204);
    await expect
      .poll(
        async () => {
          const r = await api.get(`${base}/records/terminal/${session}`);
          return r.ok() ? (await r.json()).status : "missing";
        },
        { timeout: 25_000 },
      )
      .toBe("stored");
    const queue = { request_id: randomUUID() },
      recordPath = `${base}/records/terminal/${session}`;
    const queued = await api.post(recordPath + "/archive", { data: queue });
    expect(queued.ok()).toBe(true);
    expect(await (await api.post(recordPath + "/archive", { data: queue })).json()).toEqual(
      await queued.json(),
    );
    await page.getByRole("button", { name: "Reload", exact: true }).click();
    const card = page.getByRole("article", { name: session, exact: true });
    await expect(card).toContainText("Stored and verified");
    page.on("dialog", (dialog) => void dialog.accept());
    const eviction = page.waitForResponse(
      (r) => r.request().method() === "POST" && new URL(r.url()).pathname === recordPath + "/evict",
    );
    await card.getByRole("button", { name: "Remove local original", exact: true }).click();
    const evicted = await eviction;
    expect(evicted.status(), await evicted.text()).toBe(200);
    const evictionBody = await evicted.json();
    expect(evictionBody.local_evicted_at).toBeTruthy();
    expect(
      await (
        await api.post(recordPath + "/evict", { data: evicted.request().postDataJSON() })
      ).json(),
    ).toEqual(evictionBody);
    const replay = await api.get(`/api/v1/sessions/${session}/replay`);
    expect(replay.status()).toBe(200);
    const header = JSON.parse(
      gunzipSync(await replay.body())
        .toString("utf8")
        .split("\n")[0],
    );
    expect(header.env.JMS_SESSION_ID).toBe(session);
    expect(header.version).toBe(2);
    const verification = page.waitForResponse(
      (r) =>
        r.request().method() === "POST" && new URL(r.url()).pathname === recordPath + "/verify",
    );
    await card.getByRole("button", { name: "Verify remote copy", exact: true }).click();
    const verified = await verification;
    expect(verified.status(), await verified.text()).toBe(200);
    expect(
      await (
        await api.post(recordPath + "/verify", { data: verified.request().postDataJSON() })
      ).json(),
    ).toEqual(await verified.json());
    await page.getByLabel("Show management audit", { exact: true }).check();
    await expect(page.locator(".labels-audit")).toContainText("Remove local original");
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "录像存储", exact: true })).toBeVisible();
    await expect(card).toContainText("远程校验后已清理");
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await page.screenshot({ path: info.outputPath("replay-storage-zh.png"), fullPage: true });
    expect(errors).toEqual([]);
  } finally {
    if (session) await api.delete("/api/v1/sessions/" + session);
    if (changed && initial) {
      const current = await api.get(base);
      if (current.ok()) {
        const config = (await current.json()).config;
        expect(
          (
            await api.put(base, {
              data: { ...initial, revision: config.revision, request_id: randomUUID() },
            })
          ).status(),
        ).toBe(200);
      }
    }
    try {
      if (asset && changed) await removeOwnedTree(api, asset, directory);
    } finally {
      if (asset) await api.delete("/api/v1/assets/" + asset);
      await context.close();
    }
  }
});
