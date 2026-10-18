import { test, expect, request } from "@playwright/test";
import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
const execute = promisify(execFile),
  base = process.env.JMS_PLAYBOOK_QA_BASE_URL || "http://127.0.0.1:8083",
  ui = process.env.JMS_PLAYBOOK_QA_BASE_URL || "http://127.0.0.1:5177";
if (!/^http:\/\/127\.0\.0\.\d+:\d+$/.test(base))
  throw Error("Playbook QA requires loopback isolation");
test.use({ locale: "en-US", trace: "off" });
test("native Playbooks run real SSH modules, preserve source snapshots, enforce ownership and render bilingual workspaces", async ({
  browser,
}, info) => {
  test.setTimeout(180_000);
  const api = await request.newContext({ baseURL: base }),
    context = await browser.newContext({
      locale: "en-US",
      viewport: { width: 1440, height: 1080 },
    }),
    page = await context.newPage(),
    errors: string[] = [];
  context.setDefaultTimeout(10_000);
  page.on("pageerror", (e) => errors.push(e.message));
  const stamp = Date.now(),
    name = `Playbook host ${stamp}`,
    bookName = `Playbook source ${stamp}`,
    planName = `Playbook plan ${stamp}`,
    directory = `/tmp/jms233-playbook-${stamp}`,
    retain = process.env.JMS_PLAYBOOK_QA_RETAIN === "true";
  let asset = "",
    book = "",
    plan = "",
    foreign = "",
    run = "";
  try {
    const credentials = {
      username: process.env.JMS_PLAYBOOK_QA_USERNAME || "e2e.admin",
      password: process.env.JMS_PLAYBOOK_QA_PASSWORD || "synthetic-e2e-admin-password-2468",
    };
    let login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    if (!login.ok()) {
      await api.post("/api/v1/authentication/bootstrap", { data: credentials });
      login = await api.post("/api/v1/authentication/auth/", { data: credentials });
    }
    expect(login.ok()).toBe(true);
    const token = (await login.json()).access_token;
    await context.request.post(base + "/api/v1/authentication/auth/", { data: credentials });
    const host = await (
      await api.get(process.env.JMS_PLAYBOOK_QA_FIXTURE_URL || "http://127.0.0.1:12242/health")
    ).json();
    const created = await api.post("/api/v1/assets", {
      data: {
        name,
        host: process.env.JMS_PLAYBOOK_QA_SSH_HOST || "127.0.0.1",
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
    await page.goto(ui + "/workbench");
    const panel = page.locator(".operations-panel");
    await panel.locator(":scope > summary").click();
    await panel.locator(".playbooks-manager > summary").click();
    await panel.getByRole("button", { name: "New Playbook", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await dialog.getByLabel("Workspace name", { exact: true }).fill(bookName);
    const source = `- hosts: all
  vars: {message: ready}
  tasks:
    - name: Owned directory
      file: {path: '${directory}', state: directory, mode: '0700'}
    - name: Render file
      template: {src: health.j2, dest: '${directory}/health.txt', mode: '0600'}
      notify: rendered
    - name: File facts
      stat: {path: '${directory}/health.txt'}
      register: health
    - name: Check file
      assert: {that: health.stat.exists and health.stat.size == 5}
    - name: Print loop
      command: {argv: [printf, '%s', '{{ item }}']}
      loop: [first, second]
      register: printed
    - name: Check loop
      assert: {that: "printed.results[1].stdout == 'second'"}
    - name: Skipped
      fail: {msg: never}
      when: false
  handlers:
    - name: rendered
      debug: {msg: rendered}
`;
    await dialog.getByRole("textbox", { name: "File content", exact: true }).fill(source);
    await dialog.getByLabel("New file path", { exact: true }).fill("health.j2");
    await dialog.getByRole("button", { name: "Add file", exact: true }).click();
    await dialog.getByRole("textbox", { name: "File content", exact: true }).fill("{{ message }}");
    await dialog.getByRole("button", { name: "Validate workspace", exact: true }).click();
    await expect(dialog.getByRole("status")).toContainText("Workspace valid");
    await dialog.getByRole("button", { name: "Save workspace", exact: true }).click();
    await expect(dialog).not.toBeVisible();
    await expect(panel.getByRole("row").filter({ hasText: bookName })).toBeVisible();
    const books = await (await api.get("/api/v1/ops/playbooks?offset=0&limit=100")).json();
    book = books.results.find((v: any) => v.name === bookName).id;
    const user = await api.post("/api/v1/users", {
      data: {
        username: `playbook.foreign.${stamp}`,
        password: "synthetic-playbook-foreign-233",
        role: "operator",
      },
    });
    expect(user.status()).toBe(201);
    foreign = (await user.json()).id;
    const outsider = await request.newContext({ baseURL: base });
    try {
      expect(
        (
          await outsider.post("/api/v1/authentication/auth/", {
            data: {
              username: `playbook.foreign.${stamp}`,
              password: "synthetic-playbook-foreign-233",
            },
          })
        ).ok(),
      ).toBe(true);
      expect((await outsider.get("/api/v1/ops/playbooks/" + book)).status()).toBe(404);
      expect(
        (
          await outsider.post("/api/v1/ops/playbooks", {
            data: {
              name: "forbidden publish",
              visibility: "organization",
              files: { "main.yml": "- tasks: [{debug: {msg: ok}}]" },
            },
          })
        ).status(),
      ).toBe(403);
    } finally {
      await outsider.dispose();
    }
    await panel
      .getByRole("row")
      .filter({ hasText: bookName })
      .getByRole("button", { name: "Use for a plan", exact: true })
      .click();
    await panel.getByLabel("Plan name", { exact: true }).fill(planName);
    await panel.getByRole("checkbox", { name: `${name} (keyqa)`, exact: true }).check();
    await panel
      .getByRole("textbox", { name: "Run variables (JSON object)", exact: true })
      .fill('{"message":"ready"}');
    await panel.getByRole("button", { name: "Create plan", exact: true }).click();
    await expect(panel.getByRole("status")).toHaveText(
      "Plan created with a saved command snapshot.",
    );
    const plans = await (await api.get("/api/v1/ops/plans")).json();
    plan = plans.find((v: any) => v.name === planName).id;
    await expect
      .poll(
        async () => {
          const p = await (await api.get("/api/v1/ops/plans/" + plan)).json();
          run = p.last_run_id || "";
          return run ? (await (await api.get("/api/v1/ops/runs/" + run)).json()).state : "pending";
        },
        { timeout: 60_000 },
      )
      .toBe("succeeded");
    const first = await (await api.get("/api/v1/ops/runs/" + run)).json();
    expect(first.items[0].steps).toHaveLength(9);
    expect(first.items[0].steps.filter((v: any) => v.module === "command")).toHaveLength(2);
    expect(first.items[0].steps.every((v: any) => !v.local && !v.pending_command)).toBe(true);
    const detail = await (await api.get("/api/v1/ops/playbooks/" + book)).json();
    const updated = await api.put("/api/v1/ops/playbooks/" + book, {
      data: {
        name: bookName,
        visibility: "organization",
        revision: detail.revision,
        files: { "main.yml": "- tasks: [{fail: {msg: changed-source-must-not-run}}]" },
      },
    });
    expect(updated.status()).toBe(200);
    expect(
      (
        await api.put("/api/v1/ops/playbooks/" + book, {
          data: {
            name: bookName,
            visibility: "private",
            revision: detail.revision,
            files: detail.files,
          },
        })
      ).status(),
    ).toBe(409);
    expect(
      (await (await api.get("/api/v1/ops/runs/" + run + "/program")).json()).files["main.yml"],
    ).toBe(source);
    const step = first.items[0].steps.find((v: any) => v.name === "Print loop");
    const output = await (
      await api.get(`/api/v1/ops/runs/${run}/steps/${asset}/${step.id}`)
    ).json();
    expect(output.result.stdout).toBe("first");
    await panel
      .getByRole("row")
      .filter({ hasText: planName })
      .getByRole("button", { name: "Details", exact: true })
      .click();
    await expect(panel.getByRole("heading", { name: "Playbook steps", exact: true })).toBeVisible();
    await panel.getByRole("button", { name: "Read saved source", exact: true }).click();
    await expect(panel.locator(".playbook-run pre").first()).toHaveText(source);
    await page.screenshot({ path: info.outputPath("playbooks.en.png"), fullPage: false });
    const json = info.outputPath("workspace.json");
    await writeFile(json, JSON.stringify({ files: detail.files }));
    const env = {
      ...process.env,
      JMS_SERVER_URL: base,
      JMS_TOKEN: token,
      JMS_ORG_ID: "",
      JMS_ACCOUNT: "",
      JMS_ACCESS_KEY_ID: "",
      JMS_ACCESS_KEY_SECRET: "",
    };
    const cli = async (args: string[]) =>
      JSON.parse(
        (
          await execute("go", ["run", "./cmd/jms", "ops", ...args], {
            cwd: fileURLToPath(new URL("../../server", import.meta.url)),
            env,
            timeout: 60_000,
          })
        ).stdout,
      );
    expect((await cli(["validate", "--file", json])).valid).toBe(true);
    expect((await cli(["program", run])).files["main.yml"]).toBe(source);
    expect((await cli(["step", run, asset, step.id])).result.stdout).toBe("first");
    const trigger = await api.post(`/api/v1/ops/plans/${plan}/runs`, {
      data: { request_id: `manual-${stamp}` },
    });
    expect(trigger.status()).toBe(201);
    const manual = (await trigger.json()).id;
    expect(
      (
        await (
          await api.post(`/api/v1/ops/plans/${plan}/runs`, {
            data: { request_id: `manual-${stamp}` },
          })
        ).json()
      ).id,
    ).toBe(manual);
    await expect
      .poll(async () => (await (await api.get("/api/v1/ops/runs/" + manual)).json()).state, {
        timeout: 60_000,
      })
      .toBe("succeeded");
    expect((await (await api.get("/api/v1/ops/runs/" + manual)).json()).program_id).toBe(
      first.program_id,
    );
    const zh = await browser.newContext({ locale: "zh-CN", viewport: { width: 390, height: 844 } });
    await zh.addCookies((await context.storageState()).cookies);
    const mobile = await zh.newPage();
    mobile.on("pageerror", (e) => errors.push(e.message));
    await mobile.goto(ui + "/workbench");
    await expect(mobile.locator("html")).toHaveAttribute("lang", "zh-CN");
    await mobile.locator(".operations-panel > summary").click();
    await mobile.locator(".playbooks-manager > summary").click();
    await mobile
      .locator(".playbooks-manager")
      .getByRole("row")
      .filter({ hasText: bookName })
      .getByRole("button")
      .first()
      .click();
    await expect(mobile.getByRole("dialog")).toBeVisible();
    expect(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    await mobile.screenshot({ path: info.outputPath("playbooks.zh-CN.png"), fullPage: false });
    await zh.close();
    expect(errors).toEqual([]);
  } finally {
    if (!retain) {
      if (plan) {
        const p = await (await api.get("/api/v1/ops/plans/" + plan)).json();
        if (p.last_run_id) await api.post(`/api/v1/ops/runs/${p.last_run_id}/cancel`);
      }
      if (book) {
        const b = await (await api.get("/api/v1/ops/playbooks/" + book)).json();
        await api.delete(`/api/v1/ops/playbooks/${book}?revision=${b.revision}`);
      }
      if (foreign) await api.delete("/api/v1/users/" + foreign);
      if (asset) await api.delete("/api/v1/assets/" + asset);
    }
    await context.close().catch(() => {});
    await api.dispose();
  }
});
