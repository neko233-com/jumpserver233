// Reuse the owning native installation/SSH fixture; this helper owns no resources.
import { randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

async function until(read, accept, message) {
  for (let n = 0; n < 240; n++) {
    const value = await read();
    if (accept(value)) return value;
    await delay(100);
  }
  throw Error(message);
}

export async function verifyOperationDirectories({api, admin, run, runInput, owner, sshHost, fingerprint, workspace, directory, sibling, primary, report}) {
  report.operationDirectoriesStep = "fixtures";
  const host = await api("POST", "/api/v1/assets", {name: "Native operation directory host", host: sshHost, port: 22, username: "keyqa", password: "synthetic-keyhost-password-233", host_key_fingerprint: fingerprint, ssh_workspace: workspace}, admin, 201);
  const planInput = (extra = {}) => ({name: "Directory " + randomUUID(), asset_ids: [host.id], command: "pwd -P", working_directory: directory, timeout_seconds: 10, kind: "batch", request_id: randomUUID(), ...extra});
  const create = input => api("POST", "/api/v1/ops/plans", input, admin, 201);
  const waitRun = async (plan, expected = "succeeded") => {
    const p = await until(() => api("GET", `/api/v1/ops/plans/${plan.id}`, undefined, admin), p => Boolean(p.last_run_id), "Directory plan was not dispatched");
    const result = await until(() => api("GET", `/api/v1/ops/runs/${p.last_run_id}`, undefined, admin), r => ["succeeded", "failed", "partial", "cancelled"].includes(r.state), "Directory run did not finish");
    if (result.state !== expected || result.working_directory !== directory) throw Error("Operation lost its directory or did not reach the expected result");
    return result;
  };
  const verifyJobs = async result => {
    for (const item of result.items) {
      const ids = item.steps?.length ? item.steps.filter(s => s.job_id).map(s => s.job_id) : [item.job_id];
      if (!ids.length || ids.some(id => !id)) throw Error("Operation has no remote job evidence");
      for (const id of ids) {
        const job = await api("GET", `/api/v1/ops/jobs/${id}`, undefined, admin);
        if (job.state !== "succeeded" || job.working_directory !== directory || job.execution_directory !== directory || !job.stdout.includes(directory)) throw Error("Remote operation did not execute in its verified directory");
      }
    }
  };

  const template = await api("POST", "/api/v1/ops/templates", {name: "Native directory snapshot template", command: "pwd -P", timeout_seconds: 10, working_directory: directory}, admin, 201);
  const raw = planInput({template_id: template.id}); delete raw.command; delete raw.working_directory;
  const templated = await create(raw);
  await verifyJobs(await waitRun(templated));
  const changed = await api("PUT", `/api/v1/ops/templates/${template.id}`, {name: template.name, command: template.command, timeout_seconds: template.timeout_seconds, revision: template.revision, working_directory: sibling}, admin);
  await api("DELETE", `/api/v1/ops/templates/${template.id}?revision=${changed.revision}`, undefined, admin, 204);
  await run("docker", ["pause", sshHost]);
  try {
    const started = performance.now();
    const replay = await create(raw);
    if (replay.id !== templated.id || replay.working_directory !== directory || performance.now() - started > 2500) throw Error("Template replay depended on current template or live SSH");
    await api("POST", "/api/v1/ops/plans", {...raw, working_directory: sibling}, admin, 409);
  } finally { await run("docker", ["unpause", sshHost]); }
  report.operationDirectoriesStep = "schedules";
  const batch = await create(planInput({asset_ids: [host.id, primary.id]}));
  const batchRun = await waitRun(batch); await verifyJobs(batchRun);
  if (batchRun.items.length !== 2) throw Error("Multi-host directory batch lost a host");
  const cliInput = planInput();
  const cli = async () => JSON.parse((await runInput("docker", ["exec", "-i", owner, "sh", "-ceu", 'JMS_TOKEN="$JMS_ADMIN_TOKEN" JMS_SERVER_URL=http://127.0.0.1:8080 /tmp/controller/jms ops create --file -'], JSON.stringify(cliInput))).stdout);
  const cliPlan = await cli();
  await verifyJobs(await waitRun(cliPlan));
  if ((await cli()).id !== cliPlan.id) throw Error("Native Ops CLI directory replay created another plan");
  const once = await create(planInput({kind: "once", run_at: new Date(Date.now() + 2500).toISOString()}));
  await verifyJobs(await waitRun(once));
  const triggerReceipts = [];
  for (const kind of ["interval", "cron"]) {
    const p = await create(planInput({kind, run_at: new Date(Date.now() + 3600000).toISOString(), ...(kind === "interval" ? {interval_seconds: 60} : {cron_expression: "* * * * *", timezone: "UTC"})}));
    const request = {request_id: randomUUID()};
    const first = await api("POST", `/api/v1/ops/plans/${p.id}/runs`, request, admin, 201);
    const again = await api("POST", `/api/v1/ops/plans/${p.id}/runs`, request, admin, 201);
    if (first.id !== again.id || first.working_directory !== directory) throw Error("Manual directory trigger was not idempotent");
    await verifyJobs(await waitRun(p));
    triggerReceipts.push(first.id);
    const current = await api("GET", `/api/v1/ops/plans/${p.id}`, undefined, admin);
    await api("PUT", `/api/v1/ops/plans/${p.id}`, {enabled: false, revision: current.config_revision}, admin);
  }
  report.operationDirectoriesStep = "policy";
  const rule = await api("POST", "/api/v1/command-filters", {name: "Native batch directory denial", asset_id: primary.id, account: primary.username, match: "exact", pattern: "mkdir batch-directory-denied", action: "deny", directory_match: "tree", directory_pattern: directory}, admin, 201);
  await waitRun(await create(planInput({asset_ids: [primary.id], command: "mkdir batch-directory-denied"})), "failed");
  await run("docker", ["exec", sshHost, "test", "!", "-e", directory + "/batch-directory-denied"]);
  await api("DELETE", `/api/v1/command-filters/${rule.id}`, undefined, admin, 204);
  await api("POST", "/api/v1/ops/plans", planInput({working_directory: workspace + "-outside"}), admin, 400);

  report.operationDirectoriesStep = "playbooks";
  const book = await api("POST", "/api/v1/ops/playbooks", {name: "Native directory Playbook", files: {"main.yml": "- tasks:\n  - command: pwd -P\n  - command: pwd -P\n"}}, admin, 201);
  const bookInput = planInput({playbook_id: book.id}); delete bookInput.command;
  const bookRun = await waitRun(await create(bookInput)); await verifyJobs(bookRun);
  if (bookRun.items[0].steps.length !== 2) throw Error("Playbook directory was not exercised on every remote step");
  const deniedBook = await api("POST", "/api/v1/ops/playbooks", {name: "Unsupported wrapper stays denied", files: {"main.yml": "- tasks:\n  - command: touch playbook-directory-denied\n"}}, admin, 201);
  const deniedInput = planInput({asset_ids: [primary.id], playbook_id: deniedBook.id}); delete deniedInput.command;
  await waitRun(await create(deniedInput), "failed");
  await run("docker", ["exec", sshHost, "test", "!", "-e", directory + "/playbook-directory-denied"]);
  report.operationDirectories = {hostID: host.id, batchPlanID: batch.id, templatePlanID: templated.id, playbookRunID: bookRun.id, directory, immutableTemplateSnapshot: true, replayWithoutLiveSSH: true, changedReplayConflicts: true, multiHostRealSSH: true, nativeOpsCLIAndReplay: true, onceScheduledRealSSH: true, intervalAndCronManualTriggers: triggerReceipts.length, manualTriggerReplay: true, everyPlaybookStepVerified: true, deniedCommandNeverExecuted: true, unsupportedWrapperStillDenied: true, outsideWorkspaceRefused: true, nativeNamespace: owner};
}

export async function verifyOperationDirectoryBrowser({page, expect, url, api, admin, directory, output, report}) {
  const host = report.operationDirectories.hostID, name = "Browser operation directory snapshot";
  report.operationDirectoriesStep = "browser";
  await page.goto(url + "/workbench");
  const panel = page.locator(".operations-panel");
  await panel.locator(":scope > summary").click();
  const templates = panel.locator(".operations-templates");
  await templates.locator(":scope > summary").click();
  await templates.getByLabel("Template name", {exact: true}).fill(name);
  await templates.getByLabel("Template command", {exact: true}).fill("pwd -P");
  await templates.getByLabel("Template execution directory (optional)", {exact: true}).fill(directory);
  const saved = page.waitForResponse(r => r.request().method() === "POST" && new URL(r.url()).pathname === "/api/v1/ops/templates");
  await templates.getByRole("button", {name: "Save template", exact: true}).click();
  const response = await saved;
  if (response.status() !== 201) throw Error("Browser directory template save failed");
  const tpl = await response.json();
  await panel.getByLabel("Plan name", {exact: true}).fill(name);
  await panel.getByRole("checkbox", {name: "Native operation directory host (keyqa)", exact: true}).check();
  await panel.getByRole("combobox", {name: "Command source", exact: true}).selectOption(tpl.id);
  const input = panel.getByLabel("Execution directory (optional)", {exact: true});
  await expect(input).toHaveValue(directory); await expect(input).toBeDisabled();
  const created = page.waitForResponse(r => r.request().method() === "POST" && new URL(r.url()).pathname === "/api/v1/ops/plans");
  await panel.getByRole("button", {name: "Create plan", exact: true}).click();
  const planResponse = await created;
  if (planResponse.status() !== 201) throw Error("Browser directory plan creation failed");
  // The UI only consumes this POST's status. Read its durable receipt through
  // the authenticated API, as the production browser suite does; Chromium may
  // leave an unconsumed fetch body unavailable through DevTools indefinitely.
  const posted = planResponse.request().postDataJSON();
  const plan = (await api("GET", "/api/v1/ops/plans", undefined, admin)).find(p => p.request_id === posted.request_id);
  if (!plan) throw Error("Accepted browser plan has no matching durable receipt");
  if (plan.asset_ids.length !== 1 || plan.asset_ids[0] !== host || plan.working_directory !== directory) throw Error("Browser plan lost selected host or saved directory");
  const row = panel.locator(":scope > div > .jobs-table-scroll > table.jobs-table").first().getByRole("row").filter({hasText: name});
  await expect(row).toBeVisible({timeout: 10000});
  await expect(row).toContainText(directory);
  await row.screenshot({path: resolve(output, "execution.en.png")});
  const current = await until(
    () => api("GET", `/api/v1/ops/plans/${plan.id}`, undefined, admin),
    p => typeof p.last_run_id === "string" && p.last_run_id.length > 0,
    "Browser directory plan was not dispatched",
  );
  await expect.poll(async () => (await api("GET", `/api/v1/ops/runs/${current.last_run_id}`, undefined, admin)).state).toBe("succeeded");
  const browserRun = await api("GET", `/api/v1/ops/runs/${current.last_run_id}`, undefined, admin);
  const browserJob = await api("GET", `/api/v1/ops/jobs/${browserRun.items[0].job_id}`, undefined, admin);
  if (browserJob.execution_directory !== directory || browserJob.stdout.trim() !== directory) throw Error("Browser-created plan did not run in its saved directory");
  await page.getByRole("button", {name: "中文", exact: true}).click();
  await page.setViewportSize({width: 390, height: 844});
  await expect(panel.getByLabel("执行目录（可选）", {exact: true})).toHaveValue(directory);
  const form = panel.locator(":scope > div > form.operations-form");
  await form.screenshot({path: resolve(output, "execution.zh.png")});
  const box = await form.boundingBox();
  if (!box || box.x < 0 || box.x + box.width > 392) throw Error("Operation directory form overflows mobile viewport");
  report.operationDirectories.browserTemplateAndPlanCreated = true;
  report.operationDirectories.browserBilingualDesktopAndMobile = true;
  await page.setViewportSize({width: 1280, height: 900});
  await page.getByRole("button", {name: "EN", exact: true}).click();
}
