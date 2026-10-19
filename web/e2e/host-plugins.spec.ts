import { test, expect, request, type APIRequestContext } from "@playwright/test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
const execute = promisify(execFile);
const admin = { username: "e2e.admin", password: "synthetic-e2e-admin-password-2468" };
let token = "";
let cookies: Parameters<import("@playwright/test").BrowserContext["addCookies"]>[0] = [];
let asset = "";
let protectionAsset = "";
let hostName = "";
let hostOwner = "";
test.describe.configure({ mode: "serial" });
test.use({ locale: "en-US" });
test.beforeAll(async () => {
  const api = await request.newContext({ baseURL: "http://127.0.0.1:8083" });
  try {
    let r = await api.post("/api/v1/authentication/bootstrap", { data: admin });
    if (r.status() !== 201) r = await api.post("/api/v1/authentication/auth/", { data: admin });
    expect(r.ok()).toBe(true); token = (await r.json()).access_token;
    cookies = (await api.storageState()).cookies;
    const host = await (await api.get("http://127.0.0.1:12242/health")).json();
    hostName = host.container_name; hostOwner = host.owner;
    const created = await api.post("/api/v1/assets", { headers: { Authorization: `Bearer ${token}` }, data: { name: "Native host agents QA", host: "127.0.0.1", port: 12241, username: "pluginqa", password: "synthetic-keyhost-password-233", host_key_fingerprint: host.fingerprint } });
    expect(created.status()).toBe(201); asset = (await created.json()).id;
    const root = await api.post("/api/v1/assets",{headers:{Authorization:`Bearer ${token}`},data:{name:"Native SSH protection QA",host:"127.0.0.1",port:12241,username:"root",password:"synthetic-protection-root-password-233",host_key_fingerprint:host.fingerprint}});
    expect(root.status()).toBe(201); protectionAsset=(await root.json()).id;
  } finally { await api.dispose(); }
});
test("native BanHack installation, agent lifecycle, diagnostics and bilingual UI", async ({ page }) => {
  test.setTimeout(240_000);
  const errors: string[] = []; page.on("pageerror", e => errors.push(e.message));
  await page.context().addCookies(cookies); await page.goto("/console");
  const row = page.getByRole("row").filter({ hasText: "Native host agents QA" });
  await row.getByRole("button", { name: "Tools & agents", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Host tools & agents", exact: true });
  const card = dialog.getByRole("region", { name: "banhack233 security agent", exact: true });
  await expect(card).toBeVisible();
  await dialog.press("Shift+Tab");
  await expect(dialog.locator("summary").last()).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(dialog.getByRole("button", { name: "Close", exact: true })).toBeFocused();
  const perform = async (action: string) => {
    const submitted = page.waitForResponse(r => r.url().includes("/host-plugins/banhack233/jobs") && r.request().method() === "POST");
    await card.getByRole("button", { name: action, exact: true }).click();
    const r = await submitted; expect(r.status()).toBe(201);
    const job = await r.json();
    await expect.poll(async () => {
      const next = await page.request.get(`/api/v1/ops/jobs/${job.id}`); return (await next.json()).state;
    }, { timeout: 150_000 }).toBe("succeeded");
    await expect(dialog.locator(".host-plugin-job")).toContainText("Succeeded");
  };
  await perform("Detect"); await expect(card).toContainText("Not installed");
  await perform("Install"); await expect(card).toContainText("Stopped");
  await perform("Start agent"); await expect(card).toContainText("Running");
  await card.getByText("Diagnostics & details", { exact: true }).click();
  await perform("Host inspection"); await expect(card.getByLabel("Tool output", { exact: true })).not.toBeEmpty();
  await perform("Enable supervision"); await expect(card).toContainText("Boot & recovery enabled");
  await perform("Stop agent"); await expect(card).toContainText("Stopped");
  await expect(card).toContainText("Supervision disabled");
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "中文", exact: true }).click();
  await row.getByRole("button", { name: "工具与 Agent", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("主机工具与 Agent");
  await expect(page.getByRole("dialog")).toContainText("banhack233 安全 Agent");
  await expect(page.locator("html")).toHaveAttribute("lang", "zh-CN");
  await page.getByRole("dialog").getByRole("button", { name: "关闭", exact: true }).click();
  expect(errors).toEqual([]);
});
test("Agent CLI installs exporter, reads native metrics and returns JSON audit IDs", async ({ request: api }) => {
  test.setTimeout(240_000);
  const serverDir = resolve(fileURLToPath(new URL(".", import.meta.url)), "../../server");
  async function cli(action: string) {
    let result;
    try {
      result = await execute("go", ["run", "./cmd/jms", "plugin", asset, "node_exporter", action,...(action==="install"?["--version","1.12.0"]:[])], { cwd: serverDir, env: { ...process.env, JMS_SERVER_URL: "http://127.0.0.1:8083", JMS_TOKEN: token }, timeout: 180_000, maxBuffer: 1024 * 1024 });
    } catch (error) {
      let detail: Record<string, unknown> = { action };
      try {
        const job = JSON.parse((error as { stdout?: string }).stdout || "{}");
        const value = JSON.parse(job.stdout || "{}");
        detail = { action, state: job.state, error_code: job.error_code, detail: value.detail };
      } catch { /* Preserve the CLI's nonzero result without printing credentials. */ }
      throw new Error(`Plugin CLI failed: ${JSON.stringify(detail)}`);
    }
    const job = JSON.parse(result.stdout); expect(job.state).toBe("succeeded"); expect(job.plugin.plugin).toBe("node_exporter"); expect(job.stdout).not.toContain("synthetic-keyhost-password"); return JSON.parse(job.stdout);
  }
  expect((await cli("install")).installed).toBe(true); expect((await cli("start")).running).toBe(true);
  const result = await cli("metrics"); expect(result.output).toContain("node_cpu_seconds_total");
  expect((await cli("autostart_enable")).autostart).toBe(true);
  expect((await cli("autostart_disable")).autostart).toBe(false);
  expect((await cli("stop")).running).toBe(false);
  const operator = await api.post("http://127.0.0.1:8083/api/v1/users", { headers: { Authorization: `Bearer ${token}` }, data: { username: "plugin.viewer", password: "synthetic-plugin-viewer-password", role: "operator" } });
  expect(operator.status()).toBe(201);
  const login = await api.post("http://127.0.0.1:8083/api/v1/authentication/auth/", { data: { username: "plugin.viewer", password: "synthetic-plugin-viewer-password" } });
  const denied = await api.post(`http://127.0.0.1:8083/api/v1/assets/${asset}/host-plugins/banhack233/jobs`, { headers: { Authorization: `Bearer ${(await login.json()).access_token}` }, data: { action: "install", request_id: "viewer-denied" } });
  expect(denied.status()).toBe(403);
});

async function pluginJob(api:APIRequestContext,id:string,plugin:string,action:string,extra:Record<string,unknown>={}) {
  const response=await api.post(`http://127.0.0.1:8083/api/v1/assets/${id}/host-plugins/${plugin}/jobs`,{headers:{Authorization:`Bearer ${token}`},data:{action,request_id:crypto.randomUUID(),...extra}});
  expect(response.status()).toBe(201); const submitted=await response.json();
  let job: {state:string;stdout:string}|undefined;
  await expect.poll(async()=>{const next=await api.get(`http://127.0.0.1:8083/api/v1/ops/jobs/${submitted.id}`,{headers:{Authorization:`Bearer ${token}`}});job=await next.json() as {state:string;stdout:string};return job.state;},{timeout:120_000,intervals:[200,500,1000]}).toBe("succeeded");
  return JSON.parse(job!.stdout);
}

test("browser upgrades an older pinned exporter, rolls back and restores the latest release",async({page})=>{
  test.setTimeout(90_000);await page.context().addCookies(cookies);await page.goto("/console");
  await page.getByRole("row").filter({hasText:"Native host agents QA"}).getByRole("button",{name:"Tools & agents",exact:true}).click();
  const dialog=page.getByRole("dialog");const card=dialog.getByRole("region",{name:"node_exporter monitoring agent",exact:true});
  const perform=async(name:string)=>{
    const submitted=page.waitForResponse(r=>r.url().includes(`/assets/${asset}/host-plugins/node_exporter/jobs`)&&r.request().method()==="POST");
    await card.getByRole("button",{name,exact:true}).click();
    const created=await submitted;expect(created.status()).toBe(201);const job=await created.json();
    const receipt=dialog.locator(".host-plugin-job");
    await expect(receipt).toContainText(job.id);
    await expect(receipt).toContainText("Succeeded",{timeout:60_000});
  };
  await perform("Status");await expect(card).toContainText("Installed v1.12.0");await expect(card).toContainText("Upgrade available: v1.12.1");
  await card.getByText("Diagnostics & details",{exact:true}).click();
  await perform("Upgrade to pinned release");await expect(card).toContainText("Installed v1.12.1");
  await perform("Roll back release");await expect(card).toContainText("Installed v1.12.0");
  await perform("Upgrade to pinned release");await expect(card).toContainText("Installed v1.12.1");
  await dialog.getByRole("button",{name:"Close",exact:true}).click();
});

test("native agents recover after host reboot and process crash, then uninstall without losing data", async ({ request: api }) => {
  test.setTimeout(180_000);
  expect(hostName).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
  expect(hostOwner).toMatch(/^jumpserver233-e2e-/);
  const inspected = await execute("docker", ["inspect", "--format", "{{json .Config.Labels}}", hostName]);
  expect(JSON.parse(inspected.stdout)["com.jumpserver233.qa.owner"]).toBe(hostOwner);
  const call = async (plugin: string, action: string) => {
    const created = await api.post(`http://127.0.0.1:8083/api/v1/assets/${asset}/host-plugins/${plugin}/jobs`, {
      headers: { Authorization: `Bearer ${token}` }, data: { action, request_id: crypto.randomUUID() },
    });
    expect(created.status()).toBe(201);
    const job = await created.json();
    let value: { state: string; stdout: string } | undefined;
    await expect.poll(async () => {
      const response = await api.get(`http://127.0.0.1:8083/api/v1/ops/jobs/${job.id}`, { headers: { Authorization: `Bearer ${token}` } });
      value = await response.json() as { state: string; stdout: string }; return value.state;
    }, { timeout: 25_000, intervals: [200, 500, 1000] }).toBe("succeeded");
    expect(value).toBeDefined();
    return JSON.parse(value!.stdout);
  };
  const plugins = ["banhack233", "node_exporter"];
  for (const plugin of plugins) expect((await call(plugin, "autostart_enable")).autostart).toBe(true);
  await execute("docker", ["restart", "--time", "2", hostName], { timeout: 60_000 });
  await expect.poll(async () => {
    try { return (await api.get("http://127.0.0.1:12242/health")).ok(); } catch { return false; }
  }, { timeout: 20_000 }).toBe(true);
  const processCheck = 'for p in banhack233 node_exporter; do d="/home/pluginqa/.jumpserver233/plugins/$p"; read -r pid stamp < "$d/pid" || exit 1; [ -r /proc/$pid/exe ] && [ "$(readlink /proc/$pid/exe)" = "$d/$(cat "$d/manifest" | cut -d " " -f 1)/$p" ] || exit 1; done';
  await expect.poll(async () => {
    try { await execute("docker", ["exec", "--user", "pluginqa", hostName, "sh", "-c", processCheck]); return true; } catch { return false; }
  }, { timeout: 20_000 }).toBe(true);
  for (const plugin of plugins) {
    const status = await call(plugin, "status"); expect(status.running).toBe(true); expect(status.autostart).toBe(true);
  }
  await execute("docker", ["exec", "--user", "pluginqa", hostName, "sh", "-c", 'for p in banhack233 node_exporter; do read -r pid stamp < "/home/pluginqa/.jumpserver233/plugins/$p/pid"; kill -KILL "$pid"; done']);
  // This waits for the real cron daemon, not a direct invocation of the launcher.
  await expect.poll(async () => {
    try { await execute("docker", ["exec", "--user", "pluginqa", hostName, "sh", "-c", processCheck]); return true; } catch { return false; }
  }, { timeout: 85_000, intervals: [1000, 2000, 3000] }).toBe(true);
  for (const plugin of plugins) {
    const status = await call(plugin, "status"); expect(status.running).toBe(true);
    const removed = await call(plugin, "uninstall"); expect(removed.running).toBe(false); expect(removed.installed).toBe(false); expect(removed.autostart).toBe(false);
    expect((await call(plugin, "uninstall")).installed).toBe(false);
  }
  await execute("docker", ["exec", "--user", "pluginqa", hostName, "sh", "-c", 'test -f /home/pluginqa/.jumpserver233/plugins/banhack233/config.json && test -f /home/pluginqa/.jumpserver233/plugins/banhack233/agent.log && ! crontab -l | grep -q "# jumpserver233-agent:"']);
});

test("host tools and console navigation fit narrow English and Chinese viewports", async ({ page }) => {
  await page.context().addCookies(cookies);
  await page.goto("/console");
  for (const width of [715, 375]) {
    await page.setViewportSize({ width, height: 826 });
    for (const language of ["en", "zh-CN"]) {
      if (await page.locator("html").getAttribute("lang") !== language)
        await page.getByRole("button", { name: language === "en" ? "EN" : "中文", exact: true }).click();
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBe(0);
      await expect(page.getByRole("button", { name: language === "en" ? "Sign out" : "退出登录", exact: true })).toBeVisible();
      const row = page.getByRole("row").filter({ hasText: "Native host agents QA" });
      await row.getByRole("button", { name: language === "en" ? "Tools & agents" : "工具与 Agent", exact: true }).click();
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      expect(await dialog.evaluate(el => el.getBoundingClientRect().right <= document.documentElement.clientWidth)).toBe(true);
      await dialog.getByRole("button", { name: language === "en" ? "Close" : "关闭", exact: true }).click();
    }
  }
});

test("bilingual production protection uses a real owned firewall and a separately authorized policy",async({page,request:api})=>{
  test.setTimeout(180_000);await page.context().addCookies(cookies);await page.goto("/console");
  await page.getByRole("row").filter({hasText:"Native SSH protection QA"}).getByRole("button",{name:"Tools & agents",exact:true}).click();
  const dialog=page.getByRole("dialog");const card=dialog.getByRole("region",{name:"banhack233 security agent",exact:true});
  const perform=async(name:string)=>{const submitted=page.waitForResponse(r=>r.url().includes(`/assets/${protectionAsset}/host-plugins/banhack233/jobs`)&&r.request().method()==="POST");await card.getByRole("button",{name,exact:true}).click();const created=await submitted;expect(created.status()).toBe(201);const job=await created.json();await expect.poll(async()=>{const next=await page.request.get(`/api/v1/ops/jobs/${job.id}`);return(await next.json()).state;},{timeout:120_000}).toBe("succeeded");await expect(dialog.locator(".host-plugin-job")).toContainText("Succeeded");};
  await perform("Install");await perform("Start agent");await card.getByText("Diagnostics & details",{exact:true}).click();
  await card.getByLabel("Protection mode",{exact:true}).selectOption("enforce");await card.getByLabel("Never-ban IPs or CIDRs (comma or space separated)",{exact:true}).fill("198.51.100.0/24");
  await perform("Apply protection policy");await expect(card).toContainText("Configured: SSH attack blocking");await expect(card.getByLabel("Protection mode",{exact:true})).toHaveValue("enforce");
  const state=await pluginJob(api,protectionAsset,"banhack233","protection_status");expect(state.protection_mode).toBe("enforce");expect(state.firewall_state).toBe("owned");expect(state.output).toContain("banhack233");expect(state.protection.ignore_ips).toContain("198.51.100.0/24");expect(state.protection.ssh_ports).toContain(22);
  await dialog.getByRole("button",{name:"Close",exact:true}).click();await page.getByRole("button",{name:"中文",exact:true}).click();
  await page.getByRole("row").filter({hasText:"Native SSH protection QA"}).getByRole("button",{name:"工具与 Agent",exact:true}).click();
  const chinese=page.getByRole("dialog").getByRole("region",{name:"banhack233 安全 Agent",exact:true});await chinese.getByRole("button",{name:"状态",exact:true}).click();await expect(chinese).toContainText("配置：SSH 攻击封禁");await chinese.getByText("诊断与详情",{exact:true}).click();await expect(chinese.getByLabel("防护模式",{exact:true})).toHaveValue("enforce");
  await page.getByRole("dialog").getByRole("button",{name:"关闭",exact:true}).click();
  const removed=await pluginJob(api,protectionAsset,"banhack233","uninstall");expect(removed.installed).toBe(false);
  const table=await execute("docker",["exec",hostName,"sh","-c","if nft list table inet banhack233 >/dev/null 2>&1; then exit 1; fi"]);expect(table.stderr).toBe("");
});

test("native recovery repairs a lost firewall while running, survives reboot and shows bilingual ban health", async ({ page, request: api }) => {
  test.setTimeout(240_000);
  expect(hostName).toMatch(/^jms233-keyhost-[a-f0-9-]{36}$/);
  const labels = await execute("docker", ["inspect", "--format", "{{json .Config.Labels}}", hostName]);
  expect(JSON.parse(labels.stdout)["com.jumpserver233.qa.owner"]).toBe(hostOwner);
  const remote = (script: string) => execute("docker", ["exec", hostName, "sh", "-eu", "-c", script], { timeout: 15_000 });
  const errors: string[] = []; page.on("pageerror", e => errors.push(e.message));
  await pluginJob(api, protectionAsset, "banhack233", "install");
  await pluginJob(api, protectionAsset, "banhack233", "start");
  await pluginJob(api, protectionAsset, "banhack233", "protection_apply", { protection: { mode: "enforce", max_attempts: 2, find_seconds: 60, ban_seconds: 240, interval_seconds: 1 } });
  await pluginJob(api, protectionAsset, "banhack233", "autostart_enable");
  await remote("ip addr replace 203.0.113.199/32 dev lo; for n in 1 2 3; do printf 'Oct 16 01:00:00 qa sshd[99]: Failed password for browserqa from 203.0.113.199 port 5555 ssh2\\n' >> /var/log/auth.log; done");
  const blocked = "nft get element inet banhack233 blocked '{ 203.0.113.199 }' >/dev/null";
  await expect.poll(async () => { try { await remote(blocked); return true; } catch { return false; } }, { timeout: 15_000 }).toBe(true);
  const before = await pluginJob(api, protectionAsset, "banhack233", "status");
  expect(before.recovery_state).toBe("ready"); expect(before.active_bans).toBeGreaterThanOrEqual(1);
  // Keep the daemon alive: its state alone cannot reconstruct a deleted table.
  // The actual cron launcher must detect this and perform a locked restart.
  const oldPID = (await remote("cut -d ' ' -f 1 /root/.jumpserver233/plugins/banhack233/pid")).stdout.trim();
  expect(oldPID).toMatch(/^\d+$/); await remote("nft delete table inet banhack233");
  await expect.poll(async () => { try { await remote(blocked + `; read -r pid stamp < /root/.jumpserver233/plugins/banhack233/pid; [ "$pid" != '${oldPID}' ]`); return true; } catch { return false; } }, { timeout: 90_000, intervals: [1000, 2000] }).toBe(true);
  await execute("docker", ["restart", "--time", "2", hostName], { timeout: 60_000 });
  await expect.poll(async () => { try { await remote(blocked); return true; } catch { return false; } }, { timeout: 25_000 }).toBe(true);
  const after = await pluginJob(api, protectionAsset, "banhack233", "status");
  expect(after.running).toBe(true); expect(after.autostart).toBe(true); expect(after.recovery_state).toBe("ready"); expect(after.active_bans).toBeGreaterThanOrEqual(1);
  await remote("ip addr replace 203.0.113.199/32 dev lo; if nc -z -w 1 -s 203.0.113.199 127.0.0.1 22; then exit 1; fi");
  await page.context().addCookies(cookies); await page.goto("/console");
  for (const locale of ["en", "zh-CN"]) {
    if (await page.locator("html").getAttribute("lang") !== locale) await page.getByRole("button", { name: locale === "en" ? "EN" : "中文", exact: true }).click();
    await page.getByRole("row").filter({ hasText: "Native SSH protection QA" }).getByRole("button", { name: locale === "en" ? "Tools & agents" : "工具与 Agent", exact: true }).click();
    const dialog = page.getByRole("dialog"); const card = dialog.getByRole("region", { name: locale === "en" ? "banhack233 security agent" : "banhack233 安全 Agent", exact: true });
    await card.getByRole("button", { name: locale === "en" ? "Status" : "状态", exact: true }).click();
    await expect(card).toContainText(locale === "en" ? "Persisted bans match the firewall" : "持久封禁与防火墙一致");
    await expect(card).toContainText(locale === "en" ? "Active sources in persisted state:" : "持久状态中的有效来源数：");
    await dialog.getByRole("button", { name: locale === "en" ? "Close" : "关闭", exact: true }).click();
  }
  expect(errors).toEqual([]);
  await pluginJob(api, protectionAsset, "banhack233", "uninstall");
});

test("native component update, paged event sync and scheduled collection appear in bilingual audit",async({page,request:api})=>{
 test.setTimeout(210_000);const errors:string[]=[];page.on("pageerror",e=>errors.push(e.message));
 await pluginJob(api,protectionAsset,"banhack233","install");await pluginJob(api,protectionAsset,"banhack233","agent_update");
 const synced=await pluginJob(api,protectionAsset,"banhack233","events");expect(synced.imported).toBeGreaterThan(0);
 const headers={Authorization:`Bearer ${token}`};const base=`http://127.0.0.1:8083/api/v1/assets/${protectionAsset}/agent-events`;
 let history=await(await api.get(base,{headers})).json();expect(history.results.some((r:{event?:{kind:string;trigger:string}})=>r.event?.kind==="repair_completed"&&r.event?.trigger==="supervisor")).toBe(true);
 const repeat=await pluginJob(api,protectionAsset,"banhack233","events");expect(repeat.imported).toBe(0);
 const enable=await api.post(`${base}/collection`,{headers,data:{enabled:true,interval_seconds:60,request_id:crypto.randomUUID()}});expect(enable.status()).toBe(201);
 await expect.poll(async()=>{history=await(await api.get(base,{headers})).json();return history.results.some((r:{kind:string;receipt?:{state:string}})=>r.kind==="collection_run"&&r.receipt?.state==="succeeded");},{timeout:85_000,intervals:[1000,3000]}).toBe(true);
 const receipts=history.results.filter((r:{kind:string})=>r.kind==="collection_run");expect(receipts.length).toBeGreaterThan(0);const receipt=receipts[0].receipt;expect((await api.get(`http://127.0.0.1:8083/api/v1/ops/jobs/${receipt.job_id}`,{headers})).status()).toBe(200);expect((await api.get(`http://127.0.0.1:8083/api/v1/ops/runs/${receipt.run_id}`,{headers})).status()).toBe(200);
 await page.context().addCookies(cookies);await page.goto("/console/agent-audit");
 for(const locale of ["en","zh-CN"]){if(await page.locator("html").getAttribute("lang")!==locale)await page.getByRole("button",{name:locale==="en"?"EN":"中文",exact:true}).click();await expect(page.getByRole("region",{name:locale==="en"?"Agent event audit":"Agent 事件审计",exact:true})).toContainText(locale==="en"?"Repair completed":"恢复完成");await expect(page.locator(".agent-events")).toContainText(locale==="en"?"Local supervisor recovery":"本机自动监督恢复");}
 await page.getByLabel("显示",{exact:true}).selectOption("collection");await expect(page.locator(".agent-events")).toContainText("平台采集结果");await expect(page.locator(".agent-events")).not.toContainText("本机自动监督恢复");await page.getByLabel("显示",{exact:true}).selectOption("host");await expect(page.locator(".agent-events")).toContainText("本机自动监督恢复");
 await page.setViewportSize({width:390,height:844});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1)).toBe(true);expect(errors).toEqual([]);
 expect((await api.post(`${base}/collection`,{headers,data:{enabled:false,request_id:crypto.randomUUID()}})).status()).toBe(200);
 await pluginJob(api,protectionAsset,"banhack233","uninstall");
});
