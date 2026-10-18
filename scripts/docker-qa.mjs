import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { ownedCompose, removeUnusedQAImages, pruneOwnedQACache, removeLocalBuildHistory, inspectQAContainers } from "./qa-lifecycle.mjs";
import { createServer } from "node:net";
import { randomUUID } from "node:crypto";
import { mkdirSync, createWriteStream, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { createRequire } from "node:module";
import assert from "node:assert/strict";

const args = process.argv.slice(2), command = args.shift() ?? "verify";
if (!["up", "verify", "down"].includes(command)) throw new Error("Use up, verify or down");
if (command === "verify" && args.includes("--project")) throw new Error("verify always creates a fresh disposable project; use up for a named debug environment");
function option(name, fallback) {
  const i = args.indexOf(name);
  if (i < 0) return fallback;
  const value = args[i + 1];
  if (!value || value.startsWith("--")) throw new Error(`Missing ${name}`);
  args.splice(i, 2);
  return value;
}
const project = option("--project", command === "verify" ? `jms233-qa-${randomUUID()}` : "jms233-debug");
if (!/^jms233-[a-z0-9][a-z0-9-]{0,48}$/.test(project)) throw new Error("Project must use a jms233- prefix");
const host = option("--host", "127.0.0.2");
if (!/^127\.0\.0\.(?:[2-9]|[1-9]\d|1\d\d|2[0-4]\d|25[0-4])$/.test(host)) throw new Error("Use a dedicated loopback host from 127.0.0.2 through 127.0.0.254");
const peerURL = option("--peer-url", "");
if (peerURL) {
  const peer = new URL(peerURL);
  if (peer.protocol !== "http:" || !/^127\.0\.0\.\d+$/.test(peer.hostname) || peer.hostname === host || peer.username || peer.password || peer.pathname !== "/" || peer.search || peer.hash) throw new Error("Peer must use a different local loopback host");
}
function freePort() {
  return new Promise((done, reject) => {
    const socket = createServer();
    socket.once("error", reject);
    socket.listen(0, host, () => { const { port } = socket.address(); socket.close(() => done(String(port))); });
  });
}
const webPort = option("--web-port", command === "verify" ? await freePort() : "15173");
const apiPort = option("--api-port", command === "verify" ? await freePort() : "18080");
if (![webPort, apiPort].every(p => /^\d+$/.test(p) && Number(p) > 1024 && Number(p) < 65536) || webPort === apiPort) throw new Error("Use two distinct ports between 1025 and 65535");
const browser = args.includes("--browser");
if (browser) args.splice(args.indexOf("--browser"), 1);
if (peerURL && !browser) throw new Error("--peer-url requires --browser");
const keepData = args.includes("--keep-data");
if (keepData) args.splice(args.indexOf("--keep-data"), 1);
if (keepData && command !== "down") throw new Error("--keep-data applies only to explicit debug shutdown");
if (args.length) throw new Error(`Unknown options: ${args.join(" ")}`);
const cwd = fileURLToPath(new URL("..", import.meta.url));
const output = resolve(cwd, ".cache/docker-qa", project);
mkdirSync(output, { recursive: true });
const log = createWriteStream(resolve(output, "verify.log"), { flags: "a" });
const env = { ...process.env, JMS_QA_HOST: host, JMS_QA_WEB_PORT: webPort, JMS_QA_API_PORT: apiPort };
const compose = ["compose", "-f", "compose.qa.yml", "-p", project];
const execute = promisify(execFile);
const existing = (await execute("docker", ["ps", "--all", "--quiet", "--filter", `label=com.docker.compose.project=${project}`])).stdout.trim().split(/\s+/).filter(Boolean);
if ((await inspectQAContainers(execute, existing)).some(c => !ownedCompose(c, cwd))) throw new Error("QA project belongs to another workspace or configuration");
function docker(extra) {
  return new Promise((done, reject) => {
    const process = spawn("docker", [...compose, ...extra], { cwd, env, stdio: ["ignore", "pipe", "pipe"] });
    process.stdout.pipe(log, { end: false }); process.stderr.pipe(log, { end: false });
    process.once("error", reject);
    process.once("exit", code => code === 0 ? done() : reject(new Error(`Docker ${extra[0]} failed; inspect ${resolve(output, "verify.log")}`)));
  });
}
const webURL = `http://${host}:${webPort}`, apiURL = `http://${host}:${apiPort}`;
async function httpSmoke() {
  const get = async (path, init) => { const response = await fetch(path, { signal: AbortSignal.timeout(5000), ...init }); assert.ok(response.ok, `HTTP ${response.status}`); return response; };
  await get(`${apiURL}/api/health`); await get(`${webURL}/api/health`);
  assert.equal((await fetch(`${webURL}/api/v1/assets`)).status, 401);
  const html = await (await get(`${webURL}/login`)).text();
  const entry = html.match(/src="([^"]+\.js)"/)?.[1];
  assert.ok(entry, "Production entry is missing");
  const script = await get(`${webURL}${entry}`, { headers: { "Accept-Encoding": "gzip" } });
  assert.match(script.headers.get("Cache-Control") ?? "", /immutable/);
  assert.equal(script.headers.get("Content-Encoding"), "gzip");
  const login = await get(`${webURL}/api/v1/authentication/auth/`, { method: "POST", headers: { "Content-Type": "application/json", Origin: webURL }, body: JSON.stringify({ username: "root", password: "root" }) });
  const cookie = login.headers.getSetCookie().map(v => v.split(";")[0]).join("; ");
  assert.ok(cookie, "Browser session cookie is missing");
  const me = await (await get(`${webURL}/api/v1/users/me`, { headers: { Cookie: cookie } })).json();
  assert.equal(me.username, "root");
}
async function browserSmoke() {
  const { chromium, expect } = createRequire(new URL("../web/package.json", import.meta.url))("@playwright/test");
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ locale: "en-US" });
    const page = await context.newPage();
    const errors = []; page.on("pageerror", e => errors.push(e.message));
    await page.goto(`${webURL}/login`);
    await page.getByRole("textbox", { name: "Username", exact: true }).fill("root");
    await page.getByRole("textbox", { name: "Password", exact: true }).fill("root");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Assets", exact: true })).toBeVisible();
    if (peerURL) {
      const peer = await page.context().newPage();
      peer.on("pageerror", e => errors.push(e.message));
      await peer.goto(`${peerURL}/login`);
      await peer.getByRole("textbox", { name: "Username", exact: true }).fill("root");
      await peer.getByRole("textbox", { name: "Password", exact: true }).fill("root");
      await peer.getByRole("button", { name: "Sign in", exact: true }).click();
      await expect(peer.getByRole("heading", { name: "Assets", exact: true })).toBeVisible();
      await page.reload();
      await expect(page.getByRole("heading", { name: "Assets", exact: true })).toBeVisible();
      await peer.reload();
      await expect(peer.getByRole("heading", { name: "Assets", exact: true })).toBeVisible();
      await peer.close();
    }
    const loaded = []; page.on("request", r => { if (r.resourceType() === "script") loaded.push(r.url()); });
    await page.reload();
    await expect(page.getByRole("heading", { name: "Assets", exact: true })).toBeVisible();
    assert.ok(!loaded.some(url => /\/LoginPage-/.test(url)), "Authenticated console loaded login-only animation code");
    assert.ok(!loaded.some(url => /\/AccountRisksPage-/.test(url)), "Asset inventory loaded risk-only code");
    assert.ok(!loaded.some(url => /\/AccessTicketsPage-/.test(url)), "Asset inventory loaded ticket-only code");
    await page.screenshot({ path: resolve(output, "production.en.png") });
    await page.getByRole("button", { name: "中文", exact: true }).click();
    await expect(page.getByRole("heading", { name: "资产", exact: true })).toBeVisible();
    await page.screenshot({ path: resolve(output, "production.zh-CN.png") });
    await page.getByRole("link", { name: "账号风险", exact: true }).click();
    await expect(page.getByRole("heading", { name: "账号风险", exact: true })).toBeVisible();
    if (command === "verify") {
      // Only disposable clean volumes get a scan. Retained debug instances may
      // already have an owner-controlled periodic scan running.
      const posted = page.waitForResponse(r => r.url().endsWith("/api/v1/accounts/risks/scans") && r.request().method() === "POST");
      await page.getByRole("button", { name: "立即检测", exact: true }).click();
      const response = await posted;
      assert.equal(response.status(), 201);
      const receipt = await response.json();
      assert.equal(receipt.state, "succeeded");
      assert.equal(receipt.accounts, 0);
      await expect(page.getByRole("status").filter({ hasText: "检测完成" })).toBeVisible();
    }
    await page.screenshot({ path: resolve(output, "risks.zh-CN.png") });
    await page.getByRole("button", { name: "EN", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Account risks", exact: true })).toBeVisible();
    await page.screenshot({ path: resolve(output, "risks.en.png") });
    await page.goto(webURL+"/console/rotation-plans");
    await expect(page.getByRole("heading",{name:"Credential rotation plans",exact:true})).toBeVisible();
    await page.screenshot({path:resolve(output,"rotation.en.png")});
    await page.getByRole("button",{name:"中文",exact:true}).click();
    await expect(page.getByRole("heading",{name:"账号改密计划",exact:true})).toBeVisible();
    await page.screenshot({path:resolve(output,"rotation.zh-CN.png")});
    await page.goto(webURL+"/console/access-tickets");
    await expect(page.getByRole("heading",{name:"访问授权工单",exact:true})).toBeVisible();
    await expect(page.getByRole("button",{name:"创建审批规则",exact:true})).toBeVisible();
    await page.screenshot({path:resolve(output,"tickets.zh-CN.png")});
    await page.getByRole("button",{name:"EN",exact:true}).click();
    await expect(page.getByRole("heading",{name:"Access requests",exact:true})).toBeVisible();
    await page.screenshot({path:resolve(output,"tickets.en.png")});
    assert.deepEqual(errors, []);
  } finally { await browser.close(); }
}
const started = performance.now();
let built = 0, ready = 0;
let receipt = { project, webURL, apiURL, success: false, cleaned: false };
try {
  if (command === "down") { await docker(["down", ...(keepData ? [] : ["--volumes"]), "--remove-orphans"]); receipt.success = true; receipt.cleaned = !keepData; }
  else {
    console.log(`Docker QA ${project}: building with shared dependency caches`);
    await docker(["build"]); built = performance.now();
    await docker(["up", "--detach", "--wait", "--wait-timeout", "90"]); ready = performance.now();
    await httpSmoke();
    if (browser) await browserSmoke();
    receipt = { ...receipt, success: true, buildSeconds: +((built-started)/1000).toFixed(2), startupSeconds: +((ready-built)/1000).toFixed(2), smokeSeconds: +((performance.now()-ready)/1000).toFixed(2), browser, parallelBrowser: Boolean(peerURL), retained: command === "up" };
    console.log(JSON.stringify(receipt));
  }
} finally {
  try {
    if (command === "verify") { await docker(["down", "--volumes", "--remove-orphans"]); receipt.cleaned = true; }
    if (command === "verify" || command === "down" && !keepData) { await removeUnusedQAImages(promisify(execFile), [`${project}-api:latest`, `${project}-web:latest`]); receipt.removedBuildHistory = await removeLocalBuildHistory(execute, cwd); receipt.prunedCache = await pruneOwnedQACache(execute); }
  } finally {
    writeFileSync(resolve(output, "summary.json"), JSON.stringify(receipt, null, 2));
    writeFileSync(resolve(output, `summary-${Date.now()}.json`), JSON.stringify(receipt, null, 2));
    log.end();
  }
}
