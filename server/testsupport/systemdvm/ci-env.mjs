import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { isMissingDockerResource } from "../docker-qa.mjs";

if (!process.env.RUNNER_TEMP) throw new Error("RUNNER_TEMP required");
const file = resolve(process.env.RUNNER_TEMP, "jumpserver233-systemdvm-ci.json");
if (process.argv.includes("--cleanup")) {
  if (existsSync(file)) {
    const resource = JSON.parse(readFileSync(file, "utf8"));
    if (!/^jms233-systemdvm-[a-f0-9-]{36}$/.test(resource.name) || resource.owner !== resource.name)
      throw new Error("Invalid VM fixture owner");
    try {
      const labels = JSON.parse(execFileSync("docker", ["inspect", "--format", "{{json .Config.Labels}}", resource.name], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
      if (labels["com.jumpserver233.qa.owner"] !== resource.owner) throw new Error("VM owner changed");
      execFileSync("docker", ["rm", "--force", "--volumes", resource.name], { stdio: ["ignore", "pipe", "pipe"] });
    } catch (error) {
      if (!isMissingDockerResource(error)) throw error;
    }
  }
} else {
  if (!process.env.GITHUB_ENV) throw new Error("GITHUB_ENV required");
  const url = process.env.JMS_TEST_SYSTEMD_FIXTURE_URL || "http://127.0.0.1:12324/health";
  let ready = false;
  for (let attempt = 0; attempt < 900; attempt++) {
    try { const response = await fetch(url, { signal: AbortSignal.timeout(5000) }); if (response.ok) { ready = true; break; } } catch { /* Bounded VM boot. */ }
    await new Promise(resolveWait => setTimeout(resolveWait, 1000));
  }
  if (!ready) throw new Error("Systemd VM unavailable");
  appendFileSync(process.env.GITHUB_ENV, `JMS_TEST_SYSTEMD_FIXTURE_URL=${url}\n`);
}
