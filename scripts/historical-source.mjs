import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

// An immutable, already reviewed source baseline with activation protocol 1.
// These are local rehearsal packages, never official Release versions.
export const historicalBaseline = "4367285202054181344e386096b89e8ea3059703";
const sha = /^[a-f0-9]{64}$/;
export function verifyHistoricalManifests(before, after, head) {
  if (!/^[a-f0-9]{40}$/.test(head) || head === historicalBaseline || before.commit !== historicalBaseline || after.commit !== head) throw new Error("Historical rehearsal requires two distinct pinned source commits");
  for (const manifest of [before, after]) {
    if (manifest.schema !== 1 || manifest.platform !== "linux" || !["amd64", "arm64"].includes(manifest.architecture) || manifest.preflight_protocol !== 1 || manifest.activation_protocol !== 1) throw new Error("Historical package protocol or platform differs");
    for (const name of ["jms", "jms233-server", "web/index.html"]) if (!sha.test(manifest.files?.[name]?.sha256 || "")) throw new Error("Historical package is missing verified files");
  }
  if (before.architecture !== after.architecture || before.version !== "v0.0.0" || after.version !== "v0.0.1" || before.files["jms233-server"].sha256 === after.files["jms233-server"].sha256) throw new Error("Historical rehearsal requires different server bytes and monotonic rehearsal versions");
  return { sourceCommit: before.commit, targetCommit: after.commit, differentServerBytes: true, sourceVersion: before.version, targetVersion: after.version, officialRelease: false };
}

export async function prepareHistoricalPackage({ temporary, architecture, run, phase }) {
  if (!["amd64", "arm64"].includes(architecture)) throw new Error("Unsupported historical rehearsal architecture");
  phase("historical_source");
  await run("git", ["merge-base", "--is-ancestor", historicalBaseline, "HEAD"]);
  const source = resolve(temporary, "history"), exported = resolve(temporary, "history.tar");
  mkdirSync(source);
  await run("git", ["archive", "--format=tar", "--output", exported, historicalBaseline]);
  const sourceSHA256 = createHash("sha256").update(readFileSync(exported)).digest("hex");
  await run("tar", ["-xf", exported, "-C", source]);
  const server = resolve(source, "server"), web = resolve(source, "web");
  const builtAt = (await run("git", ["show", "-s", "--format=%cI", historicalBaseline])).stdout.trim();
  phase("historical_agents");
  await run("go", ["generate", "./internal/agentbundle"], { cwd: server });
  phase("historical_frontend");
  // Fixed command text only; cwd is passed separately, including on Windows.
  await run("pnpm install --frozen-lockfile", [], { cwd: web, shell: true });
  await run("pnpm build", [], { cwd: web, shell: true });
  phase("historical_native");
  const packages = resolve(temporary, "historical-packages");
  await run("go", ["run", "./cmd/jms-package", "--version", "v0.0.0", "--commit", historicalBaseline, "--built-at", builtAt, "--target", `linux/${architecture}`, "--out", packages, "--web-dir", resolve(web, "dist")], { cwd: server });
  const archive = resolve(packages, `jumpserver233-v0.0.0-linux-${architecture}.tar.gz`);
  const manifest = JSON.parse((await run("tar", ["-xOf", archive, "manifest.json"])).stdout);
  if (manifest.commit !== historicalBaseline) throw new Error("Historical source provenance differs");
  return { archive, manifest, sourceSHA256, archiveSHA256: createHash("sha256").update(readFileSync(archive)).digest("hex"), builtAt };
}
